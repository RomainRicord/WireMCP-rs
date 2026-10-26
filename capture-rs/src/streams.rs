use std::collections::HashMap;

use crate::Cli;
use crate::parsers::{u16be, u32be, ip4_fmt, ip6_fmt, dns_name, jesc, ipv4_non_first_frag};
use crate::capture::capture_basic;

/// TCP stream tracker
struct TcpStream {
    src: String,
    dst: String,
    src_port: u16,
    dst_port: u16,
    payload: Vec<u8>,        // reassembled payload (forward direction)
    rev_payload: Vec<u8>,    // reverse direction payload
    packet_times: Vec<f64>,  // timestamps for beacon detection
    packet_count: u64,
    bytes: u64,
    first_seen: f64,
    last_seen: f64,
}

/// DNS query record for tunneling/DGA analysis
struct DnsRecord {
    domain: String,
    query_type: u16,
    src_ip: String,
    time: f64,
}

/// Calculate Shannon entropy of a byte slice (0.0 = uniform, 8.0 = max random)
fn entropy(data: &[u8]) -> f64 {
    if data.is_empty() { return 0.0; }
    let mut freq = [0u64; 256];
    for &b in data { freq[b as usize] += 1; }
    let len = data.len() as f64;
    let mut ent = 0.0f64;
    for &f in &freq {
        if f > 0 {
            let p = f as f64 / len;
            ent -= p * p.log2();
        }
    }
    ent
}

/// Check payload for suspicious patterns
fn detect_patterns(payload: &[u8]) -> Vec<&'static str> {
    let mut found = Vec::new();
    if payload.len() < 4 { return found; }

    // Shell patterns
    let text = String::from_utf8_lossy(&payload[..payload.len().min(4096)]);
    let text_lower = text.to_lowercase();

    if text_lower.contains("/bin/sh") || text_lower.contains("/bin/bash") || text_lower.contains("/bin/zsh") {
        found.push("SHELL_REFERENCE");
    }
    if text_lower.contains("whoami") || text_lower.contains("id;") || text_lower.contains("uname -a") {
        found.push("RECON_COMMAND");
    }
    if text_lower.contains("wget ") || text_lower.contains("curl ") {
        if text_lower.contains("|") || text_lower.contains("| sh") || text_lower.contains("| bash") {
            found.push("DOWNLOAD_AND_EXEC");
        }
    }
    if text_lower.contains("nc -e") || text_lower.contains("ncat -e") || text_lower.contains("netcat") {
        found.push("NETCAT_SHELL");
    }
    if text_lower.contains("python -c") || text_lower.contains("python3 -c") || text_lower.contains("perl -e") {
        if text_lower.contains("socket") || text_lower.contains("connect") {
            found.push("SCRIPTED_REVERSE_SHELL");
        }
    }
    if text_lower.contains("powershell") && (text_lower.contains("-enc") || text_lower.contains("invoke-")) {
        found.push("POWERSHELL_PAYLOAD");
    }

    // Base64 encoded data detection (long base64 strings in otherwise text content)
    if payload.iter().filter(|&&b| b == b'=').count() > 0 {
        let b64_chars = payload.iter().filter(|&&b| b.is_ascii_alphanumeric() || b == b'+' || b == b'/' || b == b'=').count();
        if b64_chars > payload.len() * 80 / 100 && payload.len() > 100 {
            found.push("BASE64_PAYLOAD");
        }
    }

    // ELF magic
    if payload.starts_with(&[0x7f, 0x45, 0x4c, 0x46]) {
        found.push("ELF_BINARY");
    }
    // PE magic
    if payload.starts_with(b"MZ") {
        found.push("PE_BINARY");
    }

    found
}

/// Detect what protocol the payload actually is (regardless of port)
fn detect_actual_protocol(payload: &[u8]) -> &'static str {
    if payload.is_empty() { return "empty"; }
    if payload.len() > 5 && payload[0] == 0x16 && payload[1] == 0x03 { return "tls"; }
    if payload.starts_with(b"SSH-") { return "ssh"; }
    if payload.starts_with(b"GET ") || payload.starts_with(b"POST ") ||
       payload.starts_with(b"PUT ") || payload.starts_with(b"HEAD ") ||
       payload.starts_with(b"HTTP/") { return "http"; }
    if payload.len() >= 12 {
        // DNS heuristic: valid header structure
        let qdcount = u16be(payload, 4);
        let ancount = u16be(payload, 6);
        if qdcount >= 1 && qdcount <= 10 && ancount <= 100 {
            if let Some((name, _)) = dns_name(payload, 12) {
                if name.contains('.') && name.len() > 3 { return "dns"; }
            }
        }
    }
    if payload.starts_with(b"\x00\x00\x00") && payload.len() > 20 { return "smb"; }
    "unknown"
}

/// Expected protocol for a given port
fn expected_protocol(port: u16) -> &'static str {
    match port {
        22 => "ssh",
        53 => "dns",
        80 | 8080 | 8000 => "http",
        443 | 8443 => "tls",
        445 => "smb",
        _ => "any"
    }
}

/// Detect C2 beacon pattern: regular time intervals between packets
fn detect_beacon(times: &[f64]) -> Option<(f64, f64)> {
    if times.len() < 5 { return None; }

    let mut intervals: Vec<f64> = Vec::new();
    for i in 1..times.len() {
        let diff = times[i] - times[i - 1];
        if diff > 0.01 { intervals.push(diff); }
    }
    if intervals.len() < 4 { return None; }

    let avg = intervals.iter().sum::<f64>() / intervals.len() as f64;
    if avg < 0.5 { return None; } // Too fast to be a beacon

    let variance = intervals.iter().map(|&i| (i - avg).powi(2)).sum::<f64>() / intervals.len() as f64;
    let std_dev = variance.sqrt();
    let jitter = if avg > 0.0 { std_dev / avg } else { 1.0 };

    // Low jitter = regular intervals = likely beacon
    if jitter < 0.15 && avg > 1.0 {
        Some((avg, jitter))
    } else {
        None
    }
}

/// Analyze DNS queries for tunneling and DGA
fn analyze_dns(records: &[DnsRecord]) -> Vec<String> {
    let mut alerts = Vec::new();

    // Group by base domain
    let mut domain_stats: HashMap<String, Vec<&DnsRecord>> = HashMap::new();
    for r in records {
        let parts: Vec<&str> = r.domain.split('.').collect();
        let base = if parts.len() >= 2 {
            format!("{}.{}", parts[parts.len() - 2], parts[parts.len() - 1])
        } else {
            r.domain.clone()
        };
        domain_stats.entry(base).or_default().push(r);
    }

    for (base_domain, queries) in &domain_stats {
        // DNS Tunneling: long subdomains with high entropy
        let subdomains: Vec<&str> = queries.iter()
            .filter_map(|r| {
                let sub = r.domain.strip_suffix(&format!(".{}", base_domain))?;
                Some(sub)
            })
            .collect();

        if !subdomains.is_empty() {
            let avg_len = subdomains.iter().map(|s| s.len()).sum::<usize>() as f64 / subdomains.len() as f64;
            let avg_entropy = subdomains.iter()
                .map(|s| entropy(s.as_bytes()))
                .sum::<f64>() / subdomains.len() as f64;

            // Long subdomains + high entropy = tunneling
            if avg_len > 25.0 && avg_entropy > 3.5 {
                alerts.push(format!("{{\"type\":\"DNS_TUNNELING\",\"severity\":\"CRITICAL\",\"domain\":\"{}\",\"avg_subdomain_length\":{:.0},\"avg_entropy\":{:.2},\"query_count\":{},\"sample_subdomains\":[{}]}}",
                    jesc(base_domain), avg_len, avg_entropy, queries.len(),
                    subdomains.iter().take(3).map(|s| format!("\"{}\"", jesc(s))).collect::<Vec<_>>().join(",")));
            }

            // Many unique subdomains = potential tunneling or DGA
            let unique_subs: std::collections::HashSet<&&str> = subdomains.iter().collect();
            if unique_subs.len() > 30 && queries.len() > 40 {
                alerts.push(format!("{{\"type\":\"DNS_HIGH_SUBDOMAIN_COUNT\",\"severity\":\"HIGH\",\"domain\":\"{}\",\"unique_subdomains\":{},\"total_queries\":{}}}",
                    jesc(base_domain), unique_subs.len(), queries.len()));
            }
        }

        // DGA detection: many unique random-looking domains queried
        if queries.len() == 1 {
            let domain = &queries[0].domain;
            let parts: Vec<&str> = domain.split('.').collect();
            if parts.len() >= 2 {
                let name_part = parts[0];
                if name_part.len() > 8 {
                    let ent = entropy(name_part.as_bytes());
                    let consonant_ratio = name_part.chars()
                        .filter(|c| !"aeiou".contains(*c) && c.is_ascii_lowercase())
                        .count() as f64 / name_part.len() as f64;

                    if ent > 3.5 && consonant_ratio > 0.7 {
                        alerts.push(format!("{{\"type\":\"DGA_SUSPECT\",\"severity\":\"HIGH\",\"domain\":\"{}\",\"entropy\":{:.2},\"consonant_ratio\":{:.2}}}",
                            jesc(domain), ent, consonant_ratio));
                    }
                }
            }
        }
    }

    // Deduplicate DGA alerts — if too many, summarize
    let dga_count = alerts.iter().filter(|a| a.contains("DGA_SUSPECT")).count();
    if dga_count > 10 {
        let dga_alerts: Vec<String> = alerts.iter().filter(|a| a.contains("DGA_SUSPECT")).take(5).cloned().collect();
        alerts.retain(|a| !a.contains("DGA_SUSPECT"));
        alerts.push(format!("{{\"type\":\"DGA_PATTERN\",\"severity\":\"CRITICAL\",\"total_dga_domains\":{},\"samples\":[{}]}}",
            dga_count, dga_alerts.join(",")));
    }

    alerts
}

/// Main stream analysis entry point
pub fn run_streams(cli: &Cli) {
    eprintln!("[streams] Analyzing streams on {} for {}s...", cli.interface, cli.duration);

    let mut tcp_streams: HashMap<String, TcpStream> = HashMap::new();
    let mut dns_records: Vec<DnsRecord> = Vec::new();
    let mut total_pkts = 0u64;

    capture_basic(cli, |data, time| {
        total_pkts += 1;
        if data.len() < 14 { return; }

        let ethertype = u16be(data, 12);
        let mut payload = &data[14..];
        let ethertype = if ethertype == 0x8100 && payload.len() >= 4 {
            let et = u16be(payload, 2); payload = &payload[4..]; et
        } else { ethertype };

        let (src_ip, dst_ip, proto, ip_payload) = match ethertype {
            0x0800 if payload.len() >= 20 => {
                let ihl = (payload[0] & 0x0F) as usize * 4;
                // Non-first fragments carry no L4 header: empty payload so no ports are read
                let l4 = if ipv4_non_first_frag(payload) { &payload[..0] } else { &payload[ihl.min(payload.len())..] };
                (ip4_fmt(&payload[12..16]), ip4_fmt(&payload[16..20]), payload[9], l4)
            }
            0x86DD if payload.len() >= 40 => {
                (ip6_fmt(&payload[8..24]), ip6_fmt(&payload[24..40]),
                 payload[6], &payload[40..])
            }
            _ => return,
        };

        match proto {
            6 if ip_payload.len() >= 20 => {
                let sp = u16be(ip_payload, 0);
                let dp = u16be(ip_payload, 2);
                let doff = ((ip_payload[12] >> 4) as usize) * 4;

                // Stream key: normalize direction
                let (key, is_forward) = {
                    let a = format!("{}:{}", src_ip, sp);
                    let b = format!("{}:{}", dst_ip, dp);
                    if a <= b { (format!("{}->{}", a, b), true) } else { (format!("{}->{}", b, a), false) }
                };

                let stream = tcp_streams.entry(key).or_insert_with(|| TcpStream {
                    src: if is_forward { src_ip.clone() } else { dst_ip.clone() },
                    dst: if is_forward { dst_ip.clone() } else { src_ip.clone() },
                    src_port: if is_forward { sp } else { dp },
                    dst_port: if is_forward { dp } else { sp },
                    payload: Vec::new(),
                    rev_payload: Vec::new(),
                    packet_times: Vec::new(),
                    packet_count: 0,
                    bytes: 0,
                    first_seen: time,
                    last_seen: time,
                });

                stream.packet_count += 1;
                stream.bytes += data.len() as u64;
                stream.last_seen = time;
                stream.packet_times.push(time);

                // Collect payload (cap at 32KB per direction)
                if doff < ip_payload.len() {
                    let app_data = &ip_payload[doff..];
                    if !app_data.is_empty() {
                        if is_forward && stream.payload.len() < 32768 {
                            let take = app_data.len().min(32768 - stream.payload.len());
                            stream.payload.extend_from_slice(&app_data[..take]);
                        } else if !is_forward && stream.rev_payload.len() < 32768 {
                            let take = app_data.len().min(32768 - stream.rev_payload.len());
                            stream.rev_payload.extend_from_slice(&app_data[..take]);
                        }
                    }
                }
            }
            17 if ip_payload.len() >= 8 => {
                let sp = u16be(ip_payload, 0);
                let dp = u16be(ip_payload, 2);
                let udp_payload = &ip_payload[8..];

                // DNS record collection
                if (sp == 53 || dp == 53) && udp_payload.len() >= 12 {
                    let flags = u16be(udp_payload, 2);
                    let is_query = (flags & 0x8000) == 0;
                    if is_query {
                        if let Some((name, _)) = dns_name(udp_payload, 12) {
                            let qtype = if udp_payload.len() > 14 {
                                // Skip past the name to get qtype
                                let mut off = 12;
                                loop {
                                    if off >= udp_payload.len() { break 0; }
                                    let b = udp_payload[off];
                                    if b == 0 { off += 1; break if off + 2 <= udp_payload.len() { u16be(udp_payload, off) } else { 0 }; }
                                    if b & 0xC0 == 0xC0 { off += 2; break if off + 2 <= udp_payload.len() { u16be(udp_payload, off) } else { 0 }; }
                                    off += 1 + b as usize;
                                }
                            } else { 0 };

                            dns_records.push(DnsRecord {
                                domain: name,
                                query_type: qtype,
                                src_ip: src_ip.clone(),
                                time,
                            });
                        }
                    }
                }
            }
            _ => {}
        }
    });

    eprintln!("[streams] {} packets, {} TCP streams, {} DNS queries",
        total_pkts, tcp_streams.len(), dns_records.len());

    // --- Analyze each TCP stream ---
    let mut stream_alerts: Vec<String> = Vec::new();
    let mut stream_results: Vec<String> = Vec::new();

    for (key, stream) in &tcp_streams {
        let mut alerts_for_stream: Vec<String> = Vec::new();

        // 1. Protocol detection (must come first, used by entropy check)
        let actual_fwd = detect_actual_protocol(&stream.payload);
        let actual_rev = detect_actual_protocol(&stream.rev_payload);
        let actual = if actual_fwd != "unknown" && actual_fwd != "empty" { actual_fwd } else { actual_rev };

        // 2. Entropy analysis
        let fwd_entropy = entropy(&stream.payload);
        let rev_entropy = entropy(&stream.rev_payload);

        // High entropy on non-TLS/SSH ports = suspicious (skip known encrypted protocols)
        let expected_dst = expected_protocol(stream.dst_port);
        let expected_src = expected_protocol(stream.src_port);
        let is_encrypted_proto = expected_dst == "tls" || expected_dst == "ssh"
            || expected_src == "tls" || expected_src == "ssh"
            || actual == "tls" || actual == "ssh";

        if fwd_entropy > 7.0 && !is_encrypted_proto && stream.payload.len() > 100 {
            alerts_for_stream.push(format!("\"HIGH_ENTROPY_OUTBOUND ({:.2})\"", fwd_entropy));
        }

        // 3. Protocol mismatch
        let expected = expected_protocol(stream.dst_port);
        if expected != "any" && actual != "unknown" && actual != "empty" && actual != expected {
            alerts_for_stream.push(format!("\"PROTOCOL_MISMATCH (port {} expects {}, got {})\"", stream.dst_port, expected, actual));
        }

        // 4. Pattern matching on payloads
        let fwd_patterns = detect_patterns(&stream.payload);
        let rev_patterns = detect_patterns(&stream.rev_payload);
        for pat in fwd_patterns.iter().chain(rev_patterns.iter()) {
            alerts_for_stream.push(format!("\"{}\"", pat));
        }

        // 5. Beacon detection
        if let Some((interval, jitter)) = detect_beacon(&stream.packet_times) {
            alerts_for_stream.push(format!("\"C2_BEACON (interval={:.1}s, jitter={:.2})\"", interval, jitter));
        }

        // Build stream result
        let severity = if alerts_for_stream.iter().any(|a| a.contains("SHELL") || a.contains("C2_BEACON") || a.contains("REVERSE_SHELL") || a.contains("DOWNLOAD_AND_EXEC")) {
            "CRITICAL"
        } else if !alerts_for_stream.is_empty() {
            if alerts_for_stream.iter().any(|a| a.contains("PROTOCOL_MISMATCH") || a.contains("HIGH_ENTROPY")) { "HIGH" } else { "MEDIUM" }
        } else {
            "CLEAN"
        };

        let payload_preview = if !stream.payload.is_empty() {
            let preview_bytes = &stream.payload[..stream.payload.len().min(64)];
            let hex: String = preview_bytes.iter().map(|b| format!("{:02x}", b)).collect::<Vec<_>>().join("");
            format!("\"{}\"", jesc(&hex))
        } else {
            "null".into()
        };

        stream_results.push(format!(
            "{{\"id\":\"{}\",\"src\":\"{}:{}\",\"dst\":\"{}:{}\",\"packets\":{},\"bytes\":{},\"duration\":{:.2},\"protocol_detected\":\"{}\",\"fwd_entropy\":{:.2},\"rev_entropy\":{:.2},\"fwd_payload_size\":{},\"rev_payload_size\":{},\"severity\":\"{}\",\"alerts\":[{}],\"payload_hex_preview\":{}}}",
            jesc(key), jesc(&stream.src), stream.src_port,
            jesc(&stream.dst), stream.dst_port,
            stream.packet_count, stream.bytes,
            stream.last_seen - stream.first_seen,
            actual,
            fwd_entropy, rev_entropy,
            stream.payload.len(), stream.rev_payload.len(),
            severity,
            alerts_for_stream.join(","),
            payload_preview
        ));

        if severity != "CLEAN" {
            for alert in &alerts_for_stream {
                stream_alerts.push(format!("{{\"stream\":\"{}:{} -> {}:{}\",\"alert\":{}}}",
                    jesc(&stream.src), stream.src_port,
                    jesc(&stream.dst), stream.dst_port,
                    alert));
            }
        }
    }

    // --- DNS analysis ---
    let dns_alerts = analyze_dns(&dns_records);

    // --- Output ---
    // Sort streams: alerts first, then by bytes
    stream_results.sort_by(|a, b| {
        let a_clean = a.contains("\"CLEAN\"");
        let b_clean = b.contains("\"CLEAN\"");
        if a_clean != b_clean { return a_clean.cmp(&b_clean); }
        // By bytes descending (rough)
        b.len().cmp(&a.len())
    });

    let total_alerts = stream_alerts.len() + dns_alerts.len();

    println!("{{");
    println!("  \"total_packets\": {},", total_pkts);
    println!("  \"tcp_streams\": {},", tcp_streams.len());
    println!("  \"dns_queries\": {},", dns_records.len());
    println!("  \"total_alerts\": {},", total_alerts);
    println!("  \"status\": \"{}\",", if total_alerts == 0 { "CLEAN" } else { "THREATS_DETECTED" });

    // Stream details (limit to 50)
    println!("  \"streams\": [");
    let limit = stream_results.len().min(50);
    for (i, s) in stream_results.iter().take(limit).enumerate() {
        let comma = if i < limit - 1 { "," } else { "" };
        println!("    {}{}", s, comma);
    }
    println!("  ],");

    // Stream alerts
    println!("  \"stream_alerts\": [");
    for (i, a) in stream_alerts.iter().enumerate() {
        let comma = if i < stream_alerts.len() - 1 { "," } else { "" };
        println!("    {}{}", a, comma);
    }
    println!("  ],");

    // DNS alerts
    println!("  \"dns_alerts\": [");
    for (i, a) in dns_alerts.iter().enumerate() {
        let comma = if i < dns_alerts.len() - 1 { "," } else { "" };
        println!("    {}{}", a, comma);
    }
    println!("  ]");

    println!("}}");
}
