use std::collections::{HashMap, HashSet};
use std::fs;

use crate::Cli;
use crate::parsers::{u16be, ip4_fmt, ip6_fmt, dns_name, jesc, ipv4_non_first_frag};
use crate::capture::capture_basic;

/// Baseline profile built from "normal" traffic
struct Profile {
    duration: f64,
    total_pkts: u64,
    total_bytes: u64,
    known_ips: HashSet<String>,
    known_ports: HashSet<u16>,
    known_protocols: HashSet<String>,
    known_dns_domains: HashSet<String>,
    packet_sizes: Vec<u64>,
    connections_per_sec: Vec<u64>,
    dns_queries_per_sec: Vec<u64>,
    bytes_per_sec: Vec<u64>,
}

impl Profile {
    fn avg_packet_size(&self) -> f64 {
        if self.packet_sizes.is_empty() { return 0.0; }
        self.packet_sizes.iter().sum::<u64>() as f64 / self.packet_sizes.len() as f64
    }
    fn std_packet_size(&self) -> f64 {
        if self.packet_sizes.len() < 2 { return 0.0; }
        let avg = self.avg_packet_size();
        let var = self.packet_sizes.iter().map(|&s| { let d = s as f64 - avg; d * d }).sum::<f64>() / self.packet_sizes.len() as f64;
        var.sqrt()
    }
    fn avg_conns_per_sec(&self) -> f64 {
        if self.connections_per_sec.is_empty() { return 0.0; }
        self.connections_per_sec.iter().sum::<u64>() as f64 / self.connections_per_sec.len() as f64
    }
    fn max_conns_per_sec(&self) -> u64 {
        self.connections_per_sec.iter().copied().max().unwrap_or(0)
    }
    fn avg_dns_per_sec(&self) -> f64 {
        if self.dns_queries_per_sec.is_empty() { return 0.0; }
        self.dns_queries_per_sec.iter().sum::<u64>() as f64 / self.dns_queries_per_sec.len() as f64
    }
    fn avg_bytes_per_sec(&self) -> f64 {
        if self.bytes_per_sec.is_empty() { return 0.0; }
        self.bytes_per_sec.iter().sum::<u64>() as f64 / self.bytes_per_sec.len() as f64
    }
    fn max_bytes_per_sec(&self) -> u64 {
        self.bytes_per_sec.iter().copied().max().unwrap_or(0)
    }

    fn to_json(&self) -> String {
        let ips: Vec<String> = self.known_ips.iter().map(|s| format!("\"{}\"", jesc(s))).collect();
        let ports: Vec<String> = self.known_ports.iter().map(|p| p.to_string()).collect();
        let protos: Vec<String> = self.known_protocols.iter().map(|s| format!("\"{}\"", jesc(s))).collect();
        let domains: Vec<String> = self.known_dns_domains.iter().map(|s| format!("\"{}\"", jesc(s))).collect();

        format!(r#"{{
  "duration": {:.1},
  "total_packets": {},
  "total_bytes": {},
  "avg_packet_size": {:.1},
  "std_packet_size": {:.1},
  "avg_connections_per_sec": {:.1},
  "max_connections_per_sec": {},
  "avg_dns_queries_per_sec": {:.1},
  "avg_bytes_per_sec": {:.0},
  "max_bytes_per_sec": {},
  "known_ips": [{}],
  "known_ports": [{}],
  "known_protocols": [{}],
  "known_dns_domains": [{}]
}}"#,
            self.duration, self.total_pkts, self.total_bytes,
            self.avg_packet_size(), self.std_packet_size(),
            self.avg_conns_per_sec(), self.max_conns_per_sec(),
            self.avg_dns_per_sec(),
            self.avg_bytes_per_sec(), self.max_bytes_per_sec(),
            ips.join(", "), ports.join(", "),
            protos.join(", "), domains.join(", "))
    }
}

/// Build a baseline profile from captured traffic
pub fn run_baseline(cli: &Cli) {
    let output_file = std::env::var("BASELINE_OUTPUT").unwrap_or_else(|_| "baseline.json".into());
    eprintln!("[baseline] Building profile on {} for {}s...", cli.interface, cli.duration);

    let mut profile = Profile {
        duration: 0.0,
        total_pkts: 0,
        total_bytes: 0,
        known_ips: HashSet::new(),
        known_ports: HashSet::new(),
        known_protocols: HashSet::new(),
        known_dns_domains: HashSet::new(),
        packet_sizes: Vec::new(),
        connections_per_sec: Vec::new(),
        dns_queries_per_sec: Vec::new(),
        bytes_per_sec: Vec::new(),
    };

    let mut conns_buckets: HashMap<u64, u64> = HashMap::new();
    let mut dns_buckets: HashMap<u64, u64> = HashMap::new();
    let mut bytes_buckets: HashMap<u64, u64> = HashMap::new();
    let mut last_time = 0.0f64;

    capture_basic(cli, |data, time| {
        profile.total_pkts += 1;
        profile.total_bytes += data.len() as u64;
        profile.packet_sizes.push(data.len() as u64);
        last_time = time;
        let bucket = time as u64;
        *bytes_buckets.entry(bucket).or_default() += data.len() as u64;

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

        profile.known_ips.insert(src_ip);
        profile.known_ips.insert(dst_ip);

        match proto {
            6 if ip_payload.len() >= 20 => {
                let sp = u16be(ip_payload, 0);
                let dp = u16be(ip_payload, 2);
                let flags = ip_payload[13];
                profile.known_ports.insert(sp);
                profile.known_ports.insert(dp);
                profile.known_protocols.insert("tcp".into());

                // Count new connections (SYN)
                if (flags & 0x02) != 0 && (flags & 0x10) == 0 {
                    *conns_buckets.entry(bucket).or_default() += 1;
                }

                // Detect app protocol
                let doff = ((ip_payload[12] >> 4) as usize) * 4;
                if doff < ip_payload.len() {
                    let app = &ip_payload[doff..];
                    if app.len() > 1 && app[0] == 0x16 {
                        profile.known_protocols.insert("tls".into());
                    } else if app.starts_with(b"GET ") || app.starts_with(b"POST ") || app.starts_with(b"HTTP/") {
                        profile.known_protocols.insert("http".into());
                    }
                    if sp == 22 || dp == 22 { profile.known_protocols.insert("ssh".into()); }
                }
            }
            17 if ip_payload.len() >= 8 => {
                let sp = u16be(ip_payload, 0);
                let dp = u16be(ip_payload, 2);
                profile.known_ports.insert(sp);
                profile.known_ports.insert(dp);
                profile.known_protocols.insert("udp".into());

                if sp == 53 || dp == 53 {
                    profile.known_protocols.insert("dns".into());
                    *dns_buckets.entry(bucket).or_default() += 1;

                    // Extract domain
                    let dns_data = &ip_payload[8..];
                    if dns_data.len() >= 12 {
                        if let Some((name, _)) = dns_name(dns_data, 12) {
                            profile.known_dns_domains.insert(name);
                        }
                    }
                }
            }
            1 | 58 => { profile.known_protocols.insert("icmp".into()); }
            _ => {}
        }
    });

    profile.duration = last_time;
    profile.connections_per_sec = conns_buckets.values().copied().collect();
    profile.dns_queries_per_sec = dns_buckets.values().copied().collect();
    profile.bytes_per_sec = bytes_buckets.values().copied().collect();

    let json = profile.to_json();
    match fs::write(&output_file, &json) {
        Ok(_) => eprintln!("[baseline] Profile saved to {}", output_file),
        Err(e) => eprintln!("[baseline] Error writing {}: {}", output_file, e),
    }
    println!("{}", json);
}

/// Simple JSON value parser for baseline files (no serde dependency)
struct BaselineData {
    known_ips: HashSet<String>,
    known_ports: HashSet<u16>,
    known_protocols: HashSet<String>,
    known_dns_domains: HashSet<String>,
    avg_packet_size: f64,
    std_packet_size: f64,
    max_connections_per_sec: u64,
    avg_dns_queries_per_sec: f64,
    max_bytes_per_sec: u64,
}

fn parse_json_string_array(json: &str, key: &str) -> HashSet<String> {
    let mut result = HashSet::new();
    if let Some(start) = json.find(&format!("\"{}\":", key)) {
        let rest = &json[start..];
        if let Some(arr_start) = rest.find('[') {
            if let Some(arr_end) = rest[arr_start..].find(']') {
                let arr = &rest[arr_start + 1..arr_start + arr_end];
                for item in arr.split(',') {
                    let trimmed = item.trim().trim_matches('"');
                    if !trimmed.is_empty() {
                        result.insert(trimmed.to_string());
                    }
                }
            }
        }
    }
    result
}

fn parse_json_u16_array(json: &str, key: &str) -> HashSet<u16> {
    let mut result = HashSet::new();
    if let Some(start) = json.find(&format!("\"{}\":", key)) {
        let rest = &json[start..];
        if let Some(arr_start) = rest.find('[') {
            if let Some(arr_end) = rest[arr_start..].find(']') {
                let arr = &rest[arr_start + 1..arr_start + arr_end];
                for item in arr.split(',') {
                    if let Ok(n) = item.trim().parse::<u16>() {
                        result.insert(n);
                    }
                }
            }
        }
    }
    result
}

fn parse_json_f64(json: &str, key: &str) -> f64 {
    if let Some(start) = json.find(&format!("\"{}\":", key)) {
        let rest = &json[start + key.len() + 3..];
        let val = rest.trim().split(|c: char| c == ',' || c == '\n' || c == '}').next().unwrap_or("0");
        val.trim().parse::<f64>().unwrap_or(0.0)
    } else { 0.0 }
}

fn parse_json_u64(json: &str, key: &str) -> u64 {
    parse_json_f64(json, key) as u64
}

fn load_baseline(path: &str) -> Option<BaselineData> {
    let json = fs::read_to_string(path).ok()?;
    Some(BaselineData {
        known_ips: parse_json_string_array(&json, "known_ips"),
        known_ports: parse_json_u16_array(&json, "known_ports"),
        known_protocols: parse_json_string_array(&json, "known_protocols"),
        known_dns_domains: parse_json_string_array(&json, "known_dns_domains"),
        avg_packet_size: parse_json_f64(&json, "avg_packet_size"),
        std_packet_size: parse_json_f64(&json, "std_packet_size"),
        max_connections_per_sec: parse_json_u64(&json, "max_connections_per_sec"),
        avg_dns_queries_per_sec: parse_json_f64(&json, "avg_dns_queries_per_sec"),
        max_bytes_per_sec: parse_json_u64(&json, "max_bytes_per_sec"),
    })
}

/// Compare live traffic against a baseline and detect anomalies
pub fn run_anomaly(cli: &Cli) {
    let baseline_file = std::env::var("BASELINE_FILE").unwrap_or_else(|_| "baseline.json".into());
    let baseline = match load_baseline(&baseline_file) {
        Some(b) => b,
        None => {
            eprintln!("Error: Cannot load baseline from {}. Run with --mode baseline first.", baseline_file);
            std::process::exit(1);
        }
    };

    eprintln!("[anomaly] Loaded baseline ({} IPs, {} ports, {} domains)",
        baseline.known_ips.len(), baseline.known_ports.len(), baseline.known_dns_domains.len());
    eprintln!("[anomaly] Monitoring on {} for {}s...", cli.interface, cli.duration);

    let mut alerts: Vec<String> = Vec::new();
    let mut new_ips: HashSet<String> = HashSet::new();
    let mut new_ports: HashSet<u16> = HashSet::new();
    let mut new_protocols: HashSet<String> = HashSet::new();
    let mut new_dns_domains: HashSet<String> = HashSet::new();
    let mut conns_buckets: HashMap<u64, u64> = HashMap::new();
    let mut dns_buckets: HashMap<u64, u64> = HashMap::new();
    let mut bytes_buckets: HashMap<u64, u64> = HashMap::new();
    let mut total_pkts = 0u64;
    let mut total_bytes = 0u64;
    let mut packet_sizes: Vec<u64> = Vec::new();

    capture_basic(cli, |data, time| {
        total_pkts += 1;
        total_bytes += data.len() as u64;
        packet_sizes.push(data.len() as u64);
        let bucket = time as u64;
        *bytes_buckets.entry(bucket).or_default() += data.len() as u64;

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

        // Check for new IPs
        if !baseline.known_ips.contains(&src_ip) { new_ips.insert(src_ip.clone()); }
        if !baseline.known_ips.contains(&dst_ip) { new_ips.insert(dst_ip.clone()); }

        match proto {
            6 if ip_payload.len() >= 20 => {
                let sp = u16be(ip_payload, 0);
                let dp = u16be(ip_payload, 2);
                let flags = ip_payload[13];

                if !baseline.known_ports.contains(&sp) { new_ports.insert(sp); }
                if !baseline.known_ports.contains(&dp) { new_ports.insert(dp); }

                if (flags & 0x02) != 0 && (flags & 0x10) == 0 {
                    *conns_buckets.entry(bucket).or_default() += 1;
                }

                let doff = ((ip_payload[12] >> 4) as usize) * 4;
                if doff < ip_payload.len() {
                    let app = &ip_payload[doff..];
                    if app.len() > 1 && app[0] == 0x16 && !baseline.known_protocols.contains("tls") {
                        new_protocols.insert("tls".into());
                    }
                    if (app.starts_with(b"GET ") || app.starts_with(b"POST ")) && !baseline.known_protocols.contains("http") {
                        new_protocols.insert("http".into());
                    }
                }
            }
            17 if ip_payload.len() >= 8 => {
                let sp = u16be(ip_payload, 0);
                let dp = u16be(ip_payload, 2);
                if !baseline.known_ports.contains(&sp) { new_ports.insert(sp); }
                if !baseline.known_ports.contains(&dp) { new_ports.insert(dp); }

                if sp == 53 || dp == 53 {
                    *dns_buckets.entry(bucket).or_default() += 1;
                    let dns_data = &ip_payload[8..];
                    if dns_data.len() >= 12 {
                        if let Some((name, _)) = dns_name(dns_data, 12) {
                            if !baseline.known_dns_domains.contains(&name) {
                                new_dns_domains.insert(name);
                            }
                        }
                    }
                }
            }
            1 | 58 => {
                if !baseline.known_protocols.contains("icmp") {
                    new_protocols.insert("icmp".into());
                }
            }
            _ => {}
        }
    });

    // --- Analyze deviations ---

    // New IPs
    if !new_ips.is_empty() {
        let severity = if new_ips.len() > 20 { "CRITICAL" } else if new_ips.len() > 5 { "HIGH" } else { "MEDIUM" };
        alerts.push(format!("{{\"type\":\"NEW_IPS\",\"severity\":\"{}\",\"count\":{},\"ips\":[{}]}}",
            severity, new_ips.len(),
            new_ips.iter().take(20).map(|s| format!("\"{}\"", jesc(s))).collect::<Vec<_>>().join(",")));
    }

    // New ports
    if !new_ports.is_empty() {
        let has_suspicious = new_ports.iter().any(|&p| p == 4444 || p == 5555 || p == 1234 || p == 31337 || p == 6667 || p == 6697);
        let severity = if has_suspicious { "CRITICAL" } else if new_ports.len() > 10 { "HIGH" } else { "MEDIUM" };
        alerts.push(format!("{{\"type\":\"NEW_PORTS\",\"severity\":\"{}\",\"count\":{},\"ports\":[{}]}}",
            severity, new_ports.len(),
            new_ports.iter().take(30).map(|p| p.to_string()).collect::<Vec<_>>().join(",")));
    }

    // New protocols
    if !new_protocols.is_empty() {
        alerts.push(format!("{{\"type\":\"NEW_PROTOCOLS\",\"severity\":\"HIGH\",\"protocols\":[{}]}}",
            new_protocols.iter().map(|s| format!("\"{}\"", jesc(s))).collect::<Vec<_>>().join(",")));
    }

    // New DNS domains
    if !new_dns_domains.is_empty() {
        let severity = if new_dns_domains.len() > 50 { "HIGH" } else { "LOW" };
        alerts.push(format!("{{\"type\":\"NEW_DNS_DOMAINS\",\"severity\":\"{}\",\"count\":{},\"domains\":[{}]}}",
            severity, new_dns_domains.len(),
            new_dns_domains.iter().take(30).map(|s| format!("\"{}\"", jesc(s))).collect::<Vec<_>>().join(",")));
    }

    // Connection rate spike
    for (&sec, &count) in &conns_buckets {
        if count > baseline.max_connections_per_sec * 3 + 5 {
            alerts.push(format!("{{\"type\":\"CONNECTION_SPIKE\",\"severity\":\"HIGH\",\"second\":{},\"count\":{},\"baseline_max\":{}}}",
                sec, count, baseline.max_connections_per_sec));
        }
    }

    // DNS query rate spike
    for (&sec, &count) in &dns_buckets {
        let threshold = (baseline.avg_dns_queries_per_sec * 5.0) as u64 + 10;
        if count > threshold {
            alerts.push(format!("{{\"type\":\"DNS_SPIKE\",\"severity\":\"HIGH\",\"second\":{},\"count\":{},\"baseline_avg\":{:.1}}}",
                sec, count, baseline.avg_dns_queries_per_sec));
        }
    }

    // Bandwidth spike
    for (&sec, &bytes) in &bytes_buckets {
        if bytes > baseline.max_bytes_per_sec * 3 + 10000 {
            alerts.push(format!("{{\"type\":\"BANDWIDTH_SPIKE\",\"severity\":\"MEDIUM\",\"second\":{},\"bytes\":{},\"baseline_max\":{}}}",
                sec, bytes, baseline.max_bytes_per_sec));
        }
    }

    // Packet size anomaly
    if !packet_sizes.is_empty() {
        let avg = packet_sizes.iter().sum::<u64>() as f64 / packet_sizes.len() as f64;
        let deviation = (avg - baseline.avg_packet_size).abs();
        if deviation > baseline.std_packet_size * 3.0 + 100.0 {
            alerts.push(format!("{{\"type\":\"PACKET_SIZE_ANOMALY\",\"severity\":\"MEDIUM\",\"current_avg\":{:.0},\"baseline_avg\":{:.0},\"baseline_std\":{:.0}}}",
                avg, baseline.avg_packet_size, baseline.std_packet_size));
        }
    }

    // Output
    println!("{{");
    println!("  \"status\": \"{}\",", if alerts.is_empty() { "NORMAL" } else { "ANOMALY_DETECTED" });
    println!("  \"packets_analyzed\": {},", total_pkts);
    println!("  \"bytes_analyzed\": {},", total_bytes);
    println!("  \"new_ips_count\": {},", new_ips.len());
    println!("  \"new_ports_count\": {},", new_ports.len());
    println!("  \"new_dns_domains_count\": {},", new_dns_domains.len());
    println!("  \"alerts\": [");
    for (i, alert) in alerts.iter().enumerate() {
        let comma = if i < alerts.len() - 1 { "," } else { "" };
        println!("    {}{}", alert, comma);
    }
    println!("  ]");
    println!("}}");
}
