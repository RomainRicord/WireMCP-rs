use std::collections::{HashMap, HashSet};

use crate::Cli;
use crate::parsers::{u16be, ip4_fmt, ip6_fmt, dns_name, pct};
use crate::capture::capture_basic;

// Amplification protocol table: (name, port, max_amplification_factor)
const AMP_PROTOCOLS: &[(&str, u16, &str)] = &[
    ("DNS",           53,    "x54000"),
    ("NTP",           123,   "x556"),
    ("SSDP/UPnP",    1900,  "x30"),
    ("SNMP",          161,   "x6.3"),
    ("Chargen",       19,    "x358"),
    ("Memcached",     11211, "x51000"),
    ("CLDAP",         389,   "x70"),
    ("NetBIOS",       137,   "x3.8"),
    ("RPC Portmap",   111,   "x7"),
    ("Steam",         27015, "x5.5"),
    ("ARMS",          3283,  "x35"),
    ("WS-Discovery",  3702,  "x500"),
    ("CoAP",          5683,  "x34"),
    ("Jenkins",       33848, "x100"),
];

struct SrcStats {
    pkts: u64, bytes: u64,
    syn_count: u64, ack_only_count: u64, rst_count: u64, fin_count: u64, psh_count: u64,
    udp_count: u64, icmp_count: u64, tcp_count: u64,
    dst_ports: HashMap<u16, u64>,
    first_seen: f64, last_seen: f64,
    // HTTP layer
    http_gets: u64, http_posts: u64, http_other: u64,
    unique_uris: HashSet<String>,
    user_agents: HashSet<String>,
    xmlrpc_hits: u64,
    // TCP connection tracking
    small_tcp_pkts: u64,  // packets < 100 bytes (slowloris indicator)
    tcp_connections: HashSet<u16>, // unique dst ports with SYN
}

impl SrcStats {
    fn new(t: f64) -> Self {
        Self { pkts: 0, bytes: 0, syn_count: 0, ack_only_count: 0, rst_count: 0,
               fin_count: 0, psh_count: 0, udp_count: 0, icmp_count: 0, tcp_count: 0,
               dst_ports: HashMap::new(), first_seen: t, last_seen: t,
               http_gets: 0, http_posts: 0, http_other: 0,
               unique_uris: HashSet::new(), user_agents: HashSet::new(),
               xmlrpc_hits: 0, small_tcp_pkts: 0, tcp_connections: HashSet::new() }
    }
    fn rate(&self) -> f64 {
        let d = self.last_seen - self.first_seen;
        if d > 0.0 { self.pkts as f64 / d } else { self.pkts as f64 }
    }
}

#[derive(Default)]
struct AmpStats { requests: u64, req_bytes: u64, responses: u64, resp_bytes: u64 }
impl AmpStats {
    fn ratio(&self) -> f64 {
        if self.req_bytes > 0 { self.resp_bytes as f64 / self.req_bytes as f64 } else if self.resp_bytes > 0 { f64::INFINITY } else { 0.0 }
    }
}

pub fn run_ddos(cli: &Cli) {
    let mut sources: HashMap<String, SrcStats> = HashMap::new();
    let mut dst_stats: HashMap<String, (u64, u64)> = HashMap::new(); // ip -> (pkts, bytes)

    // Amplification tracking per protocol per target
    let mut amp_data: HashMap<u16, HashMap<String, AmpStats>> = HashMap::new();
    for &(_, port, _) in AMP_PROTOCOLS { amp_data.insert(port, HashMap::new()); }

    // DNS carpet bombing: track queried domains
    let mut dns_queries: HashMap<String, u64> = HashMap::new(); // base domain -> count
    let mut dns_unique_subs: HashMap<String, HashSet<String>> = HashMap::new(); // base domain -> unique subdomains

    // Time buckets
    let mut time_buckets: HashMap<u64, (u64, u64)> = HashMap::new();
    let mut total_pkts = 0u64;
    let mut total_bytes = 0u64;
    let mut total_syn = 0u64;
    let mut total_synack = 0u64;
    let mut total_ack_only = 0u64;
    let mut total_rst = 0u64;
    let mut total_fin = 0u64;
    let mut frag_count = 0u64;
    let mut total_http_req = 0u64;
    let mut http_dst_ips: HashMap<String, u64> = HashMap::new();

    capture_basic(cli, |data, time| {
        total_pkts += 1;
        total_bytes += data.len() as u64;
        let bucket = time as u64;
        let e = time_buckets.entry(bucket).or_default();
        e.0 += 1; e.1 += data.len() as u64;

        if data.len() < 14 { return; }
        let ethertype = u16be(data, 12);
        let mut payload = &data[14..];
        let ethertype = if ethertype == 0x8100 && payload.len() >= 4 {
            let et = u16be(payload, 2); payload = &payload[4..]; et
        } else { ethertype };

        let (src_ip, dst_ip, proto, ip_payload) = match ethertype {
            0x0800 if payload.len() >= 20 => {
                let ihl = (payload[0] & 0x0F) as usize * 4;
                let flags = u16be(payload, 6);
                if (flags & 0x2000) != 0 || (flags & 0x1FFF) > 0 { frag_count += 1; }
                (ip4_fmt(&payload[12..16]), ip4_fmt(&payload[16..20]), payload[9], &payload[ihl.min(payload.len())..])
            }
            0x86DD if payload.len() >= 40 =>
                (ip6_fmt(&payload[8..24]), ip6_fmt(&payload[24..40]), payload[6], &payload[40..]),
            _ => return,
        };

        let pkt_len = data.len() as u64;
        let de = dst_stats.entry(dst_ip.clone()).or_default();
        de.0 += 1; de.1 += pkt_len;

        let s = sources.entry(src_ip.clone()).or_insert_with(|| SrcStats::new(time));
        s.pkts += 1; s.bytes += pkt_len; s.last_seen = time;

        match proto {
            6 if ip_payload.len() >= 20 => { // TCP
                s.tcp_count += 1;
                let sp = u16be(ip_payload, 0);
                let dp = u16be(ip_payload, 2);
                let doff = ((ip_payload[12] >> 4) as usize) * 4;
                let flags = ip_payload[13];
                let is_syn = (flags & 0x02) != 0;
                let is_ack = (flags & 0x10) != 0;
                let is_rst = (flags & 0x04) != 0;
                let is_fin = (flags & 0x01) != 0;
                let is_psh = (flags & 0x08) != 0;

                if is_syn && !is_ack { s.syn_count += 1; total_syn += 1; s.tcp_connections.insert(dp); }
                if is_syn && is_ack { total_synack += 1; }
                if is_ack && !is_syn && !is_rst && !is_fin && !is_psh { s.ack_only_count += 1; total_ack_only += 1; }
                if is_rst { s.rst_count += 1; total_rst += 1; }
                if is_fin { s.fin_count += 1; total_fin += 1; }
                if is_psh { s.psh_count += 1; }
                *s.dst_ports.entry(dp).or_default() += 1;

                // Small packet tracking (slowloris/slow POST)
                if pkt_len < 100 && is_ack && !is_syn { s.small_tcp_pkts += 1; }

                // HTTP analysis
                if doff < ip_payload.len() {
                    let app = &ip_payload[doff..];
                    if app.len() > 10 {
                        if app.starts_with(b"GET ") {
                            s.http_gets += 1; total_http_req += 1;
                            *http_dst_ips.entry(dst_ip.clone()).or_default() += 1;
                            if let Some(uri_end) = app[4..app.len().min(512)].iter().position(|&b| b == b' ') {
                                let uri = String::from_utf8_lossy(&app[4..4+uri_end]);
                                s.unique_uris.insert(uri.to_string());
                            }
                            // Extract User-Agent
                            if let Ok(text) = std::str::from_utf8(&app[..app.len().min(1024)]) {
                                for line in text.lines() {
                                    if line.len() > 12 && line[..12].eq_ignore_ascii_case("user-agent:") {
                                        s.user_agents.insert(line[12..].trim().to_string());
                                    }
                                }
                            }
                        } else if app.starts_with(b"POST ") {
                            s.http_posts += 1; total_http_req += 1;
                            *http_dst_ips.entry(dst_ip.clone()).or_default() += 1;
                            if let Some(uri_end) = app[5..app.len().min(512)].iter().position(|&b| b == b' ') {
                                let uri = String::from_utf8_lossy(&app[5..5+uri_end]).to_string();
                                if uri.contains("xmlrpc.php") { s.xmlrpc_hits += 1; }
                                s.unique_uris.insert(uri);
                            }
                        } else if app.starts_with(b"HEAD ") || app.starts_with(b"PUT ") || app.starts_with(b"DELETE ") || app.starts_with(b"OPTIONS ") {
                            s.http_other += 1; total_http_req += 1;
                        }
                    }
                }
            }
            17 if ip_payload.len() >= 8 => { // UDP
                s.udp_count += 1;
                let sp = u16be(ip_payload, 0);
                let dp = u16be(ip_payload, 2);
                *s.dst_ports.entry(dp).or_default() += 1;

                // Check all amplification protocols
                for &(_, port, _) in AMP_PROTOCOLS {
                    if sp == port || dp == port {
                        if let Some(map) = amp_data.get_mut(&port) {
                            let e = map.entry(dst_ip.clone()).or_default();
                            if sp == port { e.responses += 1; e.resp_bytes += pkt_len; }
                            else { e.requests += 1; e.req_bytes += pkt_len; }
                        }
                    }
                }

                // DNS query analysis for carpet bombing
                if (sp == 53 || dp == 53) && ip_payload.len() > 20 {
                    let dns_data = &ip_payload[8..];
                    if dns_data.len() >= 12 {
                        if let Some((name, _)) = dns_name(dns_data, 12) {
                            let parts: Vec<&str> = name.split('.').collect();
                            let base = if parts.len() >= 2 {
                                format!("{}.{}", parts[parts.len()-2], parts[parts.len()-1])
                            } else { name.clone() };
                            *dns_queries.entry(base.clone()).or_default() += 1;
                            dns_unique_subs.entry(base).or_default().insert(name);
                        }
                    }
                }
            }
            1 | 58 => { s.icmp_count += 1; }
            _ => {}
        }
    });

    // --- Analysis & Output ---
    let duration = time_buckets.keys().max().map(|&m| m as f64 + 1.0).unwrap_or(1.0);
    let pps = total_pkts as f64 / duration;
    let bps = total_bytes as f64 * 8.0 / duration;
    let mut alerts: Vec<String> = Vec::new();

    println!("========================================");
    println!("       DDoS Analysis Report");
    println!("========================================\n");

    // --- Overview ---
    println!("[Overview]");
    println!("  Duration:       {:.1}s", duration);
    println!("  Total packets:  {} ({:.0} pkt/s)", total_pkts, pps);
    println!("  Total bytes:    {} ({:.1} Mbit/s)", total_bytes, bps / 1_000_000.0);
    println!("  Unique sources: {}", sources.len());
    println!("  Fragmented:     {}", frag_count);
    println!();

    // --- Traffic Timeline ---
    println!("[Traffic Timeline]");
    let mut buckets: Vec<_> = time_buckets.iter().collect();
    buckets.sort_by_key(|(&k, _)| k);
    let max_pps = buckets.iter().map(|(_, (p, _))| *p).max().unwrap_or(1);
    for (sec, (pkts, bytes)) in &buckets {
        let bar_len = (*pkts as f64 / max_pps as f64 * 40.0) as usize;
        println!("  {:>4}s: {:>7} pkt/s {:>8} Kb/s  {}", sec, pkts, bytes * 8 / 1000, "#".repeat(bar_len));
    }
    let peak_pps = buckets.iter().map(|(_, (p, _))| *p).max().unwrap_or(0);
    let peak_bps = buckets.iter().map(|(_, (_, b))| *b * 8).max().unwrap_or(0);
    println!("  Peak: {} pkt/s, {:.1} Mbit/s\n", peak_pps, peak_bps as f64 / 1_000_000.0);

    // --- L3/L4: TCP Flood Detection ---
    let tcp_total: u64 = sources.values().map(|s| s.tcp_count).sum();
    let udp_total: u64 = sources.values().map(|s| s.udp_count).sum();
    let icmp_total: u64 = sources.values().map(|s| s.icmp_count).sum();

    println!("[L3/L4 Flood Analysis]");
    println!("  TCP: {} ({:.1}%)  UDP: {} ({:.1}%)  ICMP: {} ({:.1}%)",
        tcp_total, pct(tcp_total, total_pkts), udp_total, pct(udp_total, total_pkts), icmp_total, pct(icmp_total, total_pkts));
    println!("  TCP flags — SYN:{} SYN+ACK:{} ACK-only:{} RST:{} FIN:{}",
        total_syn, total_synack, total_ack_only, total_rst, total_fin);

    // SYN Flood — require multiple sources to avoid asymmetric capture false positives
    let syn_ratio = if total_synack > 0 { total_syn as f64 / total_synack as f64 } else if total_syn > 0 { f64::INFINITY } else { 0.0 };
    let syn_sources: usize = sources.values().filter(|s| s.syn_count > 0).count();
    if total_syn > 100 && syn_ratio > 3.0 && syn_sources > 5 {
        let msg = format!("SYN Flood: {} SYN from {} sources, ratio SYN/SYN+ACK={:.1} (normal~1.0)", total_syn, syn_sources, syn_ratio);
        println!("  >> {}", msg); alerts.push(msg);
    }
    // ACK Flood — only flag if: high ACK ratio + many sources (distributed) + low payload ratio
    let psh_total: u64 = sources.values().map(|s| s.psh_count).sum();
    let ack_no_data_ratio = if psh_total > 0 { total_ack_only as f64 / psh_total as f64 } else { 999.0 };
    if total_ack_only > 500 && pct(total_ack_only, total_pkts) > 60.0
        && ack_no_data_ratio > 10.0 && sources.len() > 20 && pps > 500.0 {
        let msg = format!("ACK Flood: {} ACK-only packets ({:.0}%), {:.0}x vs data pkts, {} sources",
            total_ack_only, pct(total_ack_only, total_pkts), ack_no_data_ratio, sources.len());
        println!("  >> {}", msg); alerts.push(msg);
    }
    // RST Flood — require multiple sources to avoid nmap scan / firewall reject false positives
    let rst_sources: usize = sources.values().filter(|s| s.rst_count > 0).count();
    if total_rst > 100 && pct(total_rst, total_pkts) > 30.0 && rst_sources > 10 {
        let msg = format!("RST Flood: {} RST packets ({:.0}%) from {} sources", total_rst, pct(total_rst, total_pkts), rst_sources);
        println!("  >> {}", msg); alerts.push(msg);
    }
    // UDP Flood — require many sources to avoid VPN/tunnel false positives
    let udp_sources: usize = sources.values().filter(|s| s.udp_count > 0).count();
    if udp_total > 100 && pct(udp_total, total_pkts) > 80.0 && pps > 100.0 && udp_sources > 10 {
        let msg = format!("UDP Flood: {:.0}% UDP at {:.0} pkt/s, {} sources", pct(udp_total, total_pkts), pps, udp_sources);
        println!("  >> {}", msg); alerts.push(msg);
    }
    // ICMP Flood — require high packet rate to avoid monitoring/traceroute false positives
    let icmp_pps = icmp_total as f64 / duration;
    if icmp_total > 50 && pct(icmp_total, total_pkts) > 50.0 && icmp_pps > 50.0 {
        let msg = format!("ICMP Flood: {} packets ({:.0}%) at {:.0} pkt/s", icmp_total, pct(icmp_total, total_pkts), icmp_pps);
        println!("  >> {}", msg); alerts.push(msg);
    }
    // Fragmentation
    if frag_count > 50 && pct(frag_count, total_pkts) > 20.0 {
        let msg = format!("Fragmentation attack: {} fragments ({:.0}%)", frag_count, pct(frag_count, total_pkts));
        println!("  >> {}", msg); alerts.push(msg);
    }
    println!();

    // --- Amplification Detection (all protocols) ---
    println!("[Amplification/Reflection Analysis]");
    let mut any_amp = false;
    for &(name, port, max_factor) in AMP_PROTOCOLS {
        if let Some(map) = amp_data.get(&port) {
            let suspicious: Vec<_> = map.iter().filter(|(_, a)| a.resp_bytes > a.req_bytes.max(1) * 3 && a.responses > 5).collect();
            for (ip, a) in &suspicious {
                any_amp = true;
                let r = a.ratio();
                let msg = format!("{} Amplification: target={} — {} resp ({} B) vs {} req ({} B) — {:.1}x (max {})",
                    name, ip, a.responses, a.resp_bytes, a.requests, a.req_bytes, r, max_factor);
                println!("  >> {}", msg); alerts.push(msg);
            }
        }
    }
    if !any_amp { println!("  No amplification detected."); }
    println!();

    // --- DNS Carpet Bombing ---
    let carpet_domains: Vec<_> = dns_unique_subs.iter()
        .filter(|(_, subs)| subs.len() > 20)
        .collect();
    if !carpet_domains.is_empty() {
        println!("[DNS Carpet Bombing]");
        for (domain, subs) in &carpet_domains {
            let total = dns_queries.get(*domain).copied().unwrap_or(0);
            let msg = format!("DNS Carpet Bomb: {} — {} unique subdomains, {} total queries", domain, subs.len(), total);
            println!("  >> {}", msg); alerts.push(msg);
            // Show sample subdomains
            let samples: Vec<_> = subs.iter().take(5).collect();
            println!("     Samples: {}", samples.iter().map(|s| s.as_str()).collect::<Vec<_>>().join(", "));
        }
        println!();
    }

    // --- L7: HTTP/S Flood Detection ---
    if total_http_req > 0 {
        let total_gets: u64 = sources.values().map(|s| s.http_gets).sum();
        let total_posts: u64 = sources.values().map(|s| s.http_posts).sum();
        let http_rps = total_http_req as f64 / duration;

        println!("[L7 HTTP Flood Analysis]");
        println!("  Total HTTP requests: {} ({:.0} req/s)", total_http_req, http_rps);
        println!("  GET: {}  POST: {}  Other: {}", total_gets, total_posts,
            sources.values().map(|s| s.http_other).sum::<u64>());

        // HTTP GET Flood — raised threshold to avoid busy web servers
        let http_sources: usize = sources.values().filter(|s| s.http_gets + s.http_posts > 0).count();
        if total_gets > 500 && http_rps > 100.0 && http_sources > 5 {
            let msg = format!("HTTP GET Flood: {} requests at {:.0} req/s from {} sources", total_gets, total_gets as f64 / duration, http_sources);
            println!("  >> {}", msg); alerts.push(msg);
        }

        // HTTP POST Flood
        if total_posts > 200 && total_posts as f64 / duration > 50.0 && http_sources > 5 {
            let msg = format!("HTTP POST Flood: {} requests at {:.0} req/s from {} sources", total_posts, total_posts as f64 / duration, http_sources);
            println!("  >> {}", msg); alerts.push(msg);
        }

        // WordPress XML-RPC
        let total_xmlrpc: u64 = sources.values().map(|s| s.xmlrpc_hits).sum();
        if total_xmlrpc > 10 {
            let msg = format!("WordPress XML-RPC Flood: {} requests to xmlrpc.php", total_xmlrpc);
            println!("  >> {}", msg); alerts.push(msg);
        }

        // Random path flood (cache bypass)
        let path_flooders: Vec<_> = sources.iter()
            .filter(|(_, s)| s.unique_uris.len() > 50 && (s.http_gets + s.http_posts) > 100)
            .collect();
        for (ip, s) in &path_flooders {
            let msg = format!("Random Path / Cache Bypass: {} — {} unique URIs in {} requests", ip, s.unique_uris.len(), s.http_gets + s.http_posts);
            println!("  >> {}", msg); alerts.push(msg);
        }

        // Rotating User-Agent (bot L7)
        let ua_rotators: Vec<_> = sources.iter()
            .filter(|(_, s)| s.user_agents.len() > 10 && (s.http_gets + s.http_posts) > 50)
            .collect();
        for (ip, s) in &ua_rotators {
            let msg = format!("L7 Bot (rotating UA): {} — {} User-Agents in {} requests", ip, s.user_agents.len(), s.http_gets + s.http_posts);
            println!("  >> {}", msg); alerts.push(msg);
        }

        // HTTP carpet bombing (many different dst IPs getting HTTP)
        if http_dst_ips.len() > 20 && total_http_req > 100 {
            let msg = format!("HTTP Carpet Bombing: {} requests spread across {} destination IPs", total_http_req, http_dst_ips.len());
            println!("  >> {}", msg); alerts.push(msg);
        }

        println!();
    }

    // --- Slowloris / Slow POST Detection ---
    let slowloris_suspects: Vec<_> = sources.iter()
        .filter(|(_, s)| {
            let dur = s.last_seen - s.first_seen;
            s.tcp_connections.len() > 5 && dur > 10.0 && s.small_tcp_pkts > 20
                && s.small_tcp_pkts as f64 / s.tcp_count.max(1) as f64 > 0.7
        }).collect();
    if !slowloris_suspects.is_empty() {
        println!("[Slowloris / Slow POST Detection]");
        for (ip, s) in &slowloris_suspects {
            let dur = s.last_seen - s.first_seen;
            let msg = format!("Slowloris suspect: {} — {} connections, {} small packets over {:.0}s ({:.0}% tiny)",
                ip, s.tcp_connections.len(), s.small_tcp_pkts, dur, s.small_tcp_pkts as f64 / s.tcp_count.max(1) as f64 * 100.0);
            println!("  >> {}", msg); alerts.push(msg);
        }
        println!();
    }

    // --- Port Scan / Scattershot ---
    let scanners: Vec<_> = sources.iter().filter(|(_, s)| s.dst_ports.len() > 100 && s.pkts > 200 && s.rate() > 50.0).collect();
    if !scanners.is_empty() {
        println!("[Port Scan / Scattershot Detection]");
        for (ip, s) in &scanners {
            let msg = format!("{} — {} ports scanned, {} packets ({:.0}/s)", ip, s.dst_ports.len(), s.pkts, s.rate());
            println!("  >> {}", msg); alerts.push(msg);
        }
        println!();
    }

    // --- Multi-vector Detection ---
    let attack_types: Vec<&str> = alerts.iter().map(|a| {
        if a.contains("SYN") { "SYN" } else if a.contains("ACK Flood") { "ACK" }
        else if a.contains("RST") { "RST" } else if a.contains("UDP Flood") { "UDP" }
        else if a.contains("ICMP") { "ICMP" } else if a.contains("Amplification") { "AMP" }
        else if a.contains("HTTP") { "HTTP" } else if a.contains("DNS Carpet") { "DNS-CB" }
        else if a.contains("Slowloris") { "SLOW" } else if a.contains("Port Scan") { "SCAN" }
        else { "OTHER" }
    }).collect::<HashSet<_>>().into_iter().collect();

    if attack_types.len() > 1 {
        println!("[Multi-Vector Attack Detected]");
        println!("  >> {} simultaneous attack vectors: {}", attack_types.len(), attack_types.join(" + "));
        println!();
    }

    // Distributed detection — require high source count and packet rate for busy servers
    if sources.len() > 100 && pps > 1000.0 {
        let msg = format!("Distributed attack (DDoS): {} unique sources at {:.0} pkt/s", sources.len(), pps);
        alerts.push(msg);
    }

    // --- Top Sources ---
    println!("[Top 15 Source IPs]");
    let mut src_sorted: Vec<_> = sources.iter().collect();
    src_sorted.sort_by(|a, b| b.1.pkts.cmp(&a.1.pkts));
    println!("  {:<40} {:>7} {:>9} {:>5} {:>5} {:>5} {:>5} {:>5} {:>5}", "IP", "Pkts", "Bytes", "SYN", "ACK", "RST", "UDP", "ICMP", "HTTP");
    for (ip, s) in src_sorted.iter().take(15) {
        let http = s.http_gets + s.http_posts + s.http_other;
        println!("  {:<40} {:>7} {:>9} {:>5} {:>5} {:>5} {:>5} {:>5} {:>5}  ({:.0}/s)",
            ip, s.pkts, s.bytes, s.syn_count, s.ack_only_count, s.rst_count, s.udp_count, s.icmp_count, http, s.rate());
    }
    println!();

    // --- Top Targets ---
    println!("[Top 10 Targets]");
    let mut dst_sorted: Vec<_> = dst_stats.iter().collect();
    dst_sorted.sort_by(|a, b| b.1.0.cmp(&a.1.0));
    for (ip, (pkts, bytes)) in dst_sorted.iter().take(10) {
        println!("  {:<40} {:>8} pkts  {:>10} bytes", ip, pkts, bytes);
    }
    println!();

    // --- Summary ---
    println!("========================================");
    println!("  DETECTION SUMMARY: {} alerts", alerts.len());
    println!("========================================");
    if alerts.is_empty() {
        println!("  No DDoS patterns detected.");
    } else {
        for (i, a) in alerts.iter().enumerate() {
            println!("  {}. {}", i + 1, a);
        }
    }
}
