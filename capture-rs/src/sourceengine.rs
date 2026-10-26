use std::collections::HashMap;

use crate::Cli;
use crate::parsers::{u16be, u32be, ip4_fmt, ip6_fmt, jesc, pct, ipv4_non_first_frag};
use crate::capture::capture_basic;

// Source Engine packet types
const A2S_INFO_REQUEST: u8 = 0x54;       // 'T'
const A2S_INFO_RESPONSE: u8 = 0x49;      // 'I'
const A2S_PLAYER_REQUEST: u8 = 0x55;     // 'U'
const A2S_PLAYER_RESPONSE: u8 = 0x44;    // 'D'
const A2S_RULES_REQUEST: u8 = 0x56;      // 'V'
const A2S_RULES_RESPONSE: u8 = 0x45;     // 'E'
const CHALLENGE_RESPONSE: u8 = 0x41;     // 'A'
const CONNECTIONLESS_HEADER: u32 = 0xFFFFFFFF;

fn se_type_name(t: u8) -> &'static str {
    match t {
        0x54 => "A2S_INFO",
        0x49 => "A2S_INFO_RESP",
        0x55 => "A2S_PLAYER",
        0x44 => "A2S_PLAYER_RESP",
        0x56 => "A2S_RULES",
        0x45 => "A2S_RULES_RESP",
        0x41 => "CHALLENGE",
        0x43 => "A2A_PING",         // 'C'
        0x6A => "A2A_PING_RESP",    // 'j'
        _ => "GAME_DATA",
    }
}

fn is_query_request(t: u8) -> bool {
    t == A2S_INFO_REQUEST || t == A2S_PLAYER_REQUEST || t == A2S_RULES_REQUEST
}

fn is_query_response(t: u8) -> bool {
    t == A2S_INFO_RESPONSE || t == A2S_PLAYER_RESPONSE || t == A2S_RULES_RESPONSE || t == CHALLENGE_RESPONSE
}

struct SourceClient {
    ip: String,
    total_pkts: u64,
    total_bytes: u64,
    query_count: u64,         // A2S_INFO, A2S_PLAYER, A2S_RULES
    game_data_count: u64,     // non-query packets
    query_types: HashMap<u8, u64>,
    packet_times: Vec<f64>,
    packet_sizes: Vec<u64>,
    first_seen: f64,
    last_seen: f64,
}

impl SourceClient {
    fn new(ip: &str, t: f64) -> Self {
        Self {
            ip: ip.to_string(),
            total_pkts: 0, total_bytes: 0,
            query_count: 0, game_data_count: 0,
            query_types: HashMap::new(),
            packet_times: Vec::new(),
            packet_sizes: Vec::new(),
            first_seen: t, last_seen: t,
        }
    }
    fn pps(&self) -> f64 {
        let d = self.last_seen - self.first_seen;
        if d > 0.1 { self.total_pkts as f64 / d } else { self.total_pkts as f64 }
    }
    fn avg_size(&self) -> f64 {
        if self.packet_sizes.is_empty() { 0.0 }
        else { self.packet_sizes.iter().sum::<u64>() as f64 / self.packet_sizes.len() as f64 }
    }
    fn query_ratio(&self) -> f64 {
        if self.total_pkts > 0 { self.query_count as f64 / self.total_pkts as f64 } else { 0.0 }
    }
}

/// Detect beacon/periodic pattern in timestamps
fn detect_periodic(times: &[f64]) -> Option<(f64, f64)> {
    if times.len() < 5 { return None; }
    let mut intervals: Vec<f64> = Vec::new();
    for i in 1..times.len() {
        let d = times[i] - times[i - 1];
        if d > 0.001 { intervals.push(d); }
    }
    if intervals.len() < 4 { return None; }
    let avg = intervals.iter().sum::<f64>() / intervals.len() as f64;
    if avg < 0.01 { return None; }
    let var = intervals.iter().map(|&i| (i - avg).powi(2)).sum::<f64>() / intervals.len() as f64;
    let jitter = var.sqrt() / avg;
    if jitter < 0.2 { Some((avg, jitter)) } else { None }
}

pub fn run_source_engine(cli: &Cli) {
    let server_port: u16 = std::env::var("SOURCE_PORT")
        .ok().and_then(|s| s.parse().ok()).unwrap_or(27015);

    eprintln!("[source-engine] Monitoring port {} on {} for {}s...",
        server_port, cli.interface, cli.duration);

    let mut clients: HashMap<String, SourceClient> = HashMap::new();
    let mut server_responses: u64 = 0;
    let mut server_resp_bytes: u64 = 0;
    let mut total_queries: u64 = 0;
    let mut total_query_bytes: u64 = 0;
    let mut total_game_pkts: u64 = 0;
    let mut total_game_bytes: u64 = 0;
    let mut query_type_counts: HashMap<u8, u64> = HashMap::new();
    let mut time_buckets: HashMap<u64, (u64, u64, u64)> = HashMap::new(); // sec -> (pkts, queries, bytes)
    let mut total_se_pkts: u64 = 0;
    let mut total_non_se: u64 = 0;

    capture_basic(cli, |data, time| {
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

        // Only UDP
        if proto != 17 || ip_payload.len() < 8 { return; }
        let sp = u16be(ip_payload, 0);
        let dp = u16be(ip_payload, 2);
        let udp_payload = &ip_payload[8..];

        // Filter for server port traffic
        let is_to_server = dp == server_port;
        let is_from_server = sp == server_port;
        if !is_to_server && !is_from_server { return; }

        // Need at least Source Engine header (4 bytes header + 1 byte type)
        if udp_payload.len() < 5 { return; }
        let header = u32be(udp_payload, 0);

        let bucket = time as u64;

        if header == CONNECTIONLESS_HEADER {
            // Connectionless packet (queries, responses)
            let pkt_type = udp_payload[4];
            let pkt_len = data.len() as u64;

            total_se_pkts += 1;

            if is_to_server {
                // Incoming to server
                let client = clients.entry(src_ip.clone())
                    .or_insert_with(|| SourceClient::new(&src_ip, time));
                client.total_pkts += 1;
                client.total_bytes += pkt_len;
                client.packet_times.push(time);
                client.packet_sizes.push(pkt_len);
                client.last_seen = time;

                if is_query_request(pkt_type) {
                    client.query_count += 1;
                    *client.query_types.entry(pkt_type).or_default() += 1;
                    total_queries += 1;
                    total_query_bytes += pkt_len;
                    *query_type_counts.entry(pkt_type).or_default() += 1;
                    let e = time_buckets.entry(bucket).or_default();
                    e.0 += 1; e.1 += 1; e.2 += pkt_len;
                } else {
                    client.game_data_count += 1;
                    total_game_pkts += 1;
                    total_game_bytes += pkt_len;
                    let e = time_buckets.entry(bucket).or_default();
                    e.0 += 1; e.2 += pkt_len;
                }
            } else {
                // Server response
                server_responses += 1;
                server_resp_bytes += pkt_len;
            }
        } else {
            // Game data (non-connectionless, split packets, etc.)
            total_se_pkts += 1;
            let pkt_len = data.len() as u64;

            if is_to_server {
                let client = clients.entry(src_ip.clone())
                    .or_insert_with(|| SourceClient::new(&src_ip, time));
                client.total_pkts += 1;
                client.total_bytes += pkt_len;
                client.game_data_count += 1;
                client.packet_times.push(time);
                client.packet_sizes.push(pkt_len);
                client.last_seen = time;
                total_game_pkts += 1;
                total_game_bytes += pkt_len;
            } else {
                server_responses += 1;
                server_resp_bytes += pkt_len;
            }
            let e = time_buckets.entry(bucket).or_default();
            e.0 += 1; e.2 += pkt_len;
        }
    });

    // --- Analysis ---
    let duration = if let (Some(&min), Some(&max)) = (time_buckets.keys().min(), time_buckets.keys().max()) {
        (max - min) as f64 + 1.0
    } else { 1.0 };

    let mut alerts: Vec<String> = Vec::new();

    // 1. A2S Query Flood Detection
    let qps = total_queries as f64 / duration;
    let unique_query_sources = clients.values().filter(|c| c.query_count > 0).count();
    if total_queries > 50 && qps > 20.0 {
        let severity = if qps > 100.0 { "CRITICAL" } else if qps > 50.0 { "HIGH" } else { "MEDIUM" };
        alerts.push(format!(
            "{{\"type\":\"A2S_QUERY_FLOOD\",\"severity\":\"{}\",\"queries_per_sec\":{:.1},\"total_queries\":{},\"unique_sources\":{}}}",
            severity, qps, total_queries, unique_query_sources));
    }

    // 2. Amplification Detection
    if total_queries > 0 && server_responses > 0 {
        let amp_ratio = server_resp_bytes as f64 / total_query_bytes.max(1) as f64;
        if amp_ratio > 3.0 && total_queries > 10 {
            alerts.push(format!(
                "{{\"type\":\"AMPLIFICATION_RISK\",\"severity\":\"HIGH\",\"ratio\":{:.1},\"query_bytes\":{},\"response_bytes\":{}}}",
                amp_ratio, total_query_bytes, server_resp_bytes));
        }
    }

    // 3. Per-client anomalies
    let mut query_only_bots: Vec<String> = Vec::new();
    let mut high_rate_clients: Vec<String> = Vec::new();
    let mut periodic_bots: Vec<String> = Vec::new();
    let mut fake_players: Vec<String> = Vec::new();

    for (ip, client) in &clients {
        // Query-only clients (bots/scanners — no game data, only queries)
        if client.query_count > 5 && client.game_data_count == 0 {
            query_only_bots.push(format!(
                "{{\"ip\":\"{}\",\"queries\":{},\"types\":[{}]}}",
                jesc(ip), client.query_count,
                client.query_types.iter()
                    .map(|(t, c)| format!("\"{}:{}\"", se_type_name(*t), c))
                    .collect::<Vec<_>>().join(",")));
        }

        // High packet rate per client
        if client.pps() > 50.0 && client.total_pkts > 20 {
            high_rate_clients.push(format!(
                "{{\"ip\":\"{}\",\"pps\":{:.1},\"pkts\":{},\"bytes\":{}}}",
                jesc(ip), client.pps(), client.total_pkts, client.total_bytes));
        }

        // Periodic/beacon pattern (bot behavior)
        if let Some((interval, jitter)) = detect_periodic(&client.packet_times) {
            if client.total_pkts > 10 {
                periodic_bots.push(format!(
                    "{{\"ip\":\"{}\",\"interval\":{:.3},\"jitter\":{:.3},\"pkts\":{}}}",
                    jesc(ip), interval, jitter, client.total_pkts));
            }
        }

        // Fake players: connected but very low game data rate
        let dur = client.last_seen - client.first_seen;
        if dur > 10.0 && client.game_data_count > 0 && client.game_data_count < 5
            && client.total_pkts > 3 {
            fake_players.push(format!(
                "{{\"ip\":\"{}\",\"duration\":{:.1},\"game_pkts\":{},\"total_pkts\":{}}}",
                jesc(ip), dur, client.game_data_count, client.total_pkts));
        }
    }

    if !query_only_bots.is_empty() {
        alerts.push(format!(
            "{{\"type\":\"QUERY_ONLY_BOTS\",\"severity\":\"MEDIUM\",\"count\":{},\"clients\":[{}]}}",
            query_only_bots.len(), query_only_bots.join(",")));
    }
    if !high_rate_clients.is_empty() {
        let severity = if high_rate_clients.len() > 10 { "CRITICAL" } else { "HIGH" };
        alerts.push(format!(
            "{{\"type\":\"HIGH_RATE_CLIENTS\",\"severity\":\"{}\",\"count\":{},\"clients\":[{}]}}",
            severity, high_rate_clients.len(), high_rate_clients.join(",")));
    }
    if !periodic_bots.is_empty() {
        alerts.push(format!(
            "{{\"type\":\"PERIODIC_BOTS\",\"severity\":\"MEDIUM\",\"count\":{},\"clients\":[{}]}}",
            periodic_bots.len(), periodic_bots.join(",")));
    }
    if !fake_players.is_empty() {
        alerts.push(format!(
            "{{\"type\":\"FAKE_PLAYERS\",\"severity\":\"HIGH\",\"count\":{},\"clients\":[{}]}}",
            fake_players.len(), fake_players.join(",")));
    }

    // 4. Traffic spike detection (per-second)
    let avg_pps = total_se_pkts as f64 / duration;
    for (&sec, &(pkts, queries, _)) in &time_buckets {
        if pkts > (avg_pps * 5.0) as u64 + 50 {
            alerts.push(format!(
                "{{\"type\":\"TRAFFIC_SPIKE\",\"severity\":\"HIGH\",\"second\":{},\"pkts\":{},\"queries\":{},\"avg_pps\":{:.1}}}",
                sec, pkts, queries, avg_pps));
        }
    }

    // 5. Distributed query detection
    if unique_query_sources > 20 && total_queries > 100 {
        alerts.push(format!(
            "{{\"type\":\"DISTRIBUTED_QUERY_ATTACK\",\"severity\":\"CRITICAL\",\"sources\":{},\"total_queries\":{},\"qps\":{:.1}}}",
            unique_query_sources, total_queries, qps));
    }

    // --- Output ---
    println!("{{");
    println!("  \"mode\": \"source-engine\",");
    println!("  \"server_port\": {},", server_port);
    println!("  \"duration\": {:.1},", duration);
    println!("  \"status\": \"{}\",", if alerts.is_empty() { "CLEAN" } else { "THREATS_DETECTED" });

    // Overview
    println!("  \"overview\": {{");
    println!("    \"total_source_engine_pkts\": {},", total_se_pkts);
    println!("    \"total_queries\": {},", total_queries);
    println!("    \"total_game_data_pkts\": {},", total_game_pkts);
    println!("    \"server_responses\": {},", server_responses);
    println!("    \"queries_per_sec\": {:.1},", qps);
    println!("    \"unique_clients\": {},", clients.len());
    println!("    \"query_sources\": {},", unique_query_sources);
    print!("    \"query_breakdown\": {{");
    let qt: Vec<String> = query_type_counts.iter()
        .map(|(t, c)| format!("\"{}\":{}", se_type_name(*t), c))
        .collect();
    print!("{}", qt.join(","));
    println!("}}");
    println!("  }},");

    // Amplification stats
    if total_queries > 0 {
        let amp_ratio = server_resp_bytes as f64 / total_query_bytes.max(1) as f64;
        println!("  \"amplification\": {{");
        println!("    \"incoming_query_bytes\": {},", total_query_bytes);
        println!("    \"outgoing_response_bytes\": {},", server_resp_bytes);
        println!("    \"ratio\": {:.1}", amp_ratio);
        println!("  }},");
    }

    // Timeline
    println!("  \"timeline\": [");
    let mut buckets: Vec<_> = time_buckets.iter().collect();
    buckets.sort_by_key(|(&k, _)| k);
    for (i, (&sec, &(pkts, queries, bytes))) in buckets.iter().enumerate() {
        let comma = if i + 1 < buckets.len() { "," } else { "" };
        println!("    {{\"sec\":{},\"pkts\":{},\"queries\":{},\"bytes\":{}}}{}", sec, pkts, queries, bytes, comma);
    }
    println!("  ],");

    // Top clients
    println!("  \"top_clients\": [");
    let mut sorted_clients: Vec<_> = clients.iter().collect();
    sorted_clients.sort_by(|a, b| b.1.total_pkts.cmp(&a.1.total_pkts));
    let limit = sorted_clients.len().min(20);
    for (i, (ip, c)) in sorted_clients.iter().take(limit).enumerate() {
        let comma = if i + 1 < limit { "," } else { "" };
        println!("    {{\"ip\":\"{}\",\"pkts\":{},\"bytes\":{},\"queries\":{},\"game_data\":{},\"pps\":{:.1},\"avg_size\":{:.0},\"query_ratio\":{:.2}}}{}",
            jesc(ip), c.total_pkts, c.total_bytes, c.query_count, c.game_data_count,
            c.pps(), c.avg_size(), c.query_ratio(), comma);
    }
    println!("  ],");

    // Alerts
    println!("  \"alerts\": [");
    for (i, a) in alerts.iter().enumerate() {
        let comma = if i < alerts.len() - 1 { "," } else { "" };
        println!("    {}{}", a, comma);
    }
    println!("  ]");
    println!("}}");
}
