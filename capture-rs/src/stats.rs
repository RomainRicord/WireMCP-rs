use std::collections::HashMap;

use crate::Cli;
use crate::parsers::{u16be, ip4_fmt, ip6_fmt};
use crate::capture::capture_basic;

// --- Stats mode: protocol hierarchy ---
pub fn run_stats(cli: &Cli) {
    let mut proto_bytes: HashMap<String, u64> = HashMap::new();
    let mut proto_pkts: HashMap<String, u64> = HashMap::new();
    let mut total_bytes = 0u64;
    let mut total_pkts = 0u64;

    capture_basic(cli, |data, _| {
        total_pkts += 1;
        total_bytes += data.len() as u64;

        if data.len() < 14 { return; }
        let ethertype = u16be(data, 12);
        let mut payload = &data[14..];
        let ethertype = if ethertype == 0x8100 && payload.len() >= 4 {
            let et = u16be(payload, 2); payload = &payload[4..]; et
        } else { ethertype };

        let mut chain = vec!["eth"];

        match ethertype {
            0x0800 if payload.len() >= 20 => {
                chain.push("ip");
                let ihl = (payload[0] & 0x0F) as usize * 4;
                let proto = payload[9];
                let app_payload = if ihl < payload.len() { &payload[ihl..] } else { &[] };
                match proto {
                    6 => { chain.push("tcp"); detect_app(&mut chain, app_payload, true); }
                    17 => { chain.push("udp"); detect_app(&mut chain, app_payload, false); }
                    1 => chain.push("icmp"),
                    _ => {}
                }
            }
            0x86DD if payload.len() >= 40 => {
                chain.push("ipv6");
                let nh = payload[6];
                let app_payload = &payload[40..];
                match nh {
                    6 => { chain.push("tcp"); detect_app(&mut chain, app_payload, true); }
                    17 => { chain.push("udp"); detect_app(&mut chain, app_payload, false); }
                    58 => chain.push("icmpv6"),
                    _ => {}
                }
            }
            0x0806 => chain.push("arp"),
            _ => {}
        }

        let full = chain.join(":");
        let len = data.len() as u64;
        // Count each level of the hierarchy
        for i in 1..=chain.len() {
            let key = chain[..i].join(":");
            *proto_bytes.entry(key.clone()).or_default() += len;
            *proto_pkts.entry(key).or_default() += 1;
        }
        *proto_bytes.entry(full.clone()).or_default(); // ensure leaf exists
        *proto_pkts.entry(full).or_default();
    });

    eprintln!("[stats] {} packets, {} bytes", total_pkts, total_bytes);

    // Output hierarchy
    let mut keys: Vec<String> = proto_pkts.keys().cloned().collect();
    keys.sort();
    println!("Protocol Hierarchy Statistics");
    println!("=============================");
    println!("Total packets: {}  Total bytes: {}\n", total_pkts, total_bytes);
    for k in &keys {
        let depth = k.matches(':').count();
        let indent = "  ".repeat(depth);
        let pkts = proto_pkts[k];
        let bytes = proto_bytes[k];
        let pct = if total_pkts > 0 { pkts as f64 / total_pkts as f64 * 100.0 } else { 0.0 };
        println!("{}{:<30} packets:{:<8} bytes:{:<12} ({:.1}%)", indent, k.rsplit(':').next().unwrap_or(k), pkts, bytes, pct);
    }
}

fn detect_app(chain: &mut Vec<&'static str>, payload: &[u8], is_tcp: bool) {
    if is_tcp && payload.len() >= 20 {
        let sp = u16be(payload, 0);
        let dp = u16be(payload, 2);
        let doff = ((payload[12] >> 4) as usize) * 4;
        let app = if doff < payload.len() { &payload[doff..] } else { return };
        if app.is_empty() { return; }
        if (sp == 443 || dp == 443 || sp == 8443 || dp == 8443) && app.len() > 1 && app[0] == 0x16 {
            chain.push("tls");
        } else if sp == 80 || dp == 80 || sp == 8080 || dp == 8080 {
            if app.starts_with(b"GET ") || app.starts_with(b"POST ") || app.starts_with(b"HTTP/") || app.starts_with(b"PUT ") || app.starts_with(b"HEAD ") {
                chain.push("http");
            }
        }
    } else if !is_tcp && payload.len() >= 8 {
        let sp = u16be(payload, 0);
        let dp = u16be(payload, 2);
        if sp == 53 || dp == 53 || sp == 5353 || dp == 5353 { chain.push("dns"); }
        else if (sp == 67 || sp == 68) && (dp == 67 || dp == 68) { chain.push("dhcp"); }
        else if dp == 51820 || sp == 51820 { chain.push("wireguard"); }
        else if dp == 1900 || sp == 1900 { chain.push("ssdp"); }
    }
}

// --- Conversations mode ---
pub fn run_conversations(cli: &Cli) {
    #[derive(Default)]
    struct Conv { pkts_ab: u64, pkts_ba: u64, bytes_ab: u64, bytes_ba: u64, start: f64, end: f64 }

    let mut tcp_convs: HashMap<String, Conv> = HashMap::new();
    let mut udp_convs: HashMap<String, Conv> = HashMap::new();

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
                (ip4_fmt(&payload[12..16]), ip4_fmt(&payload[16..20]), payload[9], &payload[ihl.min(payload.len())..])
            }
            0x86DD if payload.len() >= 40 => {
                (ip6_fmt(&payload[8..24]), ip6_fmt(&payload[24..40]), payload[6], &payload[40..])
            }
            _ => return,
        };

        if (proto != 6 && proto != 17) || ip_payload.len() < 4 { return; }
        let sp = u16be(ip_payload, 0);
        let dp = u16be(ip_payload, 2);
        let pkt_len = data.len() as u64;

        // Normalize direction: lower IP:port first
        let (key, is_forward) = {
            let a = format!("{}:{}", src_ip, sp);
            let b = format!("{}:{}", dst_ip, dp);
            if a <= b { (format!("{} <-> {}", a, b), true) } else { (format!("{} <-> {}", b, a), false) }
        };

        let map = if proto == 6 { &mut tcp_convs } else { &mut udp_convs };
        let c = map.entry(key).or_default();
        if c.start == 0.0 { c.start = time; }
        c.end = time;
        if is_forward { c.pkts_ab += 1; c.bytes_ab += pkt_len; }
        else { c.pkts_ba += 1; c.bytes_ba += pkt_len; }
    });

    let print_table = |name: &str, convs: &HashMap<String, Conv>| {
        if convs.is_empty() { return; }
        let mut sorted: Vec<_> = convs.iter().collect();
        sorted.sort_by(|a, b| (b.1.bytes_ab + b.1.bytes_ba).cmp(&(a.1.bytes_ab + a.1.bytes_ba)));
        println!("{} Conversations (sorted by total bytes)", name);
        println!("{:=<90}", "");
        println!("{:<45} {:>8} {:>8} {:>10} {:>10} {:>8}", "Endpoints", "Pkts→", "Pkts←", "Bytes→", "Bytes←", "Duration");
        for (k, c) in &sorted {
            let dur = c.end - c.start;
            println!("{:<45} {:>8} {:>8} {:>10} {:>10} {:>7.2}s", k, c.pkts_ab, c.pkts_ba, c.bytes_ab, c.bytes_ba, dur);
        }
        println!("\n{} conversations total\n", sorted.len());
    };

    print_table("TCP", &tcp_convs);
    print_table("UDP", &udp_convs);
}
