use clap::Parser;
use pcap::Capture;
use std::process::Command;
use std::time::{Duration, Instant};

// --- CLI ---
#[derive(Parser)]
#[command(name = "capture-packets", about = "Fast packet capture with native protocol parsing")]
struct Cli {
    /// Network interface
    #[arg(short, long, default_value = "wlo1")]
    interface: String,
    /// Capture duration in seconds
    #[arg(short, long, default_value_t = 5)]
    duration: u64,
    /// Mode: basic, full, stats, conversations
    #[arg(short, long, default_value = "basic")]
    mode: String,
    /// Read from pcap file instead of live capture
    #[arg(short = 'r', long)]
    file: Option<String>,
    /// Max output chars (0 = unlimited)
    #[arg(long, default_value_t = 720000)]
    max_chars: usize,
}

// --- Helpers ---
fn mac_fmt(d: &[u8]) -> String {
    format!("{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}", d[0], d[1], d[2], d[3], d[4], d[5])
}
fn ip4_fmt(d: &[u8]) -> String { format!("{}.{}.{}.{}", d[0], d[1], d[2], d[3]) }
fn ip6_fmt(d: &[u8]) -> String {
    (0..8).map(|i| format!("{:02x}{:02x}", d[i*2], d[i*2+1])).collect::<Vec<_>>().join(":")
}
fn u16be(d: &[u8], o: usize) -> u16 { ((d[o] as u16) << 8) | d[o+1] as u16 }
fn u32be(d: &[u8], o: usize) -> u32 { ((d[o] as u32) << 24) | ((d[o+1] as u32) << 16) | ((d[o+2] as u32) << 8) | d[o+3] as u32 }
fn jesc(s: &str) -> String { s.replace('\\', "\\\\").replace('"', "\\\"").replace('\n', "\\n").replace('\r', "\\r").replace('\t', "\\t") }

fn tcp_flags_str(f: u8) -> String {
    let mut s = String::new();
    if f & 0x02 != 0 { s.push_str("SYN,"); }
    if f & 0x10 != 0 { s.push_str("ACK,"); }
    if f & 0x01 != 0 { s.push_str("FIN,"); }
    if f & 0x04 != 0 { s.push_str("RST,"); }
    if f & 0x08 != 0 { s.push_str("PSH,"); }
    if f & 0x20 != 0 { s.push_str("URG,"); }
    if s.ends_with(',') { s.pop(); }
    s
}

fn proto_name(n: u8) -> &'static str {
    match n { 1 => "icmp", 6 => "tcp", 17 => "udp", 58 => "icmpv6", _ => "other" }
}

// --- Packet info builder ---
struct Pkt {
    kv: Vec<String>,
    protocols: Vec<&'static str>,
}

impl Pkt {
    fn new(num: u32, time: f64) -> Self {
        let mut kv = Vec::with_capacity(20);
        kv.push(format!(r#""num":{}"#, num));
        kv.push(format!(r#""t":{:.6}"#, time));
        Self { kv, protocols: vec![] }
    }
    fn proto(&mut self, p: &'static str) { self.protocols.push(p); }
    fn str(&mut self, k: &str, v: &str) { self.kv.push(format!(r#""{}":"{}""#, k, jesc(v))); }
    fn num<T: std::fmt::Display>(&mut self, k: &str, v: T) { self.kv.push(format!(r#""{}": {}"#, k, v)); }
    fn finish(mut self) -> String {
        self.kv.insert(2, format!(r#""proto":"{}""#, self.protocols.join(":")));
        format!("{{{}}}", self.kv.join(","))
    }
}

// --- DNS name parser with compression ---
fn dns_name(dns: &[u8], mut off: usize) -> Option<(String, usize)> {
    let mut name = String::new();
    let mut jumped = false;
    let mut end_off = off;
    for _ in 0..128 {
        if off >= dns.len() { return None; }
        let b = dns[off];
        if b == 0 {
            if !jumped { end_off = off + 1; }
            break;
        }
        if b & 0xC0 == 0xC0 {
            if off + 1 >= dns.len() { return None; }
            let ptr = ((b as usize & 0x3F) << 8) | dns[off + 1] as usize;
            if !jumped { end_off = off + 2; }
            if ptr >= dns.len() { return None; }
            off = ptr;
            jumped = true;
            continue;
        }
        let len = b as usize;
        if off + 1 + len > dns.len() { return None; }
        if !name.is_empty() { name.push('.'); }
        name.push_str(&String::from_utf8_lossy(&dns[off + 1..off + 1 + len]));
        off += 1 + len;
    }
    Some((name, end_off))
}

// --- Protocol parsers ---

fn parse_packet(data: &[u8], num: u32, time: f64) -> Option<String> {
    if data.len() < 14 { return None; }

    let mut p = Pkt::new(num, time);
    p.proto("eth");
    p.str("eth_dst", &mac_fmt(&data[0..6]));
    p.str("eth_src", &mac_fmt(&data[6..12]));

    let ethertype = u16be(data, 12);
    let mut payload = &data[14..];

    // Handle 802.1Q VLAN tag
    let ethertype = if ethertype == 0x8100 && payload.len() >= 4 {
        let et = u16be(payload, 2);
        payload = &payload[4..];
        et
    } else {
        ethertype
    };

    match ethertype {
        0x0800 => parse_ipv4(&mut p, payload),
        0x86DD => parse_ipv6(&mut p, payload),
        0x0806 => parse_arp(&mut p, payload),
        _ => {}
    }

    Some(p.finish())
}

fn parse_ipv4(p: &mut Pkt, data: &[u8]) {
    if data.len() < 20 { return; }
    p.proto("ip");
    let ihl = (data[0] & 0x0F) as usize * 4;
    if ihl < 20 || data.len() < ihl { return; }
    let total_len = u16be(data, 2) as usize;
    let proto = data[9];
    let ttl = data[8];

    p.str("ip_src", &ip4_fmt(&data[12..16]));
    p.str("ip_dst", &ip4_fmt(&data[16..20]));
    p.num("ip_ttl", ttl);
    p.num("ip_len", total_len);

    let payload_end = total_len.min(data.len());
    let payload = &data[ihl..payload_end.max(ihl)];

    match proto {
        1 => parse_icmp(p, payload),
        6 => parse_tcp(p, payload),
        17 => parse_udp(p, payload),
        _ => { p.str("ip_proto", proto_name(proto)); }
    }
}

fn parse_ipv6(p: &mut Pkt, data: &[u8]) {
    if data.len() < 40 { return; }
    p.proto("ipv6");
    let payload_len = u16be(data, 4) as usize;
    let next_header = data[6];
    let hop_limit = data[7];

    p.str("ip6_src", &ip6_fmt(&data[8..24]));
    p.str("ip6_dst", &ip6_fmt(&data[24..40]));
    p.num("ip6_hlim", hop_limit);

    let payload = &data[40..data.len().min(40 + payload_len)];

    match next_header {
        6 => parse_tcp(p, payload),
        17 => parse_udp(p, payload),
        58 => parse_icmp(p, payload),
        _ => { p.str("ip_proto", proto_name(next_header)); }
    }
}

fn parse_tcp(p: &mut Pkt, data: &[u8]) {
    if data.len() < 20 { return; }
    p.proto("tcp");
    let sp = u16be(data, 0);
    let dp = u16be(data, 2);
    let seq = u32be(data, 4);
    let ack = u32be(data, 8);
    let doff = ((data[12] >> 4) as usize) * 4;
    let flags = data[13];
    let window = u16be(data, 14);

    p.num("tcp_sp", sp);
    p.num("tcp_dp", dp);
    p.str("tcp_flags", &tcp_flags_str(flags));
    p.num("tcp_seq", seq);
    p.num("tcp_ack", ack);
    p.num("tcp_win", window);

    if doff > data.len() { return; }
    let payload = &data[doff..];
    if payload.is_empty() { return; }

    // Application layer detection
    let is_http_port = sp == 80 || dp == 80 || sp == 8080 || dp == 8080 || sp == 8000 || dp == 8000;
    let is_tls_port = sp == 443 || dp == 443 || sp == 8443 || dp == 8443;

    if is_tls_port && payload.len() > 5 && payload[0] == 0x16 {
        parse_tls(p, payload);
    } else if is_http_port {
        parse_http(p, payload);
    } else if payload.len() > 5 && payload[0] == 0x16 {
        // TLS on non-standard port
        parse_tls(p, payload);
    } else if payload.len() > 4 {
        // Try HTTP detection by method
        let start = &payload[..payload.len().min(8)];
        if start.starts_with(b"GET ") || start.starts_with(b"POST ") || start.starts_with(b"PUT ")
            || start.starts_with(b"DELETE ") || start.starts_with(b"HEAD ") || start.starts_with(b"HTTP/") {
            parse_http(p, payload);
        }
    }
}

fn parse_udp(p: &mut Pkt, data: &[u8]) {
    if data.len() < 8 { return; }
    p.proto("udp");
    let sp = u16be(data, 0);
    let dp = u16be(data, 2);
    let len = u16be(data, 4);

    p.num("udp_sp", sp);
    p.num("udp_dp", dp);
    p.num("udp_len", len);

    let payload = &data[8..];

    // DNS
    if sp == 53 || dp == 53 {
        parse_dns(p, payload);
    }
    // DHCP
    else if (sp == 67 || sp == 68) && (dp == 67 || dp == 68) {
        parse_dhcp(p, payload);
    }
    // mDNS
    else if dp == 5353 || sp == 5353 {
        parse_dns(p, payload);
    }
    // SSDP
    else if dp == 1900 || sp == 1900 {
        if payload.len() > 4 {
            parse_http(p, payload); // SSDP uses HTTP-like format
        }
    }
}

fn parse_icmp(p: &mut Pkt, data: &[u8]) {
    if data.len() < 4 { return; }
    p.proto("icmp");
    let icmp_type = data[0];
    let code = data[1];
    p.num("icmp_type", icmp_type);
    p.num("icmp_code", code);
    let desc = match icmp_type {
        0 => "Echo Reply",
        3 => match code { 0 => "Net Unreachable", 1 => "Host Unreachable", 3 => "Port Unreachable", _ => "Dest Unreachable" },
        8 => "Echo Request",
        11 => "Time Exceeded",
        _ => "",
    };
    if !desc.is_empty() { p.str("icmp_desc", desc); }
}

fn parse_arp(p: &mut Pkt, data: &[u8]) {
    if data.len() < 28 { return; }
    p.proto("arp");
    let op = u16be(data, 6);
    p.str("arp_op", if op == 1 { "request" } else if op == 2 { "reply" } else { "other" });
    p.str("arp_src_mac", &mac_fmt(&data[8..14]));
    p.str("arp_src_ip", &ip4_fmt(&data[14..18]));
    p.str("arp_dst_mac", &mac_fmt(&data[18..24]));
    p.str("arp_dst_ip", &ip4_fmt(&data[24..28]));
}

fn parse_dns(p: &mut Pkt, data: &[u8]) {
    if data.len() < 12 { return; }
    p.proto("dns");
    let flags = u16be(data, 2);
    let is_resp = (flags & 0x8000) != 0;
    let qcount = u16be(data, 4) as usize;
    let acount = u16be(data, 6) as usize;

    p.str("dns_type", if is_resp { "response" } else { "query" });

    // Parse first question
    let mut off = 12;
    for _ in 0..qcount.min(4) {
        if let Some((name, new_off)) = dns_name(data, off) {
            if new_off + 4 > data.len() { break; }
            let qtype = u16be(data, new_off);
            let qtype_str = match qtype { 1 => "A", 28 => "AAAA", 5 => "CNAME", 15 => "MX", 16 => "TXT",
                33 => "SRV", 6 => "SOA", 2 => "NS", 12 => "PTR", 65 => "HTTPS", _ => "" };
            p.str("dns_query", &name);
            if !qtype_str.is_empty() { p.str("dns_qtype", qtype_str); } else { p.num("dns_qtype_n", qtype); }
            off = new_off + 4;
            break; // first question only for kv
        } else {
            break;
        }
    }

    // Parse answers
    if is_resp && acount > 0 {
        let mut answers = Vec::new();
        for _ in 0..acount.min(8) {
            if let Some((_, new_off)) = dns_name(data, off) {
                if new_off + 10 > data.len() { break; }
                let rtype = u16be(data, new_off);
                let rdlen = u16be(data, new_off + 8) as usize;
                let rdata_off = new_off + 10;
                if rdata_off + rdlen > data.len() { break; }

                match rtype {
                    1 if rdlen == 4 => { // A
                        answers.push(ip4_fmt(&data[rdata_off..rdata_off + 4]));
                    }
                    28 if rdlen == 16 => { // AAAA
                        answers.push(ip6_fmt(&data[rdata_off..rdata_off + 16]));
                    }
                    5 => { // CNAME
                        if let Some((cname, _)) = dns_name(data, rdata_off) {
                            answers.push(format!("CNAME:{}", cname));
                        }
                    }
                    _ => {}
                }
                off = rdata_off + rdlen;
            } else {
                break;
            }
        }
        if !answers.is_empty() {
            p.str("dns_answers", &answers.join(","));
        }
    }
}

fn parse_tls(p: &mut Pkt, data: &[u8]) {
    if data.len() < 5 { return; }
    if data[0] != 0x16 { return; } // Not handshake
    p.proto("tls");

    let rec_version = format!("{}.{}", data[1], data[2]);
    let rec_len = u16be(data, 3) as usize;
    if data.len() < 5 + rec_len { return; }

    let hs = &data[5..];
    if hs.is_empty() || hs[0] != 0x01 { // Not ClientHello
        p.str("tls_version", &rec_version);
        return;
    }
    if hs.len() < 6 { return; }
    // ClientHello
    let hs_len = ((hs[1] as usize) << 16) | ((hs[2] as usize) << 8) | hs[3] as usize;
    if hs.len() < 4 + hs_len.min(hs.len()) { return; }
    let ch = &hs[4..];
    if ch.len() < 38 { return; }

    // Client version
    let ver = u16be(ch, 0);
    let ver_str = match ver { 0x0303 => "1.2", 0x0302 => "1.1", 0x0301 => "1.0", _ => "" };

    // Skip random (32B), session_id
    let mut off = 34;
    if off >= ch.len() { return; }
    let sid_len = ch[off] as usize;
    off += 1 + sid_len;
    if off + 2 > ch.len() { return; }

    // Skip cipher suites
    let cs_len = u16be(ch, off) as usize;
    off += 2 + cs_len;
    if off >= ch.len() { return; }

    // Skip compression methods
    let cm_len = ch[off] as usize;
    off += 1 + cm_len;
    if off + 2 > ch.len() { return; }

    // Extensions
    let ext_len = u16be(ch, off) as usize;
    off += 2;
    let ext_end = (off + ext_len).min(ch.len());
    let mut actual_version = ver_str.to_string();

    while off + 4 <= ext_end {
        let ext_type = u16be(ch, off);
        let ext_data_len = u16be(ch, off + 2) as usize;
        off += 4;
        if off + ext_data_len > ext_end { break; }

        match ext_type {
            0x0000 => { // SNI
                if ext_data_len >= 5 {
                    let sni_list_len = u16be(ch, off) as usize;
                    if sni_list_len + 2 <= ext_data_len && ch[off + 2] == 0 {
                        let sni_len = u16be(ch, off + 3) as usize;
                        if off + 5 + sni_len <= ext_end {
                            if let Ok(sni) = std::str::from_utf8(&ch[off + 5..off + 5 + sni_len]) {
                                p.str("tls_sni", sni);
                            }
                        }
                    }
                }
            }
            0x002b => { // Supported Versions
                // Check for TLS 1.3
                if ext_data_len >= 1 {
                    let sv_len = ch[off] as usize;
                    let mut i = 0;
                    while i + 2 <= sv_len && off + 1 + i + 2 <= ext_end {
                        let v = u16be(ch, off + 1 + i);
                        if v == 0x0304 { actual_version = "1.3".into(); break; }
                        i += 2;
                    }
                }
            }
            _ => {}
        }
        off += ext_data_len;
    }

    if !actual_version.is_empty() { p.str("tls_version", &actual_version); }
}

fn parse_http(p: &mut Pkt, data: &[u8]) {
    let text = match std::str::from_utf8(&data[..data.len().min(2048)]) {
        Ok(s) => s,
        Err(_) => return,
    };
    let first_line = match text.lines().next() {
        Some(l) => l,
        None => return,
    };

    if first_line.starts_with("HTTP/") {
        // Response
        p.proto("http");
        let parts: Vec<&str> = first_line.splitn(3, ' ').collect();
        if parts.len() >= 2 {
            if let Ok(code) = parts[1].parse::<u16>() {
                p.num("http_status", code);
            }
        }
    } else {
        // Check if request
        let methods = ["GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH", "CONNECT"];
        let is_req = methods.iter().any(|m| first_line.starts_with(m));
        if !is_req { return; }

        p.proto("http");
        let parts: Vec<&str> = first_line.splitn(3, ' ').collect();
        if parts.len() >= 2 {
            p.str("http_method", parts[0]);
            p.str("http_uri", parts[1]);
        }
    }

    // Parse headers
    for line in text.lines().skip(1) {
        if line.is_empty() || line == "\r" { break; }
        if let Some((key, value)) = line.split_once(':') {
            let key_lower = key.trim().to_lowercase();
            let val = value.trim();
            match key_lower.as_str() {
                "host" => p.str("http_host", val),
                "user-agent" => p.str("http_ua", val),
                "content-type" => p.str("http_ctype", val),
                "server" => p.str("http_server", val),
                "location" => p.str("http_location", val),
                _ => {}
            }
        }
    }
}

fn parse_dhcp(p: &mut Pkt, data: &[u8]) {
    if data.len() < 240 { return; }
    // Check magic cookie
    if data[236..240] != [0x63, 0x82, 0x53, 0x63] { return; }
    p.proto("dhcp");

    let op = data[0];
    p.str("dhcp_op", if op == 1 { "request" } else { "reply" });

    // Client MAC
    let hlen = data[2] as usize;
    if hlen == 6 {
        p.str("dhcp_client_mac", &mac_fmt(&data[28..34]));
    }

    // Assigned IP
    let yiaddr = &data[16..20];
    if yiaddr != [0, 0, 0, 0] {
        p.str("dhcp_assigned_ip", &ip4_fmt(yiaddr));
    }

    // Parse options
    let mut off = 240;
    while off < data.len() {
        let opt = data[off];
        if opt == 255 { break; } // End
        if opt == 0 { off += 1; continue; } // Padding
        if off + 1 >= data.len() { break; }
        let len = data[off + 1] as usize;
        if off + 2 + len > data.len() { break; }
        let val = &data[off + 2..off + 2 + len];

        match opt {
            53 if len == 1 => { // Message Type
                let mt = match val[0] {
                    1 => "Discover", 2 => "Offer", 3 => "Request", 4 => "Decline",
                    5 => "ACK", 6 => "NAK", 7 => "Release", 8 => "Inform", _ => "",
                };
                if !mt.is_empty() { p.str("dhcp_msg_type", mt); }
            }
            12 => { // Hostname
                if let Ok(name) = std::str::from_utf8(val) {
                    p.str("dhcp_hostname", name);
                }
            }
            60 => { // Vendor Class
                if let Ok(vc) = std::str::from_utf8(val) {
                    p.str("dhcp_vendor", vc);
                }
            }
            _ => {}
        }
        off += 2 + len;
    }
}

// --- Capture modes ---

fn capture_basic<F: FnMut(&[u8], f64)>(cli: &Cli, mut on_packet: F) {
    if let Some(ref file) = cli.file {
        let mut cap = match Capture::from_file(file) {
            Ok(c) => c,
            Err(e) => { eprintln!("Error: Cannot open {}: {}", file, e); std::process::exit(1); }
        };
        let mut first_ts: Option<f64> = None;
        while let Ok(pkt) = cap.next_packet() {
            let ts = pkt.header.ts.tv_sec as f64 + pkt.header.ts.tv_usec as f64 / 1_000_000.0;
            let first = *first_ts.get_or_insert(ts);
            on_packet(pkt.data, ts - first);
        }
    } else {
        let iface = &cli.interface;
        let mut cap = match Capture::from_device(iface as &str)
            .and_then(|c| c.promisc(true).snaplen(65535).timeout(1000).open()) {
            Ok(c) => c,
            Err(e) => { eprintln!("Error: Cannot open {}: {} (try: sudo setcap cap_net_raw,cap_net_admin=eip <binary>)", iface, e); std::process::exit(1); }
        };

        let start = Instant::now();
        let timeout = Duration::from_secs(cli.duration);
        let mut first_ts: Option<f64> = None;

        eprintln!("[capture] Capturing on {} for {}s (basic mode)...", iface, cli.duration);

        while start.elapsed() < timeout {
            let pkt = match cap.next_packet() {
                Ok(p) => p,
                Err(_) => continue,
            };
            let ts = pkt.header.ts.tv_sec as f64 + pkt.header.ts.tv_usec as f64 / 1_000_000.0;
            let first = *first_ts.get_or_insert(ts);
            on_packet(pkt.data, ts - first);
        }
    }
}

fn run_basic(cli: &Cli) {
    let max_chars = cli.max_chars;
    let mut packets: Vec<String> = Vec::new();
    let mut num = 0u32;

    capture_basic(cli, |data, time| {
        num += 1;
        if let Some(json) = parse_packet(data, num, time) {
            packets.push(json);
        }
    });

    eprintln!("[capture] {} frames captured, {} parsed", num, packets.len());

    // Build JSON array, respecting max_chars
    let mut output = String::from("[\n");
    let mut count = 0;
    for (i, pkt_json) in packets.iter().enumerate() {
        let entry = if i > 0 { format!(",\n{}", pkt_json) } else { pkt_json.clone() };
        if max_chars > 0 && output.len() + entry.len() + 2 > max_chars {
            eprintln!("[capture] Trimmed output at {} packets (max {} chars)", count, max_chars);
            break;
        }
        output.push_str(&entry);
        count += 1;
    }
    output.push_str("\n]");

    println!("{}", output);
    eprintln!("[capture] Output: {} packets, {} chars", count, output.len());
}

fn run_full(cli: &Cli) {
    let tshark = "tshark";
    let fields = [
        "-e", "frame.number", "-e", "frame.time_relative", "-e", "frame.protocols",
        "-e", "eth.src", "-e", "eth.dst",
        "-e", "ip.src", "-e", "ip.dst", "-e", "ip.proto", "-e", "ip.ttl", "-e", "ip.len",
        "-e", "ipv6.src", "-e", "ipv6.dst",
        "-e", "tcp.srcport", "-e", "tcp.dstport", "-e", "tcp.flags", "-e", "tcp.seq", "-e", "tcp.ack", "-e", "tcp.window_size",
        "-e", "udp.srcport", "-e", "udp.dstport", "-e", "udp.length",
        "-e", "http.request.method", "-e", "http.request.uri", "-e", "http.host",
        "-e", "http.user_agent", "-e", "http.response.code", "-e", "http.content_type",
        "-e", "http.server", "-e", "http.location",
        "-e", "tls.handshake.extensions_server_name", "-e", "tls.record.version",
        "-e", "dns.qry.name", "-e", "dns.qry.type", "-e", "dns.a", "-e", "dns.aaaa", "-e", "dns.cname",
        "-e", "arp.opcode", "-e", "arp.src.proto_ipv4", "-e", "arp.dst.proto_ipv4",
        "-e", "arp.src.hw_mac", "-e", "arp.dst.hw_mac",
        "-e", "icmp.type", "-e", "icmp.code",
        "-e", "dhcp.option.dhcp", "-e", "dhcp.option.hostname", "-e", "dhcp.option.vendor_class_id",
        "-e", "bootp.hw.mac_addr",
        "-e", "kerberos.CNameString", "-e", "kerberos.realm", "-e", "kerberos.cipher", "-e", "kerberos.msg_type",
        "-e", "smb.cmd", "-e", "smb2.cmd",
        "-e", "sip.Method", "-e", "sip.r-uri",
    ];

    if let Some(ref file) = cli.file {
        eprintln!("[capture] Reading {} with tshark (full mode)...", file);
        let output = Command::new(tshark)
            .args(["-r", file, "-T", "json"])
            .args(&fields)
            .output()
            .expect("Failed to run tshark");

        let stdout = String::from_utf8_lossy(&output.stdout);
        if !output.status.success() {
            eprintln!("[capture] tshark error: {}", String::from_utf8_lossy(&output.stderr));
            std::process::exit(1);
        }

        // Trim if needed
        if cli.max_chars > 0 && stdout.len() > cli.max_chars {
            println!("{}", &stdout[..cli.max_chars]);
            eprintln!("[capture] Output trimmed to {} chars", cli.max_chars);
        } else {
            print!("{}", stdout);
        }
    } else {
        // Live capture: capture to temp file with libpcap, then dissect with tshark
        let tmp = format!("/tmp/capture_rs_{}.pcap", std::process::id());
        eprintln!("[capture] Capturing on {} for {}s, saving to {}...", cli.interface, cli.duration, tmp);

        {
            let mut cap = match Capture::from_device(cli.interface.as_str())
                .and_then(|c| c.promisc(true).snaplen(65535).timeout(1000).open()) {
                Ok(c) => c,
                Err(e) => { eprintln!("Error: Cannot open {}: {}", cli.interface, e); std::process::exit(1); }
            };

            let mut savefile = match cap.savefile(&tmp) {
                Ok(s) => s,
                Err(e) => { eprintln!("Error: Cannot create savefile: {}", e); std::process::exit(1); }
            };
            let start = Instant::now();
            let timeout = Duration::from_secs(cli.duration);
            let mut count = 0u64;

            while start.elapsed() < timeout {
                if let Ok(pkt) = cap.next_packet() {
                    savefile.write(&pkt);
                    count += 1;
                }
            }
            eprintln!("[capture] Captured {} frames", count);
        }

        eprintln!("[capture] Dissecting with tshark...");
        let output = Command::new(tshark)
            .args(["-r", &tmp, "-T", "json"])
            .args(&fields)
            .output()
            .expect("Failed to run tshark");

        let _ = std::fs::remove_file(&tmp);

        if !output.status.success() {
            eprintln!("[capture] tshark error: {}", String::from_utf8_lossy(&output.stderr));
            std::process::exit(1);
        }

        let stdout = String::from_utf8_lossy(&output.stdout);
        if cli.max_chars > 0 && stdout.len() > cli.max_chars {
            println!("{}", &stdout[..cli.max_chars]);
            eprintln!("[capture] Output trimmed to {} chars", cli.max_chars);
        } else {
            print!("{}", stdout);
        }
    }
}

// --- Stats mode: protocol hierarchy ---
fn run_stats(cli: &Cli) {
    use std::collections::HashMap;
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
fn run_conversations(cli: &Cli) {
    use std::collections::HashMap;

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

// --- DDoS analysis mode ---
fn run_ddos(cli: &Cli) {
    use std::collections::HashMap;

    struct SrcStats {
        pkts: u64,
        bytes: u64,
        syn_count: u64,
        ack_count: u64,
        udp_count: u64,
        icmp_count: u64,
        dst_ports: HashMap<u16, u64>,
        first_seen: f64,
        last_seen: f64,
    }

    impl SrcStats {
        fn new(t: f64) -> Self {
            Self { pkts: 0, bytes: 0, syn_count: 0, ack_count: 0, udp_count: 0, icmp_count: 0,
                   dst_ports: HashMap::new(), first_seen: t, last_seen: t }
        }
    }

    // Per-destination tracking for amplification detection
    struct AmpStats { requests: u64, req_bytes: u64, responses: u64, resp_bytes: u64 }

    let mut sources: HashMap<String, SrcStats> = HashMap::new();
    let mut dst_stats: HashMap<String, u64> = HashMap::new();
    let mut dns_amp: HashMap<String, AmpStats> = HashMap::new();
    let mut ntp_amp: HashMap<String, AmpStats> = HashMap::new();
    let mut ssdp_amp: HashMap<String, AmpStats> = HashMap::new();

    // Time buckets (1s intervals)
    let mut time_buckets: HashMap<u64, (u64, u64)> = HashMap::new(); // second -> (pkts, bytes)
    let mut total_pkts = 0u64;
    let mut total_bytes = 0u64;
    let mut total_syn = 0u64;
    let mut total_synack = 0u64;
    let mut total_rst = 0u64;
    let mut frag_count = 0u64;

    capture_basic(cli, |data, time| {
        total_pkts += 1;
        total_bytes += data.len() as u64;

        let bucket = time as u64;
        let e = time_buckets.entry(bucket).or_default();
        e.0 += 1;
        e.1 += data.len() as u64;

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
                let mf = (flags & 0x2000) != 0;
                let frag_off = flags & 0x1FFF;
                if mf || frag_off > 0 { frag_count += 1; }
                (ip4_fmt(&payload[12..16]), ip4_fmt(&payload[16..20]), payload[9], &payload[ihl.min(payload.len())..])
            }
            0x86DD if payload.len() >= 40 => {
                (ip6_fmt(&payload[8..24]), ip6_fmt(&payload[24..40]), payload[6], &payload[40..])
            }
            _ => return,
        };

        let pkt_len = data.len() as u64;
        *dst_stats.entry(dst_ip.clone()).or_default() += 1;

        let s = sources.entry(src_ip.clone()).or_insert_with(|| SrcStats::new(time));
        s.pkts += 1;
        s.bytes += pkt_len;
        s.last_seen = time;

        match proto {
            6 if ip_payload.len() >= 14 => { // TCP
                let dp = u16be(ip_payload, 2);
                let flags = ip_payload[13];
                let is_syn = (flags & 0x02) != 0;
                let is_ack = (flags & 0x10) != 0;
                let is_rst = (flags & 0x04) != 0;

                if is_syn && !is_ack { s.syn_count += 1; total_syn += 1; }
                if is_syn && is_ack { total_synack += 1; }
                if is_rst { total_rst += 1; }
                if is_ack { s.ack_count += 1; }
                *s.dst_ports.entry(dp).or_default() += 1;
            }
            17 if ip_payload.len() >= 8 => { // UDP
                let sp = u16be(ip_payload, 0);
                let dp = u16be(ip_payload, 2);
                s.udp_count += 1;
                *s.dst_ports.entry(dp).or_default() += 1;

                // Amplification detection
                if sp == 53 || dp == 53 {
                    let e = dns_amp.entry(dst_ip.clone()).or_insert_with(|| AmpStats { requests: 0, req_bytes: 0, responses: 0, resp_bytes: 0 });
                    if sp == 53 { e.responses += 1; e.resp_bytes += pkt_len; }
                    else { e.requests += 1; e.req_bytes += pkt_len; }
                }
                if sp == 123 || dp == 123 {
                    let e = ntp_amp.entry(dst_ip.clone()).or_insert_with(|| AmpStats { requests: 0, req_bytes: 0, responses: 0, resp_bytes: 0 });
                    if sp == 123 { e.responses += 1; e.resp_bytes += pkt_len; }
                    else { e.requests += 1; e.req_bytes += pkt_len; }
                }
                if sp == 1900 || dp == 1900 {
                    let e = ssdp_amp.entry(dst_ip.clone()).or_insert_with(|| AmpStats { requests: 0, req_bytes: 0, responses: 0, resp_bytes: 0 });
                    if sp == 1900 { e.responses += 1; e.resp_bytes += pkt_len; }
                    else { e.requests += 1; e.req_bytes += pkt_len; }
                }
            }
            1 | 58 => { // ICMP / ICMPv6
                s.icmp_count += 1;
            }
            _ => {}
        }
    });

    // --- Analysis & Output ---
    let duration = if let Some(max_t) = time_buckets.keys().max() { *max_t as f64 + 1.0 } else { 1.0 };
    let pps = total_pkts as f64 / duration;
    let bps = total_bytes as f64 * 8.0 / duration;

    println!("=== DDoS Analysis Report ===\n");

    // Overview
    println!("[Overview]");
    println!("  Duration:       {:.1}s", duration);
    println!("  Total packets:  {} ({:.0} pkt/s)", total_pkts, pps);
    println!("  Total bytes:    {} ({:.1} Mbit/s)", total_bytes, bps / 1_000_000.0);
    println!("  Unique sources: {}", sources.len());
    println!("  Fragmented:     {}", frag_count);
    println!();

    // TCP flags analysis
    println!("[TCP Flags]");
    println!("  SYN:     {} ({:.1}%)", total_syn, if total_pkts > 0 { total_syn as f64 / total_pkts as f64 * 100.0 } else { 0.0 });
    println!("  SYN+ACK: {}", total_synack);
    println!("  RST:     {}", total_rst);
    let syn_ratio = if total_synack > 0 { total_syn as f64 / total_synack as f64 } else if total_syn > 0 { f64::INFINITY } else { 0.0 };
    if syn_ratio > 3.0 && total_syn > 100 {
        println!("  >> SYN FLOOD DETECTED: SYN/SYN+ACK ratio = {:.1} (expected ~1.0)", syn_ratio);
    } else if syn_ratio > 3.0 && total_syn > 10 {
        println!("  >> SYN flood suspected: SYN/SYN+ACK ratio = {:.1}", syn_ratio);
    }
    println!();

    // Traffic timeline
    println!("[Traffic Timeline (pkt/s | Kbit/s)]");
    let mut buckets: Vec<_> = time_buckets.iter().collect();
    buckets.sort_by_key(|(&k, _)| k);
    let max_pps = buckets.iter().map(|(_, (p, _))| *p).max().unwrap_or(1);
    for (sec, (pkts, bytes)) in &buckets {
        let bar_len = (*pkts as f64 / max_pps as f64 * 40.0) as usize;
        let bar: String = "#".repeat(bar_len);
        println!("  {:>4}s: {:>6} pkt/s  {:>8} Kb/s  {}", sec, pkts, bytes * 8 / 1000, bar);
    }
    let peak_pps = buckets.iter().map(|(_, (p, _))| *p).max().unwrap_or(0);
    let peak_bps = buckets.iter().map(|(_, (_, b))| *b * 8).max().unwrap_or(0);
    println!("  Peak: {} pkt/s, {:.1} Mbit/s", peak_pps, peak_bps as f64 / 1_000_000.0);
    println!();

    // Top source IPs by packets
    println!("[Top 15 Source IPs by packets]");
    let mut src_sorted: Vec<_> = sources.iter().collect();
    src_sorted.sort_by(|a, b| b.1.pkts.cmp(&a.1.pkts));
    println!("  {:<40} {:>8} {:>10} {:>6} {:>6} {:>6} {:>8}", "IP", "Packets", "Bytes", "SYN", "UDP", "ICMP", "Ports");
    for (ip, s) in src_sorted.iter().take(15) {
        let dur = s.last_seen - s.first_seen;
        let port_count = s.dst_ports.len();
        let rate = if dur > 0.0 { format!("({:.0}/s)", s.pkts as f64 / dur) } else { String::new() };
        println!("  {:<40} {:>8} {:>10} {:>6} {:>6} {:>6} {:>5} dst {}", ip, s.pkts, s.bytes, s.syn_count, s.udp_count, s.icmp_count, port_count, rate);
    }
    println!();

    // Top destination IPs (targets)
    println!("[Top 10 Destination IPs (targets)]");
    let mut dst_sorted: Vec<_> = dst_stats.iter().collect();
    dst_sorted.sort_by(|a, b| b.1.cmp(a.1));
    for (ip, pkts) in dst_sorted.iter().take(10) {
        println!("  {:<40} {:>8} packets", ip, pkts);
    }
    println!();

    // Port scan detection (many dst ports from one source)
    let scanners: Vec<_> = sources.iter().filter(|(_, s)| s.dst_ports.len() > 20 && s.pkts > 50).collect();
    if !scanners.is_empty() {
        println!("[Port Scan Detection]");
        for (ip, s) in &scanners {
            println!("  >> {} hit {} different ports ({} packets)", ip, s.dst_ports.len(), s.pkts);
        }
        println!();
    }

    // Amplification detection
    let print_amp = |name: &str, amp: &HashMap<String, AmpStats>| {
        let suspicious: Vec<_> = amp.iter().filter(|(_, a)| a.resp_bytes > a.req_bytes * 5 && a.responses > 10).collect();
        if suspicious.is_empty() { return; }
        println!("[{} Amplification Detected]", name);
        for (ip, a) in &suspicious {
            let ratio = if a.req_bytes > 0 { a.resp_bytes as f64 / a.req_bytes as f64 } else { f64::INFINITY };
            println!("  >> {} — {} requests ({} B) -> {} responses ({} B) — amplification: {:.1}x",
                ip, a.requests, a.req_bytes, a.responses, a.resp_bytes, ratio);
        }
        println!();
    };
    print_amp("DNS", &dns_amp);
    print_amp("NTP", &ntp_amp);
    print_amp("SSDP", &ssdp_amp);

    // Flood detection summary
    println!("[Flood Detection Summary]");
    let mut alerts = Vec::new();

    if syn_ratio > 3.0 && total_syn > 100 {
        alerts.push(format!("SYN Flood: {} SYN packets, ratio SYN/SYN+ACK = {:.1}", total_syn, syn_ratio));
    }

    let udp_total: u64 = sources.values().map(|s| s.udp_count).sum();
    if udp_total as f64 / total_pkts.max(1) as f64 > 0.8 && pps > 100.0 {
        alerts.push(format!("UDP Flood: {:.0}% of traffic is UDP ({:.0} pkt/s)", udp_total as f64 / total_pkts as f64 * 100.0, pps));
    }

    let icmp_total: u64 = sources.values().map(|s| s.icmp_count).sum();
    if icmp_total as f64 / total_pkts.max(1) as f64 > 0.5 && pps > 50.0 {
        alerts.push(format!("ICMP Flood: {:.0}% of traffic is ICMP ({} packets)", icmp_total as f64 / total_pkts as f64 * 100.0, icmp_total));
    }

    if frag_count as f64 / total_pkts.max(1) as f64 > 0.3 && frag_count > 50 {
        alerts.push(format!("Fragmentation attack: {} fragmented packets ({:.0}%)", frag_count, frag_count as f64 / total_pkts as f64 * 100.0));
    }

    // Many sources = distributed
    if sources.len() > 50 && pps > 500.0 {
        alerts.push(format!("Distributed attack: {} unique sources at {:.0} pkt/s", sources.len(), pps));
    }

    if alerts.is_empty() {
        println!("  No DDoS patterns detected.");
    } else {
        for a in &alerts {
            println!("  >> {}", a);
        }
    }
}

// --- Main ---
fn main() {
    let cli = Cli::parse();

    if !cli.interface.chars().all(|c| c.is_alphanumeric() || c == '_' || c == '-' || c == '.') {
        eprintln!("Error: Invalid interface name: {}", cli.interface);
        std::process::exit(1);
    }

    match cli.mode.as_str() {
        "basic" => run_basic(&cli),
        "full" => run_full(&cli),
        "stats" => run_stats(&cli),
        "conversations" => run_conversations(&cli),
        "ddos" => run_ddos(&cli),
        other => {
            eprintln!("Error: Unknown mode '{}'. Use basic, full, stats, conversations, or ddos.", other);
            std::process::exit(1);
        }
    }
}
