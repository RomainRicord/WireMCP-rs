use std::fmt;

// --- Helpers ---
pub fn mac_fmt(d: &[u8]) -> String {
    format!("{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}", d[0], d[1], d[2], d[3], d[4], d[5])
}
pub fn ip4_fmt(d: &[u8]) -> String { format!("{}.{}.{}.{}", d[0], d[1], d[2], d[3]) }
pub fn ip6_fmt(d: &[u8]) -> String {
    (0..8).map(|i| format!("{:02x}{:02x}", d[i*2], d[i*2+1])).collect::<Vec<_>>().join(":")
}
pub fn u16be(d: &[u8], o: usize) -> u16 { ((d[o] as u16) << 8) | d[o+1] as u16 }
pub fn u32be(d: &[u8], o: usize) -> u32 { ((d[o] as u32) << 24) | ((d[o+1] as u32) << 16) | ((d[o+2] as u32) << 8) | d[o+3] as u32 }
pub fn jesc(s: &str) -> String { s.replace('\\', "\\\\").replace('"', "\\\"").replace('\n', "\\n").replace('\r', "\\r").replace('\t', "\\t") }

pub fn tcp_flags_str(f: u8) -> String {
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

pub fn proto_name(n: u8) -> &'static str {
    match n { 1 => "icmp", 6 => "tcp", 17 => "udp", 58 => "icmpv6", _ => "other" }
}

pub fn pct(n: u64, total: u64) -> f64 { if total > 0 { n as f64 / total as f64 * 100.0 } else { 0.0 } }

// --- Packet info builder ---
pub struct Pkt {
    kv: Vec<String>,
    protocols: Vec<&'static str>,
}

impl Pkt {
    pub fn new(num: u32, time: f64) -> Self {
        let mut kv = Vec::with_capacity(20);
        kv.push(format!(r#""num":{}"#, num));
        kv.push(format!(r#""t":{:.6}"#, time));
        Self { kv, protocols: vec![] }
    }
    pub fn proto(&mut self, p: &'static str) { self.protocols.push(p); }
    pub fn str(&mut self, k: &str, v: &str) { self.kv.push(format!(r#""{}":"{}""#, k, jesc(v))); }
    pub fn num<T: fmt::Display>(&mut self, k: &str, v: T) { self.kv.push(format!(r#""{}": {}"#, k, v)); }
    pub fn finish(mut self) -> String {
        self.kv.insert(2, format!(r#""proto":"{}""#, self.protocols.join(":")));
        format!("{{{}}}", self.kv.join(","))
    }
}

// --- DNS name parser with compression ---
pub fn dns_name(dns: &[u8], mut off: usize) -> Option<(String, usize)> {
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

pub fn parse_packet(data: &[u8], num: u32, time: f64) -> Option<String> {
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
