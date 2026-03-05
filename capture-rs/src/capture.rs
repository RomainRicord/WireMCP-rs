use pcap::Capture;
use std::process::Command;
use std::time::{Duration, Instant};

use crate::Cli;
use crate::parsers::parse_packet;

pub fn capture_basic<F: FnMut(&[u8], f64)>(cli: &Cli, mut on_packet: F) {
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

pub fn run_basic(cli: &Cli) {
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

pub fn run_full(cli: &Cli) {
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
