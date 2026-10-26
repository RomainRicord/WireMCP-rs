//! DDoS detector regression tests.
//!
//! - `synthetic_*`: small pcaps generated on the fly (legit traffic that must stay silent, known edge cases).
//! - `dataset_*`: real attacks from the StopDDoS packet-captures collection. The dataset (~230 MB) is not
//!   committed: these tests are skipped unless it sits in `../packet-captures-main` or `$WIREMCP_PCAP_DIR`.

use std::path::{Path, PathBuf};
use std::process::Command;

fn run_ddos(pcap: &Path) -> String {
    let out = Command::new(env!("CARGO_BIN_EXE_capture-packets"))
        .args(["--mode", "ddos", "--file"]).arg(pcap)
        .output().expect("failed to run capture-packets");
    assert!(out.status.success(), "capture-packets failed: {}", String::from_utf8_lossy(&out.stderr));
    String::from_utf8_lossy(&out.stdout).into_owned()
}

/// Alerts listed under DETECTION SUMMARY
fn alerts(report: &str) -> Vec<String> {
    report.split("DETECTION SUMMARY").nth(1).unwrap_or("")
        .lines()
        .filter_map(|l| l.trim().split_once(". ").filter(|(n, _)| n.parse::<u32>().is_ok()).map(|(_, a)| a.to_string()))
        .collect()
}

fn check(report: &str, expected: &[&str], forbidden: &[&str]) {
    let alerts = alerts(report);
    for e in expected {
        assert!(alerts.iter().any(|a| a.contains(e)), "missing alert {e:?}; got {alerts:#?}");
    }
    for f in forbidden {
        assert!(!alerts.iter().any(|a| a.contains(f)), "unexpected alert {f:?}; got {alerts:#?}");
    }
}

// --- Synthetic pcap builder ---

struct Pcap { buf: Vec<u8> }

impl Pcap {
    fn new() -> Self {
        let mut buf = Vec::new();
        for v in [0xa1b2c3d4u32.to_le_bytes(), [2, 0, 4, 0], [0; 4], [0; 4], 65535u32.to_le_bytes(), 1u32.to_le_bytes()] {
            buf.extend_from_slice(&v);
        }
        Self { buf }
    }

    fn push(&mut self, t: f64, frame: &[u8]) {
        let (sec, usec) = (t as u32, ((t.fract()) * 1e6) as u32);
        for v in [sec, usec, frame.len() as u32, frame.len() as u32] { self.buf.extend_from_slice(&v.to_le_bytes()); }
        self.buf.extend_from_slice(frame);
    }

    /// Write to a temp file, run the detector on it, clean up
    fn report(&self, name: &str) -> String {
        let path = std::env::temp_dir().join(format!("wiremcp-test-{}-{name}.pcap", std::process::id()));
        std::fs::write(&path, &self.buf).unwrap();
        let report = run_ddos(&path);
        let _ = std::fs::remove_file(&path);
        report
    }
}

fn ipv4(src: [u8; 4], dst: [u8; 4], proto: u8, frag_field: u16, l4: &[u8]) -> Vec<u8> {
    let mut f = vec![0u8; 12];
    f.extend_from_slice(&[0x08, 0x00]);
    let total = (20 + l4.len()) as u16;
    f.extend_from_slice(&[0x45, 0, (total >> 8) as u8, total as u8, 0, 1, (frag_field >> 8) as u8, frag_field as u8, 64, proto, 0, 0]);
    f.extend_from_slice(&src);
    f.extend_from_slice(&dst);
    f.extend_from_slice(l4);
    f
}

fn udp(src: [u8; 4], sp: u16, dst: [u8; 4], dp: u16, payload_len: usize) -> Vec<u8> {
    let len = (8 + payload_len) as u16;
    let mut u = vec![(sp >> 8) as u8, sp as u8, (dp >> 8) as u8, dp as u8, (len >> 8) as u8, len as u8, 0, 0];
    u.resize(8 + payload_len, 0x5a);
    ipv4(src, dst, 17, 0, &u)
}

const ME: [u8; 4] = [192, 168, 1, 10];

fn assert_silent(report: &str) {
    assert!(alerts(report).is_empty(), "expected no alerts, got {:#?}", alerts(report));
}

#[test]
fn synthetic_quic_download_is_not_a_flood() {
    // 10 s download from one server: thousands of identical 1350 B packets + small upstream ACKs
    let mut p = Pcap::new();
    for i in 0..10_000 {
        let t = i as f64 / 1000.0;
        p.push(t, &udp([142, 250, 1, 1], 443, ME, 51000, 1300));
        if i % 10 == 0 { p.push(t, &udp(ME, 51000, [142, 250, 1, 1], 443, 40)); }
    }
    assert_silent(&p.report("quic"));
}

#[test]
fn synthetic_ipsec_vpn_is_not_amplification() {
    // One VPN server pushing far more data than the client sends (asymmetric, but a single "reflector")
    let mut p = Pcap::new();
    for i in 0..3_000 {
        let t = i as f64 / 300.0;
        p.push(t, &udp([203, 0, 113, 5], 4500, ME, 4500, 1200));
        if i % 20 == 0 { p.push(t, &udp(ME, 4500, [203, 0, 113, 5], 4500, 80)); }
    }
    check(&p.report("ipsec"), &[], &["Amplification"]);
}

#[test]
fn synthetic_dns_from_home_resolver_is_not_amplification() {
    // Normal browsing: queries to 2 resolvers, responses ~5x larger than queries
    let mut p = Pcap::new();
    for i in 0..400u32 {
        let t = i as f64 / 20.0;
        let resolver = if i % 2 == 0 { [1, 1, 1, 1] } else { [9, 9, 9, 9] };
        let port = 40000 + (i % 2000) as u16;
        p.push(t, &udp(ME, port, resolver, 53, 40));
        p.push(t + 0.01, &udp(resolver, 53, ME, port, 300));
    }
    check(&p.report("dns"), &[], &["Amplification", "Port Scan"]);
}

#[test]
fn synthetic_fragments_are_not_a_port_scan() {
    // One reflector sends big fragmented responses: non-first fragments hold random bytes where ports would be
    let mut p = Pcap::new();
    let src = [212, 8, 51, 69];
    for i in 0..600u32 {
        let t = i as f64 / 1000.0;
        let mut body = vec![0u8; 1200];
        body[..4].copy_from_slice(&(i.wrapping_mul(2654435761)).to_be_bytes()); // pseudo-random "ports"
        p.push(t, &ipv4(src, [10, 10, 10, 10], 17, 185, &body)); // offset 1480, last fragment
    }
    check(&p.report("frags"), &[], &["Port Scan"]);
}

#[test]
fn synthetic_uniform_udp_flood_is_detected() {
    let mut p = Pcap::new();
    for i in 0..5_000u32 {
        let src = [100, 64, 0, (i % 8) as u8 + 1];
        p.push(i as f64 / 1000.0, &udp(src, 50000 + (i % 8) as u16, [10, 10, 10, 10], 20480, 1300));
    }
    check(&p.report("uniform"), &["Uniform-size UDP Flood"], &[]);
}

// --- Real-world dataset ---

fn dataset(file: &str) -> Option<PathBuf> {
    let dir = std::env::var_os("WIREMCP_PCAP_DIR").map(PathBuf::from)
        .unwrap_or_else(|| Path::new(env!("CARGO_MANIFEST_DIR")).join("../packet-captures-main"));
    let path = dir.join(file);
    if path.exists() { Some(path) } else {
        eprintln!("skipping: {} not found (set WIREMCP_PCAP_DIR)", path.display());
        None
    }
}

macro_rules! dataset_test {
    ($name:ident, $file:expr, expect: [$($e:expr),* $(,)?], forbid: [$($f:expr),* $(,)?]) => {
        #[test]
        fn $name() {
            let Some(path) = dataset($file) else { return };
            check(&run_ddos(&path), &[$($e),*], &[$($f),*]);
        }
    };
}

dataset_test!(dataset_dns_rrsig_fragmented, "amp.dns.RRSIG.fragmented.pcap",
    expect: ["DNS Amplification", "Fragmentation attack"], forbid: ["SYN Flood"]);
dataset_test!(dataset_tcp_synack_reflection, "amp.TCP.reflection.SYNACK.pcap",
    expect: ["TCP SYN-ACK Reflection"], forbid: ["SYN Flood"]);
dataset_test!(dataset_tcp_synack_same_port, "amp.TCP.syn.optionallyACK.optionallysamePort.pcapng",
    expect: ["TCP SYN-ACK Reflection (same-port)"], forbid: ["SYN Flood"]);
dataset_test!(dataset_bacnet_dahua, "amp.UDP.bacnet.IOT.37810.pcapng",
    expect: ["BACnet Amplification", "Dahua DHDiscover Amplification"], forbid: []);
dataset_test!(dataset_dns_any, "amp.UDP.DNSANY.pcap",
    expect: ["DNS Amplification", "UDP Flood"], forbid: ["Port Scan"]);
dataset_test!(dataset_dahua_json, "amp.UDP.IOT.port37810.JSON.pcap",
    expect: ["Dahua DHDiscover Amplification"], forbid: []);
dataset_test!(dataset_isakmp, "amp.UDP.isakmp.pcap",
    expect: ["IKE/IPsec NAT-T Amplification"], forbid: ["Port Scan"]);
dataset_test!(dataset_many_protocols, "amp.UDP.manyprotocols.pcapng",
    expect: ["UDP Flood", "Distributed attack"], forbid: []);
dataset_test!(dataset_memcached_ntp_cldap, "amp.UDP.memcached.ntp.cldap.pcap",
    expect: ["Memcached Amplification", "NTP Amplification", "CLDAP Amplification"], forbid: []);
dataset_test!(dataset_snmp, "amp.UDP.snmp.src161.pcapng",
    expect: ["SNMP Amplification"], forbid: []);
dataset_test!(dataset_ubiquiti, "amp.UDP.UBNT.src10001.pcapng",
    expect: ["Ubiquiti Discovery Amplification"], forbid: []);
dataset_test!(dataset_icmp_flood, "pkt.ICMP.largeempty.pcap",
    expect: ["ICMP Flood"], forbid: ["Amplification"]);
dataset_test!(dataset_ip_protocol_flood, "pkt.IPV4.randomprotofield.pcap",
    expect: ["IP Protocol Flood"], forbid: ["Amplification"]);
dataset_test!(dataset_syn_flood_dominate, "pkt.TCP.DOMINATE.syn.ecn.cwr.pcapng",
    expect: ["SYN Flood"], forbid: ["Amplification", "Reflection"]);
dataset_test!(dataset_syn_flood_spoofed, "pkt.TCP.synflood.spoofed.pcap",
    expect: ["SYN Flood"], forbid: ["Amplification", "Reflection"]);
dataset_test!(dataset_udp_fragmented, "pkt.UDP.fragmented.pcap",
    expect: ["Fragmentation attack", "UDP Flood"], forbid: ["Port Scan"]);
dataset_test!(dataset_udp_null, "pkt.UDP.null.pcapng",
    expect: ["UDP Flood"], forbid: ["Amplification"]);
dataset_test!(dataset_udp_random_fixed_length, "pkt.UDP.rdm.fixedlength.pcapng",
    expect: ["Uniform-size UDP Flood"], forbid: ["Amplification"]);
