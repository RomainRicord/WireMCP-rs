//! DDoS detector regression tests.
//!
//! - `synthetic_*`: small pcaps generated on the fly (legit traffic that must stay silent, known edge cases).
//! - `dataset_*`: real attacks from the StopDDoS packet-captures collection. The dataset (~230 MB) is not
//!   committed: these tests are skipped unless it sits in `../packet-captures-main` or `$WIREMCP_PCAP_DIR`.

mod common;

use common::{ipv4, udp, Pcap, ME};
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
    assert_silent(&run_ddos(&p.write("quic").path));
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
    check(&run_ddos(&p.write("ipsec").path), &[], &["Amplification"]);
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
    check(&run_ddos(&p.write("dns").path), &[], &["Amplification", "Port Scan"]);
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
    check(&run_ddos(&p.write("frags").path), &[], &["Port Scan"]);
}

#[test]
fn synthetic_uniform_udp_flood_is_detected() {
    let mut p = Pcap::new();
    for i in 0..5_000u32 {
        let src = [100, 64, 0, (i % 8) as u8 + 1];
        p.push(i as f64 / 1000.0, &udp(src, 50000 + (i % 8) as u16, [10, 10, 10, 10], 20480, 1300));
    }
    check(&run_ddos(&p.write("uniform").path), &["Uniform-size UDP Flood"], &[]);
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
