//! Non-first IPv4 fragments carry no TCP/UDP header: every mode must ignore their "ports".

mod common;

use common::{ipv4, Pcap, TempPcap};
use std::process::Command;

/// 600 TCP + 600 UDP non-first fragments whose payload looks like a SYN / UDP header to port 27015
fn fragments() -> TempPcap {
    let mut p = Pcap::new();
    for i in 0..600u32 {
        let mut body = vec![0u8; 1200];
        body[..2].copy_from_slice(&((i * 7919 % 65535) as u16).to_be_bytes());
        body[2..4].copy_from_slice(&27015u16.to_be_bytes());
        body[12] = 0x50;
        body[13] = 0x02; // SYN
        for proto in [6, 17] {
            p.push(i as f64 / 100.0, &ipv4([212, 8, 51, 69], [10, 10, 10, 10], proto, 185, &body));
        }
    }
    p.write("fragments")
}

fn run(mode: &str, pcap: &TempPcap, env: &[(&str, &str)]) -> String {
    let out = Command::new(env!("CARGO_BIN_EXE_capture-packets"))
        .args(["--mode", mode, "--file"]).arg(&pcap.path)
        .envs(env.iter().copied())
        .output().expect("failed to run capture-packets");
    assert!(out.status.success(), "{mode} failed: {}", String::from_utf8_lossy(&out.stderr));
    String::from_utf8_lossy(&out.stdout).into_owned()
}

#[test]
fn streams_ignore_fragments() {
    let out = run("streams", &fragments(), &[]);
    assert!(out.contains(r#""tcp_streams": 0"#), "{out}");
}

#[test]
fn source_engine_ignores_fragments() {
    let out = run("source-engine", &fragments(), &[("SOURCE_PORT", "27015")]);
    assert!(out.contains(r#""total_source_engine_pkts": 0"#), "{out}");
    assert!(out.contains(r#""status": "CLEAN""#), "{out}");
}

#[test]
fn baseline_ignores_fragment_ports() {
    let pcaps = fragments();
    let json = pcaps.path.with_extension("baseline.json");
    run("baseline", &pcaps, &[("BASELINE_OUTPUT", json.to_str().unwrap())]);
    let profile = std::fs::read_to_string(&json).unwrap();
    let _ = std::fs::remove_file(&json);
    assert!(profile.contains(r#""known_ports": []"#), "{profile}");
    assert!(profile.contains("212.8.51.69"), "IP-level stats must still be recorded: {profile}");
}
