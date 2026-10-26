//! Shared helpers for integration tests: a minimal pcap writer and frame builders.
#![allow(dead_code)]

use std::path::PathBuf;

pub struct Pcap { buf: Vec<u8> }

/// Pcap written to the temp dir, removed on drop
pub struct TempPcap { pub path: PathBuf }

impl Drop for TempPcap {
    fn drop(&mut self) { let _ = std::fs::remove_file(&self.path); }
}

impl Pcap {
    pub fn new() -> Self {
        let mut buf = Vec::new();
        for v in [0xa1b2c3d4u32.to_le_bytes(), [2, 0, 4, 0], [0; 4], [0; 4], 65535u32.to_le_bytes(), 1u32.to_le_bytes()] {
            buf.extend_from_slice(&v);
        }
        Self { buf }
    }

    pub fn push(&mut self, t: f64, frame: &[u8]) {
        let (sec, usec) = (t as u32, (t.fract() * 1e6) as u32);
        for v in [sec, usec, frame.len() as u32, frame.len() as u32] { self.buf.extend_from_slice(&v.to_le_bytes()); }
        self.buf.extend_from_slice(frame);
    }

    pub fn write(&self, name: &str) -> TempPcap {
        let path = std::env::temp_dir().join(format!("wiremcp-test-{}-{name}.pcap", std::process::id()));
        std::fs::write(&path, &self.buf).unwrap();
        TempPcap { path }
    }
}

pub fn ipv4(src: [u8; 4], dst: [u8; 4], proto: u8, frag_field: u16, l4: &[u8]) -> Vec<u8> {
    let mut f = vec![0u8; 12];
    f.extend_from_slice(&[0x08, 0x00]);
    let total = (20 + l4.len()) as u16;
    f.extend_from_slice(&[0x45, 0, (total >> 8) as u8, total as u8, 0, 1, (frag_field >> 8) as u8, frag_field as u8, 64, proto, 0, 0]);
    f.extend_from_slice(&src);
    f.extend_from_slice(&dst);
    f.extend_from_slice(l4);
    f
}

pub fn udp(src: [u8; 4], sp: u16, dst: [u8; 4], dp: u16, payload_len: usize) -> Vec<u8> {
    let len = (8 + payload_len) as u16;
    let mut u = vec![(sp >> 8) as u8, sp as u8, (dp >> 8) as u8, dp as u8, (len >> 8) as u8, len as u8, 0, 0];
    u.resize(8 + payload_len, 0x5a);
    ipv4(src, dst, 17, 0, &u)
}

pub const ME: [u8; 4] = [192, 168, 1, 10];
