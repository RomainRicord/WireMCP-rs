use clap::Parser;
use pcap::Capture;
use std::collections::HashMap;
use std::io::Read as _;
use std::process::Command;
use std::time::{Duration, Instant};

static mut INTERRUPTED: libc::c_int = 0;

fn is_interrupted() -> bool {
    unsafe { std::ptr::read_volatile(&INTERRUPTED) != 0 }
}

extern "C" fn sigint_handler(_sig: libc::c_int) {
    unsafe { std::ptr::write_volatile(&mut INTERRUPTED, 1); }
    let msg = b"\n[monitor-scan] Ctrl+C received, stopping...\n";
    unsafe { libc::write(2, msg.as_ptr() as *const libc::c_void, msg.len()); }
}

// --- CLI ---
#[derive(Parser)]
#[command(name = "monitor-scan", about = "WiFi monitor mode scanner with HTML report")]
struct Cli {
    /// WiFi interface
    #[arg(short, long, default_value = "wlo1")]
    interface: String,
    /// WiFi channel (0 = auto-detect)
    #[arg(short, long, default_value_t = 0)]
    channel: u32,
    /// Capture duration in seconds
    #[arg(short, long, default_value_t = 30)]
    duration: u64,
    /// Output HTML file
    #[arg(short, long, default_value = "rapport_monitor.html")]
    output: String,
}

// --- Data structures ---
#[derive(Debug, Clone)]
struct ClientInfo {
    mac: [u8; 6],
    packets: u32,
    best_signal: i8,
    max_data_rate: f32,
    power_save: bool,
    randomized_mac: bool,
    wifi_standard: String,
    bandwidth: String,
    ap_hits: HashMap<[u8; 6], u32>,
    probes: Vec<String>,
}

impl ClientInfo {
    fn new(mac: [u8; 6]) -> Self {
        Self {
            mac,
            packets: 0,
            best_signal: -100,
            max_data_rate: 0.0,
            power_save: false,
            randomized_mac: (mac[0] & 0x02) != 0,
            wifi_standard: String::new(),
            bandwidth: String::new(),
            ap_hits: HashMap::new(),
            probes: Vec::new(),
        }
    }

    fn main_ap(&self) -> Option<[u8; 6]> {
        self.ap_hits.iter().max_by_key(|(_, v)| *v).map(|(k, _)| *k)
    }
}

const BROADCAST: [u8; 6] = [0xff; 6];

// --- OUI Database ---
fn get_vendor(mac: &[u8; 6]) -> &'static str {
    match [mac[0], mac[1], mac[2]] {
        [0x00, 0x17, 0xc8] => "KYOCERA",
        [0x08, 0x5b, 0xd6] => "Toshiba",
        [0x08, 0x6a, 0xc5] => "Samsung",
        [0x14, 0x13, 0x33] => "Apple",
        [0x1c, 0x70, 0xc9] => "Xiaomi",
        [0x24, 0x5a, 0x4c] => "Ubiquiti",
        [0x2c, 0xbe, 0xeb] => "Samsung",
        [0x34, 0x1c, 0xf0] => "Samsung",
        [0x34, 0x6f, 0x24] => "Xiaomi",
        [0x3c, 0x0a, 0xf3] => "Apple",
        [0x40, 0xa6, 0xb7] => "Intel",
        [0x40, 0xd1, 0x33] => "Samsung",
        [0x4c, 0x23, 0x38] => "Xiaomi",
        [0x4c, 0x82, 0xa9] => "Samsung",
        [0x4c, 0xd5, 0x77] => "Samsung",
        [0x58, 0x96, 0x71] => "Intel",
        [0x5c, 0xfb, 0x3a] => "Apple",
        [0x60, 0xb7, 0x6e] => "Huawei",
        [0x6c, 0x94, 0x66] => "Apple",
        [0x70, 0xb1, 0x3d] => "Samsung",
        [0x74, 0x83, 0xc2] => "Ubiquiti",
        [0x78, 0x2b, 0x46] => "Samsung",
        [0x80, 0x2a, 0xa8] => "Ubiquiti",
        [0x80, 0xb6, 0x55] => "Apple",
        [0x8c, 0xea, 0x48] => "Samsung",
        [0x8c, 0xfd, 0xf0] => "Qualcomm",
        [0x9c, 0x65, 0xeb] => "OnePlus",
        [0xa0, 0xaf, 0xbd] => "Samsung",
        [0xb4, 0xfb, 0xe4] => "Ubiquiti",
        [0xbc, 0xdf, 0x58] => "Google",
        [0xcc, 0x2f, 0x71] => "Intel",
        [0xd8, 0xf3, 0xbc] => "Apple",
        [0xdc, 0x21, 0x48] => "Apple",
        [0xe8, 0x84, 0xa5] => "Apple",
        [0xe8, 0xfb, 0x1c] => "Intel",
        [0xf8, 0x3d, 0xc6] => "Qualcomm",
        [0xfc, 0xec, 0xda] => "Ubiquiti",
        _ if mac[0] & 0x02 != 0 => "Private/Randomized",
        _ => "Unknown",
    }
}

fn mac_str(mac: &[u8; 6]) -> String {
    format!("{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5])
}

fn read_mac(data: &[u8], off: usize) -> Option<[u8; 6]> {
    if data.len() < off + 6 { return None; }
    let mut m = [0u8; 6];
    m.copy_from_slice(&data[off..off + 6]);
    Some(m)
}

// --- Radiotap parser ---
struct RtInfo {
    signal: Option<i8>,
    data_rate: Option<f32>,
    has_mcs: bool,
    has_vht: bool,
    vht_bw: Option<u8>,
}

fn parse_radiotap(data: &[u8]) -> Option<(usize, RtInfo)> {
    if data.len() < 8 { return None; }
    let hlen = u16::from_le_bytes([data[2], data[3]]) as usize;
    if data.len() < hlen { return None; }
    let present = u32::from_le_bytes([data[4], data[5], data[6], data[7]]);

    let mut info = RtInfo { signal: None, data_rate: None, has_mcs: false, has_vht: false, vht_bw: None };
    let mut off = 8usize;

    // Skip extended present bitmasks
    let mut p = present;
    while p & (1 << 31) != 0 {
        if off + 4 > hlen { return Some((hlen, info)); }
        p = u32::from_le_bytes([data[off], data[off+1], data[off+2], data[off+3]]);
        off += 4;
    }

    // Bit 0: TSFT (8B, align 8)
    if present & (1 << 0) != 0 { off = (off + 7) & !7; off += 8; }
    // Bit 1: Flags (1B)
    if present & (1 << 1) != 0 { off += 1; }
    // Bit 2: Rate (1B)
    if present & (1 << 2) != 0 {
        if off < hlen { info.data_rate = Some(data[off] as f32 / 2.0); }
        off += 1;
    }
    // Bit 3: Channel (4B, align 2)
    if present & (1 << 3) != 0 { off = (off + 1) & !1; off += 4; }
    // Bit 4: FHSS (2B)
    if present & (1 << 4) != 0 { off += 2; }
    // Bit 5: Signal dBm (1B)
    if present & (1 << 5) != 0 {
        if off < hlen { info.signal = Some(data[off] as i8); }
        off += 1;
    }
    // Bit 6: Noise (1B)
    if present & (1 << 6) != 0 { off += 1; }
    // Bit 7: Lock Quality (2B, align 2)
    if present & (1 << 7) != 0 { off = (off + 1) & !1; off += 2; }
    // Bits 8-9: TX Attenuation (2B each, align 2)
    if present & (1 << 8) != 0 { off = (off + 1) & !1; off += 2; }
    if present & (1 << 9) != 0 { off = (off + 1) & !1; off += 2; }
    // Bit 10: dBm TX Power (1B)
    if present & (1 << 10) != 0 { off += 1; }
    // Bit 11: Antenna (1B)
    if present & (1 << 11) != 0 { off += 1; }
    // Bit 12-13: dB Signal/Noise (1B each)
    if present & (1 << 12) != 0 { off += 1; }
    if present & (1 << 13) != 0 { off += 1; }
    // Bit 14: RX Flags (2B, align 2)
    if present & (1 << 14) != 0 { off = (off + 1) & !1; off += 2; }
    // Bits 15-18: skip (vendor namespaces, etc)
    // Bit 19: MCS (3B)
    if present & (1 << 19) != 0 {
        if off + 3 <= hlen {
            info.has_mcs = true;
            let known = data[off];
            let flags = data[off + 1];
            if known & 0x01 != 0 && (flags & 0x03) == 1 {
                info.vht_bw = Some(1); // 40MHz
            }
        }
        off += 3;
    }
    // Bit 20: A-MPDU (8B, align 4)
    if present & (1 << 20) != 0 { off = (off + 3) & !3; off += 8; }
    // Bit 21: VHT (12B, align 2)
    if present & (1 << 21) != 0 {
        off = (off + 1) & !1;
        if off + 12 <= hlen {
            info.has_vht = true;
            info.vht_bw = Some(data[off + 3]);
        }
        off += 12;
    }

    Some((hlen, info))
}

// --- 802.11 parser ---
struct FrameInfo {
    ftype: u8,
    subtype: u8,
    pwrmgt: bool,
    addr1: [u8; 6],
    addr2: Option<[u8; 6]>,
    addr3: Option<[u8; 6]>,
    ssid: Option<String>,
    has_ht: bool,
    has_vht: bool,
    has_he: bool,
}

fn parse_80211(data: &[u8]) -> Option<FrameInfo> {
    if data.len() < 10 { return None; }
    let ftype = (data[0] >> 2) & 0x03;
    let subtype = (data[0] >> 4) & 0x0f;
    let pwrmgt = (data[1] & 0x10) != 0;
    let addr1 = read_mac(data, 4)?;
    let addr2 = if data.len() >= 16 { read_mac(data, 10) } else { None };
    let addr3 = if data.len() >= 22 { read_mac(data, 16) } else { None };

    let mut ssid = None;
    let mut has_ht = false;
    let mut has_vht = false;
    let mut has_he = false;

    // Parse IEs in management frames
    if ftype == 0 {
        let ie_start = match subtype {
            0 | 2 => 28,  // assoc/reassoc req
            4 => 24,      // probe req
            5 | 8 => 36,  // probe resp / beacon
            _ => 24,
        };
        if data.len() > ie_start {
            let mut pos = ie_start;
            while pos + 2 <= data.len() {
                let id = data[pos];
                let len = data[pos + 1] as usize;
                if pos + 2 + len > data.len() { break; }
                match id {
                    0 if len > 0 => { ssid = String::from_utf8(data[pos+2..pos+2+len].to_vec()).ok(); }
                    45 => has_ht = true,
                    191 => has_vht = true,
                    255 if len >= 1 && data[pos + 2] == 35 => has_he = true,
                    _ => {}
                }
                pos += 2 + len;
            }
        }
    }

    Some(FrameInfo { ftype, subtype, pwrmgt, addr1, addr2, addr3, ssid, has_ht, has_vht, has_he })
}

// --- Interface control ---
fn run_cmd(cmd: &str, args: &[&str]) -> Result<String, String> {
    Command::new(cmd).args(args).output()
        .map_err(|e| format!("{}: {}", cmd, e))
        .and_then(|o| if o.status.success() { Ok(String::from_utf8_lossy(&o.stdout).to_string()) } else { Err(String::from_utf8_lossy(&o.stderr).to_string()) })
}

fn sudo(args: &[&str]) -> Result<String, String> {
    sudo_timeout(args, 5)
}

fn sudo_timeout(args: &[&str], timeout_secs: u64) -> Result<String, String> {
    // Skip sudo if already root
    let (cmd, cmd_args): (&str, Vec<&str>) = if unsafe { libc::geteuid() } == 0 {
        (args[0], args[1..].to_vec())
    } else {
        let mut a = vec!["-n"];
        a.extend_from_slice(args);
        ("sudo", a)
    };
    let mut child = Command::new(cmd).args(&cmd_args)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .map_err(|e| format!("{}: {}", cmd, e))?;

    let deadline = Instant::now() + Duration::from_secs(timeout_secs);
    loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                let stdout = child.stdout.take().map(|mut s| { let mut b = String::new(); s.read_to_string(&mut b).ok(); b }).unwrap_or_default();
                let stderr = child.stderr.take().map(|mut s| { let mut b = String::new(); s.read_to_string(&mut b).ok(); b }).unwrap_or_default();
                return if status.success() { Ok(stdout) } else { Err(stderr) };
            }
            Ok(None) => {
                if Instant::now() > deadline {
                    let _ = child.kill();
                    let _ = child.wait();
                    return Err(format!("timeout ({}s): {} {:?}", timeout_secs, cmd, args));
                }
                std::thread::sleep(Duration::from_millis(50));
            }
            Err(e) => return Err(format!("{}: {}", cmd, e)),
        }
    }
}

struct IfState { iface: String, conn: String }

impl IfState {
    fn save(iface: &str) -> Self {
        let conn = run_cmd("nmcli", &["-t", "-f", "DEVICE,CONNECTION", "dev", "status"])
            .unwrap_or_default().lines()
            .find(|l| l.starts_with(&format!("{}:", iface)))
            .and_then(|l| l.split(':').nth(1))
            .unwrap_or("").to_string();
        Self { iface: iface.to_string(), conn }
    }

    fn to_monitor(&self) -> Result<(), String> {
        let _ = run_cmd("nmcli", &["dev", "set", &self.iface, "managed", "no"]);
        std::thread::sleep(Duration::from_millis(500));
        sudo(&["ip", "link", "set", &self.iface, "down"])?;
        sudo(&["iw", &self.iface, "set", "type", "monitor"])?;
        sudo(&["ip", "link", "set", &self.iface, "up"])?;
        Ok(())
    }

    fn set_channel(&self, ch: u32) -> Result<(), String> {
        sudo(&["iw", &self.iface, "set", "channel", &ch.to_string()])?;
        Ok(())
    }

    fn restore(&self) {
        let _ = sudo(&["ip", "link", "set", &self.iface, "down"]);
        let _ = sudo(&["iw", &self.iface, "set", "type", "managed"]);
        let _ = sudo(&["ip", "link", "set", &self.iface, "up"]);
        let _ = run_cmd("nmcli", &["dev", "set", &self.iface, "managed", "yes"]);
        if !self.conn.is_empty() {
            // Wait for NM to detect the interface, retry connection
            for attempt in 1..=5 {
                std::thread::sleep(Duration::from_secs(2));
                if run_cmd("nmcli", &["con", "up", &self.conn]).is_ok() {
                    eprintln!("[monitor-scan] WiFi reconnected (attempt {})", attempt);
                    return;
                }
            }
            eprintln!("[monitor-scan] Warning: could not reconnect to '{}', try manually: nmcli con up \"{}\"", self.conn, self.conn);
        }
    }
}

// --- Auto channel detection ---
fn auto_detect(iface: &str, state: &IfState) -> u32 {
    let channels = [1, 6, 11, 36, 40, 44, 48, 52, 56, 60, 64, 100, 149, 153, 157, 161, 165];
    let (mut best_ch, mut best_n) = (1u32, 0u64);
    let global_timeout = Instant::now();
    let max_detect_time = Duration::from_secs(30); // Max 30s for auto-detect

    for &ch in &channels {
        if is_interrupted() { break; }
        if global_timeout.elapsed() > max_detect_time {
            eprintln!("[monitor-scan] Auto-detect timeout (30s), using best so far");
            break;
        }
        if state.set_channel(ch).is_err() { continue; }
        std::thread::sleep(Duration::from_millis(50)); // Let channel switch settle
        let cap = match Capture::from_device(iface as &str).and_then(|c| c.timeout(100).open()) {
            Ok(c) => c, Err(_) => continue,
        };
        let mut cap = match cap.setnonblock() {
            Ok(c) => c, Err(_) => continue,
        };
        let start = Instant::now();
        let mut n = 0u64;
        while start.elapsed() < Duration::from_millis(1500) {
            if is_interrupted() { break; }
            match cap.next_packet() {
                Ok(_) => { n += 1; }
                Err(_) => { std::thread::sleep(Duration::from_millis(10)); }
            }
        }
        eprint!("  ch {}: {} frames\n", ch, n);
        if n > best_n { best_n = n; best_ch = ch; }
    }
    eprintln!("[monitor-scan] Best channel: {} ({} frames)", best_ch, best_n);
    best_ch
}

// --- Capture & Parse ---
fn capture(iface: &str, dur: u64, channel: u32) -> Result<(HashMap<[u8; 6], ClientInfo>, HashMap<[u8; 6], String>, u64, String), String> {
    let cap = Capture::from_device(iface as &str)
        .map_err(|e| e.to_string())?
        .snaplen(512).timeout(100)
        .open().map_err(|e| e.to_string())?;
    let mut cap = cap.setnonblock().map_err(|e| e.to_string())?;

    let mut clients: HashMap<[u8; 6], ClientInfo> = HashMap::new();
    let mut aps: HashMap<[u8; 6], String> = HashMap::new();
    let mut total = 0u64;
    let mut ssid = String::from("Unknown");
    let start = Instant::now();
    let timeout = Duration::from_secs(dur);

    eprintln!("[monitor-scan] Capturing on channel {} for {}s...", channel, dur);

    while start.elapsed() < timeout {
        if is_interrupted() {
            eprintln!("[monitor-scan] Interrupted, stopping capture...");
            break;
        }
        let pkt = match cap.next_packet() {
            Ok(p) => p,
            Err(_) => {
                std::thread::sleep(Duration::from_millis(10));
                continue;
            }
        };
        total += 1;
        let data = pkt.data;

        let (rt_len, rt) = match parse_radiotap(data) { Some(v) => v, None => continue };
        let f = match parse_80211(&data[rt_len..]) { Some(v) => v, None => continue };
        let ta = match f.addr2 { Some(a) => a, None => continue };

        // Beacon -> AP
        if f.ftype == 0 && f.subtype == 8 {
            let name = f.ssid.clone().unwrap_or_else(|| "Hidden".into());
            if !name.is_empty() && name != "Hidden" { ssid = name.clone(); }
            aps.insert(ta, name);
            continue;
        }

        if aps.contains_key(&ta) || ta == BROADCAST { continue; }

        let c = clients.entry(ta).or_insert_with(|| ClientInfo::new(ta));
        c.packets += 1;
        if let Some(s) = rt.signal { if s > c.best_signal { c.best_signal = s; } }
        if let Some(r) = rt.data_rate { if r > c.max_data_rate { c.max_data_rate = r; } }
        if f.pwrmgt { c.power_save = true; }
        if aps.contains_key(&f.addr1) { *c.ap_hits.entry(f.addr1).or_insert(0) += 1; }
        if let Some(a3) = f.addr3 { if aps.contains_key(&a3) { *c.ap_hits.entry(a3).or_insert(0) += 1; } }

        // WiFi caps from mgmt frames
        if f.ftype == 0 {
            if f.has_he && !c.wifi_standard.contains("6") { c.wifi_standard = "WiFi 6 (802.11ax)".into(); }
            else if f.has_vht && !c.wifi_standard.contains('5') && !c.wifi_standard.contains('6') { c.wifi_standard = "WiFi 5 (802.11ac)".into(); }
            else if f.has_ht && c.wifi_standard.is_empty() { c.wifi_standard = "WiFi 4 (802.11n)".into(); }
            if f.subtype == 4 { if let Some(ref s) = f.ssid { if !s.is_empty() && !c.probes.contains(s) { c.probes.push(s.clone()); } } }
        }

        // Radiotap VHT/MCS
        if rt.has_vht && !c.wifi_standard.contains('6') && !c.wifi_standard.contains('5') { c.wifi_standard = "WiFi 5 (802.11ac)".into(); }
        else if rt.has_mcs && c.wifi_standard.is_empty() { c.wifi_standard = "WiFi 4 (802.11n)".into(); }
        if let Some(bw) = rt.vht_bw {
            if c.bandwidth.is_empty() {
                c.bandwidth = match bw { 0 => "20 MHz", 1 => "40 MHz", 2|4|5|11 => "80 MHz", 3|6|7|8|9|10 => "160 MHz", _ => "" }.into();
            }
        }
    }

    // Infer standards
    let is5 = channel >= 36;
    let ap_ac = aps.keys().any(|a| matches!(get_vendor(a), "Ubiquiti"|"Cisco"|"Aruba"|"Ruckus")) && is5;
    for c in clients.values_mut() {
        let ap = c.main_ap();
        if c.wifi_standard.is_empty() {
            if c.max_data_rate > 600.0 { c.wifi_standard = "WiFi 6 (802.11ax)".into(); }
            else if c.max_data_rate > 150.0 { c.wifi_standard = "WiFi 5 (802.11ac)".into(); }
            else if c.max_data_rate > 54.0 { c.wifi_standard = "WiFi 4 (802.11n)".into(); }
            else if ap_ac && ap.is_some() && c.packets > 5 { c.wifi_standard = "WiFi 5+ (802.11ac)".into(); }
            else if c.max_data_rate > 0.0 { c.wifi_standard = (if is5 { "802.11a" } else { "802.11b/g" }).into(); }
        }
        if is5 && c.bandwidth.is_empty() && ap.is_some() && c.packets > 5 { c.bandwidth = "80 MHz (est.)".into(); }
    }

    Ok((clients, aps, total, ssid))
}

// --- HTML ---
fn sig_quality(dbm: i8) -> (&'static str, &'static str) {
    match dbm { -50..=0 => ("Excellent","#22c55e"), -60..=-51 => ("Bon","#84cc16"), -70..=-61 => ("Correct","#eab308"), -80..=-71 => ("Faible","#f97316"), _ => ("Très faible","#ef4444") }
}
fn vc(v: &str) -> &'static str {
    if v.contains("Apple") {"apple"} else if v.contains("Samsung") {"samsung"} else if v.contains("Intel") {"intel"} else if v.contains("Xiaomi") {"xiaomi"} else if v.contains("Ubiquiti") {"ubiquiti"} else {"other"}
}
fn wc(s: &str) -> &'static str {
    if s.contains('6') {"wifi6"} else if s.contains('5') {"wifi5"} else if s.contains('4') {"wifi4"} else {"wifiold"}
}
fn esc(s: &str) -> String { s.replace('&',"&amp;").replace('<',"&lt;").replace('>',"&gt;").replace('"',"&quot;") }
fn now_str() -> String {
    Command::new("date").args(["+%d/%m/%Y %H:%M:%S"]).output().ok()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string()).unwrap_or_else(|| "N/A".into())
}

fn gen_html(clients: &HashMap<[u8;6], ClientInfo>, aps: &HashMap<[u8;6], String>, total: u64, channel: u32, ssid: &str, dur: u64) -> String {
    let now = now_str();
    let mut sorted: Vec<&ClientInfo> = clients.values().collect();
    sorted.sort_by(|a,b| b.packets.cmp(&a.packets));

    let mut ap_names: HashMap<[u8;6], String> = HashMap::new();
    for (i,ap) in aps.keys().enumerate() { ap_names.insert(*ap, format!("AP-{} ({})", i+1, get_vendor(ap))); }
    let ap_keys: Vec<[u8;6]> = aps.keys().copied().collect();

    let mut vendors: HashMap<&str,u32> = HashMap::new();
    let mut wifis: HashMap<&str,u32> = HashMap::new();
    let mut apc: HashMap<[u8;6],u32> = HashMap::new();
    let (mut rand_n, mut ps_n) = (0u32, 0u32);
    for c in &sorted {
        *vendors.entry(get_vendor(&c.mac)).or_default() += 1;
        *wifis.entry(if c.wifi_standard.is_empty() {"Unknown"} else {&c.wifi_standard}).or_default() += 1;
        if let Some(ap) = c.main_ap() { *apc.entry(ap).or_default() += 1; }
        if c.randomized_mac { rand_n += 1; }
        if c.power_save { ps_n += 1; }
    }

    let chip = |items: &mut Vec<(&&str,&u32)>| { items.sort_by(|a,b| b.1.cmp(a.1)); items.iter().map(|(v,c)| format!(r#"<div class="vendor-item"><div class="vendor-count">{}</div><div class="vendor-name">{}</div></div>"#, c, v)).collect::<Vec<_>>().join("\n") };
    let mut vs: Vec<_> = vendors.iter().collect(); let vi = chip(&mut vs);
    let mut ws: Vec<_> = wifis.iter().collect(); let wi = chip(&mut ws);
    let mut aps_sorted: Vec<_> = apc.iter().collect(); aps_sorted.sort_by(|a,b| b.1.cmp(a.1));
    let ai: String = aps_sorted.iter().map(|(ap,c)| format!(r#"<div class="vendor-item"><div class="vendor-count">{}</div><div class="vendor-name">{}</div></div>"#, c, ap_names.get(*ap).cloned().unwrap_or_else(|| mac_str(ap)))).collect::<Vec<_>>().join("\n");

    let rows: String = sorted.iter().enumerate().map(|(i,c)| {
        let ms = mac_str(&c.mac);
        let v = get_vendor(&c.mac);
        let (_, sc) = sig_quality(c.best_signal);
        let sp = ((c.best_signal as i32 + 100) * 2).clamp(0, 100);
        let st = if c.best_signal > -100 { format!("{} dBm", c.best_signal) } else { "N/A".into() };
        let ma = c.main_ap();
        let an = ma.as_ref().and_then(|a| ap_names.get(a)).cloned().unwrap_or("N/A".into());
        let ac = ma.map(|a| ap_keys.iter().position(|k| *k==a).map(|i| match i%3 { 0=>"ap1",1=>"ap2",_=>"ap3" }).unwrap_or("ap1")).unwrap_or("ap1");
        let wh = if c.wifi_standard.is_empty() { r#"<span style="color:#475569">—</span>"#.into() } else { format!(r#"<span class="wifi-badge {}">{}</span>"#, wc(&c.wifi_standard), c.wifi_standard) };
        let mut d = Vec::new();
        if !c.bandwidth.is_empty() { d.push(format!(r#"<span class="tag-small tag-bw">{}</span>"#, c.bandwidth)); }
        if c.max_data_rate > 0.0 { d.push(format!(r#"<span class="tag-small tag-bw">{} Mbps</span>"#, c.max_data_rate)); }
        if c.power_save { d.push(r#"<span class="tag-small tag-ps">Power Save</span>"#.into()); }
        if c.randomized_mac { d.push(r#"<span class="tag-small tag-rand">MAC Rand.</span>"#.into()); }
        let dh = if d.is_empty() { r#"<span style="color:#475569">—</span>"#.into() } else { d.join(" ") };
        let ph = if c.probes.is_empty() { r#"<span style="color:#475569">—</span>"#.into() } else { c.probes.iter().map(|p| format!(r#"<span class="probe-tag">{}</span>"#, esc(p))).collect::<Vec<_>>().join(" ") };
        format!(r#"<tr><td>{}</td><td><span class="mac">{}</span></td><td><span class="vendor-badge {}">{}</span></td><td>{}</td><td>{}</td><td><span class="ap-tag {}">{}</span></td><td><div class="signal-bar"><div class="signal-fill" style="width:{}%;background:{}"></div></div><span style="color:{}">{}</span></td><td>{}</td><td>{}</td></tr>"#, i+1, ms, vc(v), v, wh, dh, ac, an, sp, sc, sc, st, c.packets, ph)
    }).collect::<Vec<_>>().join("\n");

    format!(r##"<!DOCTYPE html>
<html lang="fr"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>WireMCP - Rapport Monitor {ssid}</title>
<style>
*{{margin:0;padding:0;box-sizing:border-box}}body{{font-family:'Segoe UI',system-ui,sans-serif;background:#0f172a;color:#e2e8f0;line-height:1.6}}
.container{{max-width:1400px;margin:0 auto;padding:20px}}h1{{font-size:2rem;color:#38bdf8;margin-bottom:5px}}
.subtitle{{color:#94a3b8;margin-bottom:30px;font-size:.9rem}}
.stats-grid{{display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:15px;margin-bottom:30px}}
.stat-card{{background:#1e293b;border-radius:12px;padding:20px;border:1px solid #334155}}
.stat-card .value{{font-size:2rem;font-weight:700;color:#38bdf8}}.stat-card .label{{color:#94a3b8;font-size:.85rem}}
.section{{background:#1e293b;border-radius:12px;padding:20px;margin-bottom:20px;border:1px solid #334155}}
.section h2{{color:#38bdf8;font-size:1.3rem;margin-bottom:15px;padding-bottom:10px;border-bottom:1px solid #334155}}
table{{width:100%;border-collapse:collapse;font-size:.85rem}}
th{{background:#0f172a;color:#38bdf8;text-align:left;padding:10px 12px;position:sticky;top:0}}
td{{padding:8px 12px;border-bottom:1px solid #1e293b}}tr:hover td{{background:#334155}}
.mac{{font-family:'Courier New',monospace;font-size:.8rem;color:#67e8f9}}
.vendor-badge{{display:inline-block;padding:2px 8px;border-radius:4px;font-size:.75rem;font-weight:600}}
.apple{{background:#374151;color:#a78bfa}}.samsung{{background:#1e3a5f;color:#60a5fa}}.intel{{background:#1e3a5f;color:#38bdf8}}.xiaomi{{background:#3b2f0a;color:#fbbf24}}.ubiquiti{{background:#0f2b1e;color:#4ade80}}.other{{background:#334155;color:#94a3b8}}
.signal-bar{{display:inline-block;width:60px;height:8px;background:#334155;border-radius:4px;overflow:hidden;vertical-align:middle;margin-right:5px}}
.signal-fill{{height:100%;border-radius:4px}}
.probe-tag{{display:inline-block;background:#334155;color:#fbbf24;padding:1px 6px;border-radius:3px;font-size:.75rem;margin:1px}}
.ap-tag{{display:inline-block;padding:2px 8px;border-radius:4px;font-size:.75rem;font-weight:600}}
.ap1{{background:#1e3a5f;color:#60a5fa}}.ap2{{background:#1a2e1a;color:#4ade80}}.ap3{{background:#2e1a2e;color:#c084fc}}
.wifi-badge{{display:inline-block;padding:2px 6px;border-radius:4px;font-size:.7rem;font-weight:600}}
.wifi6{{background:#0f2b1e;color:#4ade80}}.wifi5{{background:#1e293b;color:#38bdf8}}.wifi4{{background:#2e1a0a;color:#fbbf24}}.wifiold{{background:#334155;color:#94a3b8}}
.tag-small{{display:inline-block;padding:1px 5px;border-radius:3px;font-size:.7rem;margin:1px}}
.tag-bw{{background:#1e1e3b;color:#a78bfa}}.tag-ps{{background:#3b2f0a;color:#fbbf24}}.tag-rand{{background:#3b0a0a;color:#f87171}}
.vendor-chart{{display:flex;flex-wrap:wrap;gap:10px}}
.vendor-item{{background:#0f172a;border-radius:8px;padding:10px 15px;display:flex;align-items:center;gap:10px}}
.vendor-count{{font-size:1.5rem;font-weight:700;color:#38bdf8}}.vendor-name{{color:#94a3b8;font-size:.85rem}}
.footer{{text-align:center;color:#475569;font-size:.8rem;margin-top:30px;padding:15px}}
.scroll-table{{max-height:600px;overflow-y:auto}}
</style></head><body><div class="container">
<h1>📡 WireMCP — Rapport Monitor Mode</h1>
<p class="subtitle">Réseau <strong>{ssid}</strong> — Canal {channel} — Capture {dur}s — {now}</p>
<div class="stats-grid">
  <div class="stat-card"><div class="value">{nc}</div><div class="label">Clients détectés</div></div>
  <div class="stat-card"><div class="value">{na}</div><div class="label">Points d'accès</div></div>
  <div class="stat-card"><div class="value">{total}</div><div class="label">Trames capturées</div></div>
  <div class="stat-card"><div class="value">{nv}</div><div class="label">Fabricants différents</div></div>
  <div class="stat-card"><div class="value">{rand_n}</div><div class="label">MACs randomisées</div></div>
  <div class="stat-card"><div class="value">{ps_n}</div><div class="label">En Power Save</div></div>
</div>
<div class="section"><h2>📊 Répartition par fabricant</h2><div class="vendor-chart">{vi}</div></div>
<div class="section"><h2>📡 Répartition par standard WiFi</h2><div class="vendor-chart">{wi}</div></div>
<div class="section"><h2>📋 Répartition par point d'accès</h2><div class="vendor-chart">{ai}</div></div>
<div class="section"><h2>🖥️ Tous les clients détectés</h2><div class="scroll-table"><table><thead><tr>
<th>#</th><th>Adresse MAC</th><th>Fabricant</th><th>WiFi</th><th>Détails</th><th>Point d'accès</th><th>Signal</th><th>Paquets</th><th>SSIDs probés</th>
</tr></thead><tbody>
{rows}
</tbody></table></div></div>
<div class="footer">Généré par <strong>WireMCP</strong> (Rust) — Monitor Mode — {now}</div>
</div></body></html>"##,
        ssid=esc(ssid), channel=channel, dur=dur, now=now,
        nc=sorted.len(), na=aps.len(), total=total, nv=vendors.len(),
        rand_n=rand_n, ps_n=ps_n, vi=vi, wi=wi, ai=ai, rows=rows)
}

// --- Main ---
fn main() {
    let cli = Cli::parse();
    if !cli.interface.chars().all(|c| c.is_alphanumeric() || c == '_' || c == '-' || c == '.') {
        eprintln!("Error: Invalid interface name: {}", cli.interface);
        std::process::exit(1);
    }

    let state = IfState::save(&cli.interface);

    // Ignore SIGHUP/SIGTERM so terminal can't kill us before cleanup
    unsafe {
        libc::signal(libc::SIGHUP, libc::SIG_IGN);
        libc::signal(libc::SIGTERM, libc::SIG_IGN);
    }

    // Raw SIGINT handler — no SA_RESTART so poll() returns EINTR
    unsafe {
        let mut sa: libc::sigaction = std::mem::zeroed();
        sa.sa_sigaction = sigint_handler as usize;
        sa.sa_flags = 0; // No SA_RESTART — poll/read will return EINTR
        libc::sigemptyset(&mut sa.sa_mask);
        libc::sigaction(libc::SIGINT, &sa, std::ptr::null_mut());
    }

    // Panic hook to restore interface
    let (ifc, cnc) = (cli.interface.clone(), state.conn.clone());
    std::panic::set_hook(Box::new(move |info| {
        eprintln!("[monitor-scan] Panic! Restoring...");
        IfState { iface: ifc.clone(), conn: cnc.clone() }.restore();
        eprintln!("{}", info);
    }));

    eprintln!("[monitor-scan] Switching {} to monitor mode...", cli.interface);
    if let Err(e) = state.to_monitor() {
        eprintln!("Error: {}", e); state.restore(); std::process::exit(1);
    }

    let channel = if cli.channel == 0 {
        eprintln!("[monitor-scan] Auto-detecting best channel (max 30s)...");
        let ch = auto_detect(&cli.interface, &state);
        if !is_interrupted() {
            if let Err(e) = state.set_channel(ch) { eprintln!("Error: {}", e); state.restore(); std::process::exit(1); }
        }
        ch
    } else {
        if let Err(e) = state.set_channel(cli.channel) { eprintln!("Error: {}", e); state.restore(); std::process::exit(1); }
        cli.channel
    };

    if is_interrupted() {
        eprintln!("[monitor-scan] Restoring {} to managed mode...", cli.interface);
        state.restore();
        eprintln!("[monitor-scan] Interface restored.");
        std::process::exit(130);
    }

    let (clients, aps, total, ssid) = match capture(&cli.interface, cli.duration, channel) {
        Ok(r) => r,
        Err(e) => { eprintln!("Error: {}", e); state.restore(); std::process::exit(1); }
    };

    // Generate report even if interrupted (partial data is still useful)
    eprintln!("[monitor-scan] Generating report: {}", cli.output);
    let html = gen_html(&clients, &aps, total, channel, &ssid, cli.duration);
    std::fs::write(&cli.output, html).expect("Cannot write report");

    eprintln!("[monitor-scan] Restoring {} to managed mode...", cli.interface);
    state.restore();

    eprintln!("[monitor-scan] Done! {} clients, {} APs, {} frames", clients.len(), aps.len(), total);
    eprintln!("[monitor-scan] Report: {}", cli.output);
}
