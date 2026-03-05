#!/usr/bin/env node
// monitor-scan.js - Standalone WiFi monitor mode scanner
// Usage: node monitor-scan.js [--interface wlo1] [--channel 48] [--duration 30] [--output rapport.html]

const { exec } = require('child_process');
const { promisify } = require('util');
const which = require('which');
const fs = require('fs').promises;
const os = require('os');
const path = require('path');
const crypto = require('crypto');
const execAsync = promisify(exec);

// --- Parse CLI args ---
const args = process.argv.slice(2);
function getArg(name, def) {
  const idx = args.indexOf(`--${name}`);
  return idx !== -1 && args[idx + 1] ? args[idx + 1] : def;
}
if (args.includes('--help') || args.includes('-h')) {
  console.log(`Usage: node monitor-scan.js [options]

Options:
  --interface, -i   WiFi interface (default: wlo1)
  --channel, -c     WiFi channel, 0 = auto-detect (default: 0)
  --duration, -d    Capture duration in seconds (default: 30)
  --output, -o      Output HTML file path (default: ./rapport_monitor.html)
  --help, -h        Show this help`);
  process.exit(0);
}

const iface = getArg('interface', getArg('i', 'wlo1'));
const channel = parseInt(getArg('channel', getArg('c', '0')));
const duration = parseInt(getArg('duration', getArg('d', '30')));
const outputFile = getArg('output', getArg('o', path.join(process.cwd(), 'rapport_monitor.html')));

// --- Helpers ---
function tempPcapPath() {
  return path.join(os.tmpdir(), `wiremcp_${crypto.randomBytes(8).toString('hex')}.pcap`);
}

function sanitizeIface(name) {
  if (!/^[a-zA-Z0-9_.\-]+$/.test(name)) throw new Error(`Invalid interface name: ${name}`);
  return name;
}

const OUI_DB = {
  '00:17:c8': 'KYOCERA', '08:5b:d6': 'Toshiba', '08:6a:c5': 'Samsung',
  '14:13:33': 'Apple', '1c:70:c9': 'Xiaomi', '24:5a:4c': 'Ubiquiti',
  '2c:be:eb': 'Samsung', '34:1c:f0': 'Samsung', '34:6f:24': 'Xiaomi',
  '3c:0a:f3': 'Apple', '40:a6:b7': 'Intel', '40:d1:33': 'Samsung',
  '4c:23:38': 'Xiaomi', '4c:82:a9': 'Samsung', '4c:d5:77': 'Samsung',
  '58:96:71': 'Intel', '5c:fb:3a': 'Apple', '60:b7:6e': 'Huawei',
  '6c:94:66': 'Apple', '70:b1:3d': 'Samsung', '74:83:c2': 'Ubiquiti',
  '78:2b:46': 'Samsung', '80:2a:a8': 'Ubiquiti', '80:b6:55': 'Apple',
  '8c:ea:48': 'Samsung', '8c:fd:f0': 'Qualcomm', '9c:65:eb': 'OnePlus',
  'a0:af:bd': 'Samsung', 'b4:fb:e4': 'Ubiquiti', 'bc:df:58': 'Google',
  'cc:2f:71': 'Intel', 'd8:f3:bc': 'Apple', 'dc:21:48': 'Apple',
  'e8:84:a5': 'Apple', 'e8:fb:1c': 'Intel', 'f8:3d:c6': 'Qualcomm',
  'fc:ec:da': 'Ubiquiti',
};

function getVendor(mac) {
  const prefix = mac.substring(0, 8).toLowerCase();
  const firstByte = parseInt(prefix.split(':')[0], 16);
  if (OUI_DB[prefix]) return OUI_DB[prefix];
  if (firstByte & 0x02) return 'Private/Randomized';
  return 'Unknown';
}

function sigQuality(dbm) {
  if (dbm >= -50) return { label: 'Excellent', color: '#22c55e' };
  if (dbm >= -60) return { label: 'Bon', color: '#84cc16' };
  if (dbm >= -70) return { label: 'Correct', color: '#eab308' };
  if (dbm >= -80) return { label: 'Faible', color: '#f97316' };
  return { label: 'Très faible', color: '#ef4444' };
}

function log(msg) { console.log(`[monitor-scan] ${msg}`); }

async function findTshark() {
  try { return await which('tshark'); }
  catch(e) {
    for (const p of ['/usr/bin/tshark', '/usr/local/bin/tshark']) {
      try { await execAsync(`${p} -v`); return p; } catch(e) {}
    }
    throw new Error('tshark not found');
  }
}

// --- HTML generator (same as MCP tool) ---
function generateReportHTML(clients, aps, totalFrames, ch, ssid, dur) {
  const now = new Date().toLocaleString('fr-FR', { timeZone: 'Europe/Paris' });
  const sorted = Object.values(clients).sort((a, b) => b.packets - a.packets);
  const apNames = {};
  let apIdx = 1;
  for (const ap of Object.keys(aps)) { apNames[ap] = `AP-${apIdx++} (${getVendor(ap)})`; }

  const vendorCounts = {};
  for (const c of sorted) { vendorCounts[c.vendor] = (vendorCounts[c.vendor] || 0) + 1; }
  const vendorSorted = Object.entries(vendorCounts).sort((a, b) => b[1] - a[1]);

  const apCounts = {};
  for (const c of sorted) { if (c.mainAP && c.mainAP !== 'N/A') apCounts[c.mainAP] = (apCounts[c.mainAP] || 0) + 1; }

  const wifiCounts = {};
  let randCount = 0, psCount = 0;
  for (const c of sorted) {
    const std = c.wifiStandard || 'Unknown';
    wifiCounts[std] = (wifiCounts[std] || 0) + 1;
    if (c.randomizedMAC) randCount++;
    if (c.powerSave) psCount++;
  }
  const wifiSorted = Object.entries(wifiCounts).sort((a, b) => b[1] - a[1]);

  let rows = '';
  sorted.forEach((c, i) => {
    const sig = c.bestSignal > -100 ? c.bestSignal : 'N/A';
    const sq = sigQuality(c.bestSignal);
    const sigPercent = Math.min(100, Math.max(0, (c.bestSignal + 100) * 2));
    let vc = 'other';
    if (c.vendor.includes('Apple')) vc = 'apple';
    else if (c.vendor.includes('Samsung')) vc = 'samsung';
    else if (c.vendor.includes('Intel')) vc = 'intel';
    else if (c.vendor.includes('Xiaomi')) vc = 'xiaomi';
    else if (c.vendor.includes('Ubiquiti')) vc = 'ubiquiti';
    const apClass = ['ap1','ap2','ap3'][Object.keys(apNames).indexOf(c.mainAP)] || 'ap1';
    const probeHtml = c.probes.length > 0
      ? c.probes.map(p => `<span class="probe-tag">${p}</span>`).join(' ')
      : '<span style="color:#475569">—</span>';
    let wifiClass = 'wifiold';
    if (c.wifiStandard && c.wifiStandard.includes('6')) wifiClass = 'wifi6';
    else if (c.wifiStandard && c.wifiStandard.includes('5')) wifiClass = 'wifi5';
    else if (c.wifiStandard && c.wifiStandard.includes('4')) wifiClass = 'wifi4';
    const wifiHtml = c.wifiStandard ? `<span class="wifi-badge ${wifiClass}">${c.wifiStandard}</span>` : '<span style="color:#475569">—</span>';
    let details = [];
    if (c.bandwidth) details.push(`<span class="tag-small tag-bw">${c.bandwidth}</span>`);
    if (c.maxDataRate > 0) details.push(`<span class="tag-small tag-bw">${c.maxDataRate} Mbps</span>`);
    if (c.powerSave) details.push(`<span class="tag-small tag-ps">Power Save</span>`);
    if (c.randomizedMAC) details.push(`<span class="tag-small tag-rand">MAC Rand.</span>`);
    const detailsHtml = details.length > 0 ? details.join(' ') : '<span style="color:#475569">—</span>';
    rows += `<tr>
      <td>${i+1}</td>
      <td><span class="mac">${c.mac}</span></td>
      <td><span class="vendor-badge ${vc}">${c.vendor}</span></td>
      <td>${wifiHtml}</td>
      <td>${detailsHtml}</td>
      <td><span class="ap-tag ${apClass}">${apNames[c.mainAP] || c.mainAP || 'N/A'}</span></td>
      <td><div class="signal-bar"><div class="signal-fill" style="width:${sigPercent}%;background:${sq.color}"></div></div>
        <span style="color:${sq.color}">${sig !== 'N/A' ? sig+' dBm' : 'N/A'}</span></td>
      <td>${c.packets.toLocaleString()}</td>
      <td>${probeHtml}</td></tr>\n`;
  });

  const vendorItems = vendorSorted.map(([v,c]) => `<div class="vendor-item"><div class="vendor-count">${c}</div><div class="vendor-name">${v}</div></div>`).join('\n');
  const apItems = Object.entries(apCounts).sort((a,b) => b[1]-a[1]).map(([ap,c]) => `<div class="vendor-item"><div class="vendor-count">${c}</div><div class="vendor-name">${apNames[ap]||ap}</div></div>`).join('\n');
  const wifiItems = wifiSorted.map(([w,c]) => `<div class="vendor-item"><div class="vendor-count">${c}</div><div class="vendor-name">${w}</div></div>`).join('\n');

  return `<!DOCTYPE html>
<html lang="fr"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>WireMCP - Rapport Monitor ${ssid}</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}body{font-family:'Segoe UI',system-ui,sans-serif;background:#0f172a;color:#e2e8f0;line-height:1.6}
.container{max-width:1400px;margin:0 auto;padding:20px}h1{font-size:2rem;color:#38bdf8;margin-bottom:5px}
.subtitle{color:#94a3b8;margin-bottom:30px;font-size:.9rem}
.stats-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:15px;margin-bottom:30px}
.stat-card{background:#1e293b;border-radius:12px;padding:20px;border:1px solid #334155}
.stat-card .value{font-size:2rem;font-weight:700;color:#38bdf8}.stat-card .label{color:#94a3b8;font-size:.85rem}
.section{background:#1e293b;border-radius:12px;padding:20px;margin-bottom:20px;border:1px solid #334155}
.section h2{color:#38bdf8;font-size:1.3rem;margin-bottom:15px;padding-bottom:10px;border-bottom:1px solid #334155}
table{width:100%;border-collapse:collapse;font-size:.85rem}
th{background:#0f172a;color:#38bdf8;text-align:left;padding:10px 12px;position:sticky;top:0}
td{padding:8px 12px;border-bottom:1px solid #1e293b}tr:hover td{background:#334155}
.mac{font-family:'Courier New',monospace;font-size:.8rem;color:#67e8f9}
.vendor-badge{display:inline-block;padding:2px 8px;border-radius:4px;font-size:.75rem;font-weight:600}
.apple{background:#374151;color:#a78bfa}.samsung{background:#1e3a5f;color:#60a5fa}
.intel{background:#1e3a5f;color:#38bdf8}.xiaomi{background:#3b2f0a;color:#fbbf24}
.ubiquiti{background:#0f2b1e;color:#4ade80}.other{background:#334155;color:#94a3b8}
.signal-bar{display:inline-block;width:60px;height:8px;background:#334155;border-radius:4px;overflow:hidden;vertical-align:middle;margin-right:5px}
.signal-fill{height:100%;border-radius:4px}
.probe-tag{display:inline-block;background:#334155;color:#fbbf24;padding:1px 6px;border-radius:3px;font-size:.75rem;margin:1px}
.ap-tag{display:inline-block;padding:2px 8px;border-radius:4px;font-size:.75rem;font-weight:600}
.ap1{background:#1e3a5f;color:#60a5fa}.ap2{background:#1a2e1a;color:#4ade80}.ap3{background:#2e1a2e;color:#c084fc}
.wifi-badge{display:inline-block;padding:2px 6px;border-radius:4px;font-size:.7rem;font-weight:600}
.wifi6{background:#0f2b1e;color:#4ade80}.wifi5{background:#1e293b;color:#38bdf8}.wifi4{background:#2e1a0a;color:#fbbf24}.wifiold{background:#334155;color:#94a3b8}
.tag-small{display:inline-block;padding:1px 5px;border-radius:3px;font-size:.7rem;margin:1px}
.tag-bw{background:#1e1e3b;color:#a78bfa}.tag-ps{background:#3b2f0a;color:#fbbf24}.tag-rand{background:#3b0a0a;color:#f87171}
.vendor-chart{display:flex;flex-wrap:wrap;gap:10px}
.vendor-item{background:#0f172a;border-radius:8px;padding:10px 15px;display:flex;align-items:center;gap:10px}
.vendor-count{font-size:1.5rem;font-weight:700;color:#38bdf8}.vendor-name{color:#94a3b8;font-size:.85rem}
.footer{text-align:center;color:#475569;font-size:.8rem;margin-top:30px;padding:15px}
.scroll-table{max-height:600px;overflow-y:auto}
</style></head><body><div class="container">
<h1>📡 WireMCP — Rapport Monitor Mode</h1>
<p class="subtitle">Réseau <strong>${ssid}</strong> — Canal ${ch} — Capture ${dur}s — ${now}</p>
<div class="stats-grid">
  <div class="stat-card"><div class="value">${sorted.length}</div><div class="label">Clients détectés</div></div>
  <div class="stat-card"><div class="value">${Object.keys(aps).length}</div><div class="label">Points d'accès</div></div>
  <div class="stat-card"><div class="value">${totalFrames.toLocaleString()}</div><div class="label">Trames capturées</div></div>
  <div class="stat-card"><div class="value">${vendorSorted.length}</div><div class="label">Fabricants différents</div></div>
  <div class="stat-card"><div class="value">${randCount}</div><div class="label">MACs randomisées</div></div>
  <div class="stat-card"><div class="value">${psCount}</div><div class="label">En Power Save</div></div>
</div>
<div class="section"><h2>📊 Répartition par fabricant</h2><div class="vendor-chart">${vendorItems}</div></div>
<div class="section"><h2>📡 Répartition par standard WiFi</h2><div class="vendor-chart">${wifiItems}</div></div>
<div class="section"><h2>📋 Répartition par point d'accès</h2><div class="vendor-chart">${apItems}</div></div>
<div class="section"><h2>🖥️ Tous les clients détectés</h2><div class="scroll-table"><table><thead><tr>
  <th>#</th><th>Adresse MAC</th><th>Fabricant</th><th>WiFi</th><th>Détails</th><th>Point d'accès</th><th>Signal</th><th>Paquets</th><th>SSIDs probés</th>
</tr></thead><tbody>${rows}</tbody></table></div></div>
<div class="footer">Généré par <strong>WireMCP</strong> — Monitor Mode Capture — ${now}</div>
</div></body></html>`;
}

// --- Main ---
async function main() {
  const ifaceSafe = sanitizeIface(iface);
  const tempPcap = tempPcapPath();
  const env = { env: { ...process.env, PATH: `${process.env.PATH}:/usr/bin:/usr/local/bin:/usr/sbin` } };
  let originalConnection = '';

  try {
    const tsharkPath = await findTshark();
    log(`tshark: ${tsharkPath}`);

    // 1. Save state
    const { stdout: devInfo } = await execAsync(`iw dev ${ifaceSafe} info`, env);
    const wasManaged = devInfo.includes('type managed');
    if (wasManaged) {
      try {
        const { stdout: nmStatus } = await execAsync(`nmcli -t -f DEVICE,CONNECTION dev status`, env);
        const line = nmStatus.split('\n').find(l => l.startsWith(ifaceSafe + ':'));
        if (line) originalConnection = line.split(':')[1];
      } catch(e) {}
    }

    // 2. Switch to monitor mode
    log(`Switching ${ifaceSafe} to monitor mode...`);
    await execAsync(`nmcli dev set ${ifaceSafe} managed no`, env).catch(() => {});
    await new Promise(r => setTimeout(r, 500));
    await execAsync(`sudo ip link set ${ifaceSafe} down`, env);
    await execAsync(`sudo iw ${ifaceSafe} set type monitor`, env);
    await execAsync(`sudo ip link set ${ifaceSafe} up`, env);

    // 3. Channel selection
    let ch = channel;
    if (ch === 0) {
      log('Auto-detecting best channel...');
      const commonChannels = [1, 6, 11, 36, 40, 44, 48, 52, 56, 60, 64, 100, 149, 153, 157, 161, 165];
      let bestChannel = 1, bestCount = 0;
      for (const c of commonChannels) {
        try {
          await execAsync(`sudo iw ${ifaceSafe} set channel ${c}`, env);
          const { stdout } = await execAsync(
            `sudo ${tsharkPath} -i ${ifaceSafe} -a duration:1 -T fields -e wlan.ta 2>/dev/null | wc -l`,
            { ...env, timeout: 5000 }
          );
          const count = parseInt(stdout.trim()) || 0;
          process.stdout.write(`  ch ${c}: ${count} frames\n`);
          if (count > bestCount) { bestCount = count; bestChannel = c; }
        } catch(e) {}
      }
      ch = bestChannel;
      log(`Best channel: ${ch} (${bestCount} frames)`);
    }

    // 4. Capture
    await execAsync(`sudo iw ${ifaceSafe} set channel ${ch}`, env);
    log(`Capturing on channel ${ch} for ${duration}s...`);
    await execAsync(
      `sudo ${tsharkPath} -i ${ifaceSafe} -a duration:${duration} -w ${tempPcap}`,
      { ...env, timeout: (duration + 10) * 1000 }
    );

    // 5. Analyze
    log('Analyzing frames...');
    const { stdout: framesOut } = await execAsync(
      `sudo ${tsharkPath} -r ${tempPcap} -T fields -e wlan.ta -e wlan.ra -e wlan_radio.signal_dbm -e wlan.fc.type_subtype -e wlan_radio.data_rate -e wlan.fc.pwrmgt`,
      { ...env, maxBuffer: 100 * 1024 * 1024 }
    );
    const { stdout: probesOut } = await execAsync(
      `sudo ${tsharkPath} -r ${tempPcap} -Y "wlan.fc.type_subtype == 0x04" -T fields -e wlan.ta -e wlan.ssid`, env
    );
    const { stdout: beaconsOut } = await execAsync(
      `sudo ${tsharkPath} -r ${tempPcap} -Y "wlan.fc.type_subtype == 0x08" -T fields -e wlan.ta -e wlan.ssid`, env
    );
    const { stdout: capsOut } = await execAsync(
      `sudo ${tsharkPath} -r ${tempPcap} -Y "wlan.fc.type == 0" -T fields -e wlan.ta -e wlan.ht.capabilities -e wlan.vht.capabilities -e wlan.he.mac_capabilities -e radiotap.vht.bw -e wlan_radio.11ac.bandwidth -e radiotap.mcs.index -e radiotap.he.data_3.data_mcs`,
      { ...env, maxBuffer: 50 * 1024 * 1024 }
    ).catch(() => ({ stdout: '' }));
    const { stdout: radioOut } = await execAsync(
      `sudo ${tsharkPath} -r ${tempPcap} -Y "wlan.fc.type == 2" -T fields -e wlan.ta -e radiotap.mcs.index -e radiotap.vht.mcs.0 -e radiotap.he.data_3.data_mcs -e radiotap.vht.bw -e radiotap.he.data_5.data_bw`,
      { ...env, maxBuffer: 100 * 1024 * 1024 }
    ).catch(() => ({ stdout: '' }));

    // 6. Parse APs
    const aps = {};
    let networkSSID = 'Unknown';
    for (const line of beaconsOut.split('\n').filter(l => l.trim())) {
      const [ta, ssidHex] = line.split('\t');
      if (ta) {
        let ssid = '';
        try { ssid = ssidHex ? Buffer.from(ssidHex, 'hex').toString('utf8') : ''; } catch(e) { ssid = ssidHex || ''; }
        aps[ta] = ssid || 'Hidden';
        if (ssid) networkSSID = ssid;
      }
    }
    const apSet = new Set(Object.keys(aps));
    apSet.add('ff:ff:ff:ff:ff:ff');

    // 7. Parse clients
    const clients = {};
    const lines = framesOut.split('\n').filter(l => l.trim());
    for (const line of lines) {
      const [ta, ra, signal, subtype, dataRate, pwrmgt] = line.split('\t');
      if (!ta || apSet.has(ta)) continue;
      if (!clients[ta]) {
        clients[ta] = { mac: ta, packets: 0, bestSignal: -100, apHits: {}, probes: [], vendor: getVendor(ta),
          maxDataRate: 0, powerSave: false, wifiStandard: '', bandwidth: '', randomizedMAC: false };
      }
      const c = clients[ta];
      c.packets++;
      const sig = parseInt(signal);
      if (!isNaN(sig) && sig > c.bestSignal) c.bestSignal = sig;
      if (apSet.has(ra)) c.apHits[ra] = (c.apHits[ra] || 0) + 1;
      const rate = parseFloat(dataRate);
      if (!isNaN(rate) && rate > c.maxDataRate) c.maxDataRate = rate;
      if (pwrmgt === '1') c.powerSave = true;
      const firstByte = parseInt(ta.split(':')[0], 16);
      if (firstByte & 0x02) c.randomizedMAC = true;
    }

    // 8. Parse capabilities
    for (const line of capsOut.split('\n').filter(l => l.trim())) {
      const [ta, htCap, vhtCap, heCap, vhtBw, acBw, mcsIdx, heMcs] = line.split('\t');
      if (!ta || !clients[ta]) continue;
      const c = clients[ta];
      if (heCap || heMcs) c.wifiStandard = 'WiFi 6 (802.11ax)';
      else if (vhtCap || vhtBw) c.wifiStandard = 'WiFi 5 (802.11ac)';
      else if (htCap || mcsIdx) c.wifiStandard = 'WiFi 4 (802.11n)';
      const bwVal = parseInt(vhtBw || acBw);
      if (!isNaN(bwVal) && !c.bandwidth) {
        if (bwVal >= 3 || bwVal === 160) c.bandwidth = '160 MHz';
        else if (bwVal === 2 || bwVal === 80) c.bandwidth = '80 MHz';
        else if (bwVal === 1 || bwVal === 40) c.bandwidth = '40 MHz';
        else c.bandwidth = '20 MHz';
      }
    }
    for (const line of radioOut.split('\n').filter(l => l.trim())) {
      const [ta, mcsIdx, vhtMcs, heMcs, vhtBw, heBw] = line.split('\t');
      if (!ta || !clients[ta]) continue;
      const c = clients[ta];
      if (heMcs && !c.wifiStandard.includes('6')) c.wifiStandard = 'WiFi 6 (802.11ax)';
      else if (vhtMcs && !c.wifiStandard.includes('6') && !c.wifiStandard.includes('5')) c.wifiStandard = 'WiFi 5 (802.11ac)';
      else if (mcsIdx && !c.wifiStandard) c.wifiStandard = 'WiFi 4 (802.11n)';
      const bw = parseInt(heBw || vhtBw);
      if (!isNaN(bw) && !c.bandwidth) {
        if (bw >= 3 || bw === 160) c.bandwidth = '160 MHz';
        else if (bw === 2 || bw === 80) c.bandwidth = '80 MHz';
        else if (bw === 1 || bw === 40) c.bandwidth = '40 MHz';
        else c.bandwidth = '20 MHz';
      }
    }

    // 9. Infer WiFi standard
    const is5GHz = ch >= 36;
    const apVendors = Object.keys(aps).map(a => getVendor(a));
    const apIsAC = apVendors.some(v => ['Ubiquiti','Cisco','Aruba','Ruckus'].includes(v)) && is5GHz;
    for (const c of Object.values(clients)) {
      if (!c.wifiStandard) {
        if (c.maxDataRate > 600) c.wifiStandard = 'WiFi 6 (802.11ax)';
        else if (c.maxDataRate > 150) c.wifiStandard = 'WiFi 5 (802.11ac)';
        else if (c.maxDataRate > 54) c.wifiStandard = 'WiFi 4 (802.11n)';
        else if (is5GHz && apIsAC && c.mainAP !== 'N/A' && c.packets > 5) c.wifiStandard = 'WiFi 5+ (802.11ac)';
        else if (c.maxDataRate > 0) c.wifiStandard = is5GHz ? '802.11a' : '802.11b/g';
      }
      if (is5GHz && !c.bandwidth && c.mainAP !== 'N/A' && c.packets > 5) c.bandwidth = '80 MHz (est.)';
    }

    // Assign main AP
    for (const c of Object.values(clients)) {
      const entries = Object.entries(c.apHits);
      if (entries.length > 0) { entries.sort((a, b) => b[1] - a[1]); c.mainAP = entries[0][0]; }
      else c.mainAP = 'N/A';
    }

    // 10. Parse probes
    for (const line of probesOut.split('\n').filter(l => l.trim())) {
      const [ta, ssidHex] = line.split('\t');
      if (!ta || !ssidHex || ssidHex === '<MISSING>') continue;
      if (!clients[ta]) {
        clients[ta] = { mac: ta, packets: 0, bestSignal: -100, apHits: {}, probes: [], vendor: getVendor(ta),
          maxDataRate: 0, powerSave: false, wifiStandard: '', bandwidth: '', randomizedMAC: false, mainAP: 'N/A' };
      }
      try {
        const ssid = Buffer.from(ssidHex, 'hex').toString('utf8');
        if (!clients[ta].probes.includes(ssid)) clients[ta].probes.push(ssid);
      } catch(e) {
        if (!clients[ta].probes.includes(ssidHex)) clients[ta].probes.push(ssidHex);
      }
    }

    // 11. Generate HTML
    log(`Generating report: ${outputFile}`);
    const html = generateReportHTML(clients, aps, lines.length, ch, networkSSID, duration);
    await fs.writeFile(outputFile, html, 'utf8');

    // 12. Restore
    log(`Restoring ${ifaceSafe} to managed mode...`);
    await execAsync(`sudo ip link set ${ifaceSafe} down`, env);
    await execAsync(`sudo iw ${ifaceSafe} set type managed`, env);
    await execAsync(`sudo ip link set ${ifaceSafe} up`, env);
    await execAsync(`nmcli dev set ${ifaceSafe} managed yes`, env).catch(() => {});
    if (originalConnection) {
      await new Promise(r => setTimeout(r, 1000));
      await execAsync(`nmcli con up "${originalConnection}"`, env).catch(() => {});
    }
    await fs.unlink(tempPcap).catch(() => {});

    const clientCount = Object.keys(clients).length;
    log(`Done! ${clientCount} clients, ${Object.keys(aps).length} APs, ${lines.length.toLocaleString()} frames`);
    log(`Report: ${outputFile}`);

  } catch (error) {
    // Restore on error
    try {
      await execAsync(`sudo ip link set ${ifaceSafe} down`, env).catch(() => {});
      await execAsync(`sudo iw ${ifaceSafe} set type managed`, env).catch(() => {});
      await execAsync(`sudo ip link set ${ifaceSafe} up`, env).catch(() => {});
      await execAsync(`nmcli dev set ${ifaceSafe} managed yes`, env).catch(() => {});
      if (originalConnection) {
        await new Promise(r => setTimeout(r, 1000));
        await execAsync(`nmcli con up "${originalConnection}"`, env).catch(() => {});
      }
    } catch(e) {}
    await fs.unlink(tempPcap).catch(() => {});
    console.error(`Error: ${error.message}`);
    process.exit(1);
  }
}

main();
