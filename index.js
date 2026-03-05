// index.js - WireMCP Server
const axios = require('axios');
const { exec } = require('child_process');
const { promisify } = require('util');
const which = require('which');
const fs = require('fs').promises;
const path = require('path');
const execAsync = promisify(exec);
const { McpServer } = require('@modelcontextprotocol/sdk/server/mcp.js');
const { StdioServerTransport } = require('@modelcontextprotocol/sdk/server/stdio.js');
const { z } = require('zod');

// Redirect console.log to stderr
const originalConsoleLog = console.log;
console.log = (...args) => console.error(...args);

// Dynamically locate tshark
async function findTshark() {
  try {
    const tsharkPath = await which('tshark');
    console.error(`Found tshark at: ${tsharkPath}`);
    return tsharkPath;
  } catch (err) {
    console.error('which failed to find tshark:', err.message);
    const fallbacks = process.platform === 'win32'
      ? ['C:\\Program Files\\Wireshark\\tshark.exe', 'C:\\Program Files (x86)\\Wireshark\\tshark.exe']
      : ['/usr/bin/tshark', '/usr/local/bin/tshark', '/opt/homebrew/bin/tshark', '/Applications/Wireshark.app/Contents/MacOS/tshark'];
    
    for (const path of fallbacks) {
      try {
        await execAsync(`${path} -v`);
        console.error(`Found tshark at fallback: ${path}`);
        return path;
      } catch (e) {
        console.error(`Fallback ${path} failed: ${e.message}`);
      }
    }
    throw new Error('tshark not found. Please install Wireshark (https://www.wireshark.org/download.html) and ensure tshark is in your PATH.');
  }
}

// Sanitize network interface name (alphanumeric, dash, underscore, dot only)
function sanitizeIface(name) {
  if (!/^[a-zA-Z0-9_.\-]+$/.test(name)) {
    throw new Error(`Invalid interface name: ${name}`);
  }
  return name;
}

// Initialize MCP server
const server = new McpServer({
  name: 'wiremcp',
  version: '1.0.0',
});

// Tool 1: Capture live packet data (Rust backend)
server.tool(
  'capture_packets',
  'Capture live traffic and provide raw packet data as JSON for LLM analysis. Uses native Rust parsing (basic) or tshark deep dissection (full).',
  {
    interface: z.string().optional().default('wlo1').describe('Network interface to capture from (e.g., eth0, wlo1)'),
    duration: z.number().optional().default(5).describe('Capture duration in seconds'),
    mode: z.enum(['basic', 'full']).optional().default('basic').describe('basic = fast native Rust parsing (IP, TCP, UDP, DNS, TLS SNI, HTTP, ARP, ICMP, DHCP), full = tshark deep dissection (all protocols)'),
  },
  async (args) => {
    const captureBin = path.join(__dirname, 'capture-rs', 'target', 'release', 'capture-packets');
    try {
      await fs.access(captureBin);
    } catch {
      return { content: [{ type: 'text', text: `Error: Rust binary not found at ${captureBin}. Run: cd capture-rs && cargo build --release` }], isError: true };
    }

    try {
      const iface = sanitizeIface(args.interface);
      const duration = args.duration;
      const mode = args.mode;
      console.error(`[capture_packets] ${mode} mode on ${iface} for ${duration}s`);

      const { stdout, stderr } = await execAsync(
        `${captureBin} --interface ${iface} --duration ${duration} --mode ${mode} --max-chars 720000`,
        { timeout: (duration + 60) * 1000, maxBuffer: 10 * 1024 * 1024 }
      );
      if (stderr) console.error(stderr);

      return {
        content: [{
          type: 'text',
          text: `Captured packet data (${mode} mode, JSON):\n${stdout}`,
        }],
      };
    } catch (error) {
      console.error(`Error in capture_packets: ${error.message}`);
      const stderr = error.stderr || '';
      return { content: [{ type: 'text', text: `Error: ${error.message}\n${stderr}` }], isError: true };
    }
  }
);

// Tool 2: Capture and provide summary statistics (Rust backend)
server.tool(
  'get_summary_stats',
  'Capture live traffic and provide protocol hierarchy statistics for LLM analysis. Uses native Rust packet parsing.',
  {
    interface: z.string().optional().default('wlo1').describe('Network interface to capture from (e.g., eth0, wlo1)'),
    duration: z.number().optional().default(5).describe('Capture duration in seconds'),
  },
  async (args) => {
    const captureBin = path.join(__dirname, 'capture-rs', 'target', 'release', 'capture-packets');
    try { await fs.access(captureBin); } catch {
      return { content: [{ type: 'text', text: `Error: Rust binary not found at ${captureBin}. Run: cd capture-rs && cargo build --release` }], isError: true };
    }
    try {
      const iface = sanitizeIface(args.interface);
      const duration = args.duration;
      console.error(`[get_summary_stats] Rust stats on ${iface} for ${duration}s`);
      const { stdout, stderr } = await execAsync(
        `${captureBin} --interface ${iface} --duration ${duration} --mode stats`,
        { timeout: (duration + 60) * 1000 }
      );
      if (stderr) console.error(stderr);
      return { content: [{ type: 'text', text: `Protocol hierarchy statistics:\n${stdout}` }] };
    } catch (error) {
      console.error(`Error in get_summary_stats: ${error.message}`);
      return { content: [{ type: 'text', text: `Error: ${error.message}\n${error.stderr || ''}` }], isError: true };
    }
  }
);

// Tool 3: Capture and provide conversation stats (Rust backend)
server.tool(
  'get_conversations',
  'Capture live traffic and provide TCP/UDP conversation statistics for LLM analysis. Uses native Rust packet parsing.',
  {
    interface: z.string().optional().default('wlo1').describe('Network interface to capture from (e.g., eth0, wlo1)'),
    duration: z.number().optional().default(5).describe('Capture duration in seconds'),
  },
  async (args) => {
    const captureBin = path.join(__dirname, 'capture-rs', 'target', 'release', 'capture-packets');
    try { await fs.access(captureBin); } catch {
      return { content: [{ type: 'text', text: `Error: Rust binary not found at ${captureBin}. Run: cd capture-rs && cargo build --release` }], isError: true };
    }
    try {
      const iface = sanitizeIface(args.interface);
      const duration = args.duration;
      console.error(`[get_conversations] Rust conversations on ${iface} for ${duration}s`);
      const { stdout, stderr } = await execAsync(
        `${captureBin} --interface ${iface} --duration ${duration} --mode conversations`,
        { timeout: (duration + 60) * 1000 }
      );
      if (stderr) console.error(stderr);
      return { content: [{ type: 'text', text: `TCP/UDP conversation statistics:\n${stdout}` }] };
    } catch (error) {
      console.error(`Error in get_conversations: ${error.message}`);
      return { content: [{ type: 'text', text: `Error: ${error.message}\n${error.stderr || ''}` }], isError: true };
    }
  }
);

// Tool 4: Capture traffic and check threats against URLhaus (Rust capture + JS URLhaus)
server.tool(
  'check_threats',
  'Capture live traffic and check IPs against URLhaus blacklist. Uses Rust for fast capture, JS for threat lookup.',
  {
    interface: z.string().optional().default('wlo1').describe('Network interface to capture from (e.g., eth0, wlo1)'),
    duration: z.number().optional().default(5).describe('Capture duration in seconds'),
  },
  async (args) => {
    const captureBin = path.join(__dirname, 'capture-rs', 'target', 'release', 'capture-packets');
    try { await fs.access(captureBin); } catch {
      return { content: [{ type: 'text', text: `Error: Rust binary not found at ${captureBin}. Run: cd capture-rs && cargo build --release` }], isError: true };
    }
    try {
      const iface = sanitizeIface(args.interface);
      const duration = args.duration;
      console.error(`[check_threats] Capturing on ${iface} for ${duration}s`);

      const { stdout, stderr } = await execAsync(
        `${captureBin} --interface ${iface} --duration ${duration} --mode basic --max-chars 0`,
        { timeout: (duration + 60) * 1000, maxBuffer: 10 * 1024 * 1024 }
      );
      if (stderr) console.error(stderr);

      // Extract unique IPs from Rust JSON output
      const ipRegex = /\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b/g;
      const packets = JSON.parse(stdout);
      const ips = [...new Set(packets.flatMap(p => {
        const found = [];
        if (p.ip_src) found.push(p.ip_src);
        if (p.ip_dst) found.push(p.ip_dst);
        return found;
      }).filter(ip => ip))];
      console.error(`Captured ${ips.length} unique IPs`);

      // URLhaus check
      let urlhausThreats = [];
      try {
        const response = await axios.get('https://urlhaus.abuse.ch/downloads/text/');
        const urlhausIps = [...new Set(response.data.split('\n')
          .map(line => { const m = line.match(/\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b/); return m ? m[0] : null; })
          .filter(ip => ip))];
        console.error(`URLhaus: ${urlhausIps.length} blacklist IPs`);
        urlhausThreats = ips.filter(ip => urlhausIps.includes(ip));
      } catch (e) {
        console.error(`Failed to fetch URLhaus: ${e.message}`);
      }

      return {
        content: [{ type: 'text', text: `Captured IPs:\n${ips.join('\n')}\n\nThreat check against URLhaus blacklist:\n${
          urlhausThreats.length > 0 ? `Potential threats: ${urlhausThreats.join(', ')}` : 'No threats detected in URLhaus blacklist.'
        }` }],
      };
    } catch (error) {
      console.error(`Error in check_threats: ${error.message}`);
      return { content: [{ type: 'text', text: `Error: ${error.message}\n${error.stderr || ''}` }], isError: true };
    }
  }
);

// Tool 5: Check a specific IP against URLhaus IOCs
server.tool(
  'check_ip_threats',
  'Check a given IP address against URLhaus blacklist for IOCs',
  {
    ip: z.string().regex(/\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b/).describe('IP address to check (e.g., 192.168.1.1)'),
  },
  async (args) => {
    try {
      const { ip } = args;
      console.error(`Checking IP ${ip} against URLhaus blacklist`);

      const urlhausUrl = 'https://urlhaus.abuse.ch/downloads/text/';
      console.error(`Fetching URLhaus blacklist from ${urlhausUrl}`);
      let urlhausData;
      let isThreat = false;
      try {
        const response = await axios.get(urlhausUrl);
        console.error(`URLhaus response status: ${response.status}, length: ${response.data.length} chars`);
        console.error(`URLhaus raw data (first 200 chars): ${response.data.slice(0, 200)}`);
        const ipRegex = /\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b/;
        urlhausData = [...new Set(response.data.split('\n')
          .map(line => {
            const match = line.match(ipRegex);
            return match ? match[0] : null;
          })
          .filter(ip => ip))];
        console.error(`URLhaus lookup successful: ${urlhausData.length} blacklist IPs fetched`);
        console.error(`Sample URLhaus IPs: ${urlhausData.slice(0, 5).join(', ') || 'None'}`);
        isThreat = urlhausData.includes(ip);
        console.error(`IP ${ip} checked against URLhaus: ${isThreat ? 'Threat found' : 'No threat found'}`);
      } catch (e) {
        console.error(`Failed to fetch URLhaus data: ${e.message}`);
        urlhausData = [];
      }

      const outputText = `IP checked: ${ip}\n\n` +
        `Threat check against URLhaus blacklist:\n${
          isThreat ? 'Potential threat detected in URLhaus blacklist.' : 'No threat detected in URLhaus blacklist.'
        }`;

      return {
        content: [{ type: 'text', text: outputText }],
      };
    } catch (error) {
      console.error(`Error in check_ip_threats: ${error.message}`);
      return { content: [{ type: 'text', text: `Error: ${error.message}` }], isError: true };
    }
  }
);

// Tool 6: Analyze an existing PCAP file (Rust backend)
server.tool(
  'analyze_pcap',
  'Analyze a PCAP file and provide packet data as JSON for LLM analysis. Uses native Rust parsing (basic) or tshark deep dissection (full).',
  {
    pcapPath: z.string().describe('Path to the PCAP file to analyze (e.g., ./demo.pcap)'),
    mode: z.enum(['basic', 'full']).optional().default('basic').describe('basic = fast native Rust parsing, full = tshark deep dissection'),
  },
  async (args) => {
    const captureBin = path.join(__dirname, 'capture-rs', 'target', 'release', 'capture-packets');
    try {
      await fs.access(captureBin);
    } catch {
      return { content: [{ type: 'text', text: `Error: Rust binary not found at ${captureBin}. Run: cd capture-rs && cargo build --release` }], isError: true };
    }

    try {
      const { pcapPath, mode } = args;
      console.error(`[analyze_pcap] ${mode} mode on ${pcapPath}`);
      await fs.access(pcapPath);

      const { stdout, stderr } = await execAsync(
        `${captureBin} --mode ${mode} --file "${pcapPath}" --max-chars 720000`,
        { timeout: 120000, maxBuffer: 10 * 1024 * 1024 }
      );
      if (stderr) console.error(stderr);

      return {
        content: [{ type: 'text', text: `Analyzed PCAP (${mode} mode): ${pcapPath}\n\n${stdout}` }],
      };
    } catch (error) {
      console.error(`Error in analyze_pcap: ${error.message}`);
      return { content: [{ type: 'text', text: `Error: ${error.message}` }], isError: true };
    }
  }
);

// Tool 7: Extract credentials from a PCAP file
server.tool(
    'extract_credentials',
    'Extract potential credentials (HTTP Basic Auth, FTP, Telnet) from a PCAP file for LLM analysis',
    {
      pcapPath: z.string().describe('Path to the PCAP file to analyze (e.g., ./demo.pcap)'),
    },
    async (args) => {
      try {
        const tsharkPath = await findTshark();
        const { pcapPath } = args;
        console.error(`Extracting credentials from PCAP file: ${pcapPath}`);
  
        await fs.access(pcapPath);
  
        // Extract plaintext credentials
        const { stdout: plaintextOut } = await execAsync(
          `${tsharkPath} -r "${pcapPath}" -T fields -e http.authbasic -e ftp.request.command -e ftp.request.arg -e telnet.data -e frame.number`,
          { env: { ...process.env, PATH: `${process.env.PATH}:/usr/bin:/usr/local/bin:/opt/homebrew/bin` } }
        );

        // Extract Kerberos credentials
        const { stdout: kerberosOut } = await execAsync(
          `${tsharkPath} -r "${pcapPath}" -T fields -e kerberos.CNameString -e kerberos.realm -e kerberos.cipher -e kerberos.type -e kerberos.msg_type -e frame.number`,
          { env: { ...process.env, PATH: `${process.env.PATH}:/usr/bin:/usr/local/bin:/opt/homebrew/bin` } }
        );

        const lines = plaintextOut.split('\n').filter(line => line.trim());
        const packets = lines.map(line => {
          const [authBasic, ftpCmd, ftpArg, telnetData, frameNumber] = line.split('\t');
          return {
            authBasic: authBasic || '',
            ftpCmd: ftpCmd || '',
            ftpArg: ftpArg || '',
            telnetData: telnetData || '',
            frameNumber: frameNumber || ''
          };
        });
  
        const credentials = {
          plaintext: [],
          encrypted: []
        };
  
        // Process HTTP Basic Auth
        packets.forEach(p => {
          if (p.authBasic) {
            const [username, password] = Buffer.from(p.authBasic, 'base64').toString().split(':');
            credentials.plaintext.push({ type: 'HTTP Basic Auth', username, password, frame: p.frameNumber });
          }
        });
  
        // Process FTP
        packets.forEach(p => {
          if (p.ftpCmd === 'USER') {
            credentials.plaintext.push({ type: 'FTP', username: p.ftpArg, password: '', frame: p.frameNumber });
          }
          if (p.ftpCmd === 'PASS') {
            const lastUser = credentials.plaintext.findLast(c => c.type === 'FTP' && !c.password);
            if (lastUser) lastUser.password = p.ftpArg;
          }
        });
  
        // Process Telnet
        packets.forEach(p => {
          if (p.telnetData) {
            const telnetStr = p.telnetData.trim();
            if (telnetStr.toLowerCase().includes('login:') || telnetStr.toLowerCase().includes('password:')) {
              credentials.plaintext.push({ type: 'Telnet Prompt', data: telnetStr, frame: p.frameNumber });
            } else if (telnetStr && !telnetStr.match(/[A-Z][a-z]+:/) && !telnetStr.includes(' ')) {
              const lastPrompt = credentials.plaintext.findLast(c => c.type === 'Telnet Prompt');
              if (lastPrompt && lastPrompt.data.toLowerCase().includes('login:')) {
                credentials.plaintext.push({ type: 'Telnet', username: telnetStr, password: '', frame: p.frameNumber });
              } else if (lastPrompt && lastPrompt.data.toLowerCase().includes('password:')) {
                const lastUser = credentials.plaintext.findLast(c => c.type === 'Telnet' && !c.password);
                if (lastUser) lastUser.password = telnetStr;
                else credentials.plaintext.push({ type: 'Telnet', username: '', password: telnetStr, frame: p.frameNumber });
              }
            }
          }
        });

        // Process Kerberos credentials
        const kerberosLines = kerberosOut.split('\n').filter(line => line.trim());
        kerberosLines.forEach(line => {
          const [cname, realm, cipher, type, msgType, frameNumber] = line.split('\t');
          
          if (cipher && type) {
            let hashFormat = '';
            // Format hash based on message type
            if (msgType === '10' || msgType === '30') { // AS-REQ or TGS-REQ
              hashFormat = '$krb5pa$23$';
              if (cname) hashFormat += `${cname}$`;
              if (realm) hashFormat += `${realm}$`;
              hashFormat += cipher;
            } else if (msgType === '11') { // AS-REP
              hashFormat = '$krb5asrep$23$';
              if (cname) hashFormat += `${cname}@`;
              if (realm) hashFormat += `${realm}$`;
              hashFormat += cipher;
            }

            if (hashFormat) {
              credentials.encrypted.push({
                type: 'Kerberos',
                hash: hashFormat,
                username: cname || 'unknown',
                realm: realm || 'unknown',
                frame: frameNumber,
                crackingMode: msgType === '11' ? 'hashcat -m 18200' : 'hashcat -m 7500'
              });
            }
          }
        });

        console.error(`Found ${credentials.plaintext.length} plaintext and ${credentials.encrypted.length} encrypted credentials`);
  
        const outputText = `Analyzed PCAP: ${pcapPath}\n\n` +
          `Plaintext Credentials:\n${credentials.plaintext.length > 0 ? 
            credentials.plaintext.map(c => 
              c.type === 'Telnet Prompt' ? 
                `${c.type}: ${c.data} (Frame ${c.frame})` : 
                `${c.type}: ${c.username}:${c.password} (Frame ${c.frame})`
            ).join('\n') : 
            'None'}\n\n` +
          `Encrypted/Hashed Credentials:\n${credentials.encrypted.length > 0 ?
            credentials.encrypted.map(c =>
              `${c.type}: User=${c.username} Realm=${c.realm} (Frame ${c.frame})\n` +
              `Hash=${c.hash}\n` +
              `Cracking Command: ${c.crackingMode}\n`
            ).join('\n') :
            'None'}\n\n` +
          `Note: Encrypted credentials can be cracked using tools like John the Ripper or hashcat.\n` +
          `For Kerberos hashes:\n` +
          `- AS-REQ/TGS-REQ: hashcat -m 7500 or john --format=krb5pa-md5\n` +
          `- AS-REP: hashcat -m 18200 or john --format=krb5asrep`;
  
        return {
          content: [{ type: 'text', text: outputText }],
        };
      } catch (error) {
        console.error(`Error in extract_credentials: ${error.message}`);
        return { content: [{ type: 'text', text: `Error: ${error.message}` }], isError: true };
      }
    }
  );

// Tool 8: Monitor mode scan with HTML report (Rust backend)
server.tool(
  'monitor_scan',
  'Switch to monitor mode, scan WiFi clients on a channel, generate an HTML report, then restore managed mode. Uses native Rust binary for fast 802.11 parsing.',
  {
    interface: z.string().optional().default('wlo1').describe('WiFi interface to use'),
    channel: z.number().optional().default(0).describe('WiFi channel to monitor (0 = auto-detect best channel)'),
    duration: z.number().optional().default(30).describe('Capture duration in seconds'),
    outputPath: z.string().optional().default('').describe('Output HTML file path (default: ./rapport_monitor.html)'),
  },
  async (args) => {
    const iface = sanitizeIface(args.interface);
    const duration = args.duration;
    const outputFile = args.outputPath || path.join(process.cwd(), 'rapport_monitor.html');
    const binPath = path.join(__dirname, 'monitor-scan-rs', 'target', 'release', 'monitor-scan');

    try {
      // Check binary exists
      await fs.access(binPath);
    } catch {
      return { content: [{ type: 'text', text: `Error: Rust binary not found at ${binPath}. Run: cd monitor-scan-rs && cargo build --release` }], isError: true };
    }

    try {
      console.error(`[monitor_scan] Running Rust scanner: ${iface} ch${args.channel} ${duration}s`);
      const { stdout, stderr } = await execAsync(
        `${binPath} --interface ${iface} --channel ${args.channel} --duration ${duration} --output "${outputFile}"`,
        { timeout: (duration + 120) * 1000 }
      );

      // Parse summary from stderr
      const lines = stderr.split('\n').filter(l => l.trim());
      const doneLine = lines.find(l => l.includes('Done!')) || '';
      const summary = doneLine
        ? `Monitor scan complete (Rust):\n${doneLine.replace('[monitor-scan] ', '')}\n- Report saved to: ${outputFile}`
        : `Monitor scan complete. Report saved to: ${outputFile}`;

      console.error(stderr);
      return { content: [{ type: 'text', text: summary }] };

    } catch (error) {
      console.error(`Error in monitor_scan: ${error.message}`);
      // stderr often contains useful info even on failure
      const stderr = error.stderr || '';
      console.error(stderr);
      return { content: [{ type: 'text', text: `Error: ${error.message}\n${stderr}` }], isError: true };
    }
  }
);

// Add prompts for each tool
server.prompt(
  'capture_packets_prompt',
  {
    interface: z.string().optional().describe('Network interface to capture from'),
    duration: z.number().optional().describe('Duration in seconds to capture'),
    mode: z.string().optional().describe('basic (fast Rust) or full (tshark deep)'),
  },
  ({ interface: iface = 'wlo1', duration = 5, mode = 'basic' }) => ({
    messages: [{
      role: 'user',
      content: {
        type: 'text',
        text: `Please analyze the network traffic on interface ${iface} for ${duration} seconds (mode: ${mode}) and provide insights about:
1. The types of traffic observed
2. Any notable patterns or anomalies
3. Key IP addresses and ports involved
4. DNS queries and TLS connections (SNI)
5. Potential security concerns`
      }
    }]
  })
);

server.prompt(
  'summary_stats_prompt',
  {
    interface: z.string().optional().describe('Network interface to capture from'),
    duration: z.number().optional().describe('Duration in seconds to capture'),
  },
  ({ interface = 'en0', duration = 5 }) => ({
    messages: [{
      role: 'user',
      content: {
        type: 'text',
        text: `Please provide a summary of network traffic statistics from interface ${interface} over ${duration} seconds, focusing on:
1. Protocol distribution
2. Traffic volume by protocol
3. Notable patterns in protocol usage
4. Potential network health indicators`
      }
    }]
  })
);

server.prompt(
  'conversations_prompt',
  {
    interface: z.string().optional().describe('Network interface to capture from'),
    duration: z.number().optional().describe('Duration in seconds to capture'),
  },
  ({ interface = 'en0', duration = 5 }) => ({
    messages: [{
      role: 'user',
      content: {
        type: 'text',
        text: `Please analyze network conversations on interface ${interface} for ${duration} seconds and identify:
1. Most active IP pairs
2. Conversation durations and data volumes
3. Unusual communication patterns
4. Potential indicators of network issues`
      }
    }]
  })
);

server.prompt(
  'check_threats_prompt',
  {
    interface: z.string().optional().describe('Network interface to capture from'),
    duration: z.number().optional().describe('Duration in seconds to capture'),
  },
  ({ interface = 'en0', duration = 5 }) => ({
    messages: [{
      role: 'user',
      content: {
        type: 'text',
        text: `Please analyze traffic on interface ${interface} for ${duration} seconds and check for security threats:
1. Compare captured IPs against URLhaus blacklist
2. Identify potential malicious activity
3. Highlight any concerning patterns
4. Provide security recommendations`
      }
    }]
  })
);

server.prompt(
  'check_ip_threats_prompt',
  {
    ip: z.string().describe('IP address to check'),
  },
  ({ ip }) => ({
    messages: [{
      role: 'user',
      content: {
        type: 'text',
        text: `Please analyze the following IP address (${ip}) for potential security threats:
1. Check against URLhaus blacklist
2. Evaluate the IP's reputation
3. Identify any known malicious activity
4. Provide security recommendations`
      }
    }]
  })
);

server.prompt(
  'analyze_pcap_prompt',
  {
    pcapPath: z.string().describe('Path to the PCAP file'),
    mode: z.string().optional().describe('basic (fast Rust) or full (tshark deep)'),
  },
  ({ pcapPath, mode = 'basic' }) => ({
    messages: [{
      role: 'user',
      content: {
        type: 'text',
        text: `Please analyze the PCAP file at ${pcapPath} (mode: ${mode}) and provide insights about:
1. Overall traffic patterns
2. Unique IPs and their interactions
3. DNS queries and resolved domains
4. TLS connections and SNI hostnames
5. Protocols and services used
6. Notable events or anomalies
7. Potential security concerns`
      }
    }]
  })
);

server.prompt(
  'extract_credentials_prompt',
  {
    pcapPath: z.string().describe('Path to the PCAP file'),
  },
  ({ pcapPath }) => ({
    messages: [{
      role: 'user',
      content: {
        type: 'text',
        text: `Please analyze the PCAP file at ${pcapPath} for potential credential exposure:
1. Look for plaintext credentials (HTTP Basic Auth, FTP, Telnet)
2. Identify Kerberos authentication attempts
3. Extract any hashed credentials
4. Provide security recommendations for credential handling`
      }
    }]
  })
);

server.prompt(
  'monitor_scan_prompt',
  {
    interface: z.string().optional().describe('WiFi interface to use'),
    channel: z.number().optional().describe('WiFi channel (0 for auto)'),
    duration: z.number().optional().describe('Capture duration in seconds'),
  },
  ({ interface: iface = 'wlo1', channel = 0, duration = 30 }) => ({
    messages: [{
      role: 'user',
      content: {
        type: 'text',
        text: `Please perform a monitor mode scan on interface ${iface} (channel: ${channel === 0 ? 'auto' : channel}, duration: ${duration}s) and analyze:
1. All WiFi clients detected with their MAC addresses and vendors
2. Which access points they are connected to
3. Signal strength analysis
4. Any interesting SSIDs being probed by devices
5. Generate a full HTML report`
      }
    }]
  })
);

// Start the server
server.connect(new StdioServerTransport())
  .then(() => console.error('WireMCP Server is running...'))
  .catch(err => {
    console.error('Failed to start WireMCP:', err);
    process.exit(1);
  });