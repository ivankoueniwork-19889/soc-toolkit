# 🌐 Network Forensics Analyzer — SOC Analyst Tool

**Author:** Ivan Koueni
**Lab:** CySA+ Lab 2B — Network Forensics & Packet Analysis
**MITRE ATT&CK:** T1071.001 (Web C2), T1071.004 (DNS C2), T1048 (Exfiltration)

---

## 📋 Overview

A Python-based network traffic analysis tool built for SOC analysts.
Analyzes packet capture data to detect C2 beaconing patterns, DNS tunneling,
and suspicious external connections. Outputs a structured JSON report for
incident documentation and SIEM ingestion.

---

## 🎯 What It Does

- Counts external connections per destination IP — identifies top talkers
- Detects C2 beaconing by analyzing connection interval variance
- Flags DNS tunneling via unusually long subdomain query names
- Filters RFC1918 private ranges — focuses on external threats only
- Generates timestamped JSON report with executive summary

---

## 🛠️ Requirements

```bash
pip install -r requirements.txt
```

---

## 🚀 Usage

**Run against a real capture file:**
```bash
python pcap_analyzer.py captures/traffic.json
```

**Run in demo mode (no file needed):**
```bash
python pcap_analyzer.py
```

**Generate test data:**
```bash
python generate_test_data.py
```

---

## 📊 Sample Output

**Terminal:**
```
[*] No file provided — using demo capture
[*] Loaded 79 packets
[+] Analysis complete
[+] External IPs:       3
[+] Beaconing IPs:      1
[+] DNS tunnel queries: 2
[+] Top talker:         8.8.8.8 (54 connections)
[+] Report saved:       reports/network_report_20260423_1045.json
```

**JSON Report:**
```json
{
  "incident_id": "NET-20260423-1045",
  "analyst": "Ivan Koueni",
  "total_packets": 79,
  "beaconing": [
    {
      "ip": "203.0.113.99",
      "count": 20,
      "avg_interval": 300.0,
      "variance": 0.0,
      "verdict": "BEACONING"
    }
  ],
  "dns_tunneling": [
    {
      "query": "aGVsbG8gd29ybGQ.evil-c2.xyz",
      "length": 47,
      "src": "192.168.1.50",
      "verdict": "DNS_TUNNELING"
    }
  ],
  "summary": {
    "beaconing_candidates": 1,
    "dns_tunnel_queries": 2,
    "threat_indicators": 3
  }
}
```

---

## 🏗️ Code Architecture

```
load_packets(filepath)          — reads JSON capture file
get_connections(packets)        — counts external destination IPs
detect_beaconing(packets)       — variance analysis for C2 timing detection
analyze_dns(packets)            — long query detection for DNS tunneling
build_report(filepath, packets) — assembles all findings into JSON report
```

---

## 🔐 Security Concepts Demonstrated

| Concept | Implementation |
|---------|---------------|
| C2 beaconing detection | Interval variance analysis |
| DNS tunneling detection | Query length threshold |
| Private IP filtering | RFC1918 startswith() check |
| Statistical analysis | Variance calculation without numpy |
| Evidence preservation | Timestamped JSON report |

---

## 📁 Files

| File | Description |
|------|-------------|
| `pcap_analyzer.py` | Main analysis script |
| `generate_test_data.py` | Generates simulated traffic for testing |
| `captures/test_traffic.json` | Sample capture file (generated) |
| `reports/` | JSON reports saved here (gitignored) |

---

## 🗺️ Part of CySA+ Portfolio Series

- ✅ Lab 1B — IOC Extractor (Python)
- ✅ Lab 3B — Malware Analyzer (Python)
- ✅ Lab 2B — Network Forensics (Python) ← You are here
- 🔲 Lab 1C — Linux Host Triage (Bash)
- 🔲 Lab 1D — Persistence Hunter (PowerShell)
