"""
Generates simulated network traffic data for testing pcap_analyzer.py
Creates a JSON file mimicking parsed PCAP data
"""
import json
from datetime import datetime, timedelta
import random

# Simulate packets as dicts
# Real Scapy packets would have same structure
packets = []
base_time = datetime.now()

# Scenario 1 — C2 beaconing every 300 seconds
for i in range(20):
    packets.append({
        "time":     (base_time + timedelta(seconds=i*300)).timestamp(),
        "src":      "192.168.1.50",
        "dst":      "203.0.113.99",
        "dport":    443,
        "proto":    "TCP",
        "length":   random.randint(200, 250)
    })

# Scenario 2 — DNS tunneling (long queries)
dns_queries = [
    "aGVsbG8gd29ybGQgdGhpcyBpcyBhIHRlc3Q.evil-c2.xyz",
    "dGhpcyBpcyBhIGxvbmcgZG5zIHF1ZXJ5IGZv.evil-c2.xyz",
    "normal.google.com",
    "short.com"
]
for q in dns_queries:
    packets.append({
        "time":     base_time.timestamp(),
        "src":      "192.168.1.50",
        "dst":      "8.8.8.8",
        "dport":    53,
        "proto":    "DNS",
        "query":    q,
        "length":   len(q)
    })

# Scenario 3 — Large data exfiltration
for i in range(5):
    packets.append({
        "time":     base_time.timestamp(),
        "src":      "192.168.1.50",
        "dst":      "185.220.101.45",
        "dport":    443,
        "proto":    "TCP",
        "length":   random.randint(50000, 100000)
    })

# Scenario 4 — Normal traffic (noise)
for i in range(50):
    packets.append({
        "time":     base_time.timestamp(),
        "src":      "192.168.1.10",
        "dst":      "8.8.8.8",
        "dport":    443,
        "proto":    "TCP",
        "length":   random.randint(100, 1000)
    })

# Save test data
with open("captures/test_traffic.json", "w") as f:
    json.dump(packets, f, indent=2)

print(f"[+] Generated {len(packets)} test packets")
print(f"[+] Saved to captures/test_traffic.json")