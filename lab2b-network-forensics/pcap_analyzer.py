import json
import os
from datetime import datetime
from collections import Counter, defaultdict



def load_packets(filepath):
    """
    Loads packet data from JSON test file.
    In production this would use scapy rdpcap().
    Returns list of packet dicts.
    """
    #Read from file
    with open(filepath,'r') as file:
        packets= json.load(file)
    return packets

def get_connections(packets):
    """
    Counts connections per external destination IP.
    Filters RFC1918 private ranges.
    Returns Counter of {ip: count} sorted by frequency.
    """
    dst= [
        packet["dst"]
        for packet in packets
        if not packet["dst"].startswith(("10.","192.168","172.","127."))]
    return Counter(dst)

def detect_beaconing(packets, threshold=10):
    """
    Detects C2 beaconing by analyzing connection intervals per IP.
    Collects timestamps per destination IP, calculates intervals,
    and flags IPs with low variance (regular timing = possible beacon).
    Threshold is maximum allowed variance in seconds.
    Returns list of suspicious beaconing IPs with stats.
    """
    #Build a dict of {ip: [list of timestamps]}
    timestamps= defaultdict(list)
    beacons=[]
    for ip in packets:
        if not ip["dst"].startswith(("10.","192.168","172.","127.")):
            timestamps[ip["dst"]].append(ip["time"])
    # For each IP with more than 5 timestamps
    for ip, times in timestamps.items():
        
        if len(times) < 5:
            continue
        times.sort()
    #calculate intervals between consecutive timestamps
        intervals= [times[i+1] - times[i] for i in range(len(times)-1)]
    #calculate the average
        avg= sum(intervals) / len(intervals)
        variance= sum((x - avg) **2 for x in intervals)/ len(intervals)
        if variance < threshold and avg > 10:
            beacons.append({
                "ip":       ip,
                "count":    len(times),
                "avg_interval": round(avg, 1),
                "variance": round(variance, 2)
        })
    return beacons

def analyze_dns(packets):
    """
    Analyzes DNS queries for tunneling indicators.
    Flags queries with unusually long subdomain names —
    a common data encoding technique for C2 or exfiltration.
    Returns list of suspicious queries with lengths and source IPs.
    """
    #Filter packets where packet["proto"] == "DNS"
    dns_packets= [packet for packet in packets if packet["proto"] == "DNS" ]
    #For each DNS packet get packet["query"]
    flags=[]
    for packet in dns_packets:
        if len(packet["query"]) > 40:
            flags.append({
                'query': packet["query"] ,
                'length': len(packet["query"]),
                'src': packet["src"] ,
                "verdict": 'DNS_TUNNELING'
        
        })
    return flags





packets= load_packets("captures/test_traffic.json")


def build_report(packets):
    """
    Runs all analysis functions and assembles findings
    into a structured JSON report with timestamp and
    incident ID for evidence documentation.
    """
    report= {}
    connections = get_connections(packets)
    beacons= detect_beaconing(packets, threshold=10)
    dns_findings = analyze_dns(packets)
    report= {
    "incident_id":   f"NET-{datetime.now():%Y%m%d-%H%M}",
    "analyst":       "Ivan Koueni",
    "timestamp":     datetime.now().isoformat(),
    "total_packets": len(packets),
    "connections":   dict(connections),
    "beaconing":     beacons,
    "dns_tunneling": dns_findings,
    "summary": {
        "beaconing_ips":      len(beacons),
        "dns_tunneling_queries": len(dns_findings),
        "top_talker": 	connections.most_common(1)[0]
        }
    }
    return report

report= build_report(packets)
os.makedirs("reports", exist_ok=True)
report_path = f"reports/network_report_{datetime.now():%Y%m%d_%H%M}.json"
with open(report_path, "w") as f:
    json.dump(report, f, indent=2)
