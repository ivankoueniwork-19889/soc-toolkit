"""
Tool:       IOC Extractor
Author:     Ivan Koueni
Purpose:    Analyzes authentication logs to identify brute force attacks,
            suspicious external IPs, and targeted user accounts.
            Outputs a structured JSON report for incident documentation.
MITRE:      T1110 - Brute Force | T1078 - Valid Accounts
Usage:      python ioc_extractor.py auth.log
            python ioc_extractor.py          (demo mode)
"""

import re
import json
import sys
from datetime import datetime
from collections import Counter

# Built-in demo data — used when no log file is provided
login_events = """
    Failed login from 198.51.100.45 for user admin
    Failed login from 198.51.100.45 for user root
    Failed login from 10.0.0.5 for user admin
    Accepted login from 203.0.113.99 for user jsmith
    System error on host 192.168.1.1
"""

def load_log(filepath):
    """
    Reads a log file from disk and returns its contents as a string.
    Falls back to built-in demo data if the file is not found,
    allowing the tool to run in demo mode without a real log file.
    """
    try:
        with open(filepath, 'r') as file:
            return file.read()
    except FileNotFoundError:
        print("[!] File not found — using demo data")
        return login_events

def extract_ips(text):
    """
    Extracts all IPv4 addresses from raw log text using regex.
    Filters out RFC1918 private address ranges (10.x, 192.168.x,
    172.x, 127.x) since internal IPs are not external threat actors.
    Returns a list of external IP addresses only.
    """
    ip_pattern = r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b'
    ips = re.findall(ip_pattern, text)

    # Skip private RFC1918 ranges — internal IPs are not external attackers
    external_ips = [ip for ip in ips if not ip.startswith(("10.","192.168","172.","127."))]
    return external_ips

def extract_users(text):
    """
    Extracts targeted usernames from log entries using a regex
    capture group matching the pattern 'user <username>'.
    Returns a raw list — duplicates intentionally preserved
    so the caller can perform frequency analysis.
    """
    user_pattern = r"user\s(\w+)"
    users = re.findall(user_pattern, text)
    return users

def count_suspicious(ips, threshold):
    """
    Counts IP address frequency and flags IPs exceeding the threshold
    as suspicious brute force candidates.
    Returns a dict of {ip: count} for IPs above the threshold,
    preserving counts as evidence for incident reporting.
    """
    ips_filtered = Counter(ips)
    suspicious = {}
    for key, value in ips_filtered.items():
        # Only flag IPs exceeding threshold — single attempts may be noise
        if value > threshold:
            suspicious[key] = value
    return suspicious


# ── MAIN LOGIC ──────────────────────────────────────────────────────────────

# Load from file if provided, otherwise use demo data for testing
if len(sys.argv) > 1:
    log_data = load_log(sys.argv[1])
else:
    print("[*] No file provided — using demo data")
    log_data = login_events

# Extract and filter IPs — private ranges excluded automatically
ips = extract_ips(log_data)

# Wrap in Counter to get attack frequency per username
# Most attacked accounts indicate primary targets for the report
users = Counter(extract_users(log_data))

# Threshold=1 flags IPs with MORE than 1 attempt
# Single attempts may be noise — repeated attempts indicate intent
hits = count_suspicious(ips, threshold=1)

# Build structured report — JSON format for SIEM/ticketing integration
report = {
    "timestamp":             datetime.now().isoformat(),
    "suspicious_ips":        hits,
    "targeted_users":        users,
    "total_events_analyzed": len(log_data.strip().splitlines()),
    "recommendations":       [f"Block {hit} at perimeter firewall" for hit in hits]
}

# Write report to disk — overwrites previous run
with open("ioc_report.json", "w") as file:
    json.dump(report, file, indent=2)

print("[+] Report saved: ioc_report.json")