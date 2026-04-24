#!/bin/bash
# ════════════════════════════════════════════════════════════
# Tool:     Linux Host Triage Script
# Author:   Ivan Koueni
# Purpose:  Automated evidence collection for incident response
#           Captures volatile data before it disappears —
#           processes, network connections, file indicators,
#           and persistence mechanisms.
# MITRE:    T1057, T1049, T1083, T1053, T1547
# Usage:    bash linux_triage.sh
# Output:   /tmp/triage_HOSTNAME_DATE/
# ════════════════════════════════════════════════════════════
 
# ── SECTION 1: SETUP ────────────────────────────────────────
# Timestamped output folder — hostname + date prevents collisions
# between multiple triage runs on the same system
OUTPUT="/tmp/triage_$(hostname)_$(date +%Y%m%d_%H%M)"
mkdir -p "$OUTPUT"
 
# Print triage header — timestamp captured for chain of custody
echo "[*] Starting triage on: $(hostname)"
echo "[*] Date/Time: $(date '+%Y-%m-%d %H:%M:%S')"
echo "[*] Analyst: $(whoami)"
echo "[*] Output: $OUTPUT"
echo "================================================="
 
# ── SECTION 2: IDENTITY ─────────────────────────────────────
# Capture who is running this triage and on which machine
# Critical for chain of custody documentation
# MITRE: T1033 - System Owner/User Discovery
echo "[*] Collecting identity information..."
echo "=== IDENTITY ===" | tee "$OUTPUT/identity.txt"
 
# Current user — root = full compromise, other = limited access
whoami | tee -a "$OUTPUT/identity.txt"
 
# Machine hostname — tags all evidence to this specific system
hostname | tee -a "$OUTPUT/identity.txt"
 
# User groups — reveals privilege level and group memberships
id | tee -a "$OUTPUT/identity.txt"
 
# Timestamp — documents exact collection time for evidence
date '+%Y-%m-%d %H:%M:%S' | tee -a "$OUTPUT/identity.txt"
 
echo "[+] Identity saved to $OUTPUT/identity.txt"
echo "[-] Section 2 complete"
echo ""
 
# ════════════════════════════════════════════════════════════
# SECTION 3: RUNNING PROCESSES
# Purpose:  Capture all running processes — volatile data
#           Parent-child relationships reveal malware hiding
#           inside legitimate processes
# MITRE:    T1057 - Process Discovery
#           T1059 - Command and Scripting Interpreter
# ════════════════════════════════════════════════════════════
echo "[*] Collecting running processes..."
 
# ── 3.1 FULL PROCESS LIST ───────────────────────────────────
# All users, all details — complete snapshot of system activity
echo "=== RUNNING PROCESSES ===" | tee "$OUTPUT/processes.txt"
ps aux 2>/dev/null | tee -a "$OUTPUT/processes.txt"
 
# ── 3.2 PROCESS TREE ────────────────────────────────────────
# Parent-child relationships — malware often hides as child
# of legitimate process (e.g. apache2 spawning bash = web shell)
echo "=== PROCESS TREE ===" | tee -a "$OUTPUT/processes.txt"
ps auxf 2>/dev/null | tee -a "$OUTPUT/processes.txt"
 
echo "[+] Processes saved to $OUTPUT/processes.txt"
echo "[-] Section 3 complete"
echo ""
 
# ════════════════════════════════════════════════════════════
# SECTION 4: NETWORK CONNECTIONS
# Purpose:  Capture all network connections — volatile data
#           Established connections to unknown IPs = possible C2
#           Unexpected listeners = possible backdoor
# MITRE:    T1049 - System Network Connections Discovery
#           T1071 - Application Layer Protocol (C2)
# ════════════════════════════════════════════════════════════
echo "[*] Collecting network connections..."
 
# ── 4.1 ALL CONNECTIONS ─────────────────────────────────────
# Full picture — TCP and UDP, all states, all processes
echo "=== NETWORK CONNECTIONS ===" | tee "$OUTPUT/network.txt"
netstat -ano 2>/dev/null | tee -a "$OUTPUT/network.txt"
 
# ── 4.2 ESTABLISHED ONLY ────────────────────────────────────
# Active communications right now — focus of C2 investigation
echo "=== ESTABLISHED CONNECTIONS ===" | tee -a "$OUTPUT/network.txt"
netstat -ano 2>/dev/null | grep ESTABLISHED | tee -a "$OUTPUT/network.txt"
 
# ── 4.3 SUSPICIOUS PORT CHECK ───────────────────────────────
# Known malicious ports — immediate red flag if any match found
# 4444=Metasploit, 31337=Back Orifice, 1337=common backdoor
echo "=== SUSPICIOUS PORTS CHECK ===" | tee -a "$OUTPUT/network.txt"
netstat -ano 2>/dev/null | grep -E ":4444|:31337|:1337|:8888|:9999" | tee -a "$OUTPUT/network.txt"
 
echo "[+] Network data saved to $OUTPUT/network.txt"
echo "[-] Section 4 complete"
echo ""
 
# ════════════════════════════════════════════════════════════
# SECTION 5: FILE SYSTEM INDICATORS
# Purpose:  Identify recently modified files and executables
#           in suspicious locations — common malware staging.
#           Attacker-dropped files appear in world-writable dirs.
# MITRE:    T1083 - File and Directory Discovery
#           T1074 - Data Staged in Local System
# ════════════════════════════════════════════════════════════
echo "[*] Collecting file system indicators..."
 
# ── 5.1 RECENTLY MODIFIED FILES IN /TMP ─────────────────────
# /tmp is world-writable — primary malware staging location
# Any executable here is suspicious and should be hashed
echo "=== RECENTLY MODIFIED FILES IN /TMP (24hrs) ===" | tee "$OUTPUT/files.txt"
find /tmp -mtime -1 -type f 2>/dev/null | tee -a "$OUTPUT/files.txt"
 
# ── 5.2 EXECUTABLES IN SUSPICIOUS LOCATIONS ─────────────────
# Legitimate software never executes from /tmp, /var/tmp, /dev/shm
# Any executable found here warrants immediate investigation
echo "=== EXECUTABLES IN SUSPICIOUS LOCATIONS ===" | tee -a "$OUTPUT/files.txt"
find /tmp /var/tmp /dev/shm -type f -executable 2>/dev/null | tee -a "$OUTPUT/files.txt"
 
# ── 5.3 RECENTLY MODIFIED SYSTEM BINARIES ───────────────────
# Attackers replace legitimate binaries with trojaned versions
# Any modification without a known patch event is suspicious
echo "=== RECENTLY MODIFIED SYSTEM BINARIES ===" | tee -a "$OUTPUT/files.txt"
find /bin /usr/bin -mtime -7 -type f 2>/dev/null | tee -a "$OUTPUT/files.txt"
 
echo "[+] File system indicators saved to $OUTPUT/files.txt"
echo "[-] Section 5 complete"
echo ""
 
# ════════════════════════════════════════════════════════════
# SECTION 6: PERSISTENCE MECHANISMS
# Purpose:  Detect attacker-installed persistence mechanisms
#           that survive reboots and maintain access
# MITRE:    T1053 - Scheduled Task/Job (Cron)
#           T1547 - Boot/Logon Autostart Execution
#           T1098 - Account Manipulation (SSH Keys)
# NOTE:     Some commands require real Linux — unavailable on
#           Windows/Git Bash. Script handles both gracefully.
# ════════════════════════════════════════════════════════════
echo "[*] Collecting persistence indicators..."
 
# ── 6.1 CRON JOBS ───────────────────────────────────────────
# Attackers add cron jobs for persistent code execution
# Survive reboots — check all users not just current user
echo "=== CRON JOBS ===" | tee "$OUTPUT/persistence.txt"
crontab -l 2>/dev/null | tee -a "$OUTPUT/persistence.txt" || \
    echo "[!] crontab not available — run on real Linux for full results" | tee -a "$OUTPUT/persistence.txt"
 
# ── 6.2 SYSTEM CRONTAB ──────────────────────────────────────
# System-wide scheduled tasks — requires root to modify
# Any unknown entries warrant immediate investigation
echo "=== SYSTEM CRONTAB ===" | tee -a "$OUTPUT/persistence.txt"
cat /etc/crontab 2>/dev/null | tee -a "$OUTPUT/persistence.txt" || \
    echo "[!] /etc/crontab not found — Windows/Git Bash environment" | tee -a "$OUTPUT/persistence.txt"
 
# ── 6.3 STARTUP SERVICES ────────────────────────────────────
# Services configured to start at boot
# Malware registers as a service for persistent execution
echo "=== ENABLED STARTUP SERVICES ===" | tee -a "$OUTPUT/persistence.txt"
systemctl list-unit-files --state=enabled 2>/dev/null | tee -a "$OUTPUT/persistence.txt" || \
    echo "[!] systemctl not available — Windows/Git Bash environment" | tee -a "$OUTPUT/persistence.txt"
 
# ── 6.4 SSH AUTHORIZED KEYS ─────────────────────────────────
# SSH keys allow passwordless access — common backdoor method
# Attacker adds their public key for persistent remote access
# Show file path AND contents — key comment reveals attacker identity
echo "=== SSH AUTHORIZED KEYS ===" | tee -a "$OUTPUT/persistence.txt"
find /home /root -name 'authorized_keys' 2>/dev/null | while read keyfile; do
    echo "[!] Found: $keyfile" | tee -a "$OUTPUT/persistence.txt"
    cat "$keyfile" | tee -a "$OUTPUT/persistence.txt"
done
 
echo "[+] Persistence indicators saved to $OUTPUT/persistence.txt"
echo "[-] Section 6 complete"
echo ""
 
# ════════════════════════════════════════════════════════════
# SECTION 7: EVIDENCE ARCHIVING
# Purpose:  Package all collected evidence into a single
#           compressed archive for secure transport to
#           forensic workstation. SHA256 hash verifies
#           integrity — required for chain of custody.
# MITRE:    Supports chain of custody requirements
# ════════════════════════════════════════════════════════════
echo "[*] Archiving all evidence collected..."
 
# ── 7.1 CREATE ARCHIVE ──────────────────────────────────────
# Compress entire output folder into single transportable file
# Filename includes hostname and timestamp for identification
# tar flags: c=create, z=gzip compress, f=filename
ARCHIVE="/tmp/triage_evidence_$(hostname)_$(date +%Y%m%d_%H%M).tar.gz"
tar czf "$ARCHIVE" "$OUTPUT" 2>/dev/null
 
# ── 7.2 VERIFY INTEGRITY ────────────────────────────────────
# SHA256 hash proves archive was not modified during transport
# Analyst at receiving end must verify this hash matches
# This hash becomes part of chain of custody documentation
echo "[+] Archive: $ARCHIVE"
echo "[+] SHA256: $(sha256sum "$ARCHIVE")"
 
# ── 7.3 COMPLETION SUMMARY ──────────────────────────────────
# Final triage summary — confirms all sections completed
# Documents who ran the triage and when for evidence records
echo ""
echo "================================================="
echo "[+] TRIAGE COMPLETE"
echo "[+] Host:     $(hostname)"
echo "[+] Analyst:  $(whoami)"
echo "[+] Finished: $(date '+%Y-%m-%d %H:%M:%S')"
echo "[+] Evidence: $ARCHIVE"
echo "================================================="
echo "[-] linux_triage.sh complete"
 