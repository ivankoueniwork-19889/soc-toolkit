# 🔍 Linux Host Triage — SOC Analyst Tool

**Author:** Ivan Koueni
**Lab:** CySA+ Lab 1C — Threat Detection & Log Analysis
**MITRE ATT&CK:** T1057, T1049, T1083, T1053, T1547, T1098

---

## 📋 Overview

A bash-based automated triage tool for SOC analysts responding to
Linux host incidents. Captures volatile evidence in the correct order
of volatility — processes and network connections before disk artifacts.
Packages all findings into a timestamped, SHA256-verified archive for
secure transport to a forensic workstation.

---

## 🎯 What It Does

- Captures system identity and timestamps for chain of custody
- Collects running processes and process tree relationships
- Records all network connections and flags suspicious ports
- Finds recently modified files and executables in suspicious locations
- Checks persistence mechanisms — cron, services, SSH keys
- Archives all evidence with SHA256 integrity verification

---

## 🛠️ Requirements

```bash
bash        ← any Linux system or Git Bash on Windows
netstat     ← net-tools package
find        ← coreutils (default on all Linux)
sha256sum   ← coreutils (default on all Linux)
```

No external dependencies — runs on any Linux system.

---

## 🚀 Usage

**Run triage on a live Linux system:**
```bash
bash linux_triage.sh
```

**Run as root for complete evidence collection:**
```bash
sudo bash linux_triage.sh
```

**Evidence is saved to:**
```
/tmp/triage_HOSTNAME_YYYYMMDD_HHMM/
    identity.txt        ← user, hostname, groups, timestamp
    processes.txt       ← running processes + process tree
    network.txt         ← all connections, established, suspicious ports
    files.txt           ← recently modified files and executables
    persistence.txt     ← cron jobs, services, SSH keys
```

**Archive is saved to:**
```
/tmp/triage_evidence_HOSTNAME_YYYYMMDD_HHMM.tar.gz
```

---

## 📊 Sample Output

```
[*] Starting triage on: PROD-WEB-01
[*] Date/Time: 2026-04-24 10:52:05
[*] Analyst: ivank
[*] Output: /tmp/triage_PROD-WEB-01_20260424_1052
=================================================
[*] Collecting identity information...
=== IDENTITY ===
www-data
PROD-WEB-01
uid=33(www-data) gid=33(www-data) groups=33(www-data)
[+] Identity saved to /tmp/triage_PROD-WEB-01_20260424_1052/identity.txt
[-] Section 2 complete

[*] Collecting running processes...
[*] Collecting network connections...
=== SUSPICIOUS PORTS CHECK ===
TCP  0.0.0.0:4444  LISTENING  PID 3892   ← [!] BACKDOOR DETECTED
[*] Collecting file system indicators...
[*] Collecting persistence indicators...
[*] Archiving all evidence collected...
[+] Archive: /tmp/triage_evidence_PROD-WEB-01_20260424_1052.tar.gz
[+] SHA256: aa9e2ee248834812...
=================================================
[+] TRIAGE COMPLETE
[+] Host:     PROD-WEB-01
[+] Analyst:  ivank
[+] Finished: 2026-04-24 10:52:08
[+] Evidence: /tmp/triage_evidence_PROD-WEB-01_20260424_1052.tar.gz
=================================================
```

---

## 🏗️ Script Architecture

```
Section 1 — Setup
    Creates timestamped output folder
    Prints triage header for chain of custody

Section 2 — Identity          T1033
    whoami, hostname, id, date

Section 3 — Running Processes  T1057, T1059
    ps aux (all processes)
    ps auxf (process tree — reveals malware hiding in legit processes)

Section 4 — Network            T1049, T1071
    All connections (netstat -ano)
    Established connections only
    Suspicious port check (4444, 31337, 1337, 8888, 9999)

Section 5 — File System        T1083, T1074
    Recently modified files in /tmp (24 hours)
    Executables in suspicious locations (/tmp, /var/tmp, /dev/shm)
    Recently modified system binaries (7 days)

Section 6 — Persistence        T1053, T1547, T1098
    Cron jobs (user + system)
    Enabled startup services
    SSH authorized keys (path + contents)

Section 7 — Archive
    tar.gz of all evidence
    SHA256 hash for integrity verification
```

---

## 🔐 Security Concepts Demonstrated

| Concept | Implementation |
|---------|---------------|
| Order of volatility | Processes captured before disk artifacts |
| Chain of custody | Timestamped folders, SHA256 archive hash |
| Persistence detection | Cron, systemctl, SSH key inspection |
| Backdoor detection | Suspicious port check (4444, 31337) |
| Malware staging | Executable detection in /tmp, /var/tmp |
| Binary tampering | Recently modified system binary check |

---

## 📁 Files

| File | Description |
|------|-------------|
| `linux_triage.sh` | Main triage script |

---

## 🧠 CySA+ Exam Relevance

| Command | Exam Objective |
|---------|---------------|
| `ps auxf` | Process discovery — T1057 |
| `netstat -ano` | Network connection discovery — T1049 |
| `find /tmp -mtime -1` | File system investigation — T1083 |
| `crontab -l` | Persistence via cron — T1053 |
| `authorized_keys` | SSH backdoor detection — T1098 |

---

## ⚠️ Platform Notes

Some commands require real Linux and are not available on
Windows/Git Bash:
- `crontab` — requires Linux cron daemon
- `/etc/crontab` — Linux only
- `systemctl` — requires systemd
- `/home/*/authorized_keys` — Linux file structure

Script handles both environments gracefully with fallback messages.

---

## 🗺️ Part of CySA+ Portfolio Series

- ✅ Lab 1B — IOC Extractor (Python)
- ✅ Lab 1C — Linux Host Triage (Bash) ← You are here
- ✅ Lab 2B — Network Forensics (Python)
- ✅ Lab 3B — Malware Analyzer (Python)
- 🔲 Lab 1D — Persistence Hunter (PowerShell)
