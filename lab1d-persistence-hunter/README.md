# 🔍 Windows Persistence Hunter — SOC Analyst Tool

**Author:** Ivan Koueni
**Lab:** CySA+ Lab 1D — Threat Detection & Persistence Analysis
**MITRE ATT&CK:** T1547, T1053, T1546, T1543

---

## 📋 Overview

A PowerShell-based automated persistence hunting tool for SOC analysts
responding to Windows host incidents. Hunts across five persistence
mechanisms used by malware to survive reboots and maintain access.
Packages all findings into a timestamped SHA256-verified archive for
chain of custody documentation.

---

## 🎯 What It Hunts

- Registry Run keys — most common malware persistence location
- Scheduled tasks — filters out Microsoft built-in tasks
- Startup folders — user and system level
- WMI event subscriptions — advanced stealthy persistence
- Suspicious services — non-Microsoft services with unusual paths

---

## 🛠️ Requirements

```powershell
PowerShell 5.1+   ← built into Windows 10/11
Admin rights      ← required for WMI and service queries
```

No external dependencies — runs on any Windows system.

---

## 🚀 Usage

**Run as Administrator:**
```powershell
powershell -ExecutionPolicy Bypass -File persistence_hunter.ps1
```

**Evidence is saved to:**
```
C:\IR\persistence_HOSTNAME_YYYYMMDD_HHMM\
    registry.csv          ← autorun registry entries
    scheduled_tasks.csv   ← non-Microsoft scheduled tasks
    startup_folders.csv   ← startup folder contents
    wmi_subscriptions.csv ← WMI event subscriptions
    services.csv          ← suspicious services
    summary.txt           ← findings summary report
```

**Archive saved to:**
```
C:\IR\persistence_evidence_HOSTNAME_YYYYMMDD_HHMM.zip
```

---

## 📊 Sample Output

```
[*] Persistence Hunter starting on: WORKSTATION-01
[*] Date/Time: 2026-04-28 10:52:05
[*] Analyst:   ivank
[*] Output:    C:\IR\persistence_WORKSTATION-01_20260428_1052
=================================================
[*] Hunting registry autorun keys...
[+] Found 8 autorun entries
[-] Section 2 complete

[*] Hunting scheduled tasks...
[+] Found 12 non-Microsoft scheduled tasks
[-] Section 3 complete

[*] Hunting startup folder entries...
[+] Startup folders are empty — no entries found
[-] Section 4 complete

[*] Hunting WMI event subscriptions...
[!] WARNING: 2 WMI subscriptions found!
[-] Section 5 complete

[*] Hunting suspicious services...
[!] 5 non-Microsoft services found — review PathName column
[-] Section 6 complete

================================================
PERSISTENCE HUNTER — SUMMARY REPORT
================================================
Host:       WORKSTATION-01
Analyst:    ivank
Date:       2026-04-28 10:52:08
================================================
FINDINGS:
  Registry Autorun Keys:     8
  Scheduled Tasks:           12
  Startup Folder Entries:    0
  WMI Subscriptions:         2
  Suspicious Services:       5
================================================
[+] Archive:  C:\IR\persistence_evidence_WORKSTATION-01_20260428_1052.zip
[+] SHA256:   a1b2c3d4e5f6...
=================================================
[+] PERSISTENCE HUNT COMPLETE
=================================================
```

---

## 🏗️ Script Architecture

```
Section 1 — Setup
    Timestamped output folder
    Chain of custody header

Section 2 — Registry Run Keys          T1547.001
    HKLM and HKCU Run and RunOnce keys
    Excludes PowerShell metadata properties

Section 3 — Scheduled Tasks            T1053.005
    Filters out \Microsoft\* namespace
    Extracts execute path and arguments

Section 4 — Startup Folders            T1547.001
    User startup folder
    System startup folder (all users)

Section 5 — WMI Subscriptions          T1546.003
    __EventFilter
    __EventConsumer
    __FilterToConsumerBinding

Section 6 — Suspicious Services        T1543.003
    Filters out Windows and Microsoft paths
    Flags services in unexpected locations

Section 7 — Archive and Report
    CSV outputs per section
    Human readable summary
    ZIP archive with SHA256 hash
```

---

## 🔐 Security Concepts Demonstrated

| Concept | Implementation |
|---------|---------------|
| Registry persistence | Get-ItemProperty on Run keys |
| Task persistence | Get-ScheduledTask with path filter |
| Startup persistence | Get-ChildItem on startup folders |
| WMI persistence | Get-WMIObject root\subscription |
| Service persistence | Win32_Service PathName analysis |
| Chain of custody | Timestamped folder + SHA256 archive |

---

## 🚩 Red Flags to Look For

| Location | Red Flag |
|----------|---------|
| Registry | Values pointing to %TEMP% or %APPDATA% |
| Tasks | Execute path in user folders not Program Files |
| Startup | Any executable or script files |
| WMI | ANY subscription — rare on clean systems |
| Services | PathName in C:\Users\ or C:\Temp\ |

---

## 📁 Files

| File | Description |
|------|-------------|
| `persistence_hunter.ps1` | Main persistence hunting script |

---

## 🧠 CySA+ Exam Relevance

| Technique | MITRE ID | Detection Method |
|-----------|---------|-----------------|
| Registry Run Keys | T1547.001 | Get-ItemProperty |
| Scheduled Tasks | T1053.005 | Get-ScheduledTask |
| Startup Folder | T1547.001 | Get-ChildItem |
| WMI Subscription | T1546.003 | Get-WMIObject root\subscription |
| Malicious Service | T1543.003 | Win32_Service query |

---

## 🗺️ Part of CySA+ Portfolio Series

- ✅ Lab 1B — IOC Extractor (Python)
- ✅ Lab 1C — Linux Host Triage (Bash)
- ✅ Lab 1D — Persistence Hunter (PowerShell) ← You are here
- ✅ Lab 2B — Network Forensics (Python)
- ✅ Lab 3B — Malware Analyzer (Python)
