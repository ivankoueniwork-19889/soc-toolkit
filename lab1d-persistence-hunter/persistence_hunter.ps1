# ════════════════════════════════════════════════════════════
# Tool:     Windows Persistence Hunter
# Author:   Ivan Koueni
# Purpose:  Hunts for malware persistence mechanisms across
#           registry, scheduled tasks, startup folders,
#           WMI subscriptions, and suspicious services.
#           Evidence saved to timestamped folder with SHA256
#           verified archive for chain of custody.
# MITRE:    T1547 - Boot/Logon Autostart Execution
#           T1053 - Scheduled Task/Job
#           T1546 - WMI Event Subscription
#           T1543 - Create or Modify System Process
# Usage:    powershell -ExecutionPolicy Bypass -File persistence_hunter.ps1
# Output:   C:\IR\persistence_HOSTNAME_DATE\
# ════════════════════════════════════════════════════════════

# ── SECTION 1: SETUP ────────────────────────────────────────
$Date=   Get-Date -Format 'yyyyMMdd_HHmm'
$Output= "C:\IR\persistence_$($env:COMPUTERNAME)_$Date"
New-Item -Path $Output -ItemType Directory -Force | Out-Null
Write-Host "[*] Persistence Hunter starting on: $($env:COMPUTERNAME)" -ForegroundColor Cyan
Write-Host "[*] Date/Time: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"  -ForegroundColor Cyan
Write-Host "[*] Analyst:   $($env:USERNAME)"                           -ForegroundColor Cyan
Write-Host "[*] Output:    $Output"                                     -ForegroundColor Cyan
Write-Host "================================================="

# ════════════════════════════════════════════════════════════
# SECTION 2: REGISTRY AUTORUN KEYS
# MITRE: T1547.001
# ════════════════════════════════════════════════════════════
Write-Host "[*] Hunting registry autorun keys..." -ForegroundColor Cyan
$RunKeys = @(
    "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run",
    "HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce",
    "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run",
    "HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce"
)
$RegistryResults = foreach ($Key in $RunKeys) {
    if (Test-Path $Key) {
        $Properties = Get-ItemProperty $Key -ErrorAction SilentlyContinue
        if ($Properties) {
            $Properties | Get-Member -MemberType NoteProperty |
            Where-Object { $_.Name -notlike "PS*" } |
            ForEach-Object {
                [PSCustomObject]@{ KeyPath = $Key; Name = $_.Name; Value = $Properties.($_.Name) }
            }
        }
    }
}
if ($RegistryResults) {
    $RegistryResults | Export-Csv "$Output\registry.csv" -NoTypeInformation
    Write-Host "[+] Found $($RegistryResults.Count) autorun entries" -ForegroundColor Yellow
} else { Write-Host "[+] No registry autorun entries found" -ForegroundColor Green }
Write-Host "[-] Section 2 complete`n"

# ════════════════════════════════════════════════════════════
# SECTION 3: SCHEDULED TASKS
# MITRE: T1053.005
# ════════════════════════════════════════════════════════════
Write-Host "[*] Hunting scheduled tasks..." -ForegroundColor Cyan
$Tasks = Get-ScheduledTask | Where-Object { $_.TaskPath -notlike '\Microsoft\*' }
$TaskResults = foreach ($Task in $Tasks) {
    $Action = $Task.Actions | Select-Object -First 1
    [PSCustomObject]@{ TaskName = $Task.TaskName; TaskPath = $Task.TaskPath; State = $Task.State; Execute = $Action.Execute; Arguments = $Action.Arguments }
}
$TaskResults | Format-Table -AutoSize
if ($TaskResults) {
    $TaskResults | Export-Csv "$Output\scheduled_tasks.csv" -NoTypeInformation
    Write-Host "[+] Found $($TaskResults.Count) non-Microsoft tasks" -ForegroundColor Yellow
} else { Write-Host "[+] No suspicious scheduled tasks found" -ForegroundColor Green }
Write-Host "[-] Section 3 complete`n"

# ════════════════════════════════════════════════════════════
# SECTION 4: STARTUP FOLDERS
# MITRE: T1547.001
# ════════════════════════════════════════════════════════════
Write-Host "[*] Hunting startup folder entries..." -ForegroundColor Cyan
$StartupPaths = @(
    "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup",
    "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\Startup"
)
$StartupResults = foreach ($Path in $StartupPaths) {
    Write-Host "`n=== $Path ===" -ForegroundColor Cyan
    if (Test-Path $Path) {
        Get-ChildItem -Path $Path -ErrorAction SilentlyContinue | ForEach-Object {
            [PSCustomObject]@{ FolderPath = $Path; Name = $_.Name; FullPath = $_.FullName; Extension = $_.Extension; LastWriteTime = $_.LastWriteTime; SizeBytes = $_.Length }
        }
    } else { Write-Host "  [!] Path not found: $Path" -ForegroundColor Yellow }
}
if ($StartupResults) {
    $StartupResults | Export-Csv "$Output\startup_folders.csv" -NoTypeInformation
    Write-Host "[+] Found $($StartupResults.Count) startup entries" -ForegroundColor Yellow
} else { Write-Host "[+] Startup folders empty" -ForegroundColor Green }
Write-Host "[-] Section 4 complete`n"

# ════════════════════════════════════════════════════════════
# SECTION 5: WMI EVENT SUBSCRIPTIONS
# MITRE: T1546.003
# ════════════════════════════════════════════════════════════
Write-Host "[*] Hunting WMI event subscriptions..." -ForegroundColor Cyan
$WMI_Classes = @("__EventFilter","__EventConsumer","__FilterToConsumerBinding")
$WMIResults = foreach ($Class in $WMI_Classes) {
    Write-Host "`n=== $Class ===" -ForegroundColor Cyan
    $Entries = Get-WMIObject -Namespace "root\subscription" -Class $Class -ErrorAction SilentlyContinue
    if ($Entries) {
        foreach ($Entry in $Entries) {
            [PSCustomObject]@{ WMIClass = $Class; Name = $Entry.Name; Details = $Entry | Select-Object * | Out-String }
        }
    } else { Write-Host "  [+] No entries in $Class" -ForegroundColor Green }
}
if ($WMIResults) {
    $WMIResults | Export-Csv "$Output\wmi_subscriptions.csv" -NoTypeInformation
    Write-Host "[!] WARNING: $($WMIResults.Count) WMI subscriptions found!" -ForegroundColor Red
} else { Write-Host "[+] No WMI subscriptions found" -ForegroundColor Green }
Write-Host "[-] Section 5 complete`n"

# ════════════════════════════════════════════════════════════
# SECTION 6: SUSPICIOUS SERVICES
# MITRE: T1543.003
# ════════════════════════════════════════════════════════════
Write-Host "[*] Hunting suspicious services..." -ForegroundColor Cyan
$Services = Get-WmiObject Win32_Service | Where-Object { $_.PathName -notmatch "Windows|Microsoft" }
$ServiceResults = foreach ($svc in $Services) {
    [PSCustomObject]@{ Name = $svc.Name; DisplayName = $svc.DisplayName; Status = $svc.State; StartType = $svc.StartMode; PathName = $svc.PathName }
}
if ($ServiceResults) {
    $ServiceResults | Export-Csv "$Output\services.csv" -NoTypeInformation
    Write-Host "[!] $($ServiceResults.Count) non-Microsoft services found" -ForegroundColor Yellow
} else { Write-Host "[+] No suspicious services found" -ForegroundColor Green }
Write-Host "[-] Section 6 complete`n"

# ════════════════════════════════════════════════════════════
# SECTION 7: FINAL REPORT AND EVIDENCE ARCHIVE
# ════════════════════════════════════════════════════════════
Write-Host "[*] Building final report and archiving evidence..." -ForegroundColor Cyan
$RegistryCount = if (Test-Path "$Output\registry.csv")         { (Import-Csv "$Output\registry.csv").Count }         else { 0 }
$TaskCount     = if (Test-Path "$Output\scheduled_tasks.csv")  { (Import-Csv "$Output\scheduled_tasks.csv").Count }  else { 0 }
$StartupCount  = if (Test-Path "$Output\startup_folders.csv")  { (Import-Csv "$Output\startup_folders.csv").Count }  else { 0 }
$WMICount      = if (Test-Path "$Output\wmi_subscriptions.csv"){ (Import-Csv "$Output\wmi_subscriptions.csv").Count } else { 0 }
$ServiceCount  = if (Test-Path "$Output\services.csv")         { (Import-Csv "$Output\services.csv").Count }          else { 0 }

$Summary = @"
================================================
PERSISTENCE HUNTER — SUMMARY REPORT
================================================
Host:       $($env:COMPUTERNAME)
Analyst:    $($env:USERNAME)
Date:       $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
Output:     $Output
================================================
FINDINGS:
  Registry Autorun Keys:     $RegistryCount
  Scheduled Tasks:           $TaskCount
  Startup Folder Entries:    $StartupCount
  WMI Subscriptions:         $WMICount
  Suspicious Services:       $ServiceCount
================================================
"@
$Summary | Out-File "$Output\summary.txt"
Write-Host $Summary -ForegroundColor Cyan

$Archive = "C:\IR\persistence_evidence_$($env:COMPUTERNAME)_$Date.zip"
Compress-Archive -Path "$Output\*" -DestinationPath $Archive -Force
$Hash = Get-FileHash -Path $Archive -Algorithm SHA256
Write-Host "[+] Archive:  $Archive"      -ForegroundColor Green
Write-Host "[+] SHA256:   $($Hash.Hash)" -ForegroundColor Green
Write-Host ""
Write-Host "=================================================" -ForegroundColor Cyan
Write-Host "[+] PERSISTENCE HUNT COMPLETE"                     -ForegroundColor Green
Write-Host "[+] Host:     $($env:COMPUTERNAME)"                -ForegroundColor Green
Write-Host "[+] Analyst:  $($env:USERNAME)"                    -ForegroundColor Green
Write-Host "[+] Finished: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor Green
Write-Host "[+] Evidence: $Archive"                            -ForegroundColor Green
Write-Host "=================================================" -ForegroundColor Cyan
Write-Host "[-] persistence_hunter.ps1 complete"              -ForegroundColor Gray