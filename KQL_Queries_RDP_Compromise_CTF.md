# KQL Query Portfolio
## RDP Compromise Threat Hunt — Josh Madakor Cyber Range CTF
**Analyst:** Kenneth Gates | Gates Cyber Consulting  
**Platform:** Microsoft Sentinel — Log Analytics Workspace (LAW-Cyber-Range)  
**Incident Date:** September 16, 2025  
**Completed:** May 3, 2026  

---

## Environment Discovery

### Table Discovery — Find All Data Sources for Incident Date
```kql
search *
| where TimeGenerated between (datetime(2025-09-14 00:00:00) .. datetime(2025-09-14 23:59:59))
| summarize count() by $table
| order by count_ desc
```
**Purpose:** Identify which tables contain data for the incident timeframe before hunting.  
**Result:** Confirmed DeviceLogonEvents, DeviceProcessEvents, DeviceFileEvents, DeviceNetworkEvents, DeviceRegistryEvents, DeviceEvents all populated.

---

## Flag 1 — Attacker IP Address
**MITRE:** T1110.001 – Brute Force: Password Guessing  
**Answer:** `159.26.106.84`

```kql
// Initial_Access_RDP_Attacker_IP
DeviceLogonEvents
| where TimeGenerated > todatetime('2025-09-14T00:00:00.0000000Z')
| where DeviceName contains "flare"
| where RemoteIP !in ("","–")
| order by TimeGenerated asc
```
**What to look for:** An IP with multiple `LogonFailed` ActionType rows followed by a `LogonSuccess` row — that's the password spray pattern.

---

## Flag 2 — Compromised Account
**MITRE:** T1078 – Valid Accounts  
**Answer:** `slflare`

```kql
// Initial_Access_Compromised_Account
DeviceLogonEvents
| where TimeGenerated > todatetime('2025-09-16T18:00:00.0000000Z')
| where DeviceName contains "flare"
| where ActionType == "LogonSuccess"
| where LogonType == "RemoteInteractive"
| where RemoteIP == "159.26.106.84"
| project TimeGenerated, DeviceName, AccountName, RemoteIP, ActionType
| order by TimeGenerated asc
```
**What to look for:** The AccountName tied to the first successful logon from the attacker IP.

---

## Flag 3 — Executed Binary Name
**MITRE:** T1204.002 – User Execution: Malicious File  
**Answer:** `msupdate.exe`

```kql
// Execution_Malicious_Binary
DeviceProcessEvents
| where TimeGenerated > todatetime('2025-09-16T18:40:00.0000000Z')
| where DeviceName contains "flare"
| where AccountName == "slflare"
| where FolderPath contains "Public"
    or FolderPath contains "Temp"
    or FolderPath contains "Downloads"
| project TimeGenerated, AccountName, FileName, FolderPath, ProcessCommandLine
| order by TimeGenerated asc
```
**What to look for:** Executables launched from non-standard paths (Public, Temp, Downloads) shortly after the RDP compromise. Red flag: fake Microsoft utility names.

---

## Flag 4 — Full Command Line Used to Execute Binary
**MITRE:** T1059 – Command and Scripting Interpreter  
**Answer:** `"msupdate.exe" -ExecutionPolicy Bypass -File C:\Users\Public\update_check.ps1`

```kql
// Execution_Malicious_Binary_CommandLine
DeviceProcessEvents
| where TimeGenerated > todatetime('2025-09-16T18:40:00.0000000Z')
| where DeviceName contains "flare"
| where AccountName == "slflare"
| where FileName == "msupdate.exe"
| project TimeGenerated, AccountName, FileName, FolderPath, ProcessCommandLine
```
**What to look for:** `-ExecutionPolicy Bypass` is a classic indicator of malicious PowerShell execution. The `-File` parameter reveals the actual payload script.

---

## Flag 5 — Persistence Mechanism (Scheduled Task)
**MITRE:** T1053.005 – Scheduled Task/Job  
**Answer:** `MicrosoftUpdateSync`

```kql
// Persistence_ScheduledTask_DeviceEvents
DeviceEvents
| where TimeGenerated > todatetime('2025-09-16T19:00:00.0000000Z')
| where TimeGenerated < todatetime('2025-09-18T00:00:00.0000000Z')
| where DeviceName contains "flare"
| where ActionType == "ScheduledTaskCreated"
| project TimeGenerated, ActionType, AdditionalFields, InitiatingProcessCommandLine
| order by TimeGenerated asc
```
**What to look for:** `ActionType == "ScheduledTaskCreated"` in DeviceEvents captures the exact task name in the `AdditionalFields` JSON. Look for tasks created immediately after execution — timing correlation is key.

**Supporting query — schtasks.exe command line:**
```kql
// Persistence_Schtasks_Commands
DeviceProcessEvents
| where TimeGenerated > todatetime('2025-09-16T18:40:00.0000000Z')
| where DeviceName contains "flare"
| where FileName == "schtasks.exe"
| where ProcessCommandLine contains "/create"
| project TimeGenerated, ProcessCommandLine
| order by TimeGenerated asc
```

---

## Flag 6 — Defender Exclusion Path Added
**MITRE:** T1562.001 – Impair Defenses: Disable or Modify Windows Defender  
**Answer:** `C:\Windows\Temp`

```kql
// DefenseEvasion_AddMpPreference_Commands
DeviceProcessEvents
| where TimeGenerated > todatetime('2025-09-16T19:00:00.0000000Z')
| where TimeGenerated < todatetime('2025-09-28T00:00:00.0000000Z')
| where DeviceName contains "flare"
| where ProcessCommandLine contains "MpPreference"
    or ProcessCommandLine contains "ExclusionPath"
    or ProcessCommandLine contains "Add-Mp"
| project TimeGenerated, FileName, ProcessCommandLine
| order by TimeGenerated asc
```
**What to look for:** `Add-MpPreference -ExclusionPath` reveals the excluded path. `Set-MpPreference -DisableRealtimeMonitoring $true` disables real-time scanning entirely.

**Supporting query — Registry exclusion validation:**
```kql
// DefenseEvasion_Defender_Registry_Exclusions
DeviceRegistryEvents
| where TimeGenerated > todatetime('2025-09-16T19:00:00.0000000Z')
| where DeviceName contains "flare"
| where RegistryKey contains "Defender"
| where RegistryKey contains "Exclusion"
| project TimeGenerated, ActionType, RegistryKey, RegistryValueName, RegistryValueData
| order by TimeGenerated asc
```

---

## Flag 7 — Discovery Command
**MITRE:** T1082 – System Information Discovery  
**Answer:** `"cmd.exe" /c systeminfo`

```kql
// Discovery_System_Enumeration
DeviceProcessEvents
| where TimeGenerated > todatetime('2025-09-16T19:30:00.0000000Z')
| where DeviceName contains "flare"
| where AccountName == "slflare"
| where FileName in ("whoami.exe", "ipconfig.exe", "systeminfo.exe", "net.exe",
    "netstat.exe", "hostname.exe", "query.exe", "tasklist.exe", "arp.exe", "WMIC.exe")
    or ProcessCommandLine contains "whoami"
    or ProcessCommandLine contains "ipconfig"
    or ProcessCommandLine contains "systeminfo"
    or ProcessCommandLine contains "net user"
    or ProcessCommandLine contains "netstat"
| project TimeGenerated, AccountName, FileName, FolderPath, ProcessCommandLine
| order by TimeGenerated asc
```
**What to look for:** Built-in Windows tools used in rapid succession indicate systematic host enumeration. The `InitiatingProcessCommandLine` column shows the parent — if it's `powershell.exe`, a script is automating the recon.

**Full enumeration commands observed:**
- `"cmd.exe" /c systeminfo`
- `"cmd.exe" /c "whoami /all"`
- `"cmd.exe" /c "net user"`
- `"cmd.exe" /c "net localgroup administrators"`
- `"cmd.exe" /c "ipconfig /all"`
- `"cmd.exe" /c "netstat -ano"`
- `"cmd.exe" /c "tasklist /svc"`
- `"cmd.exe" /c "query user"`

---

## Flag 8 — Archive File Created
**MITRE:** T1560.001 – Archive Collected Data: Local Archiving  
**Answer:** `backup_sync.zip`

```kql
// Collection_Archive_File
DeviceFileEvents
| where TimeGenerated > todatetime('2025-09-16T19:00:00.0000000Z')
| where DeviceName contains "flare"
| where FileName endswith ".zip"
    or FileName endswith ".rar"
    or FileName endswith ".7z"
| project TimeGenerated, ActionType, FileName, FolderPath, InitiatingProcessCommandLine
| order by TimeGenerated asc
```
**What to look for:** Archive files created in non-standard user directories (AppData, Public, Temp) by PowerShell or cmd processes. Timing correlation with the compromise timeline confirms attacker activity.

---

## Flag 9 — C2 Destination
**MITRE:** T1071.001 – Application Layer Protocol: Web Protocols  
**Answer:** `185.92.220.87`

```kql
// C2_Outbound_Connection
DeviceNetworkEvents
| where TimeGenerated > todatetime('2025-09-16T19:38:00.0000000Z')
| where TimeGenerated < todatetime('2025-09-17T00:00:00.0000000Z')
| where DeviceName contains "flare"
| where InitiatingProcessAccountName == "slflare"
| where RemoteIPType == "Public"
| project TimeGenerated, InitiatingProcessFileName, InitiatingProcessCommandLine, RemoteIP, RemoteUrl, RemotePort
| order by TimeGenerated asc
```
**What to look for:** Outbound connections from attacker-dropped binaries (msupdate.exe, powershell.exe) to public IPs shortly after execution. Multiple processes connecting to the same IP confirms C2 infrastructure.

---

## Flag 10 — Exfiltration IP and Port
**MITRE:** T1048.003 – Exfiltration Over Unencrypted Protocol  
**Answer:** `185.92.220.87:8081`

```kql
// Exfiltration_Curl_Command
DeviceNetworkEvents
| where TimeGenerated > todatetime('2025-09-16T19:41:00.0000000Z')
| where DeviceName contains "flare"
| where InitiatingProcessFileName == "curl.exe"
| project TimeGenerated, InitiatingProcessCommandLine, RemoteIP, RemotePort, RemoteUrl
| order by TimeGenerated asc
```
**What to look for:** `curl.exe` used with `-X POST -F "file=@..."` pattern is a direct exfiltration indicator. The `RemotePort` column reveals the non-standard port used to evade port-based firewall rules.

---

## Bonus Queries

### Full Attack Chain Overview
```kql
// Full_Attack_Timeline_Overview
let attackerAccount = "slflare";
let startTime = todatetime('2025-09-16T18:30:00.0000000Z');
DeviceProcessEvents
| where TimeGenerated > startTime
| where DeviceName contains "flare"
| where AccountName == attackerAccount
| project TimeGenerated, FileName, ProcessCommandLine
| order by TimeGenerated asc
| take 100
```

### Files Dropped by Attacker
```kql
// Files_Dropped_In_Public_Folder
DeviceFileEvents
| where TimeGenerated > todatetime('2025-09-16T18:00:00.0000000Z')
| where DeviceName contains "flare"
| where FolderPath contains "Public"
    or FolderPath contains "Temp"
| where ActionType == "FileCreated"
| project TimeGenerated, ActionType, FileName, FolderPath, InitiatingProcessCommandLine
| order by TimeGenerated asc
```

### All Scheduled Tasks Created by Attacker
```kql
// All_Attacker_Scheduled_Tasks
DeviceEvents
| where TimeGenerated > todatetime('2025-09-16T19:00:00.0000000Z')
| where DeviceName contains "flare"
| where ActionType == "ScheduledTaskCreated"
| extend TaskName = tostring(parse_json(AdditionalFields).TaskName)
| project TimeGenerated, TaskName, InitiatingProcessCommandLine
| order by TimeGenerated asc
```

### All Outbound C2 Traffic
```kql
// All_C2_Traffic_To_Attacker_Server
DeviceNetworkEvents
| where TimeGenerated > todatetime('2025-09-16T19:00:00.0000000Z')
| where DeviceName contains "flare"
| where RemoteIP == "185.92.220.87"
| project TimeGenerated, InitiatingProcessFileName, InitiatingProcessCommandLine, RemoteIP, RemotePort
| order by TimeGenerated asc
```

---

## Key Lessons Learned

1. **Start broad, narrow down** — Use `search *` to discover available tables before filtering
2. **DeviceEvents for scheduled tasks** — `ActionType == "ScheduledTaskCreated"` is more reliable than registry or process queries
3. **UTC timezone matters** — Incident date was Sept 16 in logs despite Sept 14 stated date (timezone offset)
4. **Correlation is everything** — Link events by AccountName, timestamp proximity, and FolderPath
5. **Public folder is a red flag** — Attackers use `C:\Users\Public\` because it's world-writable
6. **curl for exfil** — `-X POST -F "file=@..."` pattern is a reliable exfiltration indicator
7. **Fake Microsoft names** — msupdate.exe, MicrosoftUpdateSync, WindowsDefenderUpdate all designed to blend in

---

*Kenneth Gates | GitHub: KennethGates | Josh Madakor Cyber Range CTF | May 2026*
