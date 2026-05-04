# Threat Hunt: RDP Compromise
**Platform:** Microsoft Sentinel | Log Analytics Workspace  
**Tools:** KQL, Microsoft Defender for Endpoint  
**Date:** September 2025 (Investigated May 2026)  
**Source:** Josh Madakor Cyber Range CTF — 10/10 Flags  

## Scenario
A cloud-hosted Windows server was compromised via RDP password spray. 
This repo documents the full investigation from initial access through 
exfiltration using KQL queries in Microsoft Sentinel.

## Attack Chain (MITRE ATT&CK)
| Stage | Technique | Finding |
|-------|-----------|---------|
| Initial Access | T1110.001 | RDP brute force from 159.26.106.84 |
| Valid Accounts | T1078 | Account: slflare |
| Execution | T1204.002 | msupdate.exe from C:\Users\Public\ |
| Persistence | T1053.005 | Scheduled task: MicrosoftUpdateSync |
| Defense Evasion | T1562.001 | Defender exclusion: C:\Windows\Temp |
| Discovery | T1082 | systeminfo, whoami, ipconfig, netstat |
| Collection | T1560.001 | backup_sync.zip |
| C2 | T1071.001 | 185.92.220.87 |
| Exfiltration | T1048.003 | 185.92.220.87:8081 via curl |

## Files
- [`KQL_Queries_RDP_Compromise_CTF.md`](./KQL_Queries_RDP_Compromise_CTF.md) — All hunting queries with explanations
- [`SOC_Investigation_Report_RDP_Compromise.docx`](./SOC_Investigation_Report_RDP_Compromise.docx) — Full SOC investigation report

## Skills Demonstrated
- KQL threat hunting in Microsoft Sentinel
- MITRE ATT&CK technique mapping
- Incident timeline reconstruction
- IOC identification and documentation
- SOC investigation methodology
