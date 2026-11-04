# Security Incident Investigation Report Template

**Incident Reference**: `INC-FIM-[YEAR]-[NUMBER]`  
**Classification**: `[CRITICAL / HIGH / MEDIUM / LOW]`  
**Date & Time Detected**: `[YYYY-MM-DD HH:MM:SS UTC]`  
**Lead Investigator / Analyst**: `[Analyst Name / Badge]`  
**Host / Asset Impacted**: `[Hostname / IP / Operating System]`  

---

## 1. Executive Summary
*Provide a concise non-technical summary of the security event, the detection trigger, root cause, and current containment status.*

> **Example**: On 2026-11-04 at 16:58 UTC, the Wazuh Host-based IDS alerted on an unauthorized modification to `/etc/passwd` on host `ubuntu-lab-endpoint` (Rule 100010, Level 10). The FIM unified diff revealed a rogue UID 0 user `backdoor_admin` was injected. Active response quarantined the related session, and the unauthorized account was removed within 8 minutes. No data exfiltration was detected.

---

## 2. Detection & Alert Telemetry

| Parameter | Value |
|---|---|
| **Wazuh Rule ID** | `100010` |
| **Rule Description** | `Critical system identity or privilege file modified` |
| **Alert Level** | `10 (High)` |
| **MITRE ATT&CK ID** | `T1098 (Account Manipulation), T1078 (Valid Accounts)` |
| **Monitored File Path** | `/etc/passwd` |
| **Integrity Event Type** | `FILE_MODIFIED` |
| **SHA256 (Prior)** | `a43421811b344a1c8073edb27436f7499aed30fc64b2efac9460b00d4384c4f9` |
| **SHA256 (Current)** | `ac1cbcf32b52b149408bfa01c76de8c2c461885706eb81449a84a77dd35f69af` |

### FIM Cryptographic Content Diff (report_changes)
```diff
--- a/passwd
+++ b/passwd
@@ -4,3 +4,4 @@
 sysadmin:x:1000:1000:SysAdmin,,,:/home/sysadmin:/bin/bash
 www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
+backdoor_admin:x:0:0:Root Backdoor:/root:/bin/bash
```

---

## 3. Whodata & Process Forensics

- **Executing User (Audit UID)**: `UID 0 (root)`
- **Process Executable**: `/usr/bin/python3`
- **Process ID (PID)**: `14820`
- **Parent Process (PPID)**: `14790 (/bin/bash)`
- **Associated Network Connections**: `198.51.100.45:4444 (ESTABLISHED)`

---

## 4. Timeline of Events

| Timestamp (UTC) | Source / Component | Event Description |
|---|---|---|
| `16:55:12` | SSH Daemon | Multiple failed authentication attempts from `203.0.113.88` |
| `16:57:30` | Web Server | HTTP POST request to `/upload.php` uploading `backdoor_shell.php` |
| `16:58:10` | Wazuh Syscheck | Rule 100011 triggered: Web shell created in `/var/www/html` |
| `16:58:12` | Active Response | `quarantine_file.sh` moved web shell to quarantine folder |
| `16:58:56` | Wazuh Syscheck | Rule 100010 triggered: Rogue account injected into `/etc/passwd` |
| `17:02:00` | SOC Tier 1 | Incident acknowledged and escalated to Tier 2 |
| `17:05:00` | Containment | Rogue entry removed from `/etc/passwd`, host isolated |

---

## 5. Containment & Remediation Log
1. **Host Isolation**: Network interface isolated via host firewall.
2. **Account Termination**: `userdel -r backdoor_admin` executed.
3. **Integrity Restoration**: `/etc/passwd` restored from known-good baseline backup.
4. **Vulnerability Mitigation**: File upload validation patch applied to web application.

---

## 6. Lessons Learned & Recommendations
- **Action Item 1**: Restrict write permissions on `/var/www/html/` to read-only for web application runtime user.
- **Action Item 2**: Enforce multi-factor authentication (MFA) and disable password-based SSH authentication in favor of ED25519 keys.
- **Action Item 3**: Deploy Wazuh Active Response automated IP blocking across all DMZ endpoints.
