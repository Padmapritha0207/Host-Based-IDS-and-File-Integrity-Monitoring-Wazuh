# MITRE ATT&CK Matrix Mapping: Wazuh HIDS & FIM Rules

This document maps all detection rules, decoders, and active responses developed in this project to the official [MITRE ATT&CK Enterprise Matrix](https://attack.mitre.org/).

---

## 1. Summary Matrix

| Rule ID | Severity | Category | Technique Name | MITRE ID | Tactic |
|---|---|---|---|---|---|
| **100010** | High (10) | Syscheck FIM | Account Manipulation | **T1098** | Persistence, Privilege Escalation |
| **100010** | High (10) | Syscheck FIM | Valid Accounts | **T1078** | Defense Evasion, Initial Access |
| **100011** | Critical (12) | Syscheck FIM | Server Software Component: Web Shell | **T1505.003** | Persistence |
| **100011** | Critical (12) | Syscheck FIM | Ingress Tool Transfer | **T1105** | Command and Control |
| **100012** | High (10) | Syscheck FIM | SSH Authorized Keys Backdoor | **T1098.004** | Persistence |
| **100013** | Critical (12) | Syscheck FIM | Masquerading: Match Legitimate Name | **T1036.005** | Defense Evasion |
| **100013** | Critical (12) | Syscheck FIM | Data Stored: Binary Tampering | **T1565.001** | Impact |
| **100014** | Medium (9) | Syscheck FIM | Scheduled Task/Job: Cron | **T1053.003** | Execution, Persistence |
| **100015** | Critical (14) | Syscheck FIM | Data Encrypted for Impact (Ransomware) | **T1486** | Impact |
| **100015** | Critical (14) | Syscheck FIM | Data Destruction | **T1485** | Impact |
| **100016** | Critical (13) | Syscheck Heuristic | Mass File Alteration (Automated Encryption) | **T1486** | Impact |
| **100017** | High (11) | Registry FIM | Boot or Logon Autostart Execution: Registry Run Keys | **T1547.001** | Persistence, Privilege Escalation |
| **100018** | Medium (8) | Syscheck FIM | Stored Data Manipulation (/etc/hosts) | **T1565.001** | Impact, Defense Evasion |
| **100020** | High (10) | HIDS Log Rule | Brute Force: Password Guessing | **T1110.001** | Credential Access |

---

## 2. In-Depth Technique Descriptions & Detection Logic

### T1098 / T1078: Account Manipulation & Privileged Identity Tampering
- **Target Files**: `/etc/passwd`, `/etc/shadow`, `/etc/sudoers`, `/etc/group`
- **Adversary Behavior**: Adversaries create rogue superuser accounts with UID `0` or add existing unprivileged users to the `sudo` group to bypass authentication controls and maintain persistent administrative access.
- **Wazuh Detection Mechanism**: Syscheck real-time monitor (`realtime="yes"`) flags any file write event. Unified diff inspection (`report_changes="yes"`) exposes the newly appended user record.

### T1505.003: Server Software Component - Web Shell
- **Target Directories**: `/var/www/html/`, `/var/www/`, `C:\inetpub\wwwroot\`
- **Adversary Behavior**: Uploading executable scripts (`.php`, `.jsp`, `.asp`, `.py`) allowing remote command execution via HTTP query parameters.
- **Wazuh Detection Mechanism**: Rule 100011 uses regular expressions to detect new executable file creations in web-accessible directories. Paired with Active Response to quarantine the file instantly.

### T1486 / T1485: Ransomware & Data Destruction (Canary Tripwires)
- **Target Directories**: `/var/canaries/`, `C:\canaries\`
- **Adversary Behavior**: Ransomware runs an automated loop seeking documents (`.xlsx`, `.docx`, `.pdf`, `.sql`) to encrypt or wipe.
- **Wazuh Detection Mechanism**: Canary honeypot files are pre-seeded in decoy locations. Any modification, truncation, or deletion triggers Rule 100015 at Critical Level 14, alerting the SOC prior to full disk encryption.

### T1547.001: Registry Run Keys Persistence
- **Target Keys**: `HKLM\Software\Microsoft\Windows\CurrentVersion\Run`, `HKCU\...\RunOnce`
- **Adversary Behavior**: Adding registry values pointing to malicious payloads to execute automatically upon user logon or system boot.
- **Wazuh Detection Mechanism**: Native Windows Registry monitoring in `ossec.conf` polls and captures registry value additions and modifications.

### T1110.001: Password Guessing / SSH Brute Force
- **Target Logs**: `/var/log/auth.log`, `/var/log/secure`
- **Adversary Behavior**: Automated botnets or attackers executing dictionary attacks against exposed SSH port 22.
- **Wazuh Detection Mechanism**: Rule 100020 counts failed authentication attempts matching child rule 5710 from the same source IP within a 60-second window, automatically calling `firewall-drop` active response.
