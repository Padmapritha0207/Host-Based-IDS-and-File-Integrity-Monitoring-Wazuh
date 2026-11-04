"""
Terminal SOC Console Dashboard for Wazuh FIM Simulator
Renders colorized security alerts, unified diffs, and MITRE ATT&CK telemetry.
"""

import os
import sys
from typing import Dict, Any, List

# Reconfigure stdout for utf-8 if on Python 3.7+
if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

class Colors:
    RESET = "\033[0m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    RED = "\033[91m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    BLUE = "\033[94m"
    MAGENTA = "\033[95m"
    CYAN = "\033[96m"
    WHITE = "\033[97m"
    BG_RED = "\033[41m"
    BG_YELLOW = "\033[43m"
    BG_BLUE = "\033[44m"

def print_banner():
    banner = f"""
{Colors.CYAN}{Colors.BOLD}================================================================================
          WAZUH / OSSEC HOST-BASED INTRUSION DETECTION & FIM LAB
                     Security Operations Console (SOC)
================================================================================{Colors.RESET}
"""
    print(banner)

def get_severity_badge(level: int) -> str:
    if level >= 12:
        return f"{Colors.BG_RED}{Colors.WHITE}{Colors.BOLD} CRITICAL (Lvl {level}) {Colors.RESET}"
    elif level >= 8:
        return f"{Colors.BG_YELLOW}{Colors.BOLD} HIGH (Lvl {level}) {Colors.RESET}"
    elif level >= 5:
        return f"{Colors.BG_BLUE}{Colors.WHITE} MEDIUM (Lvl {level}) {Colors.RESET}"
    else:
        return f"{Colors.DIM} LOW (Lvl {level}) {Colors.RESET}"

def safe_print(text: str):
    """Safely prints text handling legacy terminal encodings."""
    try:
        print(text)
    except UnicodeEncodeError:
        print(text.encode("ascii", errors="replace").decode("ascii"))

def render_alert(alert: Dict[str, Any]):
    rule = alert["rule"]
    syscheck = alert["syscheck"]
    level = rule["level"]
    badge = get_severity_badge(level)

    safe_print(f"\n{badge} {Colors.BOLD}[Rule {rule['id']}]{Colors.RESET} {Colors.WHITE}{rule['description']}{Colors.RESET}")
    safe_print(f"  {Colors.DIM}Timestamp:{Colors.RESET} {alert['timestamp']}  |  {Colors.DIM}Agent:{Colors.RESET} {alert['agent']['name']} ({alert['agent']['ip']})")

    # MITRE ATT&CK
    mitre_ids = rule.get("mitre", {}).get("id", [])
    if mitre_ids:
        mitre_str = ", ".join([f"{Colors.MAGENTA}{Colors.BOLD}{m}{Colors.RESET}" for m in mitre_ids])
        safe_print(f"  {Colors.DIM}MITRE ATT&CK:{Colors.RESET} {mitre_str}")

    # File integrity details
    event_color = Colors.GREEN if syscheck["event"] == "file_created" else (Colors.RED if syscheck["event"] == "file_deleted" else Colors.YELLOW)
    safe_print(f"  {Colors.DIM}Action:{Colors.RESET} {event_color}{syscheck['event'].upper()}{Colors.RESET}  -->  {Colors.BOLD}{syscheck['path']}{Colors.RESET}")

    if syscheck.get("sha256_before"):
        safe_print(f"  {Colors.DIM}SHA256 (Before):{Colors.RESET} {syscheck['sha256_before']}")
    if syscheck.get("sha256_after"):
        safe_print(f"  {Colors.DIM}SHA256 (After): {Colors.RESET} {Colors.CYAN}{syscheck['sha256_after']}{Colors.RESET}")

    # Unified Diff (report_changes)
    diff = syscheck.get("diff")
    if diff:
        safe_print(f"\n  {Colors.BOLD}Content Integrity Diff (report_changes=yes):{Colors.RESET}")
        safe_print(f"  {Colors.DIM}------------------------------------------------------------{Colors.RESET}")
        for line in diff.splitlines():
            clean_line = line.strip("\r\n")
            if clean_line.startswith("+") and not clean_line.startswith("+++"):
                safe_print(f"  {Colors.GREEN}{clean_line}{Colors.RESET}")
            elif clean_line.startswith("-") and not clean_line.startswith("---"):
                safe_print(f"  {Colors.RED}{clean_line}{Colors.RESET}")
            elif clean_line.startswith("@"):
                safe_print(f"  {Colors.CYAN}{clean_line}{Colors.RESET}")
            else:
                safe_print(f"  {Colors.DIM}{clean_line}{Colors.RESET}")
        safe_print(f"  {Colors.DIM}------------------------------------------------------------{Colors.RESET}")

def render_summary(alerts: List[Dict[str, Any]]):
    total = len(alerts)
    critical = sum(1 for a in alerts if a["rule"]["level"] >= 12)
    high = sum(1 for a in alerts if 8 <= a["rule"]["level"] < 12)
    medium = sum(1 for a in alerts if 5 <= a["rule"]["level"] < 8)

    safe_print(f"\n{Colors.CYAN}{Colors.BOLD}========================== DETECTION METRICS =========================={Colors.RESET}")
    safe_print(f"  Total Alerts Dispatched: {Colors.BOLD}{total}{Colors.RESET}")
    safe_print(f"  Critical (Level >= 12):  {Colors.RED}{Colors.BOLD}{critical}{Colors.RESET}")
    safe_print(f"  High (Level 8-11):       {Colors.YELLOW}{Colors.BOLD}{high}{Colors.RESET}")
    safe_print(f"  Medium (Level 5-7):      {Colors.BLUE}{Colors.BOLD}{medium}{Colors.RESET}")
    safe_print(f"{Colors.CYAN}======================================================================={Colors.RESET}\n")
