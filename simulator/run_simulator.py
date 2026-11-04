#!/usr/bin/env python3
"""
Wazuh Host-based IDS & File Integrity Monitoring (FIM) Interactive Simulator
Runs end-to-end automated attack simulations or live monitoring.

Usage:
  python run_simulator.py --demo
  python run_simulator.py --watch /path/to/directory
"""

import os
import sys
import json
import time
import argparse
from pathlib import Path

# Add current directory to path
CURRENT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(CURRENT_DIR))

from engine import FIMEngine
from rule_evaluator import RuleEvaluator
from cli_dashboard import print_banner, render_alert, render_summary, Colors

def setup_demo_sandbox(sandbox_dir: Path):
    """Sets up realistic files in sandbox for simulation."""
    import shutil
    if sandbox_dir.exists():
        shutil.rmtree(sandbox_dir)

    configs_dir = sandbox_dir / "critical_configs"
    web_dir = sandbox_dir / "web_root"
    canaries_dir = sandbox_dir / "canaries"

    for d in [configs_dir, web_dir, canaries_dir]:
        d.mkdir(parents=True, exist_ok=True)

    # 1. Baseline mock /etc/passwd
    passwd_file = configs_dir / "passwd"
    with open(passwd_file, "w", encoding="utf-8") as f:
        f.write("root:x:0:0:root:/root:/bin/bash\n"
                "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"
                "sysadmin:x:1000:1000:SysAdmin,,,:/home/sysadmin:/bin/bash\n"
                "www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin\n")

    # 2. Baseline mock /etc/hosts
    hosts_file = configs_dir / "hosts"
    with open(hosts_file, "w", encoding="utf-8") as f:
        f.write("127.0.0.1 localhost\n"
                "127.0.1.1 security-lab-endpoint\n"
                "192.168.10.1 gateway.corp.local\n"
                "192.168.10.100 dc01.corp.local\n")

    # 3. Baseline web root
    index_file = web_dir / "index.html"
    with open(index_file, "w", encoding="utf-8") as f:
        f.write("<!DOCTYPE html>\n<html>\n<head><title>Corporate Portal</title></head>\n"
                "<body><h1>Welcome to Corporate Portal</h1></body>\n</html>\n")

    # 4. Baseline canary tripwire file
    canary_file = canaries_dir / "finance_q4_confidential.xlsx"
    with open(canary_file, "w", encoding="utf-8") as f:
        f.write("=== CORPORATE FINANCE CANARY TRIPWIRE DATA ===\n"
                "DO NOT MODIFY OR DELETE - TRIPWIRE ENCRYPTION MONITOR\n")

    return configs_dir, web_dir, canaries_dir

def run_automated_demo(sandbox_dir: Path):
    print_banner()
    print(f"{Colors.YELLOW}[*] Initializing Wazuh HIDS & FIM Simulation Environment...{Colors.RESET}")
    configs_dir, web_dir, canaries_dir = setup_demo_sandbox(sandbox_dir)

    rules_xml = CURRENT_DIR.parent / "configs" / "manager" / "local_rules.xml"
    evaluator = RuleEvaluator(str(rules_xml))
    engine = FIMEngine([str(sandbox_dir)])

    print(f"{Colors.BLUE}[*] Indexing baseline cryptographic hashes across monitored directories...{Colors.RESET}")
    count = engine.build_baseline()
    print(f"{Colors.GREEN}[+] Baseline established: {count} files indexed into Syscheck database.{Colors.RESET}")
    time.sleep(1)

    print(f"\n{Colors.BOLD}{Colors.MAGENTA}>>> SIMULATING RED TEAM ATTACK SCENARIOS <<<{Colors.RESET}\n")

    all_alerts = []

    # Scenario 1: Identity / Privileged User Injection
    print(f"{Colors.YELLOW}[Attack 1] Adversary injects rogue UID 0 backdoor account into passwd...{Colors.RESET}")
    time.sleep(0.8)
    passwd_file = configs_dir / "passwd"
    with open(passwd_file, "a", encoding="utf-8") as f:
        f.write("backdoor_admin:x:0:0:Root Backdoor:/root:/bin/bash\n")

    events = engine.scan_for_changes()
    for ev in events:
        alert = evaluator.evaluate(ev)
        if alert:
            all_alerts.append(alert)
            render_alert(alert)

    # Scenario 2: Web Shell Dropped into Web Root
    print(f"\n{Colors.YELLOW}[Attack 2] Adversary uploads malicious PHP web shell into web root...{Colors.RESET}")
    time.sleep(0.8)
    shell_file = web_dir / "backdoor_shell.php"
    with open(shell_file, "w", encoding="utf-8") as f:
        f.write("<?php\n"
                "// C2 Backdoor Execution Endpoint\n"
                "if(isset($_REQUEST['cmd'])){\n"
                "    echo '<pre>' . shell_exec($_REQUEST['cmd']) . '</pre>';\n"
                "}\n"
                "?>\n")

    events = engine.scan_for_changes()
    for ev in events:
        alert = evaluator.evaluate(ev)
        if alert:
            all_alerts.append(alert)
            render_alert(alert)

    # Scenario 3: Decoy Canary Tripwire Encrypted / Destroyed
    print(f"\n{Colors.YELLOW}[Attack 3] Ransomware routine modifies Canary Tripwire honeypot...{Colors.RESET}")
    time.sleep(0.8)
    canary_file = canaries_dir / "finance_q4_confidential.xlsx"
    with open(canary_file, "wb") as f:
        f.write(os.urandom(1024)) # Overwrite with encrypted pseudo-random bytes

    events = engine.scan_for_changes()
    for ev in events:
        alert = evaluator.evaluate(ev)
        if alert:
            all_alerts.append(alert)
            render_alert(alert)

    # Scenario 4: Network Tampering / DNS Redirection
    print(f"\n{Colors.YELLOW}[Attack 4] Host network configuration tampering (/etc/hosts redirection)...{Colors.RESET}")
    time.sleep(0.8)
    hosts_file = configs_dir / "hosts"
    with open(hosts_file, "a", encoding="utf-8") as f:
        f.write("198.51.100.45 internal-portal.corp.local  # Malicious C2 Redirection\n")

    events = engine.scan_for_changes()
    for ev in events:
        alert = evaluator.evaluate(ev)
        if alert:
            all_alerts.append(alert)
            render_alert(alert)

    render_summary(all_alerts)

    # Export alerts to sample-alerts directory
    output_path = CURRENT_DIR.parent / "sample-alerts" / "simulation_run_alerts.json"
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(all_alerts, f, indent=2)

    print(f"{Colors.GREEN}[+] Automated run completed. Full Wazuh alerts exported to:{Colors.RESET}")
    print(f"    {output_path}\n")

def run_live_watch(watch_dir: Path):
    print_banner()
    print(f"{Colors.CYAN}[*] Starting Real-time Syscheck Watcher on: {watch_dir}{Colors.RESET}")
    rules_xml = CURRENT_DIR.parent / "configs" / "manager" / "local_rules.xml"
    evaluator = RuleEvaluator(str(rules_xml))
    engine = FIMEngine([str(watch_dir)])

    count = engine.build_baseline()
    print(f"{Colors.GREEN}[+] Initial baseline indexed {count} files. Monitoring active (Press Ctrl+C to stop)...{Colors.RESET}\n")

    try:
        while True:
            time.sleep(1.5)
            events = engine.scan_for_changes()
            for ev in events:
                alert = evaluator.evaluate(ev)
                if alert:
                    render_alert(alert)
    except KeyboardInterrupt:
        print(f"\n{Colors.YELLOW}[*] Monitoring halted by operator.{Colors.RESET}")

def main():
    parser = argparse.ArgumentParser(description="Wazuh HIDS & FIM Interactive Simulator")
    parser.add_argument("--demo", action="store_true", help="Execute complete automated attack & detection demonstration")
    parser.add_argument("--watch", type=str, help="Directory to monitor in real-time")
    args = parser.parse_args()

    sandbox_dir = CURRENT_DIR / "sample_data"
    if args.watch:
        run_live_watch(Path(args.watch))
    else:
        run_automated_demo(sandbox_dir)

if __name__ == "__main__":
    main()
