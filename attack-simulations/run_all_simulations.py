#!/usr/bin/env python3
"""
Master Attack Simulation Orchestrator
Executes all attack scenarios against the local test sandbox:
1. System File Tampering (/etc/passwd, /etc/hosts)
2. Web Shell Upload (/var/www/html)
3. Ransomware Canary Trigger
4. SSH Brute Force Simulation
"""

import sys
import subprocess
from pathlib import Path

CURRENT_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = CURRENT_DIR.parent

def run_step(title: str, script_name: str, args: list):
    print(f"\n{'='*70}")
    print(f"[*] RUNNING: {title}")
    print(f"{'='*70}")
    cmd = [sys.executable, str(CURRENT_DIR / script_name)] + args
    res = subprocess.run(cmd, capture_output=False)
    if res.returncode != 0:
        print(f"[-] Step '{title}' exited with code {res.returncode}")
    else:
        print(f"[+] Step '{title}' completed successfully.")

def main():
    print("======================================================================")
    print("      WAZUH / OSSEC HIDS & FIM RED TEAM SIMULATION SUITE")
    print("======================================================================")

    sandbox = PROJECT_ROOT / "simulator" / "sample_data"
    passwd_path = sandbox / "critical_configs" / "passwd"
    hosts_path = sandbox / "critical_configs" / "hosts"
    web_root = sandbox / "web_root"
    canary_dir = sandbox / "canaries"

    run_step("1. System Configuration File Tampering",
             "01_system_file_tampering.py",
             ["--passwd-path", str(passwd_path), "--hosts-path", str(hosts_path)])

    run_step("2. Web Shell Drop Injection",
             "02_webshell_injection.py",
             ["--web-root", str(web_root), "--filename", "c2_backdoor.php"])

    run_step("3. Ransomware Canary Encryption Sweep",
             "03_ransomware_canary_test.py",
             ["--canary-dir", str(canary_dir)])

    run_step("4. SSH Brute Force Authentication Flooding",
             "04_ssh_bruteforce_attack.py",
             ["--log-path", str(sandbox / "simulated_auth.log"), "--count", "5"])

    print("\n[+] All attack simulations executed successfully.")
    print("    Launch the simulator dashboard to observe FIM & HIDS detection:")
    print("    python simulator/run_simulator.py --demo\n")

if __name__ == "__main__":
    main()
