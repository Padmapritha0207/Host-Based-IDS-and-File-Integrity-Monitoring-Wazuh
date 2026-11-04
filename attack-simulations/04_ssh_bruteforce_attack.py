#!/usr/bin/env python3
"""
Red Team Simulation: SSH Brute-Force Authentication Attack
Simulates adversary launching automated credential stuffing or dictionary attack
against the SSH daemon. Generates repeated failed login events.
Corresponds to Wazuh Rule 5710 / 5712 & Custom Rule 100020 (MITRE T1110.001).
Triggers Active Response 'firewall-drop' rule.
"""

import sys
import time
import socket
import argparse
from datetime import datetime

SAMPLE_USERS = ["root", "admin", "test", "user", "oracle", "postgres", "guest"]

def generate_syslog_auth_failure(logfile: str, attacker_ip: str, iterations: int):
    print(f"[*] Simulating {iterations} failed SSH attempts from {attacker_ip} into {logfile}...")
    timestamp = datetime.now().strftime("%b %d %H:%M:%S")
    hostname = socket.gethostname()

    with open(logfile, "a", encoding="utf-8") as f:
        for i in range(iterations):
            user = SAMPLE_USERS[i % len(SAMPLE_USERS)]
            port = 45000 + i
            log_line = f"{timestamp} {hostname} sshd[{12000 + i}]: Failed password for invalid user {user} from {attacker_ip} port {port} ssh2\n"
            f.write(log_line)
            f.flush()
            print(f"  [>] Injected auth failure: user='{user}' from '{attacker_ip}'")
            time.sleep(0.2)

    print(f"[+] Brute-force simulation finished. Expected rule: 100020 (Active Response firewall-drop)")

def main():
    parser = argparse.ArgumentParser(description="Simulate SSH Brute Force Attacks")
    parser.add_argument("--log-path", type=str, default="/var/log/auth.log")
    parser.add_argument("--attacker-ip", type=str, default="203.0.113.88")
    parser.add_argument("--count", type=int, default=8)
    args = parser.parse_args()

    try:
        generate_syslog_auth_failure(args.log_path, args.attacker_ip, args.count)
    except PermissionError:
        print(f"[-] Note: Direct write to {args.log_path} requires elevated permissions.")
        print(f"    Testing against local demo log file instead: ./simulated_auth.log")
        generate_syslog_auth_failure("./simulated_auth.log", args.attacker_ip, args.count)

if __name__ == "__main__":
    main()
