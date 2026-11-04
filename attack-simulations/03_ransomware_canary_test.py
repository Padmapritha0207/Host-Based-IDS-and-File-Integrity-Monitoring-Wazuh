#!/usr/bin/env python3
"""
Red Team Simulation: Ransomware Canary Tripwire & Mass File Modification
Simulates ransomware behavior:
1. Deploys decoy canary files (honeypots) into monitored folders.
2. Simulates an automated encryption routine modifying files and appending `.locked` extension.
Corresponds to Wazuh Rule 100015 (MITRE T1486) & Rule 100016 (Mass Alteration).
"""

import os
import sys
import time
import argparse
from pathlib import Path

CANARY_NAMES = [
    "Q3_Financial_Projections.xlsx",
    "Employee_SSN_Records.csv",
    "Executive_Meeting_Minutes.docx",
    "Customer_Billing_Database.sql"
]

def seed_canaries(canary_dir: Path):
    print(f"[*] Seeding honeypot canary files in: {canary_dir}")
    canary_dir.mkdir(parents=True, exist_ok=True)
    created = []
    for fname in CANARY_NAMES:
        fpath = canary_dir / fname
        with open(fpath, "w", encoding="utf-8") as f:
            f.write(f"CONFIDENTIAL DATA -- DO NOT MODIFY -- TRIPWIRE CANARY {fname}\n")
        created.append(fpath)
    print(f"[+] Seeded {len(created)} canary tripwires.")
    return created

def simulate_encryption(canary_dir: Path):
    print(f"\n[*] Simulating adversary ransomware sweep across: {canary_dir}")
    files = list(canary_dir.glob("*"))
    if not files:
        print("[-] No files found to encrypt.")
        return

    for fpath in files:
        if fpath.suffix == ".locked":
            continue
        print(f"  [!] Encrypting file: {fpath.name}")
        # Overwrite with encrypted pseudo-random bytes
        with open(fpath, "wb") as f:
            f.write(os.urandom(2048))

        # Rename to simulate ransomware extension
        locked_path = fpath.with_name(fpath.name + ".locked")
        if fpath.exists():
            fpath.rename(locked_path)
        time.sleep(0.3)

    print(f"[+] Ransomware encryption sweep completed.")
    print(f"    Expected Alerts: Rule 100015 (Canary Tripwire Triggered - Level 14)")

def main():
    parser = argparse.ArgumentParser(description="Simulate Ransomware Canary Attack")
    parser.add_argument("--canary-dir", type=str, default="/var/canaries")
    parser.add_argument("--seed-only", action="store_true", help="Only generate canary files")
    parser.add_argument("--encrypt-only", action="store_true", help="Encrypt existing canary files")
    args = parser.parse_args()

    canary_path = Path(args.canary_dir)
    if args.seed_only:
        seed_canaries(canary_path)
    elif args.encrypt_only:
        simulate_encryption(canary_path)
    else:
        seed_canaries(canary_path)
        print("[*] Waiting 2 seconds for Syscheck baseline sync...")
        time.sleep(2)
        simulate_encryption(canary_path)

if __name__ == "__main__":
    main()
