#!/bin/bash
# ==============================================================================
# Automated Wazuh Lab Deployment Script
# Deploys Wazuh Indexer, Manager, Dashboard, and Target Node with Custom Rules
# ==============================================================================

set -e

echo "======================================================================"
echo "      DEPLOYING WAZUH HOST-BASED IDS & FIM LAB ENVIRONMENT"
echo "======================================================================"

if ! command -v docker &> /dev/null; then
    echo "[-] Error: Docker is not installed. Please install Docker Engine."
    exit 1
fi

if ! command -v docker-compose &> /dev/null && ! docker compose version &> /dev/null; then
    echo "[-] Error: docker compose is not available."
    exit 1
fi

echo "[*] Ensuring required kernel memory parameters (sysctl)..."
if [ "$(sysctl -n vm.max_map_count 2>/dev/null)" -lt 262144 ]; then
    echo "[*] Setting vm.max_map_count=262144 for Wazuh Indexer / OpenSearch..."
    sudo sysctl -w vm.max_map_count=262144
fi

echo "[*] Starting Wazuh Lab cluster containers..."
docker compose up -d

echo "[*] Waiting for Wazuh Manager API and Dashboard..."
sleep 15

echo ""
echo "[+] Wazuh Lab successfully initialized!"
echo "    - Wazuh Dashboard:  https://localhost:443  (User: admin / admin)"
echo "    - Wazuh API:        https://localhost:55000"
echo "    - Agent Connection: 127.0.0.1:1514"
echo ""
echo "[*] Custom FIM rules (local_rules.xml) and decoders are mounted and active."
