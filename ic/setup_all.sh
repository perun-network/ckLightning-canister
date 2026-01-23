#!/bin/bash
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

echo "=== Step 1: Starting DFX ==="
./start_dfx.sh > /dev/null 2>&1

echo "=== Waiting 10 seconds for DFX to initialize ==="
sleep 10

echo "=== Step 2: Creating Identities ==="
./create_identities.sh

echo "=== Waiting 2 seconds ==="
sleep 2

echo "=== Step 3: Deploying Contracts ==="
./deploy_contracts_devnet.sh

echo "=== All setup completed! ==="
