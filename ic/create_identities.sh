#!/bin/bash
set -e

# Function to generate a new identity and return its principal
generate_identity() {
    local name=$1
    dfx identity new "$name" --storage-mode=plaintext || true
    dfx identity use "$name"
    dfx identity get-principal
}

# Function to get account ID from principal
get_account_id() {
    local principal=$1
    dfx ledger account-id --of-principal "$principal"
}

# Generate minting account
dfx identity new minting_ledger --storage-mode=plaintext || true

# Generate initial_ledger account
dfx identity new initial_ledger --storage-mode=plaintext || true

# Generate archive controller account and both identities for the ckLightning node operator and a user
dfx identity new archive_ledger --storage-mode=plaintext || true
dfx identity new user --storage-mode=plaintext || true
dfx identity new node --storage-mode=plaintext || true

echo "Finished generating identities"
