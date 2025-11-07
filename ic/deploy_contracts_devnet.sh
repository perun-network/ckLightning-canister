#!/bin/bash
set -e

# Function to get account ID from principal
get_account_id() {
    local principal=$1
    dfx ledger account-id --of-principal "$principal"
}

echo "Checking dependencies..."
# Check for required commands
REQUIRED_COMMANDS="dfx cargo candid-extractor"

for cmd in $REQUIRED_COMMANDS; do
    if ! command -v $cmd >/dev/null 2>&1; then
        case $cmd in
            "dfx")
                echo "dfx is required but not installed. Please install dfx: https://internetcomputer.org/docs/current/developer-docs/setup/install/" >&2
                ;;
            "cargo")
                echo "cargo is required but not installed. Please install Rust: https://rustup.rs/" >&2
                ;;
            "candid-extractor")
                echo "candid-extractor is required but not installed. Please install: cargo install candid-extractor" >&2
                ;;
        esac
        exit 1
    fi
done

# Retrieve minting principal and account 
dfx identity use minting_ledger
MINTING_PRINCIPAL=$(dfx identity get-principal)
MINTING_ACCOUNT=$(get_account_id "$MINTING_PRINCIPAL")


dfx identity use default
DEFAULT_PRINCIPAL=$(dfx identity get-principal)

# Retrieve initial account for distributing cycles
dfx identity use initial_ledger
INITIAL_PRINCIPAL=$(dfx identity get-principal)
INITIAL_ACCOUNT=$(get_account_id "$INITIAL_PRINCIPAL")

# Retrieve user and node account to fund them with cycles and ckBTC

dfx identity use user
USER_PRINCIPAL=$(dfx identity get-principal)
USER_ACCOUNT=$(get_account_id "$USER_PRINCIPAL")


dfx identity use node
NODE_PRINCIPAL=$(dfx identity get-principal)
NODE_ACCOUNT=$(get_account_id "$NODE_PRINCIPAL")

# Retrieve archive controller principal
dfx identity use archive_ledger
ARCHIVE_PRINCIPAL=$(dfx identity get-principal)



dfx canister create btc_checker
dfx canister create btcledger
dfx canister create minter
dfx canister create index
dfx canister create mock_contract
dfx canister create archive
dfx canister create ledger
dfx canister create cklightning
dfx canister create basic_bitcoin

dfx build

echo "Setting up init args and installing"

# Get the IDs
LEDGER_ID=$(dfx canister id ledger)
CHECKER_ID=$(dfx canister id btc_checker)
BTC_LEDGER_ID=$(dfx canister id btcledger)
CKL_ID=$(dfx canister id cklightning)
BASIC_BITCOIN_ID=$(dfx canister id basic_bitcoin)


# Prepare btc checker initialization argument

BTC_CHECKER_INIT_ARG="(variant { InitArg = record { btc_network = variant 
{ regtest = record { json_rpc_url = \"http://ic-btc-integration:QPQiNaph19FqUsCrBRN0FII7lyM26B51fAMeBQzCb-E=@127.0.0.1:18443\"}}; 
check_mode = variant { AcceptAll }; num_subnet_nodes = 34; } })"

# Prepare ledger initialization argument

LEDGER_INIT_ARG="(variant { Init = record { 
    minting_account = \"${MINTING_ACCOUNT}\"; 
    initial_values = vec { 
        record { \"${INITIAL_ACCOUNT}\"; record { e8s = 200_000_000 } } 
    }; 
    send_whitelist = vec {}; 
    transfer_fee = opt record { e8s = 10_000 }; 
    token_symbol = opt \"LICP\"; 
    token_name = opt \"Local Internet Computer Protocol Token\"; 
    archive_options = opt record { 
        trigger_threshold = 2000; 
        num_blocks_to_archive = 1000; 
        controller_id = principal \"${ARCHIVE_PRINCIPAL}\" 
    }; 
} })"

# Prepare ckbtc ledger initialization argument
BTCLEDGER_INIT_ARG="(variant { Init = record { 
    minting_account = record { owner = principal \"${MINTING_PRINCIPAL}\" }; 
    initial_balances = vec { record { record { owner = principal \"${USER_PRINCIPAL}\"} ; 101_000_000  };
     record { record { owner = principal \"${NODE_PRINCIPAL}\"} ; 100_000_000  }} ; 
    send_whitelist = vec {}; 
    transfer_fee = 1000 ; 
    token_symbol =  \"ckTESTBTC\"; 
    token_name =  \"Chain key testnet Bitcoin\"; 
    metadata = vec {};
    max_memo_length = opt 80;
    archive_options = record { 
        trigger_threshold = 2000; 
        num_blocks_to_archive = 1000; 
        max_message_size_bytes = null;
        cycles_for_archive_creation = opt 1_000_000_000_000;
        controller_id = principal \"${ARCHIVE_PRINCIPAL}\" 
    }; 
} })"


# Prepare minter initialization argument
MINTER_INIT_ARG="(variant { Init = record { 
    btc_network = variant { Regtest }; 
    ledger_id = principal \"${BTC_LEDGER_ID}\"; 
    ecdsa_key_name = \"dfx_test_key\"; 
    retrieve_btc_min_amount = 5_000; 
    max_time_in_queue_nanos = 420_000_000_000; 
    btc_checker_principal = opt principal \"${CHECKER_ID}\"; 
    check_fee = opt 100; 
    mode = variant { GeneralAvailability }; 
} })"

INDEX_INIT_ARG="(opt variant { Init = record { 
    ledger_id = principal \"${BTC_LEDGER_ID}\"} })"

ARCHIVE_INIT_ARG="( principal \"${BTC_LEDGER_ID}\", 0, opt 3_221_225_472, null)"

# Install canisters

dfx canister install btc_checker --argument "$BTC_CHECKER_INIT_ARG"
dfx canister install minter --argument "$MINTER_INIT_ARG"
dfx canister install ledger --argument "$LEDGER_INIT_ARG"
dfx canister install btcledger --argument "$BTCLEDGER_INIT_ARG"
dfx canister install index --argument "$INDEX_INIT_ARG"
dfx canister install archive --argument "$ARCHIVE_INIT_ARG"
dfx canister install mock_contract --argument "(principal \"${LEDGER_ID}\")"
dfx canister install cklightning
dfx deploy basic_bitcoin --argument '(variant { regtest })'


MOCK_ID=$(dfx canister id mock_contract)

# Switch back to initial_ledger identity to distribute cycles for contract usage
dfx identity use initial_ledger

USER_WALLET_ID=$(dfx identity get-wallet)
NODE_WALLET_ID=$(dfx identity get-wallet)

dfx ledger fabricate-cycles --canister $USER_WALLET_ID --amount 200000
dfx ledger fabricate-cycles --canister $NODE_WALLET_ID --amount 200000
dfx canister deposit-cycles 1000000 $MOCK_ID
dfx canister deposit-cycles 1000000 $CKL_ID



echo -e "\n=== Deployment Summary ==="
echo "Context Contract ID: ${MOCK_ID}"
echo "BTC Ledger Contract ID: ${BTC_LEDGER_ID}"
echo "Ledger Contract ID: ${LEDGER_ID}"
echo "Demo Mock Contract ID: ${MOCK_ID}"
echo "ckLightning Principal: ${CKL_ID}"
echo "Basic Bitcoin Principal: ${BASIC_BITCOIN_ID}"

echo -e "\nAccount Information:"
echo "Minting Account: ${MINTING_ACCOUNT}"
echo "User Principal: ${USER_PRINCIPAL}"
echo "User Account: ${USER_ACCOUNT}"
echo "Node Principal: ${NODE_PRINCIPAL}"
echo "Node Account: ${NODE_ACCOUNT}"
echo "Default Principal: ${DEFAULT_PRINCIPAL}"
echo "Archive Principal: ${ARCHIVE_PRINCIPAL}"
echo -e "\nDeployment completed successfully!"
