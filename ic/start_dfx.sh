#!/bin/bash
set -e

# Before starting devnet Chain via dfx, start a Bitcoin Node + Chain, connecting to Dfinity Bitcoin Canisters
# If need to stop before restarting: ./bin/bitcoin-cli -conf=$(pwd)/bitcoin.conf -datadir=$(pwd)/data stop
# Inside bitcoin-25.0 directory: ./bin/bitcoind -conf=$(pwd)/bitcoin.conf -datadir=$(pwd)/data --port=18444
# If wallet does not exist yet, create it:
# ./bitcoin-cli -regtest -rpcuser=ic-btc-integration -rpcpassword=QPQiNaph19FqUsCrBRN0FII7lyM26B51fAMeBQzCb-E= createwallet testwallet
# If wallet already exists, load it:
# ./bitcoin-cli -regtest -rpcuser=ic-btc-integration -rpcpassword=QPQiNaph19FqUsCrBRN0FII7lyM26B51fAMeBQzCb-E= loadwallet testwallet
# ./bitcoin-cli -regtest -rpcwallet=testwallet -rpcuser=ic-btc-integration -rpcpassword=QPQiNaph19FqUsCrBRN0FII7lyM26B51fAMeBQzCb-E= getnewaddress
# ./bitcoin-cli -regtest -rpcwallet=testwallet -rpcuser=ic-btc-integration -rpcpassword=QPQiNaph19FqUsCrBRN0FII7lyM26B51fAMeBQzCb-E= generatetoaddress 1 <address>

dfx stop
rm -rf .dfx
rm -rf ~/.config/dfx/replica-configuration/
rm -rf ~/.config/dfx/identity/minting
rm -rf ~/.config/dfx/identity/initial
rm -rf ~/.config/dfx/identity/archive
rm -rf ~/.cache/dfinity/
rm -rf ~/.config/dfx/
dfxvm default 0.29.2
# Remove canister_ids.json if it exists
if [ -f "canister_ids.json" ]; then
    rm canister_ids.json
fi

# Reset Bitcoin regtest for clean state (no leftover UTXOs from prior runs)
BITCOIN_DIR="/home/ilja/workrepos/bitcoin-25.0"
BITCOIN_CLI="$BITCOIN_DIR/bin/bitcoin-cli -regtest -rpcuser=ic-btc-integration -rpcpassword=QPQiNaph19FqUsCrBRN0FII7lyM26B51fAMeBQzCb-E="

echo "=== Resetting Bitcoin regtest ==="
$BITCOIN_CLI stop 2>/dev/null || true
sleep 3

rm -rf "$BITCOIN_DIR/data/regtest"

$BITCOIN_DIR/bin/bitcoind -conf=$BITCOIN_DIR/bitcoin.conf -datadir=$BITCOIN_DIR/data --port=18444 -daemon
sleep 3

$BITCOIN_CLI createwallet testwallet
echo "Created testwallet"

ADDR=$($BITCOIN_CLI -rpcwallet=testwallet getnewaddress)
$BITCOIN_CLI generatetoaddress 101 $ADDR > /dev/null
echo "Mined 101 blocks for coinbase maturity"

dfx start --clean --enable-bitcoin --background