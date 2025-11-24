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

dfx start --clean --enable-bitcoin --background