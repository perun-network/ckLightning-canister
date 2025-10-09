#!/bin/bash
set -e

# Before starting devnet Chain via dfx, start a Bitcoin Node + Chain, connecting to Dfinity Bitcoin Canisters
# Inside bitcoin-25.0 directory: ./bin/bitcoind -conf=$(pwd)/bitcoin.conf -datadir=$(pwd)/data --port=18444
# ./bitcoin-cli -regtest -rpcuser=ic-btc-integration -rpcpassword=QPQiNaph19FqUsCrBRN0FII7lyM26B51fAMeBQzCb-E= createwallet testwallet
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
dfxvm default 0.24.3
# Remove canister_ids.json if it exists
if [ -f "canister_ids.json" ]; then
    rm canister_ids.json
fi

dfx start --clean --enable-bitcoin --background