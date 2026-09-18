# Operating the ckLightning canister

Deploying, configuring, monitoring and recovering the canister. Written 2026-09-17 against
`staging-april-deployment`; settings and their per-environment values are listed in the relay repository's
`PARAMETERS.md`, and the relay side of operations in its `OPERATIONS.md`.

The canister is the trust anchor: it holds the channel keys, the pool accounting and the swap state. It
has no operator UI — everything below is `dfx` against the canister, or the client's admin commands.

---

## 1. Roles

| Role | Set how | May do |
|---|---|---|
| Controller | IC canister setting | install, upgrade, snapshots, settings, `set_admin` |
| Admin | `set_admin` by a controller | StableSwap config, anti-DDoS fee, swap caps, pruning, fee withdrawal, relay registration |
| Registered relay | `register_relay` records the caller | signing, swap completion, channel bookkeeping |
| User | any principal | own swaps, own LP positions, own addresses |

Keep these apart if you can. On the April staging build one identity was all three at once, which means a
compromise of the relay host is a compromise of the controller.

## 2. Install and upgrade

Build with the interface embedded, otherwise explorers and `dfx canister call` cannot decode it:

```bash
cargo build --locked --release --target wasm32-unknown-unknown -p cklightning
candid-extractor target/wasm32-unknown-unknown/release/cklightning.wasm > cklightning.did
ic-wasm target/wasm32-unknown-unknown/release/cklightning.wasm \
  -o cklightning-with-did.wasm metadata candid:service -f cklightning.did -v public
sha256sum cklightning-with-did.wasm      # compare with the module hash after installing
```

Install (`--mode install` on an empty canister) or upgrade, always passing the same network argument in
lowercase — `regtest`, `testnet` or `mainnet`:

```bash
dfx canister stop   <id> --network ic --identity <controller>
dfx canister snapshot create <id> --network ic --identity <controller>
dfx canister start  <id> --network ic --identity <controller>
dfx canister install <id> --mode upgrade --wasm cklightning-with-did.wasm \
  --argument '(variant { testnet })' --network ic --identity <controller>
```

After every upgrade **restart the relay**: it caches the funding pubkey at startup, and signing fails
until it fetches it again.

Never use `--mode reinstall` on a canister with open channels. The per-channel secrets come from
`raw_rand()` and exist only in canister state; a reinstall makes every existing channel unsignable.

The init argument also selects the ECDSA key name. On the current code that is `test_key_1` for both
testnet and mainnet — production must move to `key_1`, which changes every derived address.

## 3. First-time configuration

```bash
CAN=<canister id>; ID=<controller>
ME=$(dfx identity get-principal --identity $ID)

dfx canister update-settings $CAN --freezing-threshold 15552000 --network ic --identity $ID
dfx canister update-settings $CAN --add-controller <second-principal> --network ic --identity $ID

dfx canister call $CAN set_admin "(principal \"$ME\")" --network ic --identity $ID
dfx canister call $CAN set_icp_ddos_fee '(100_000 : nat64)' --network ic --identity $ID   # staging used 0.001 ICP; the code default is 1 ICP
dfx canister call $CAN set_swap_caps '(<max_single_sats> : nat64, <max_hourly_sats> : nat64)' --network ic --identity $ID
```

Swap caps are disabled (`0`) by default: with them off, a single swap is bounded only by the pool size and
the slippage limit. The relay is registered afterwards, by the identity the relay itself runs as —
`register_relay` binds the caller — with its node pubkey, webhook URL and token.

StableSwap parameters (`amplification`, `fee_bps`, `imbalance_fee_bps`, `rebate_bps`,
`protocol_fee_share_bps`, `max_slippage_bps`, `max_swap_pct_bps`) are changed with
`update_stableswap_config`, or the client's `update-config`. Every basis-point field is capped at 10 000
and `imbalance_fee_bps` must be at least `fee_bps`.

## 4. Monitoring

```bash
dfx canister status $CAN --network ic --identity $ID          # cycles, memory, module hash, freezing threshold
dfx canister call $CAN get_total_lp_balance '()' --network ic --query
dfx canister call $CAN get_state_stats '()' --network ic --query
dfx canister call $CAN get_relay_info '()' --network ic --query
dfx canister call $CAN get_expired_swap_counts_query '()' --network ic --query
dfx canister call $CAN get_stableswap_config '()' --network ic --query
```

Watch two things above all.

**Cycles.** The canister runs a heartbeat every consensus round and pays roughly 26 B cycles per
threshold-ECDSA signature. The April deployment went from a healthy balance to uninstalled — code and
state deleted — because nobody topped it up. Set a high freezing threshold, check the balance on a
schedule, and top up with `dfx cycles top-up`.

**State size.** The whole state is serialised into stable memory on every upgrade, and terminal swap
records are only removed when an admin calls `prune_state(<nanosecond cutoff>)`. Watch
`get_state_stats` and prune before it becomes large.

## 5. Funds the canister holds

| What | Where | Moved by |
|---|---|---|
| Pool ckBTC | canister's ICRC-1 account | swaps, LP withdrawals |
| Pool and user BTC | threshold-ECDSA addresses derived per principal and purpose | `withdraw_btc`, `send_btc_from_depositor_address`, `fund_channel` |
| Protocol fees (ckBTC) | counter in state | `withdraw_protocol_fees`, or `redistribute_fees` to the LPs |
| Anti-DDoS fees (ICP) | canister's ICP account | `withdraw_icp_fees` |

`withdraw_icp_fees` sends the **entire** ICP balance, which includes fees still owed back to users with
pending swaps. Only use it when nothing is in flight.

Do not use the legacy address endpoints (`set_btc_address`, `get_p2pkh_address`, `get_p2wpkh_address`,
`get_p2tr_key_path_only_address`, `send_from_p2pkh_address`). They derive a fixed address that is not
bound to the caller's principal, unlike the per-principal endpoints, so different users can end up sharing
one address. They are leftovers from the DFINITY Bitcoin example and should be removed.

## 6. Recovery

Bitcoin addresses and the Lightning funding key derive from the canister ID, the key name and fixed
paths, so they survive anything short of losing the canister ID: reinstalling the same code with the same
network argument gives back the same addresses, and ledger balances are untouched because they live in the
ledger canisters.

Everything in stable memory does not survive a reinstall or an out-of-cycles uninstall: per-LP accounting,
swap and channel records, the relay registration, the admin principal, commitment counters, and the
per-channel secrets. Without those secrets the existing channels cannot be force-closed by the canister —
only a cooperative close remains possible, because the funding key is deterministic.

Take a snapshot before every upgrade (`dfx canister snapshot create`, canister stopped) and keep the
relay's `monitors/` backed up on its side. A snapshot restores canister state; it does nothing for the
relay's channel state.

## 7. Health checks you can run

- Module hash from `dfx canister status` equals the `sha256sum` of the Wasm you installed.
- `get_relay_info` shows the relay principal and pubkey you expect.
- `query_ln_channels` matches the relay's `listchannels`, and each funding output is confirmed on chain
  (the relay's `verifychannels`).
- A completed swap's preimage hashes to its payment hash.
- `get_total_lp_balance` against the on-chain balances of the pool addresses; note that BTC locked in open
  channels is counted separately and that the reported total drifts after channel opens (a known accounting
  issue).
