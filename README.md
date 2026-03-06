# ckLightning-canister

IC canister for the ckLightning bridge. Manages liquidity pools, atomic BTC/ckBTC swaps, channel signing, and fee collection.

## Related Components

| Component | Repo | Role |
|-----------|------|------|
| **ic-lightning-relay** | [perun-network/ic-lightning-relay](https://github.com/perun-network/ic-lightning-relay) | LDK Lightning node — swap execution, invoice creation, channel management |
| **ckLightning-client** | [perun-network/ck-lightning-client](https://github.com/perun-network/ck-lightning-client) | CLI — user-facing swap requests, LP operations, admin |

## Prerequisites

- Rust toolchain (stable, with `wasm32-unknown-unknown` target)
- `dfx` (version 0.29.2, set via `dfxvm default 0.29.2`)
- `candid-extractor` (`cargo install candid-extractor`)
- Bitcoin Core (`bitcoind`) for regtest

## Architecture

- **Liquidity pools**: Dual-asset LP (ckBTC + BTC) with proportional share tracking
- **StableSwap AMM**: Curve-style pricing for BTC ↔ ckBTC swaps with configurable amplification, fees, and slippage limits
- **Channel signing**: Canister holds all channel secrets, signs commitment/HTLC transactions via local ECDSA and chainkey ECDSA
- **Webhook outcalls**: HTTPS outcalls notify the relay on new swap requests
- **Anti-DDoS**: Configurable ICP security deposit on swap requests (refunded on success)

See [ARCHITECTURE.md](ARCHITECTURE.md) for detailed component design, swap flows, and signing mechanics.

## Key Files

```
src/
├── canister.rs                  # #[update]/#[query] endpoints
├── ic_types.rs                  # Candid types (requests, responses, state enums)
├── canister_state/
│   ├── mod.rs                   # CanisterState + access control
│   ├── swap_onramp.rs           # Lightning → ckBTC swap logic
│   ├── swap_offramp.rs          # ckBTC → Lightning swap logic
│   ├── lp_ckbtc.rs              # ckBTC LP operations (deposit/withdraw)
│   ├── lp_btc.rs                # BTC LP operations (deposit/withdraw)
│   ├── ln_channels.rs           # Channel registration and balance tracking
│   ├── channel_funding.rs       # Funding transaction signing
│   ├── commitment_signing.rs    # Commitment transaction signing
│   ├── htlc_signing.rs          # HTLC success/timeout signing
│   ├── htlc_ops.rs              # HTLC state management
│   ├── bolt3_keys.rs            # Channel key derivation
│   ├── admin.rs                 # Admin/fee operations
│   └── http_outcall.rs          # Relay webhook notifications
├── stableswap.rs                # StableSwap AMM implementation
├── liquidity_pool.rs            # LP share accounting
├── htlc.rs                      # HTLC structs and Bitcoin scripts
├── btc/                         # Bitcoin address derivation (P2TR, P2WSH)
└── helpers.rs                   # Shared utilities
```

## Build

```bash
cargo build --release --target wasm32-unknown-unknown
cp target/wasm32-unknown-unknown/release/cklightning.wasm ic/canisters/ckl/
```

## Deploy (local)

```bash
cd ic
./setup_all.sh  # Starts bitcoind + dfx, creates identities, deploys all canisters
```

## License

Copyright 2026 PolyCrypt GmbH. Licensed under [Apache 2.0](LICENSE).
