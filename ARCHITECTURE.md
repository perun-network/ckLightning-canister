# Architecture

## Overview

The ckLightning canister is the trust anchor of the system. It holds all channel secrets and the channel funding key, signs all channel transactions, manages liquidity pools, executes atomic BTC/ckBTC swaps, and enforces access control. The relay and client interact with the canister via Candid endpoints. The relay keeps its own node seed (node identity, and the LDK payout/sweep scripts used when channels close); it cannot produce channel signatures without the canister.

_Updated 2026-09-15 for the handover; verified against `main` and `staging-april-deployment`._

## State Model (canister_state/)

All mutable state lives in a global `RwLock<CanisterState>` (`lazy_static`). On upgrade the whole state is Candid-encoded into stable memory (`pre_upgrade`) and restored in `post_upgrade`, which also runs migrations. A full reinstall or an out-of-cycles uninstall loses everything below, including the non-recreatable channel secrets. Selected fields:

```
CanisterState
├── Swap Requests
│   ├── onramp_requests: HashMap<RequestId, OnrampRequestInfo>
│   ├── offramp_requests: HashMap<RequestId, OfframpRequestInfo>
│   └── swaps: HashMap<PaymentHash, SwapInfo>
│
├── Lightning Channels
│   ├── ln_channels: HashMap<ChannelId, LnChannelInfo>
│   ├── channel_balances: HashMap<ChannelId, LnChannelBalance>
│   ├── channel_secrets: HashMap<ChannelId, ChannelSecretsInternal>
│   ├── channel_counterparty_pubkeys: HashMap<ChannelId, Vec<u8>>
│   ├── channel_commitment_state: HashMap<ChannelId, ChannelCommitmentState>  (obscure factor, highest counterparty commitment)
│   ├── htlc_tx_details: HashMap<ChannelId, HtlcTxDetails>
│   ├── htlc_manager: HtlcManager
│   ├── channel_funding_reservations / funded_channels
│   └── reserved_utxos: HashMap<Outpoint, ChannelId>
│
├── Liquidity Pool
│   ├── liq_pool: LiquidityPool
│   │   ├── holdings_total: HashMap<PoolAsset, Nat>
│   │   └── depositors: HashMap<Principal, DepositorBalance>
│   ├── processed_utxos: HashMap<Outpoint, Principal>
│   ├── lp_btc_address: Option<String>
│   └── btc_liquidity_addresses: HashMap<Principal, String>
│
├── Admin & Config
│   ├── admin: Option<Principal>
│   ├── stableswap_config: StableSwapConfig
│   ├── icp_ddos_fee_e8s: u64
│   ├── protocol_fees_ckbtc: u64
│   ├── max_single_swap_sats / max_hourly_swap_sats (0 = disabled)
│   ├── known_txs, active_onramp_ids, active_offramp_ids, reserved_ckbtc_sats
│   └── registered_relay: Option<RelayRegistration>  (principal, node pubkey, webhook URL + token)
│
└── Rate Limiting
    ├── onramp_rate_limits: HashMap<Principal, RateLimitInfo>
    └── offramp_rate_limits: HashMap<Principal, RateLimitInfo>
```

## Swap Flows

### Onramp: Lightning → ckBTC

```
State: Pending → Ready → Completed (or Expired after 30 min)
```

1. **Client** calls `request_onramp_invoice(recipient, amount_sats)`
   - Canister collects ICP anti-DDoS fee via ICRC-2 `transfer_from`
   - Creates pending request, fires webhook to relay
2. **Relay** polls `get_pending_invoice_requests()`, creates BOLT11 invoice
3. **Relay** calls `submit_invoice(request_id, invoice, payment_hash)`
   - Canister verifies invoice was created by registered relay (anti-substitution)
   - Request transitions to Ready
4. **Client** polls `get_invoice_by_request(request_id)` for the invoice
5. User pays invoice via external Lightning wallet
6. **Relay** receives payment, calls `complete_swap(payment_hash, preimage)`
   - Under one write lock: checks the swap is `Pending`, marks it `InFlight`, prices it via StableSwap, checks swap caps, debits LPs proportionally
   - Transfers ckBTC to the recipient (ICRC-1 with `created_at_time` for ledger deduplication)
   - On transfer error: restores the LP debit and marks the swap `Failed` (terminal — there is no retry endpoint)
   - On success: marks `Completed`, refunds the ICP fee to the requester

### Offramp: ckBTC → Lightning

```
State: Pending → PaymentInProgress → Completed/Failed (or Expired after 10 min)
```

1. **Client** calls `request_offramp(invoice, fallback_address)`
   - Canister parses invoice, computes ckBTC cost via StableSwap
   - Collects ICP fee + ckBTC via ICRC-2 `transfer_from`
   - Creates pending request, fires webhook to relay
2. **Relay** polls `get_pending_offramp_requests()`, pays Lightning invoice
3. On success: **Relay** calls `complete_offramp(request_id, payment_hash, preimage)`
   - Canister verifies preimage matches payment_hash (SHA256)
   - Credits ckBTC to LP proportionally, refunds ICP fee
4. On failure: **Relay** calls `fail_offramp(request_id)`
   - Canister refunds ckBTC to user (ICP fee not refunded)

## Channel Signing

The canister holds all channel secrets and performs two types of signing:

### Chainkey ECDSA (via IC management canister)
- Used for: funding key operations (commitment signatures, cooperative close, channel funding, anchor inputs)
- Latency: 2–4 seconds (IC subnet consensus); ~26 B cycles per signature
- Key name from the init `Network` (`src/lib.rs:122-126`): `dfx_test_key` on regtest, `test_key_1` on testnet **and** mainnet
- One funding key for all channels, derivation path `["lightning", "funding"]` (`src/helpers.rs`); deterministic, so it survives a reinstall on the same canister ID

### Canister-local ECDSA (secp256k1 in WASM)
- Used for: HTLC signatures, justice/penalty transactions, revocation
- Latency: < 1 ms
- Keys derived from per-channel secrets generated via `raw_rand()` and stored in canister state
- The relay never sees these secrets — it only receives the resulting signatures

### Per-Channel Secret Generation

When `generate_channel_secrets()` is called, the canister uses IC's `raw_rand()` to generate a master seed, then derives 5 secrets via HMAC-SHA256(master_seed, channel_keys_id ‖ tag). The master seed is not kept, so the secrets cannot be recreated if canister state is lost:

| Secret | Purpose |
|--------|---------|
| `htlc_base_secret` | Derive per-HTLC signing keys |
| `revocation_base_secret` | Derive penalty/justice keys |
| `delayed_payment_base_secret` | Delayed payment outputs |
| `payment_secret` | Payment basepoint |
| `commitment_seed` | Per-commitment secret tree (BOLT-3) |

### Signing Flow (Counterparty Commitment)

1. Relay serializes full commitment tx + HTLC txs
2. Relay calls `sign_counterparty_commitment(tx_bytes, htlcs, ...)`
3. Canister computes P2WSH sighash for funding input
4. Canister signs with **chainkey ECDSA** → `commitment_sig`
5. For each HTLC: derive key from `htlc_base_secret` + `per_commitment_point`, sign with **local ECDSA** → `htlc_sig`
6. Return `(commitment_sig, vec![htlc_sigs])`

The canister also extracts the commitment number (BOLT-3 obscured `locktime`/`sequence`, using the obscure factor stored by `register_channel_info`) and records the highest counterparty commitment it has signed.

### Holder Commitment (Force-Close)

1. Relay calls `sign_holder_commitment_v2` with the commitment transaction and the counterparty's signature
2. Canister rejects commitment numbers behind the recorded counter ("Stale commitment rejected") — protection against broadcasting revoked states
3. Canister signs with chainkey ECDSA, builds the 2-of-2 witness and broadcasts via the IC Bitcoin API

The commitment-number direction fix (`96d0fda`, forward-counting numbers plus a `post_upgrade` migration) is on `staging-april-deployment` only; without it, force-close with the latest state is rejected.

## Liquidity Pool (liquidity_pool.rs)

Dual-asset pool: ckBTC (on-chain ICRC-1) + BTC (on-chain Bitcoin via threshold ECDSA).

### Proportional Distribution

All pool operations distribute costs/returns proportionally across LPs:

```
per_lp_amount = total_amount × (lp_balance / total_pool_balance)
```

- Channel funding: `deduct_proportional(BTC)` — all LPs share the cost
- Channel closure: `credit_proportional(BTC)` — returned BTC shared among LPs
- Offramp completion: `credit_proportional(CkBTC)` — LPs receive ckBTC from user
- Fee redistribution: `credit_proportional(CkBTC)` — protocol fees shared among LPs

### BTC Pool

Per-user P2WPKH addresses derived via chainkey ECDSA from each depositor's principal. The canister tracks which UTXOs belong to which LP via `processed_utxos`. Deposits require `REQUIRED_BTC_CONFIRMATIONS` confirmations (`src/canister_state/lp_btc.rs:31`): 6 on `main`, 1 on `staging-april-deployment`. UTXO queries use `bitcoin_get_utxos` without pagination or a minimum-confirmation filter. BTC is only visible once the IC Bitcoin canister has synced the block (lags of ~20 minutes were observed on testnet4).

## StableSwap AMM (stableswap.rs)

Curve-style invariant: `4A(x+y) + D = 4AD + D³/(4xy)`

### Parameters (StableSwapConfig)

| Parameter | Description | Default |
|-----------|-------------|---------|
| `amplification` | Curve flatness near balance (higher = flatter) | 200 |
| `fee_bps` | Base swap fee (basis points) | 10 (0.1%) |
| `protocol_fee_share_bps` | Protocol's share of fees | 5000 (50%) |
| `imbalance_fee_bps` | Additional fee at max imbalance | 100 |
| `rebate_bps` | Discount for rebalancing swaps | 0 (disabled) |
| `max_slippage_bps` | Max price impact before rejection | 500 |
| `max_swap_pct_bps` | Max single swap as % of output pool | 0 (disabled) |

Defaults from `CanisterState` initialisation (`src/canister_state/mod.rs`); change at runtime with `update_stableswap_config` (admin).

### Pricing

- Newton-Raphson iteration to solve invariant for output amount
- Dynamic fee: scales with pool imbalance (more imbalanced = higher fee)
- Rebate: swaps that improve balance get a fee discount
- Supports both directions: `BtcToCkbtc` and `CkbtcToBtc`

## Access Control

| Caller | Can Do |
|--------|--------|
| **Controller** (deployer) | `set_admin`, `register_relay` |
| **Admin** | `update_stableswap_config`, `withdraw_protocol_fees`, `redistribute_fees`, `set_icp_ddos_fee`, `withdraw_icp_fees`, `set_swap_caps`, `prune_state`, `set_test_timeouts`, `register_relay`, `retry_offramp_refund` |
| **Relay** (registered) | `register_relay` (re-register), `retry_offramp_refund`, `submit_invoice`, `complete_swap`, `mark_offramp_in_progress`, `complete_offramp`, `fail_offramp`, `fund_channel`, `channel_funded`, `channel_closed`, all channel signing endpoints, `get_pending_*` queries |
| **Any user** | `request_onramp_invoice`, `request_offramp`, LP operations, user BTC operations, balance queries |

Two layers: `inspect_message` (`src/canister.rs:857-936`) rejects ingress update calls from the wrong role before arguments are decoded (unknown methods are rejected), and the relay-only endpoints and sensitive queries additionally call `assert_relay_caller()`. `register_relay` stores the **caller** as the relay principal; a different principal cannot replace an existing registration.

## Anti-DDoS Protections

- ICP fee: collected upfront on swap requests (initial value 1 ICP, admin-configurable), refunded only on success
- Rate limiting: 10 requests per hour per principal per direction
- Swap timeouts: 30 min (onramp), 10 min (offramp) — checked by the `#[heartbeat]`, which runs every consensus round and therefore burns cycles continuously
- Swap caps: per-swap and hourly volume limits, disabled (0) until an admin sets them

## HTTP Outcalls (http_outcall.rs)

Fire-and-forget HTTPS outcalls to relay webhook on new swap requests:

- `POST /webhook/onramp` and `POST /webhook/offramp`
- Auth via `Authorization: Bearer <token>`
- Transform function ensures deterministic response across IC replicas
- Errors logged but never block the update call

## Endpoints (canister.rs)

91 Candid endpoints (67 update, 23 query, 1 heartbeat), organized by category:

| Category | Key Endpoints |
|----------|--------------|
| Onramp | `request_onramp_invoice`, `get_pending_invoice_requests`, `submit_invoice`, `get_invoice_by_request`, `complete_swap` |
| Offramp | `request_offramp`, `get_pending_offramp_requests`, `mark_offramp_in_progress`, `complete_offramp`, `fail_offramp`, `retry_offramp_refund`, `get_offramp_status` |
| LP (ckBTC) | `deposit_ckbtc`, `withdraw_ckbtc`, `get_my_lp_balance`, `get_total_lp_balance` |
| LP (BTC) | `get_lp_btc_user_address`, `deposit_btc_user`, `withdraw_btc`, `get_lp_liquidity_status` |
| Channels | `register_ln_channel`, `verify_ln_channel`, `query_ln_channels`, `fund_channel`, `get_funding_utxos`, `channel_funded`, `channel_closed`, `cancel_channel_funding`, `update_channel_balance` |
| Signing | `get_ln_funding_pubkey`, `generate_channel_secrets`, `register_channel_info`, `get_per_commitment_point`, `release_commitment_secret`, `sign_counterparty_commitment`, `sign_holder_commitment_v2`, `sign_closing_tx`, `sign_justice_tx`, `sign_htlc_tx`, `sign_ln_message` (legacy) |
| HTLC | `create_htlc_with_tx_details`, `sign_htlc_success`, `sign_htlc_timeout` |
| Relay | `register_relay`, `get_relay_info`, `transform_webhook_response` |
| Admin | `set_admin`, `update_stableswap_config`, `withdraw_protocol_fees`, `redistribute_fees`, `set_icp_ddos_fee`, `withdraw_icp_fees`, `set_swap_caps`, `prune_state`, `set_test_timeouts` |
| User BTC | `get_depositor_btc_balance`, `send_btc_from_depositor_address`, `get_btc_balance` |
| Queries | `get_swap_quote`, `get_stableswap_config`, `get_icp_ddos_fee`, `get_rate_limit_status`, `get_timeout_values`, `get_expired_swap_counts_query`, `get_state_stats` |

The address example endpoints in `src/btc/address.rs` (`get_p2pkh_address`, `send_from_p2pkh_address`, …) are left over from the DFINITY Bitcoin example and are rejected by `inspect_message`.
