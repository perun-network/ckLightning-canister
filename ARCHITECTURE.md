# Architecture

## Overview

The ckLightning canister is the trust anchor of the system. It holds all channel secrets, signs all channel transactions, manages liquidity pools, executes atomic BTC/ckBTC swaps, and enforces access control. The relay and client interact with the canister via Candid endpoints — neither holds any keys that can move funds.

## State Model (canister_state/)

All mutable state lives in a global `RwLock<CanisterState>`:

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
│   ├── htlc_tx_details: HashMap<ChannelId, HtlcTxDetails>
│   ├── htlc_manager: HtlcManager
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
│   └── registered_relay: Option<RelayRegistration>
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
   - Canister transfers ckBTC from LP to recipient
   - Refunds ICP fee to requester

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
- Latency: 2–4 seconds (IC subnet consensus)
- The funding pubkey is derived from a canister-specific derivation path

### Canister-local ECDSA (secp256k1 in WASM)
- Used for: HTLC signatures, justice/penalty transactions, revocation
- Latency: < 1 ms
- Keys derived from per-channel secrets generated via `raw_rand()` and stored in canister state
- The relay never sees these secrets — it only receives the resulting signatures

### Per-Channel Secret Generation

When `generate_channel_secrets()` is called, the canister uses IC's `raw_rand()` to generate a master seed, then derives 5 secrets via HMAC-SHA256:

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

## Liquidity Pool (liquidity_pool.rs)

Dual-asset pool: ckBTC (on-chain ICRC-1) + BTC (on-chain Bitcoin via threshold ECDSA).

### Proportional Distribution

All pool operations distribute costs/returns proportionally across LPs:

```
per_lp_amount = total_amount × (lp_balance / total_pool_balance)
```

- **Channel funding**: `deduct_proportional(BTC)` — all LPs share the cost
- **Channel closure**: `credit_proportional(BTC)` — returned BTC shared among LPs
- **Offramp completion**: `credit_proportional(CkBTC)` — LPs receive ckBTC from user
- **Fee redistribution**: `credit_proportional(CkBTC)` — protocol fees shared among LPs

### BTC Pool

Single shared P2WPKH address derived via chainkey ECDSA. The canister tracks which UTXOs belong to which LP via `processed_utxos`. Deposits require 6 confirmations.

## StableSwap AMM (stableswap.rs)

Curve-style invariant: `4A(x+y) + D = 4AD + D³/(4xy)`

### Parameters (StableSwapConfig)

| Parameter | Description | Default |
|-----------|-------------|---------|
| `amplification` | Curve flatness near balance (higher = flatter) | ~100 |
| `fee_bps` | Base swap fee (basis points) | ~25 (0.25%) |
| `protocol_fee_share_bps` | Protocol's share of fees | — |
| `imbalance_fee_bps` | Additional fee at max imbalance | — |
| `rebate_bps` | Discount for rebalancing swaps | — |
| `max_slippage_bps` | Max price impact before rejection | — |
| `max_swap_pct_bps` | Max single swap as % of output pool | — |

### Pricing

- Newton-Raphson iteration to solve invariant for output amount
- Dynamic fee: scales with pool imbalance (more imbalanced = higher fee)
- Rebate: swaps that improve balance get a fee discount
- Supports both directions: `BtcToCkbtc` and `CkbtcToBtc`

## Access Control

| Caller | Can Do |
|--------|--------|
| **Controller** (deployer) | `set_admin` |
| **Admin** | `update_stableswap_config`, `withdraw_protocol_fees`, `redistribute_fees`, `set_icp_ddos_fee`, `withdraw_icp_fees`, `register_relay` |
| **Relay** (registered) | `submit_invoice`, `complete_swap`, `complete_offramp`, `fail_offramp`, `get_pending_*` |
| **Any user** | `request_onramp_invoice`, `request_offramp`, LP operations, balance queries |

Relay-only endpoints are guarded by `assert_relay_caller()` which checks the caller principal matches the registered relay.

## Anti-DDoS Protections

- **ICP fee**: collected upfront on swap requests (default 1 ICP), refunded only on success
- **Rate limiting**: 10 requests per hour per principal per direction
- **Swap timeouts**: 30 min (onramp), 10 min (offramp) — checked via heartbeat

## HTTP Outcalls (http_outcall.rs)

Fire-and-forget HTTPS outcalls to relay webhook on new swap requests:

- `POST /webhook/onramp` and `POST /webhook/offramp`
- Auth via `Authorization: Bearer <token>`
- Transform function ensures deterministic response across IC replicas
- Errors logged but never block the update call

## Endpoints (canister.rs)

50+ Candid endpoints organized by category:

| Category | Key Endpoints |
|----------|--------------|
| Onramp | `request_onramp_invoice`, `get_pending_invoice_requests`, `submit_invoice`, `complete_swap` |
| Offramp | `request_offramp`, `get_pending_offramp_requests`, `complete_offramp`, `fail_offramp` |
| LP (ckBTC) | `deposit_ckbtc`, `withdraw_ckbtc`, `get_my_lp_balance`, `get_total_lp_balance` |
| LP (BTC) | `get_lp_btc_address`, `deposit_btc`, `withdraw_btc` |
| Channels | `register_ln_channel`, `verify_ln_channel`, `fund_channel` |
| Signing | `generate_channel_secrets`, `sign_counterparty_commitment`, `sign_holder_commitment`, `sign_closing_tx`, `sign_justice_tx`, `sign_htlc_tx` |
| HTLC | `create_htlc_with_tx_details`, `sign_htlc_success`, `sign_htlc_timeout` |
| Admin | `set_admin`, `update_stableswap_config`, `withdraw_protocol_fees`, `redistribute_fees` |
| User BTC | `get_depositor_btc_address`, `get_depositor_btc_balance`, `send_btc_from_depositor` |
| Queries | `get_invoice_by_request`, `get_offramp_status`, `get_swap_quote`, `query_state` |
