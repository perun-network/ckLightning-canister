// =============================================================================
// HTLC State Management
// =============================================================================

use super::STATE;
use crate::ic_types::{
    CreateHtlcRequest, CreateHtlcResponse,
    FulfillHtlcRequest, FulfillHtlcResponse,
    TimeoutHtlcRequest, TimeoutHtlcResponse,
    HtlcInfo,
};

/// Create a new HTLC
///
/// Called by the relay when an HTLC is added to a commitment transaction.
/// The canister tracks the HTLC state for later fulfillment or timeout.
pub fn create_htlc_impl(request: CreateHtlcRequest) -> CreateHtlcResponse {
    let payment_hash: [u8; 32] = match request.payment_hash.try_into() {
        Ok(h) => h,
        Err(_) => {
            return CreateHtlcResponse {
                success: false,
                error: Some("Invalid payment_hash length (expected 32 bytes)".to_string()),
            }
        }
    };

    if request.sender_pubkey.len() != 33 {
        return CreateHtlcResponse {
            success: false,
            error: Some("Invalid sender_pubkey length (expected 33 bytes)".to_string()),
        };
    }

    if request.receiver_pubkey.len() != 33 {
        return CreateHtlcResponse {
            success: false,
            error: Some("Invalid receiver_pubkey length (expected 33 bytes)".to_string()),
        };
    }

    let mut state = STATE.write().expect("STATE lock: create_htlc");
    match state.htlc_manager.add_htlc(
        payment_hash,
        request.amount_msat,
        request.cltv_expiry,
        request.sender_pubkey,
        request.receiver_pubkey,
    ) {
        Ok(()) => CreateHtlcResponse {
            success: true,
            error: None,
        },
        Err(e) => CreateHtlcResponse {
            success: false,
            error: Some(e),
        },
    }
}

/// Fulfill an HTLC by revealing the preimage
///
/// Called by the relay when a preimage is received (payment successful).
/// Returns the payment_hash and amount for confirmation.
pub fn fulfill_htlc_impl(request: FulfillHtlcRequest) -> FulfillHtlcResponse {
    let mut state = STATE.write().expect("STATE lock: fulfill_htlc");
    match state.htlc_manager.fulfill_htlc(request.preimage) {
        Ok((payment_hash, amount_msat)) => FulfillHtlcResponse {
            success: true,
            payment_hash: Some(payment_hash.to_vec()),
            amount_msat: Some(amount_msat),
            error: None,
        },
        Err(e) => FulfillHtlcResponse {
            success: false,
            payment_hash: None,
            amount_msat: None,
            error: Some(e),
        },
    }
}

/// Timeout an HTLC after CLTV expiry
///
/// Called by the relay when an HTLC has expired without being fulfilled.
/// The sender can reclaim the funds.
pub fn timeout_htlc_impl(request: TimeoutHtlcRequest) -> TimeoutHtlcResponse {
    let payment_hash: [u8; 32] = match request.payment_hash.try_into() {
        Ok(h) => h,
        Err(_) => {
            return TimeoutHtlcResponse {
                success: false,
                amount_msat: None,
                error: Some("Invalid payment_hash length (expected 32 bytes)".to_string()),
            }
        }
    };

    let mut state = STATE.write().expect("STATE lock: timeout_htlc");
    match state.htlc_manager.timeout_htlc(&payment_hash) {
        Ok(amount_msat) => TimeoutHtlcResponse {
            success: true,
            amount_msat: Some(amount_msat),
            error: None,
        },
        Err(e) => TimeoutHtlcResponse {
            success: false,
            amount_msat: None,
            error: Some(e),
        },
    }
}

/// Get an HTLC by payment hash
pub fn get_htlc_impl(payment_hash: Vec<u8>) -> Option<HtlcInfo> {
    let payment_hash: [u8; 32] = payment_hash.try_into().ok()?;
    let state = STATE.read().expect("STATE lock: get_htlc");
    state.htlc_manager.get_htlc(&payment_hash).map(|htlc| HtlcInfo {
        payment_hash: htlc.payment_hash.to_vec(),
        amount_msat: htlc.amount_msat,
        cltv_expiry: htlc.cltv_expiry,
        state: format!("{:?}", htlc.state),
        sender_pubkey: htlc.sender_pubkey.clone(),
        receiver_pubkey: htlc.receiver_pubkey.clone(),
    })
}

/// Get all pending HTLCs
pub fn get_pending_htlcs_impl() -> Vec<HtlcInfo> {
    let state = STATE.read().expect("STATE lock: get_pending_htlcs");
    state
        .htlc_manager
        .pending_htlcs()
        .iter()
        .map(|htlc| HtlcInfo {
            payment_hash: htlc.payment_hash.to_vec(),
            amount_msat: htlc.amount_msat,
            cltv_expiry: htlc.cltv_expiry,
            state: format!("{:?}", htlc.state),
            sender_pubkey: htlc.sender_pubkey.clone(),
            receiver_pubkey: htlc.receiver_pubkey.clone(),
        })
        .collect()
}
