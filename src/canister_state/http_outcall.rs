// =============================================================================
// HTTPS Outcall Helper for Relay Webhook Notifications
// =============================================================================

use super::STATE;
use ic_cdk::management_canister::{
    http_request, transform_context_from_query,
    HttpHeader, HttpMethod, HttpRequestArgs, HttpRequestResult, TransformArgs,
};

/// Notify the relay via HTTPS outcall (fire-and-forget).
///
/// Sends a POST to the relay's webhook endpoint to wake it immediately.
/// Errors are logged but never propagated — the 30s fallback polling
/// catches anything missed.
pub fn notify_relay_webhook(path: &str) {
    // Read relay URL + token from state
    let (url, token) = {
        let state = STATE.read().expect("STATE lock: notify_relay_webhook");
        match &state.registered_relay {
            Some(relay) => {
                match (&relay.relay_http_url, &relay.relay_auth_token) {
                    (Some(url), Some(token)) => (url.clone(), token.clone()),
                    _ => return, // No webhook configured, skip silently
                }
            }
            None => return,
        }
    };

    let full_url = format!("{url}{path}");

    // Fire-and-forget: spawn the outcall, don't block the update call
    ic_cdk::futures::spawn(async move {
        let request = HttpRequestArgs {
            url: full_url.clone(),
            method: HttpMethod::POST,
            headers: vec![
                HttpHeader {
                    name: "Content-Type".to_string(),
                    value: "application/json".to_string(),
                },
                HttpHeader {
                    name: "Authorization".to_string(),
                    value: format!("Bearer {token}"),
                },
            ],
            body: Some(br#"{"request_id":null}"#.to_vec()),
            max_response_bytes: Some(256),
            transform: Some(transform_context_from_query(
                "transform_webhook_response".to_string(),
                vec![],
            )),
        };

        match http_request(&request).await {
            Ok(_response) => {
                ic_cdk::println!("Webhook outcall to {} succeeded", full_url);
            }
            Err(e) => {
                ic_cdk::println!(
                    "Webhook outcall to {} failed: {:?}",
                    full_url, e
                );
            }
        }
    });
}

/// Transform function for HTTPS outcalls (required by IC consensus).
///
/// All replicas must produce the same response. We extract just the status code
/// and discard the body, ensuring deterministic consensus across replicas.
pub fn transform_webhook_response(args: TransformArgs) -> HttpRequestResult {
    HttpRequestResult {
        status: args.response.status,
        headers: vec![],
        body: vec![],
    }
}
