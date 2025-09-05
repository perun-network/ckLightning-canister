use candid::{CandidType, Deserialize};
use serde::Serialize;

#[derive(Clone, Debug, CandidType, Deserialize, Serialize)]
pub enum SimpleCtlMsg {
    Hello,
    Track { txid: [u8; 32], depth: u32 },
}

impl SimpleCtlMsg {
    pub fn new_track(txid: [u8; 32], depth: u32) -> Self {
        SimpleCtlMsg::Track { txid, depth }
    }
}
