//  Copyright 2025 PolyCrypt GmbH
//
//  Licensed under the Apache License, Version 2.0 (the "License");
//  you may not use this file except in compliance with the License.
//  You may obtain a copy of the License at
//
//    http://www.apache.org/licenses/LICENSE-2.0
//
//  Unless required by applicable law or agreed to in writing, software
//  distributed under the License is distributed on an "AS IS" BASIS,
//  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//  See the License for the specific language governing permissions and
//  limitations under the License.

use bitcoin::Txid;
use bitcoin_scripts::PubkeyScript;
use bitcoin_scripts::hlc::HashLock;
use internet2::addr::{NodeAddr, NodeId};
use internet2::presentation::sphinx::Hop;
use lnp::channel::bolt::{CommonParams, LocalKeyset, PeerParams, Policy};
use lnp::p2p::bolt::{ChannelId, OpenChannel, PaymentOnion, TempChannelId};
use lnp::router::gossip::LocalChannelInfo;
use lnp_rpc::{ChannelInfo, Failure, PeerInfo};
use microservices::esb::ClientId;
use microservices::util::OptionDetails;
use strict_encoding::{NetworkDecode, NetworkEncode};
use wallet::psbt::Psbt;

// use crate::rpc::ServiceId;
use lnp_rpc::ServiceId;
// use microservices::rpc::ServiceId;

/// RPC API requests over CTL message bus between LNP Node daemons and from/to clients.
#[derive(Clone, Debug, NetworkEncode, NetworkDecode)]
#[non_exhaustive]
pub enum CtlMsg {
    // #[display("hello()")]
    Hello,

    // Node connectivity API
    // ---------------------
    // Sent from lnpd to peerd
    // #[display("get_info()")]
    GetInfo,

    // #[display("ping_peer()")]
    PingPeer,

    // Channel creation API
    // --------------------
    /// Initiates creation of a new channel by a local node. Sent from lnpd to a newly instantiated
    /// channeld.
    // #[display("open_channel_with({0})")]
    OpenChannelWith(OpenChannelWith),

    /// Initiates acceptance of a new channel proposed by a remote node. Sent from lnpd to a newly
    /// instantiated channeld.
    AcceptChannelFrom(AcceptChannelFrom),

    /// Constructs funding PSBT to fund a locally-created new channel. Sent from peerd to lnpd.
    ConstructFunding(FundChannel),

    /// Provides channeld with the information about funding transaction output used to fund the
    /// newly created channel. Sent from lnpd to channeld.
    FundingConstructed(Psbt),

    /// Signs previously prepared funding transaction and publishes it to bitcoin network. Sent
    /// from channeld to lnpd upon receival of `funding_signed` message from a remote peer.
    PublishFunding,

    FundingConfirmed,

    // On-chain tracking API
    // ---------------------
    /// Asks on-chain tracking service to send updates on the transaction mining status.
    ///
    /// Depth 0 indicates that a transaction must be tracked in a mempool.
    Track {
        txid: Txid,
        depth: u32,
    },

    /// Asks on-chain tracking service to stop sending updates on the transaction mining status
    Untrack(Txid),

    /// Reports changes in the mining status for previously requested transaction tracked by an
    /// on-chain service
    TxFound(TxStatus),

    // Routing & payments
    /// Request to channel daemon to perform payment using provided route
    Payment {
        route: Vec<Hop<PaymentOnion>>,
        hash_lock: HashLock,
        enquirer: ClientId,
    },

    /// Notifies routing daemon about a new local channel
    ChannelCreated(LocalChannelInfo),

    /// Notifies routing daemon to remove information about a local channel
    ChannelClosed(ChannelId),

    /// Notifies routing daemon new balance of a local channel
    ChannelBalanceUpdate {
        channel_id: ChannelId,
        local_amount_msat: u64,
        remote_amount_msat: u64,
    },

    // Key-related tasks
    // -----------------
    Sign(Psbt),

    Signed(Psbt),

    // lnpd -> signd
    DeriveKeyset(u64),

    // signd -> lnpd
    Keyset(ServiceId, LocalKeyset),

    // Responses
    // ---------
    Report(Report),

    /// Error returned back by response-reply type of daemons (like signed) in case if the
    /// operation has failed.
    Error {
        destination: ServiceId,
        request: String,
        error: String,
    },

    /// Error returned if the destination service is offline
    EsbError {
        destination: ServiceId,
        error: String,
    },

    PeerInfo(PeerInfo),

    ChannelInfo(ChannelInfo),

    // Channel tasks
    // -----------------
    ChannelUpdate {
        old_id: TempChannelId,
        new_id: ChannelId,
    },

    // ckLightning events and commands
    CKLightningDepositRequest {
        amount: u64,
        destination: String,
        source: bitcoin::secp256k1::PublicKey,
    },

    // construct funding
    FundingRequest {
        amount: u64,
        destination: String,
        source: String,
    }, //bitcoin::secp256k1::PublicKey },

    CKLightningDepositApproved {
        destination: String,
    },

    CkBtcLiquidityRequest {
        request: u64,
        account: String,
        amount: u64,
    },

    CKLightningWithdraw {
        destination_pk: bitcoin::secp256k1::PublicKey,
        destination_id: bitcoin::XpubIdentifier,
        account: String,
        source: String,
        amount: u64,
    },

    AssertBTCDeposit {
        destination_pk: bitcoin::secp256k1::PublicKey,
        destination_id: bitcoin::XpubIdentifier,
        account: String,
        source: String,
        amount: u64,
    },

    CkBtcDeposit {
        request: u64,
        account: String,
        amount: u64,
    },

    CkBtcResponse {
        request: u64,
        status: bool,
    },

    CkBtcInvoice {
        account_user: String,
        account_node: String,
        amount: u64,
        invoice: String,
    },
    CkBtcWithdraw {
        request: u64,
        account: String,
        receiver: String,
        amount: u64,
    },
    CkBtcApprove {
        request: u64,
        account: String,
        approved_by: String,
        amount: u64,
    },
    CkBtcTransfer {
        request: u64,
        account: String,
        amount: u64,
    },
}

impl CtlMsg {
    pub fn with_error(
        destination: &ServiceId,
        message: &CtlMsg,
        err: &impl std::error::Error,
    ) -> CtlMsg {
        CtlMsg::Error {
            destination: destination.clone(),
            request: format!("{:?}", message),
            error: err.to_string(),
        }
    }
}

/// Request configuring newly launched channeld instance
#[derive(Clone, PartialEq, Eq, Debug, NetworkEncode, NetworkDecode)]
pub struct OpenChannelWith {
    /// Node to open a channel with
    pub remote_peer: NodeAddr,

    /// Client identifier to report about the progress
    pub report_to: Option<ClientId>,

    /// Amount of satoshis for channel funding
    pub funding_sat: u64,

    /// Amount of millisatoshis to pay to the remote peer at the channel opening
    pub push_msat: u64,

    /// Channel policies
    pub policy: Policy,

    /// Channel common parameters
    pub common_params: CommonParams,

    /// Channel local parameters
    pub local_params: PeerParams,

    /// Channel local keyset
    pub local_keys: LocalKeyset,
}

/// Request configuring newly launched channeld instance
#[derive(Clone, PartialEq, Eq, Debug, NetworkEncode, NetworkDecode)]
pub struct AcceptChannelFrom {
    /// Node to open a channel with
    pub remote_id: NodeId,

    /// Client identifier to report about the progress
    pub report_to: Option<ServiceId>,

    /// Channel policies
    pub policy: Policy,

    /// Channel common parameters
    pub common_params: CommonParams,

    /// Channel local parameters
    pub local_params: PeerParams,

    /// Channel local keyset
    pub local_keys: LocalKeyset,

    /// Request received from a remote peer to open channel
    pub channel_req: OpenChannel,
}

/// Request information about constructing funding transaction
#[derive(Clone, PartialEq, Eq, Debug, NetworkEncode, NetworkDecode)]
pub struct FundChannel {
    /// Address for the channel funding
    pub script_pubkey: PubkeyScript,

    /// Amount of funds to be sent to the funding address
    pub amount: u64,

    /// Fee rate to use for the funding transaction, per kilo-weight unit
    pub feerate_per_kw: Option<u32>,
}

/// TODO: Move to descriptor wallet
/// Information about block position and transaction position in a block
#[derive(
    Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug, NetworkEncode, NetworkDecode,
)]
pub struct BlockPos {
    /// Depths from the chain tip; always greater than 0
    pub depth: u32,

    /// Height of the block containing transaction
    pub height: u32,

    /// Transaction position within the block
    pub pos: u32,
}

/// TODO: Move to descriptor wallet
/// Update on a transaction mining status
#[derive(
    Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug, NetworkEncode, NetworkDecode,
)]
pub struct TxStatus {
    /// Id of a transaction previously requested to be tracked
    pub txid: Txid,

    /// Optional block position given only if the depth is greater than 0 zero
    pub block_pos: Option<BlockPos>,
}

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug, NetworkEncode, NetworkDecode)]
pub struct Report {
    pub client: ClientId,
    pub status: Status,
}

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug, NetworkEncode, NetworkDecode)]
pub enum Status {
    Progress(String),

    Success(OptionDetails),

    Failure(Failure),
}
