use chia_streamable_macro::{streamable, Streamable};

use crate::Bytes;

#[cfg(feature = "py-bindings")]
use chia_py_streamable_macro::{PyJsonDict, PyStreamable};

#[repr(u8)]
#[cfg_attr(feature = "py-bindings", derive(PyJsonDict, PyStreamable))]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[derive(Streamable, Hash, Debug, Copy, Clone, Eq, PartialEq)]
pub enum ProtocolMessageTypes {
    // Shared protocol (all services)
    Handshake = 1,

    // Harvester protocol (harvester <-> farmer)
    HarvesterHandshake = 3,
    // NewSignagePointHarvester = 4 Changed to 66 in new protocol
    NewProofOfSpace = 5,
    RequestSignatures = 6,
    RespondSignatures = 7,

    // Farmer protocol (farmer <-> fullNode)
    NewSignagePoint = 8,
    DeclareProofOfSpace = 9,
    RequestSignedValues = 10,
    SignedValues = 11,
    FarmingInfo = 12,

    // Timelord protocol (timelord <-> fullNode)
    NewPeakTimelord = 13,
    NewUnfinishedBlockTimelord = 14,
    NewInfusionPointVdf = 15,
    NewSignagePointVdf = 16,
    NewEndOfSubSlotVdf = 17,
    RequestCompactProofOfTime = 18,
    RespondCompactProofOfTime = 19,

    // Full node protocol (fullNode <-> fullNode)
    NewPeak = 20,
    NewTransaction = 21,
    RequestTransaction = 22,
    RespondTransaction = 23,
    RequestProofOfWeight = 24,
    RespondProofOfWeight = 25,
    RequestBlock = 26,
    RespondBlock = 27,
    RejectBlock = 28,
    RequestBlocks = 29,
    RespondBlocks = 30,
    RejectBlocks = 31,
    NewUnfinishedBlock = 32,
    RequestUnfinishedBlock = 33,
    RespondUnfinishedBlock = 34,
    NewSignagePointOrEndOfSubSlot = 35,
    RequestSignagePointOrEndOfSubSlot = 36,
    RespondSignagePoint = 37,
    RespondEndOfSubSlot = 38,
    RequestMempoolTransactions = 39,
    RequestCompactVDF = 40,
    RespondCompactVDF = 41,
    NewCompactVDF = 42,
    RequestPeers = 43,
    RespondPeers = 44,
    NoneResponse = 91,

    // Wallet protocol (wallet <-> fullNode)
    RequestPuzzleSolution = 45,
    RespondPuzzleSolution = 46,
    RejectPuzzleSolution = 47,
    SendTransaction = 48,
    TransactionAck = 49,
    NewPeakWallet = 50,
    RequestBlockHeader = 51,
    RespondBlockHeader = 52,
    RejectHeaderRequest = 53,
    RequestRemovals = 54,
    RespondRemovals = 55,
    RejectRemovalsRequest = 56,
    RequestAdditions = 57,
    RespondAdditions = 58,
    RejectAdditionsRequest = 59,
    RequestHeaderBlocks = 60,
    RejectHeaderBlocks = 61,
    RespondHeaderBlocks = 62,

    // Introducer protocol (introducer <-> fullNode)
    RequestPeersIntroducer = 63,
    RespondPeersIntroducer = 64,

    // Simulator protocol
    FarmNewBlock = 65,

    // New harvester protocol
    NewSignagePointHarvester = 66,
    RequestPlots = 67,
    RespondPlots = 68,
    PlotSyncStart = 78,
    PlotSyncLoaded = 79,
    PlotSyncRemoved = 80,
    PlotSyncInvalid = 81,
    PlotSyncKeysMissing = 82,
    PlotSyncDuplicates = 83,
    PlotSyncDone = 84,
    PlotSyncResponse = 85,

    // More wallet protocol
    CoinStateUpdate = 69,
    RegisterForPhUpdates = 70,
    RespondToPhUpdates = 71,
    RegisterForCoinUpdates = 72,
    RespondToCoinUpdates = 73,
    RequestChildren = 74,
    RespondChildren = 75,
    RequestSesInfo = 76,
    RespondSesInfo = 77,
    RequestBlockHeaders = 86,
    RejectBlockHeaders = 87,
    RespondBlockHeaders = 88,
    RequestFeeEstimates = 89,
    RespondFeeEstimates = 90,

    // Unfinished block protocol
    NewUnfinishedBlock2 = 92,
    RequestUnfinishedBlock2 = 93,

    // New wallet sync protocol
    RequestRemovePuzzleSubscriptions = 94,
    RespondRemovePuzzleSubscriptions = 95,
    RequestRemoveCoinSubscriptions = 96,
    RespondRemoveCoinSubscriptions = 97,
    RequestPuzzleState = 98,
    RespondPuzzleState = 99,
    RejectPuzzleState = 100,
    RequestCoinState = 101,
    RespondCoinState = 102,
    RejectCoinState = 103,

    // Wallet protocol mempool updates
    MempoolItemsAdded = 104,
    MempoolItemsRemoved = 105,
    RequestCostInfo = 106,
    RespondCostInfo = 107,

    // -------------------------------------------------------------------------
    // DIG L2 consensus band (200-217) — the `DigMessageType` opcodes (#1404).
    // These extend Chia's namespace so a stock `Message` can carry a DIG consensus
    // opcode on the wire (its `msg_type` field is a `ProtocolMessageTypes`). Each
    // value MUST equal the matching `dig_peer_protocol::DigMessageType` discriminant;
    // `frame_dig_message` in dig-gossip converts one to the other losslessly. They are
    // ADDITIVE (§5.1): no existing opcode moves. dig-gossip's `broadcast_dig`/`send_dig`
    // (via `route_dig_message`) are the ONLY sanctioned way to put them on the wire.
    // -------------------------------------------------------------------------
    NewAttestation = 200,
    NewCheckpointProposal = 201,
    NewCheckpointSignature = 202,
    RequestCheckpointSignatures = 203,
    RespondCheckpointSignatures = 204,
    RequestStatus = 205,
    RespondStatus = 206,
    NewCheckpointSubmission = 207,
    ValidatorAnnounce = 208,
    RequestBlockTransactions = 209,
    RespondBlockTransactions = 210,
    ReconciliationSketch = 211,
    ReconciliationResponse = 212,
    StemTransaction = 213,
    PlumtreeLazyAnnounce = 214,
    PlumtreePrune = 215,
    PlumtreeGraft = 216,
    PlumtreeRequestByHash = 217,

    // -------------------------------------------------------------------------
    // DIG dig-gossip extension — introducer registration (DSC-005 / SPEC §6.5).
    // Upstream Chia does not assign these; `dig-gossip` vendors `chia-protocol` to reserve
    // stable opcodes for `RegisterPeer` / `RegisterAck` bodies (`introducer_register_wire.rs`).
    // -------------------------------------------------------------------------
    RegisterPeer = 218,
    RegisterAck = 219,

    // -------------------------------------------------------------------------
    // DIG dig-message directed-envelope transport (WU6 / epic #796, Wave A).
    // Opcode 220 carries a dig-message envelope as OPAQUE bytes in `Message.data`.
    // dig-gossip is the transport only — it never seals/opens the envelope. This
    // is the FIRST opcode of the 220-255 "free" band (200-219 are the consensus
    // band, `DigMessageType`); the canonical constant is `dig_protocol::DIG_MESSAGE`
    // and `crate::service::dig_message::DIG_MESSAGE`.
    // -------------------------------------------------------------------------
    DigMessage = 220,

    // -------------------------------------------------------------------------
    // DIG store-melted broadcast (epic #1316, piece #1).
    // Opcode 221 announces that a dig-store's on-chain coin has been melted so peers
    // stop hosting its `.dig` content. A PUBLIC all-peers flood broadcast (public-by-
    // nature: store deletion is addressed to everyone), signed + mTLS-authenticated,
    // NOT recipient-sealed (§5.4-EXEMPT, same carve-out as L2 consensus gossip). The
    // payload is `StoreMeltedAnnounce` (`crate::service::store_melted`); the canonical
    // constant is `crate::service::store_melted::STORE_MELTED`. Second opcode of the
    // 220-255 "free" band, after `DigMessage = 220`.
    // -------------------------------------------------------------------------
    StoreMelted = 221,

    // -------------------------------------------------------------------------
    // DIG holdings-announce broadcast (#1428, decider-locked spec #1394).
    // Opcode 222 announces a batch of signed holdings add/remove deltas so peers learn
    // which content a provider holds (feeds dig-dht's holder set). A PUBLIC all-peers
    // flood broadcast (public discovery, addressed to everyone), signed + mTLS-
    // authenticated, NOT recipient-sealed (§5.4-EXEMPT, same carve-out as L2 consensus
    // gossip). The payload is `HoldingsAnnounce` (`crate::service::holdings_announce`);
    // the canonical constant is `crate::service::holdings_announce::HOLDINGS_ANNOUNCE`.
    // Third opcode of the 220-255 "free" band, after `StoreMelted = 221`.
    // -------------------------------------------------------------------------
    HoldingsAnnounce = 222,
}

#[cfg(feature = "py-bindings")]
impl chia_traits::ChiaToPython for ProtocolMessageTypes {
    fn to_python<'a>(&self, py: pyo3::Python<'a>) -> pyo3::PyResult<pyo3::Bound<'a, pyo3::PyAny>> {
        Ok(pyo3::IntoPyObject::into_pyobject(*self as u8, py)?
            .clone()
            .into_any())
    }
}

pub trait ChiaProtocolMessage {
    fn msg_type() -> ProtocolMessageTypes;
}

#[repr(u8)]
#[cfg_attr(feature = "py-bindings", derive(PyJsonDict, PyStreamable))]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[derive(Streamable, Hash, Debug, Copy, Clone, Eq, PartialEq)]
pub enum NodeType {
    FullNode = 1,
    Harvester = 2,
    Farmer = 3,
    Timelord = 4,
    Introducer = 5,
    Wallet = 6,
    DataLayer = 7,
}

#[cfg(feature = "py-bindings")]
impl chia_traits::ChiaToPython for NodeType {
    fn to_python<'a>(&self, py: pyo3::Python<'a>) -> pyo3::PyResult<pyo3::Bound<'a, pyo3::PyAny>> {
        Ok(pyo3::IntoPyObject::into_pyobject(*self as u8, py)?
            .clone()
            .into_any())
    }
}

#[streamable(no_serde)]
pub struct Message {
    msg_type: ProtocolMessageTypes,
    id: Option<u16>,
    data: Bytes,
}

#[streamable(message)]
pub struct Handshake {
    // Network id, usually the genesis challenge of the blockchain
    network_id: String,
    // Protocol version to determine which messages the peer supports
    protocol_version: String,
    // Version of the software, to debug and determine feature support
    software_version: String,
    // Which port the server is listening on
    server_port: u16,
    // NodeType (full node, wallet, farmer, etc.)
    node_type: NodeType,
    // Key value dict to signal support for additional capabilities/features
    capabilities: Vec<(u16, String)>,
}
