//! MS-EVEN6 — the EventLog Remoting Protocol v6, the Vista-era replacement for MS-EVEN.
//! Speaks over MS-RPCE (SMB named pipe `\pipe\eventlog`, interface UUID
//! `F6BEAFF7-1E19-4FBB-9F8F-B89E2018337C` v1.0). Lets a remote caller open a channel by
//! name, register an XPath query against it, pull matching event records, and read the
//! payload as BinXml (MS-EVEN6 §2.2.17) — the same wire form the local Vista+ EventLog
//! service hands to `EvtRender`.
//!
//! **Status: pre-alpha / 0.1.0-dev.** The wire encoders for the core opnums exist and
//! round-trip against hand-crafted golden bytes; the BinXml decoder recognises the
//! commonly-used token subset (element open/close, attribute, value UTF-16LE, template
//! reference, EOF) and produces a structured `Event`. Full spec conformance and live-DC
//! iteration are deferred to a later revision.
//!
//! # Layout
//! - [`transport`] — a small `Transport` trait so the client can be driven by dcerpc's
//!   `SmbPipe` (real DC) or a byte-scripted mock (tests). The dcerpc adapter is `todo`
//!   for 0.2.0 — it needs async plumbing that the sync-facing API doesn't offer yet.
//! - [`opnums`]    — opnum wire encoders/decoders (EvtRpcOpenLogHandle, RegisterLogQuery,
//!   QueryNext, Close).
//! - [`binxml`]    — the BinXml token-stream decoder (channel, provider, event id,
//!   record id, time_created, and a rendered XML string).
//! - [`gaps`]      — record-id gap detection over a set of pulled events.
//!
//! The public API on this crate ([`EvenClient`], [`open_log_handle`](EvenClient::open_log_handle),
//! [`register_log_query`](EvenClient::register_log_query),
//! [`query_next`](EvenClient::query_next), [`decode_binxml`], [`detect_gaps`]) is sync —
//! the transport trait is sync too. A DC-real caller wraps their `SmbPipe` (async) via a
//! `tokio::runtime::Handle::block_on` shim; see `examples/` (TBD) for the pattern.

pub mod binxml;
pub mod gaps;
pub mod opnums;
pub mod transport;

use ms_ndr::NdrError;

pub use binxml::{decode_binxml, Event};
pub use gaps::{detect_gaps, RecordIdGap};
pub use transport::Transport;

/// A DCE/RPC abstract syntax (UUID + interface version) — the tiny local stand-in
/// for `dcerpc::Syntax` while the dcerpc integration is deferred. Wire byte layout
/// matches DCE (little-endian UUID, u16 major, u16 minor).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Syntax {
    pub uuid: [u8; 16],
    pub ver_major: u16,
    pub ver_minor: u16,
}

/// The MS-EVEN6 interface: UUID F6BEAFF7-1E19-4FBB-9F8F-B89E2018337C, v1.0.
pub fn even6_syntax() -> Syntax {
    // Canonical UUID → DCE on-wire byte order:
    //   time_low (u32 LE), time_mid (u16 LE), time_hi_and_version (u16 LE),
    //   clock_seq_hi_reserved (u8), clock_seq_low (u8), node (6 bytes).
    let uuid = [
        0xF7, 0xAF, 0xBE, 0xF6, // f6beaff7 LE
        0x19, 0x1E, // 1e19    LE
        0xBB, 0x4F, // 4fbb    LE
        0x9F, 0x8F, // 9f 8f   (clock_seq)
        0xB8, 0x9E, 0x20, 0x18, 0x33, 0x7C, // node
    ];
    Syntax {
        uuid,
        ver_major: 1,
        ver_minor: 0,
    }
}

/// Only way anything in this crate fails.
#[derive(Debug, thiserror::Error)]
pub enum EvenError {
    #[error("transport: {0}")]
    Transport(String),
    #[error("event log server returned Win32 status {0:#010x}")]
    Server(u32),
    #[error("ndr underrun at pos {pos}, need {need}")]
    Underrun { need: usize, pos: usize },
    #[error("binxml: {0}")]
    BinXml(String),
    #[error("unexpected token {tok:#04x} at pos {pos}")]
    UnexpectedToken { tok: u8, pos: usize },
    #[error("short input, need {need} at {pos}")]
    Short { need: usize, pos: usize },
    #[error("protocol: {0}")]
    Protocol(String),
}

impl From<NdrError> for EvenError {
    fn from(e: NdrError) -> Self {
        match e {
            NdrError::Underrun { need, pos } => EvenError::Underrun { need, pos },
        }
    }
}

pub type Result<T> = std::result::Result<T, EvenError>;

/// A remote MS-EVEN6 CONTEXT_HANDLE (20 bytes: attributes u32 + 16-byte UUID).
/// Returned by EvtRpcOpenLogHandle; passed back to Read/Clear/QueryChannel calls.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ContextHandle(pub [u8; 20]);

impl ContextHandle {
    pub const NULL: ContextHandle = ContextHandle([0u8; 20]);
    pub fn is_null(&self) -> bool {
        self.0 == [0u8; 20]
    }
}

/// The handle a caller keeps for pulling records after RegisterLogQuery.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct QueryHandle(pub [u8; 20]);

impl QueryHandle {
    pub const NULL: QueryHandle = QueryHandle([0u8; 20]);
    pub fn is_null(&self) -> bool {
        self.0 == [0u8; 20]
    }
}

/// The high-level MS-EVEN6 client.
///
/// Owns a `Transport` (bound to the remote `\pipe\eventlog`, RPC bound to
/// [`even6_syntax`]) and tracks the caller's open handles. Split across trait/impl so
/// live-DC and test-mock transports plug into the same code path.
pub struct EvenClient<T: Transport> {
    pub transport: T,
}

impl<T: Transport> EvenClient<T> {
    pub fn new(transport: T) -> Self {
        Self { transport }
    }

    /// EvtRpcOpenLogHandle (opnum 0): open a channel by name (e.g. `"Security"`,
    /// `"Application"`) for reading. Returns the CONTEXT_HANDLE the server will accept
    /// on read/clear calls.
    ///
    /// Wire (MS-EVEN6 §3.1.4.19): `[in,string] wchar_t* Channel, [in] DWORD Flags,
    /// [out] CONTEXT_HANDLE_LOG_HANDLE* Handle, [out] RpcInfo* Error`.
    pub fn open_log_handle(&mut self, channel: &str, flags: u32) -> Result<ContextHandle> {
        let stub = opnums::encode_open_log_handle(channel, flags);
        let resp = self
            .transport
            .call(opnums::OPNUM_OPEN_LOG_HANDLE, &stub)
            .map_err(EvenError::Transport)?;
        opnums::decode_open_log_handle(&resp)
    }

    /// EvtRpcRegisterLogQuery (opnum 5): register an XPath / structured-XML query and
    /// receive a query handle for pulling matching events.
    pub fn register_log_query(&mut self, xpath: &str, flags: u32) -> Result<QueryHandle> {
        let stub = opnums::encode_register_log_query(xpath, flags);
        let resp = self
            .transport
            .call(opnums::OPNUM_REGISTER_LOG_QUERY, &stub)
            .map_err(EvenError::Transport)?;
        opnums::decode_register_log_query(&resp)
    }

    /// EvtRpcQueryNext (opnum 11): pull up to `n` events from a registered query,
    /// blocking on the server for at most `timeout_ms`. Empty result means the query
    /// has drained. Each BinXml fragment is decoded into an [`Event`].
    pub fn query_next(&mut self, h: &QueryHandle, n: u32, timeout_ms: u32) -> Result<Vec<Event>> {
        let stub = opnums::encode_query_next(h, n, timeout_ms);
        let resp = self
            .transport
            .call(opnums::OPNUM_QUERY_NEXT, &stub)
            .map_err(EvenError::Transport)?;
        let frags = opnums::decode_query_next(&resp)?;
        let mut out = Vec::with_capacity(frags.len());
        for f in frags {
            out.push(decode_binxml(&f)?);
        }
        Ok(out)
    }

    /// EvtRpcClose (opnum 13): release either a log handle or a query handle.
    pub fn close(&mut self, handle: &[u8; 20]) -> Result<()> {
        let stub = opnums::encode_close(handle);
        let resp = self
            .transport
            .call(opnums::OPNUM_CLOSE, &stub)
            .map_err(EvenError::Transport)?;
        opnums::decode_close(&resp)
    }
}
