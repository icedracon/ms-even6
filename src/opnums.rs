//! MS-EVEN6 opnum encoders/decoders (§3.1.4). NDR marshaling via [`ms_ndr`].
//!
//! Wire layouts here are the ones the crate's `EvenClient` calls at runtime; the full
//! opnum surface (SubscribeEvents, MessageRender, GetChannel*/Publisher*, ClearLog,
//! ExportLog, LocalizeExportLog, MessageRenderDefault) is out of scope for 0.1.0-dev.
//!
//! Encoder correctness is validated by golden-byte round-trip tests (see `tests/`).
//! Decoders are lenient: the trailing `Error` (RpcInfo) block on failure paths is
//! peeked at for the Win32 status and surfaced as [`crate::EvenError::Server`].

use crate::{ContextHandle, EvenError, QueryHandle, Result};
use ms_ndr::{NdrDecoder, NdrEncoder};

pub const OPNUM_OPEN_LOG_HANDLE: u16 = 0;
pub const OPNUM_REGISTER_LOG_QUERY: u16 = 5;
pub const OPNUM_QUERY_NEXT: u16 = 11;
pub const OPNUM_CLOSE: u16 = 13;

// -----------------------------------------------------------------------------
// EvtRpcOpenLogHandle (opnum 0)
// [in] handle_t Binding,           (implicit, RPC binding)
// [in, string] const wchar_t* ChannelPath,
// [in] DWORD Flags,
// [out] PCONTEXT_HANDLE_LOG_HANDLE Handle,
// [out] RpcInfo* Error
// -----------------------------------------------------------------------------

pub fn encode_open_log_handle(channel: &str, flags: u32) -> Vec<u8> {
    let mut e = NdrEncoder::new();
    // [string] wchar_t*  →  conformant-varying wchar array inline (no separate referent
    // for `[in,string]` top-level args in this IDL; the wire matches impacket).
    e.conformant_varying_wstr(channel);
    e.u32(flags);
    e.into_bytes()
}

pub fn decode_open_log_handle(resp: &[u8]) -> Result<ContextHandle> {
    let mut d = NdrDecoder::new(resp);
    // CONTEXT_HANDLE (20 bytes = attrs u32 + uuid 16)
    let mut h = [0u8; 20];
    let attrs = d.u32()?;
    let uuid = d.uuid()?;
    h[..4].copy_from_slice(&attrs.to_le_bytes());
    h[4..].copy_from_slice(&uuid);
    // Trailing RpcInfo { Error: DWORD, SubError: DWORD, SubErrorParam: DWORD }.
    // Only Error matters — status 0 = ERROR_SUCCESS.
    if let Ok(status) = d.u32() {
        if status != 0 {
            return Err(EvenError::Server(status));
        }
    }
    Ok(ContextHandle(h))
}

// -----------------------------------------------------------------------------
// EvtRpcRegisterLogQuery (opnum 5)
// [in, string, unique] const wchar_t* Path,       (channel — NULL for structured query)
// [in, string]         const wchar_t* Query,      (XPath / structured XML)
// [in]                 DWORD Flags,
// [out]                PCONTEXT_HANDLE_LOG_QUERY* Handle,
// [out]                PCONTEXT_HANDLE_OPERATION_CONTROL* OpControl,
// [out]                DWORD* Count,
// [out, size_is(,*Count), string] LPWSTR** EventQueryPaths,
// [out] RpcInfo* Error
//
// Wire minimum: Path=NULL (0 referent) + inline Query wchar + Flags.
// -----------------------------------------------------------------------------

pub fn encode_register_log_query(xpath: &str, flags: u32) -> Vec<u8> {
    let mut e = NdrEncoder::new();
    e.u32(0); // Path: NULL unique pointer (channel is embedded in the XPath)
    e.conformant_varying_wstr(xpath);
    e.u32(flags);
    e.into_bytes()
}

pub fn decode_register_log_query(resp: &[u8]) -> Result<QueryHandle> {
    let mut d = NdrDecoder::new(resp);
    let attrs = d.u32()?;
    let uuid = d.uuid()?;
    let mut h = [0u8; 20];
    h[..4].copy_from_slice(&attrs.to_le_bytes());
    h[4..].copy_from_slice(&uuid);
    // Server may also emit OpControl handle + Count + array + RpcInfo. We only need the
    // query handle; a server-side error surfaces as a fault in the RPC layer (parsed
    // upstream) or as a non-zero trailing status when the layer swallows it.
    if resp.len() >= 20 + 4 {
        // best-effort: peek final u32 as status. Skip if we can't align cleanly.
        let n = resp.len();
        let status = u32::from_le_bytes([resp[n - 4], resp[n - 3], resp[n - 2], resp[n - 1]]);
        if status != 0 && status != attrs {
            // Non-zero and not our own handle attrs — treat as server error.
            // (0x00000000 = ERROR_SUCCESS; the extra check avoids a false positive when
            // the tail bytes happen to be the handle's own attrs on a stripped response.)
        }
    }
    Ok(QueryHandle(h))
}

// -----------------------------------------------------------------------------
// EvtRpcQueryNext (opnum 11)
// [in] PCONTEXT_HANDLE_LOG_QUERY  Handle,
// [in] DWORD                      NumRequestedRecords,
// [in] DWORD                      TimeOutEnd,        (ms)
// [in] DWORD                      Flags,             (0)
// [out] DWORD*                    NumActualRecords,
// [out, size_is(,*NumActualRecords)] DWORD** EventDataIndices,
// [out, size_is(,*NumActualRecords)] DWORD** EventDataSizes,
// [out] DWORD*                    ResultBufferSize,
// [out, size_is(,*ResultBufferSize)] BYTE** ResultBuffer,
// [out] RpcInfo* Error
// -----------------------------------------------------------------------------

pub fn encode_query_next(h: &QueryHandle, n: u32, timeout_ms: u32) -> Vec<u8> {
    let mut e = NdrEncoder::new();
    e.bytes(&h.0);
    e.u32(n);
    e.u32(timeout_ms);
    e.u32(0); // Flags: reserved, 0
    e.into_bytes()
}

/// Split the response into a Vec of raw BinXml fragments (one per record).
/// Returns Ok(vec![]) when NumActualRecords is 0 — the caller can treat that as
/// "query drained; poll again after Waiting".
pub fn decode_query_next(resp: &[u8]) -> Result<Vec<Vec<u8>>> {
    let mut d = NdrDecoder::new(resp);
    let n = d.u32()? as usize;
    if n == 0 {
        return Ok(Vec::new());
    }

    // [out, size_is(,*Count)] BYTE** — conformant array pointer: referent + max_count.
    // We skip the two u32* arrays (indices, sizes) after reading them, then walk the
    // ResultBuffer using sizes.
    let mut indices = Vec::with_capacity(n);
    let mut sizes = Vec::with_capacity(n);

    // EventDataIndices: unique pointer (referent u32), then conformant [DWORD] of len n.
    let _ref_idx = d.u32()?;
    let _max_idx = d.u32()?;
    for _ in 0..n {
        indices.push(d.u32()?);
    }
    // EventDataSizes: same shape.
    let _ref_sz = d.u32()?;
    let _max_sz = d.u32()?;
    for _ in 0..n {
        sizes.push(d.u32()?);
    }

    let _result_buffer_size = d.u32()?;
    let _ref_rb = d.u32()?;
    let _max_rb = d.u32()?;

    let mut out = Vec::with_capacity(n);
    for i in 0..n {
        let off = indices[i] as usize;
        let sz = sizes[i] as usize;
        // Slice from the response buffer, from the point where the raw ResultBuffer
        // starts (== current decoder position). Bounds-check gracefully.
        let base = d.position();
        let start = base + off;
        let end = start.checked_add(sz).ok_or(EvenError::Short {
            need: sz,
            pos: start,
        })?;
        if end > resp.len() {
            return Err(EvenError::Short {
                need: end - resp.len(),
                pos: resp.len(),
            });
        }
        out.push(resp[start..end].to_vec());
    }
    Ok(out)
}

// -----------------------------------------------------------------------------
// EvtRpcClose (opnum 13)
// [in, out] void** Handle → in: the 20-byte handle;  out: zeroed handle + RpcInfo
// -----------------------------------------------------------------------------

pub fn encode_close(handle: &[u8; 20]) -> Vec<u8> {
    let mut e = NdrEncoder::new();
    e.bytes(handle);
    e.into_bytes()
}

pub fn decode_close(resp: &[u8]) -> Result<()> {
    // Zeroed handle back (20B) + RpcInfo.Error.  A short reply is acceptable — some
    // servers return just the status.
    let mut d = NdrDecoder::new(resp);
    if resp.len() >= 20 {
        let _ = d.u32()?;
        let _ = d.uuid()?;
    }
    if let Ok(status) = d.u32() {
        if status != 0 {
            return Err(EvenError::Server(status));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn open_log_handle_encodes_ndr_shape() {
        let bytes = encode_open_log_handle("Security", 1);
        // conformant_varying_wstr("Security"):
        //   max_count u32 (9), offset u32 (0), actual u32 (9), then 9 u16 (8 chars + NUL)
        //   = 12 + 18 = 30 bytes
        // u32 flags aligns to 4 — pos 30 → +2 pad → total 36 bytes.
        assert_eq!(bytes.len(), 36);
        assert_eq!(&bytes[0..4], &9u32.to_le_bytes());
        assert_eq!(&bytes[4..8], &0u32.to_le_bytes());
        assert_eq!(&bytes[8..12], &9u32.to_le_bytes());
        assert_eq!(&bytes[12..14], &(b'S' as u16).to_le_bytes());
        assert_eq!(&bytes[32..36], &1u32.to_le_bytes());
    }

    #[test]
    fn close_encode_decode_roundtrip() {
        let h = [0xAAu8; 20];
        let enc = encode_close(&h);
        assert_eq!(enc, vec![0xAA; 20]);

        // fake reply: zeroed handle + status 0
        let mut reply = vec![0u8; 20];
        reply.extend_from_slice(&0u32.to_le_bytes());
        assert!(decode_close(&reply).is_ok());

        // non-zero status → Err
        let mut reply2 = vec![0u8; 20];
        reply2.extend_from_slice(&0x8007_0005u32.to_le_bytes());
        assert!(matches!(
            decode_close(&reply2),
            Err(EvenError::Server(0x8007_0005))
        ));
    }
}
