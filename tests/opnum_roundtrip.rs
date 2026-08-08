//! Wire-shape tests for the four opnum encoders/decoders. Golden bytes are hand-derived
//! from the NDR rules ms-ndr already round-trips (primitives + conformant-varying wstr).

use ms_even6::opnums::*;
use ms_even6::{transport::MockTransport, ContextHandle, EvenClient, EvenError, QueryHandle};

#[test]
fn open_log_handle_wire_matches_golden() {
    // ChannelPath = "Application"  Flags = 1
    let stub = encode_open_log_handle("Application", 1);

    // wstr("Application") =  max=12  offset=0  actual=12  then 12 wchar (11 + NUL)
    //   = 12 + 24 = 36 bytes
    // Then u32 flags = 4 bytes → total 40.
    assert_eq!(stub.len(), 40);
    assert_eq!(&stub[0..4], &12u32.to_le_bytes());
    assert_eq!(&stub[4..8], &0u32.to_le_bytes());
    assert_eq!(&stub[8..12], &12u32.to_le_bytes());
    // 'A' as u16 LE
    assert_eq!(stub[12], b'A');
    assert_eq!(stub[13], 0);
    // Trailing NUL wchar just before flags
    assert_eq!(stub[34], 0);
    assert_eq!(stub[35], 0);
    assert_eq!(&stub[36..40], &1u32.to_le_bytes());

    // Decode: server hands back a CONTEXT_HANDLE (attrs=1, uuid=…) + status 0
    let mut resp = Vec::new();
    resp.extend_from_slice(&1u32.to_le_bytes());
    resp.extend_from_slice(&[
        0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF,
        0x00,
    ]);
    resp.extend_from_slice(&0u32.to_le_bytes()); // status = 0
    let h = decode_open_log_handle(&resp).unwrap();
    let mut expect = [0u8; 20];
    expect[..4].copy_from_slice(&1u32.to_le_bytes());
    expect[4..].copy_from_slice(&[
        0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF,
        0x00,
    ]);
    assert_eq!(h, ContextHandle(expect));

    // Non-zero status surfaces as Server(code).
    let mut bad = Vec::new();
    bad.extend_from_slice(&1u32.to_le_bytes());
    bad.extend_from_slice(&[0u8; 16]);
    bad.extend_from_slice(&0x8007_0005u32.to_le_bytes());
    assert!(matches!(
        decode_open_log_handle(&bad),
        Err(EvenError::Server(0x8007_0005))
    ));
}

#[test]
fn client_open_log_handle_drives_transport() {
    // Wire up EvenClient with a mock that returns a known handle on opnum 0.
    let mut reply = Vec::new();
    reply.extend_from_slice(&1u32.to_le_bytes());
    reply.extend_from_slice(&[0xAA; 16]);
    reply.extend_from_slice(&0u32.to_le_bytes());
    let mock = MockTransport::new(vec![(OPNUM_OPEN_LOG_HANDLE, reply)]);
    let mut client = EvenClient::new(mock);

    let h = client.open_log_handle("Security", 0x100).unwrap();
    assert_eq!(&h.0[4..], &[0xAA; 16]);
    // Verify what we sent — first four bytes are max_count = len("Security") + 1 = 9.
    assert_eq!(&client.transport.calls[0].1[0..4], &9u32.to_le_bytes());
}

#[test]
fn close_roundtrips_over_client() {
    // Close returns zeroed handle + status. A short reply with just a status is also OK.
    let mut reply = vec![0u8; 20];
    reply.extend_from_slice(&0u32.to_le_bytes());
    let mock = MockTransport::new(vec![(OPNUM_CLOSE, reply)]);
    let mut client = EvenClient::new(mock);
    let handle = [0xFEu8; 20];
    client.close(&handle).unwrap();
    // Stub carried the handle bytes verbatim.
    assert_eq!(client.transport.calls[0].1, handle.to_vec());
}

#[test]
fn register_log_query_encodes_null_path() {
    let stub = encode_register_log_query("*[System/EventID=4624]", 0x100);
    // Leading 4 bytes = NULL Path unique-ptr (0).
    assert_eq!(&stub[0..4], &0u32.to_le_bytes());
    // Then max_count = utf16-len("*[System/EventID=4624]") + 1
    let expected_len = "*[System/EventID=4624]".encode_utf16().count() as u32 + 1;
    assert_eq!(&stub[4..8], &expected_len.to_le_bytes());
    // Flags at the very end
    let n = stub.len();
    assert_eq!(&stub[n - 4..n], &0x100u32.to_le_bytes());
}

#[test]
fn query_handle_shape_is_20b() {
    let q = QueryHandle::default();
    assert_eq!(q.0.len(), 20);
    assert!(q.is_null());
}
