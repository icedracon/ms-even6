# ms-even6

STATUS: **pre-alpha (0.1.0-dev)** — API surface + partial implementation. Not on
crates.io. Not yet driven against a live DC.

Pure-Rust client for **MS-EVEN6**, the Windows EventLog Remoting Protocol v6.
Remote-query, subscribe to and clear a Vista+ event log over MS-RPCE
(SMB named pipe `\pipe\eventlog`, interface UUID
`F6BEAFF7-1E19-4FBB-9F8F-B89E2018337C`). Includes a token-stream BinXml decoder
(MS-EVEN6 §2.2.17) for the record fragments the server hands back.

## What works
- The four opnums the client uses (OpenLogHandle, RegisterLogQuery, QueryNext,
  Close) marshal + unmarshal round-trip against golden bytes.
- The BinXml decoder handles the inline-name element/attribute/value subset and
  extracts EventRecordID, EventID, Provider, Channel, TimeCreated for records
  emitted in that form.
- `detect_gaps` finds every hole in a record-id stream (channel skew /
  wraparound / competing consumer).

## What's stubbed / deferred
- The `dcerpc::transport::SmbPipe` adapter isn't wired in (dcerpc's transport
  is async and this crate's API is sync). A `Transport` trait is provided; the
  test suite drives a `MockTransport`. Live-DC integration = 0.2.0 work.
- BinXml `TemplateInstance` (token 0x0C) is where real-DC records almost always
  live. The decoder currently records the fact, sets `Event.xml` to
  `<!--template@…-->` and returns whatever fields it filled — enough for
  `detect_gaps` to work, not enough to render.
- `EvtRpcSubscribe` and `EvtRpcClear` aren't implemented yet.

## Minimal usage (with a mock transport)

```rust
use ms_even6::{EvenClient, transport::MockTransport};

let script = vec![
    // (opnum, response_bytes) pairs — see tests/ for a full round-trip.
];
let mut c = EvenClient::new(MockTransport::new(script));
let h = c.open_log_handle("Security", 1).unwrap();
let q = c.register_log_query("*[System/EventID=4624]", 0x100).unwrap();
let events = c.query_next(&q, 10, 5_000).unwrap();
for e in &events {
    println!("{} {}: id={} channel={}", e.record_id, e.time_created, e.event_id, e.channel);
}
c.close(&q.0).unwrap();
c.close(&h.0).unwrap();
```

## Deps (all pinned locally to the icedracon workspace)
- `ms-ndr` — NDR marshaling
- `dcerpc` — MS-RPCE stack (Syntax type + transports)
- `thiserror`

License: MIT.
