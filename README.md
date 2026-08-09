# ms-even6

[![Crates.io](https://img.shields.io/crates/v/ms-even6.svg)](https://crates.io/crates/ms-even6)
[![Docs.rs](https://docs.rs/ms-even6/badge.svg)](https://docs.rs/ms-even6)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

Pure-Rust client for **MS-EVEN6**, the Windows EventLog Remoting Protocol v6
— the Vista-era replacement for MS-EVEN. Lets a remote caller open a channel
by name (`Security`, `Application`, `Microsoft-Windows-Sysmon/Operational`),
register an XPath query, pull matching event records, and read the payload
as BinXml. Built for blue-team collectors and red-team log-audit workflows
that today run through impacket's `even6.py` or WEC forwarders.

## Status

**`0.1.0-dev`** — pre-alpha, expect breaking changes before `0.1.0`. Wire
encoders round-trip against golden bytes; not yet driven against a live DC.
Part of the [icedracon](https://github.com/icedracon) Rust offensive AD
ecosystem.

## What it does

Speaks MS-EVEN6 over MS-RPCE on the SMB named pipe `\pipe\eventlog`,
interface UUID `F6BEAFF7-1E19-4FBB-9F8F-B89E2018337C` v1.0. Implements the
four opnums the client actually uses:

- `EvtRpcOpenLogHandle` (opnum 0) — open a channel for reading.
- `EvtRpcRegisterLogQuery` (opnum 5) — install an XPath / structured-XML query.
- `EvtRpcQueryNext` (opnum 11) — pull up to *n* matching records, blocking up
  to `timeout_ms`.
- `EvtRpcClose` (opnum 13) — release a log or query handle.

Each pulled record is a BinXml token stream (MS-EVEN6 §2.2.17). The included
decoder handles the inline-name element/attribute/value subset and extracts
`EventRecordID`, `EventID`, `Provider`, `Channel`, and `TimeCreated`. A
`detect_gaps` helper walks a stream of `Event`s and returns every hole in the
record-id sequence — the primitive you need to catch channel skew,
wraparound, or a competing consumer clearing entries out from under you.

## Usage

```rust
use ms_even6::{transport::MockTransport, EvenClient};

// Real callers plug their `SmbPipe` into the `Transport` trait; tests script
// (opnum, response_bytes) pairs into MockTransport.
let script = vec![
    // (opnum, response_bytes) pairs — see tests/ for a full round-trip.
];
let mut c = EvenClient::new(MockTransport::new(script));

let log   = c.open_log_handle("Security", 1)?;
let query = c.register_log_query("*[System/EventID=4624]", 0x100)?;

for e in c.query_next(&query, 10, 5_000)? {
    println!(
        "{} {} id={} channel={} provider={}",
        e.record_id, e.time_created, e.event_id, e.channel, e.provider,
    );
}

c.close(&query.0)?;
c.close(&log.0)?;
# Ok::<(), ms_even6::EvenError>(())
```

## What works / what does not (this version)

- Working
  - Four opnums (Open/Register/QueryNext/Close) marshal + unmarshal
    round-trip against golden bytes.
  - BinXml decoder for inline-name element/attribute/value token subset.
  - `detect_gaps` — finds every hole in a record-id stream.
- Stubbed / partial
  - `dcerpc::transport::SmbPipe` adapter — not wired in yet (dcerpc's
    transport is async and this crate's `Transport` trait is sync). Live-DC
    integration lands in 0.2.0 behind a `dcerpc-transport` feature.
  - BinXml `TemplateInstance` (token `0x0C`) — where real-DC records almost
    always live. The decoder records the reference, sets `Event.xml` to
    `<!--template@…-->` and returns whatever fields it filled — enough for
    `detect_gaps`, not enough to render.
  - `EvtRpcSubscribe` and `EvtRpcClear` — not implemented.

## Related icedracon crates

- [`msldap-ext`](https://github.com/icedracon/msldap-ext) — MS-ADTS LDAP
  extension controls (Paged / DirSync / ExtendedDN / SD_FLAGS / VLV).
- [`ms-tds`](https://github.com/icedracon/ms-tds) — TDS 7.4 client for
  Microsoft SQL Server with NTLM login and pentest primitives.
- [`ms-ndr`](https://github.com/icedracon/ms-ndr) — NDR marshaling used for
  MS-RPCE stubs.

Together the three cover the LDAP / EventLog / MSSQL data-plane primitives
that Python + impacket dominate today.

## License

MIT (c) 2026 [zevs](https://github.com/icedracon)
