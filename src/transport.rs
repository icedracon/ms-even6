//! Transport trait — one `call(opnum, stub) -> Result<Vec<u8>>` method the client uses
//! to move NDR stubs to/from the remote. Sync so [`crate::EvenClient`]'s API stays sync;
//! a live-DC driver wraps its async `dcerpc::transport::SmbPipe` behind `block_on`.

/// A synchronous MS-RPCE call: opnum + stub in, response stub out. Error is a free-form
/// string so any underlying transport can report without a new error enum.
pub trait Transport {
    fn call(&mut self, opnum: u16, stub: &[u8]) -> std::result::Result<Vec<u8>, String>;
}

/// A tiny reply-scripted transport for tests: enqueue expected `(opnum, response)` pairs
/// and call it. Panics on mismatch — that's what a test wants.
pub struct MockTransport {
    pub script: Vec<(u16, Vec<u8>)>,
    pub calls: Vec<(u16, Vec<u8>)>,
}

impl MockTransport {
    pub fn new(script: Vec<(u16, Vec<u8>)>) -> Self {
        MockTransport {
            script,
            calls: Vec::new(),
        }
    }
}

impl Transport for MockTransport {
    fn call(&mut self, opnum: u16, stub: &[u8]) -> Result<Vec<u8>, String> {
        self.calls.push((opnum, stub.to_vec()));
        if self.script.is_empty() {
            return Err(format!("no scripted response for opnum {opnum}"));
        }
        let (want, reply) = self.script.remove(0);
        if want != opnum {
            return Err(format!("opnum mismatch: got {opnum}, want {want}"));
        }
        Ok(reply)
    }
}
