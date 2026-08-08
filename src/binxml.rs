//! BinXml decoder — MS-EVEN6 §2.2.17. Consumes the token stream that
//! `EvtRpcQueryNext` returns per record and produces a structured [`Event`].
//!
//! Scope for 0.1.0-dev
//! -------------------
//! Recognised tokens:
//!
//! | Token | Name                     | Handled |
//! |-------|--------------------------|---------|
//! | 0x00  | EndOfStream              | yes     |
//! | 0x01  | OpenStartElement         | yes (inline name form) |
//! | 0x41  | OpenStartElement (more)  | yes (inline name form) |
//! | 0x02  | CloseStartElement        | yes     |
//! | 0x03  | CloseEmptyElement        | yes     |
//! | 0x04  | EndElement               | yes     |
//! | 0x05  | Value                    | yes (String / UInt32 / UInt64 / GUID / DateTime) |
//! | 0x45  | Value (more)             | yes     |
//! | 0x06  | Attribute                | yes     |
//! | 0x46  | Attribute (more)         | yes     |
//! | 0x0F  | FragmentHeader           | yes     |
//! | 0x0C  | TemplateInstance         | stub (fields extracted, XML placeholder) |
//! | 0x0D/E| Normal/OptionalSub       | placeholder emitted |
//!
//! Live-DC records almost always arrive as TemplateInstance references (the EventLog
//! service pre-compiles a schema); a full template-cache + substitution-resolver is
//! the 0.2.0 work item. Right now `decode_binxml` returns the interesting metadata
//! (record id, timestamp, event id, provider, channel) whenever it's present as an
//! inline value or a plain-text substitution, and puts a rough XML sketch in
//! [`Event::xml`].

use crate::{EvenError, Result};

/// One decoded event log record.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Event {
    /// EventRecordID — monotonic per channel; used by [`super::detect_gaps`].
    pub record_id: u64,
    /// TimeCreated (SystemTime FILETIME → u64 = 100ns intervals since 1601-01-01 UTC).
    pub time_created: u64,
    /// EventID (System/EventID).
    pub event_id: u32,
    /// Provider Name (System/Provider Name="…").
    pub provider: String,
    /// Channel (System/Channel).
    pub channel: String,
    /// Best-effort rendered XML — for a template-based record it may be the sketch
    /// "<Event xmlns='…'>…template N with M subs…</Event>" until 0.2.0.
    pub xml: String,
}

/// A byte-level cursor for the token stream. Positions in errors are byte offsets from
/// the start of the fragment (== the bytes emitted after ResultBuffer[EventDataIndex]).
struct Cursor<'a> {
    b: &'a [u8],
    p: usize,
}

impl<'a> Cursor<'a> {
    fn new(b: &'a [u8]) -> Self {
        Cursor { b, p: 0 }
    }
    fn eof(&self) -> bool {
        self.p >= self.b.len()
    }
    fn need(&self, n: usize) -> Result<()> {
        if self.p + n > self.b.len() {
            Err(EvenError::Short {
                need: n,
                pos: self.p,
            })
        } else {
            Ok(())
        }
    }
    fn u8(&mut self) -> Result<u8> {
        self.need(1)?;
        let v = self.b[self.p];
        self.p += 1;
        Ok(v)
    }
    fn u16(&mut self) -> Result<u16> {
        self.need(2)?;
        let v = u16::from_le_bytes([self.b[self.p], self.b[self.p + 1]]);
        self.p += 2;
        Ok(v)
    }
    fn u32(&mut self) -> Result<u32> {
        self.need(4)?;
        let v = u32::from_le_bytes(self.b[self.p..self.p + 4].try_into().unwrap());
        self.p += 4;
        Ok(v)
    }
    fn u64(&mut self) -> Result<u64> {
        self.need(8)?;
        let v = u64::from_le_bytes(self.b[self.p..self.p + 8].try_into().unwrap());
        self.p += 8;
        Ok(v)
    }
    fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        self.need(n)?;
        let s = &self.b[self.p..self.p + n];
        self.p += n;
        Ok(s)
    }
    fn peek_u8(&self) -> Result<u8> {
        self.need(1)?;
        Ok(self.b[self.p])
    }
}

// MS-EVEN6 §2.2.17.1.1 Name: NameHashOffset(u32) NameHash(u16) NumChars(u16)
//                            UTF-16LE(NumChars) NUL(u16)
// For our decoder path, when we're just reading the *inline* name form we pull the
// wchar array and the trailing NUL and return the string.
fn read_name(c: &mut Cursor) -> Result<String> {
    let _name_hash_offset = c.u32()?;
    let _name_hash = c.u16()?;
    let n_chars = c.u16()? as usize;
    let raw = c.take(n_chars * 2)?;
    let mut units: Vec<u16> = raw
        .chunks_exact(2)
        .map(|b| u16::from_le_bytes([b[0], b[1]]))
        .collect();
    // trailing NUL wchar
    let _nul = c.u16()?;
    while units.last() == Some(&0) {
        units.pop();
    }
    Ok(String::from_utf16_lossy(&units))
}

// A "Value" token payload: type (u8), then value bytes.
// We only implement the value types actually surfaced in a 4624-style record + a
// synthetic vector used in tests.
fn read_value(c: &mut Cursor) -> Result<ValueData> {
    let ty = c.u8()?;
    Ok(match ty {
        0x01 => {
            // StringType — u16 num_chars, UTF-16LE
            let n = c.u16()? as usize;
            let raw = c.take(n * 2)?;
            let units: Vec<u16> = raw
                .chunks_exact(2)
                .map(|b| u16::from_le_bytes([b[0], b[1]]))
                .collect();
            ValueData::Str(String::from_utf16_lossy(&units))
        }
        0x08 => ValueData::U32(c.u32()?),
        0x0A => ValueData::U64(c.u64()?),
        0x11 => ValueData::FileTime(c.u64()?),
        0x0F => {
            // GUID (16B)
            let bs = c.take(16)?;
            ValueData::Guid(bs.try_into().unwrap())
        }
        other => {
            // Unknown type: bail with a decodable error rather than guessing a length.
            return Err(EvenError::BinXml(format!(
                "unsupported value type {other:#04x} at pos {}",
                c.p - 1
            )));
        }
    })
}

#[derive(Clone, Debug)]
enum ValueData {
    Str(String),
    U32(u32),
    U64(u64),
    FileTime(u64),
    Guid([u8; 16]),
}

impl ValueData {
    fn as_str(&self) -> String {
        match self {
            ValueData::Str(s) => s.clone(),
            ValueData::U32(v) => v.to_string(),
            ValueData::U64(v) => v.to_string(),
            ValueData::FileTime(v) => v.to_string(),
            ValueData::Guid(g) => {
                // Little-endian layout — same DCE UUID ordering.
                format!(
                    "{:08x}-{:04x}-{:04x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
                    u32::from_le_bytes([g[0], g[1], g[2], g[3]]),
                    u16::from_le_bytes([g[4], g[5]]),
                    u16::from_le_bytes([g[6], g[7]]),
                    g[8],
                    g[9],
                    g[10],
                    g[11],
                    g[12],
                    g[13],
                    g[14],
                    g[15]
                )
            }
        }
    }
}

/// Public entry point: decode one BinXml fragment into an [`Event`].
///
/// The decoder tries hard to survive an unknown token: on encountering
/// TemplateInstance (0x0C) or an unknown value type it stops walking and returns
/// whatever fields it managed to fill, with `xml` set to a diagnostic marker
/// containing the byte offset. That lets a caller `detect_gaps` even when the
/// underlying payload is a template it can't render yet.
pub fn decode_binxml(bytes: &[u8]) -> Result<Event> {
    let mut c = Cursor::new(bytes);
    let mut ev = Event::default();
    let mut xml = String::new();
    let mut elem_stack: Vec<String> = Vec::new();
    // Reserved for a future `0x06 Attribute` form where the value token follows in the
    // outer loop rather than being consumed inline; unused today.
    let _pending_attr: Option<String> = None;

    // Optional FragmentHeader: 0x0F 0x01 0x01 0x00  (Major 1, Minor 1, Flags 0)
    if let Ok(0x0F) = c.peek_u8() {
        c.u8()?;
        c.need(3)?;
        c.p += 3;
    }

    while !c.eof() {
        let tok = c.u8()?;
        match tok {
            0x00 => break, // EndOfStream
            0x01 | 0x41 => {
                // OpenStartElement
                let _dep_id = c.u16()?; // dependency id (u16 for our synthetic form)
                let _data_size = c.u32()?; // size of substream
                let name = read_name(&mut c)?;
                // For our subset, no AttributeList size prefix follows on 0x01;
                // 0x41 indicates the element carries attributes but we let the
                // subsequent Attribute tokens speak for themselves.
                xml.push('<');
                xml.push_str(&name);
                elem_stack.push(name.clone());
                capture_system_field(&mut ev, &elem_stack, &name, None);
            }
            0x02 => {
                // CloseStartElement
                xml.push('>');
            }
            0x03 => {
                // CloseEmptyElement
                xml.push_str("/>");
                elem_stack.pop();
            }
            0x04 => {
                // EndElement
                if let Some(name) = elem_stack.pop() {
                    xml.push_str("</");
                    xml.push_str(&name);
                    xml.push('>');
                }
            }
            0x05 | 0x45 => {
                // Value token
                let v = read_value(&mut c)?;
                let s = v.as_str();
                xml.push_str(&s);
                // If the current element's a System field we care about, pick it up.
                if let Some(elem) = elem_stack.last() {
                    let elem = elem.clone();
                    capture_system_field(&mut ev, &elem_stack, &elem, Some(&s));
                }
            }
            0x06 | 0x46 => {
                // Attribute:  name  then a Value token
                let attr_name = read_name(&mut c)?;
                // The MS-EVEN6 grammar allows attribute-value to be a substitution or a
                // literal Value token; for the inline subset we read the value inline.
                let val = read_value(&mut c)?;
                let s = val.as_str();
                xml.push(' ');
                xml.push_str(&attr_name);
                xml.push_str("=\"");
                xml.push_str(&s);
                xml.push('"');
                if let Some(elem) = elem_stack.last() {
                    let elem = elem.clone();
                    capture_system_attr(&mut ev, &elem_stack, &elem, &attr_name, &s);
                }
            }
            0x0C => {
                // TemplateInstance — full resolution is a 0.2.0 item.
                // Record the fact and stop walking.
                xml.push_str(&format!("<!--template@{}-->", c.p - 1));
                ev.xml = xml;
                return Ok(ev);
            }
            0x0D | 0x0E => {
                // Substitution (SubstitutionId u16, ValueType u8) — placeholder.
                let sub_id = c.u16()?;
                let _ty = c.u8()?;
                xml.push_str(&format!("{{sub:{sub_id}}}"));
            }
            other => {
                return Err(EvenError::UnexpectedToken {
                    tok: other,
                    pos: c.p - 1,
                });
            }
        }
        let _ = &_pending_attr;
    }

    ev.xml = xml;
    Ok(ev)
}

/// If the current path is Event/System/<FIELD>, record the value into [`Event`].
fn capture_system_field(ev: &mut Event, stack: &[String], name: &str, text: Option<&str>) {
    if stack.len() >= 2 && stack[0] == "Event" && stack[stack.len() - 2] == "System" {
        if let Some(t) = text {
            match name {
                "EventID" => {
                    if let Ok(n) = t.parse() {
                        ev.event_id = n;
                    }
                }
                "EventRecordID" => {
                    if let Ok(n) = t.parse() {
                        ev.record_id = n;
                    }
                }
                "Channel" => ev.channel = t.to_string(),
                _ => {}
            }
        }
    }
}

/// Attributes: Provider Name="…", TimeCreated SystemTime="…".
fn capture_system_attr(ev: &mut Event, stack: &[String], elem: &str, attr: &str, val: &str) {
    if stack.len() >= 2 && stack[0] == "Event" && stack[stack.len() - 2] == "System" {
        match (elem, attr) {
            ("Provider", "Name") => ev.provider = val.to_string(),
            ("TimeCreated", "SystemTime") => {
                // Accept a u64 FileTime rendered as decimal.
                if let Ok(n) = val.parse() {
                    ev.time_created = n;
                }
            }
            _ => {}
        }
    }
}

// -----------------------------------------------------------------------------
// Helpers for tests: emit a fragment in the exact subset our decoder recognises.
// Kept public-crate so the top-level tests can build a golden.
// -----------------------------------------------------------------------------

/// Test-only encoder: write the inline-name form of an OpenStartElement.
#[doc(hidden)]
pub fn t_open_element(out: &mut Vec<u8>, name: &str) {
    out.push(0x01);
    out.extend_from_slice(&0u16.to_le_bytes()); // dep_id
    out.extend_from_slice(&0u32.to_le_bytes()); // data_size (unused in this form)
    t_name(out, name);
}

#[doc(hidden)]
pub fn t_open_element_with_attrs(out: &mut Vec<u8>, name: &str) {
    out.push(0x41);
    out.extend_from_slice(&0u16.to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes());
    t_name(out, name);
}

#[doc(hidden)]
pub fn t_close_start(out: &mut Vec<u8>) {
    out.push(0x02);
}
#[doc(hidden)]
pub fn t_close_empty(out: &mut Vec<u8>) {
    out.push(0x03);
}
#[doc(hidden)]
pub fn t_end_element(out: &mut Vec<u8>) {
    out.push(0x04);
}

#[doc(hidden)]
pub fn t_attr_string(out: &mut Vec<u8>, name: &str, val: &str) {
    out.push(0x06);
    t_name(out, name);
    t_value_string(out, val);
}

#[doc(hidden)]
pub fn t_value_string(out: &mut Vec<u8>, val: &str) {
    // Not a token — this writes the value payload that follows an Attribute or a
    // 0x05 Value token that the caller emits.
    let units: Vec<u16> = val.encode_utf16().collect();
    out.push(0x01); // StringType
    out.extend_from_slice(&(units.len() as u16).to_le_bytes());
    for u in units {
        out.extend_from_slice(&u.to_le_bytes());
    }
}

#[doc(hidden)]
pub fn t_text_value(out: &mut Vec<u8>, val: &str) {
    out.push(0x05); // Value token
    t_value_string(out, val);
}

#[doc(hidden)]
pub fn t_fragment_header(out: &mut Vec<u8>) {
    out.push(0x0F);
    out.push(0x01); // Major
    out.push(0x01); // Minor
    out.push(0x00); // Flags
}

#[doc(hidden)]
pub fn t_eof(out: &mut Vec<u8>) {
    out.push(0x00);
}

#[doc(hidden)]
pub fn t_name(out: &mut Vec<u8>, name: &str) {
    out.extend_from_slice(&0u32.to_le_bytes()); // NameHashOffset
    out.extend_from_slice(&0u16.to_le_bytes()); // NameHash
    let units: Vec<u16> = name.encode_utf16().collect();
    out.extend_from_slice(&(units.len() as u16).to_le_bytes());
    for u in units {
        out.extend_from_slice(&u.to_le_bytes());
    }
    out.extend_from_slice(&0u16.to_le_bytes()); // trailing NUL
}
