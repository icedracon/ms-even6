//! Record-id gap detection. EventRecordID is monotonically increasing per channel; any
//! break means the caller lost coverage (log wraparound, service restart, clear, or a
//! competing consumer). Given a pulled batch of events this returns each contiguous
//! `[missing_start, missing_end]` inclusive range.

use crate::binxml::Event;

/// One detected gap in the record-id sequence.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RecordIdGap {
    /// First record id known to be missing (inclusive).
    pub missing_start: u64,
    /// Last record id known to be missing (inclusive).
    pub missing_end: u64,
    /// The last-seen record id immediately before the gap.
    pub prev: u64,
    /// The first record id observed after the gap.
    pub next: u64,
}

/// Scan `records` in order and return every gap in EventRecordID.
///
/// Records with record_id == 0 are skipped — 0 is the default and indicates a fragment
/// the BinXml decoder couldn't render (template payload the resolver doesn't yet
/// support). Duplicate ids are ignored (each id is counted once).
pub fn detect_gaps(records: &[Event]) -> Vec<RecordIdGap> {
    let mut ids: Vec<u64> = records
        .iter()
        .map(|e| e.record_id)
        .filter(|&r| r != 0)
        .collect();
    ids.sort_unstable();
    ids.dedup();
    let mut out = Vec::new();
    for w in ids.windows(2) {
        let (a, b) = (w[0], w[1]);
        if b > a + 1 {
            out.push(RecordIdGap {
                missing_start: a + 1,
                missing_end: b - 1,
                prev: a,
                next: b,
            });
        }
    }
    out
}
