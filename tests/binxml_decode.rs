//! Build a small BinXml fragment in our recognised subset (an <Event>/<System> shape
//! representing a Windows 4624 successful logon) and verify the decoder extracts the
//! interesting fields.

use ms_even6::binxml::*;
use ms_even6::detect_gaps;

fn build_4624_fragment() -> Vec<u8> {
    let mut b = Vec::new();
    t_fragment_header(&mut b);

    // <Event ...>
    t_open_element(&mut b, "Event");
    t_close_start(&mut b);

    // <System>
    t_open_element(&mut b, "System");
    t_close_start(&mut b);

    // <Provider Name="Microsoft-Windows-Security-Auditing"/>
    t_open_element_with_attrs(&mut b, "Provider");
    t_attr_string(&mut b, "Name", "Microsoft-Windows-Security-Auditing");
    t_close_empty(&mut b);

    // <EventID>4624</EventID>
    t_open_element(&mut b, "EventID");
    t_close_start(&mut b);
    t_text_value(&mut b, "4624");
    t_end_element(&mut b);

    // <TimeCreated SystemTime="132500000000000000"/>
    t_open_element_with_attrs(&mut b, "TimeCreated");
    t_attr_string(&mut b, "SystemTime", "132500000000000000");
    t_close_empty(&mut b);

    // <EventRecordID>987654321</EventRecordID>
    t_open_element(&mut b, "EventRecordID");
    t_close_start(&mut b);
    t_text_value(&mut b, "987654321");
    t_end_element(&mut b);

    // <Channel>Security</Channel>
    t_open_element(&mut b, "Channel");
    t_close_start(&mut b);
    t_text_value(&mut b, "Security");
    t_end_element(&mut b);

    // </System>
    t_end_element(&mut b);
    // </Event>
    t_end_element(&mut b);
    t_eof(&mut b);
    b
}

#[test]
fn decodes_4624_fragment_end_to_end() {
    let bytes = build_4624_fragment();
    let ev = decode_binxml(&bytes).expect("decode");
    assert_eq!(ev.event_id, 4624);
    assert_eq!(ev.record_id, 987_654_321);
    assert_eq!(ev.time_created, 132_500_000_000_000_000);
    assert_eq!(ev.provider, "Microsoft-Windows-Security-Auditing");
    assert_eq!(ev.channel, "Security");
    assert!(ev.xml.starts_with("<Event"));
    assert!(ev.xml.contains("<EventID>4624</EventID>"));
    assert!(ev.xml.contains("Channel>Security</Channel>"));
}

#[test]
fn detect_gaps_finds_holes() {
    // Three synthetic events with a gap between the first and second.
    let make = |rid| {
        let mut e = Event::default();
        e.record_id = rid;
        e
    };
    let evs = vec![make(100), make(105), make(106), make(200)];
    let gaps = detect_gaps(&evs);
    assert_eq!(gaps.len(), 2);
    assert_eq!(gaps[0].missing_start, 101);
    assert_eq!(gaps[0].missing_end, 104);
    assert_eq!(gaps[0].prev, 100);
    assert_eq!(gaps[0].next, 105);
    assert_eq!(gaps[1].missing_start, 107);
    assert_eq!(gaps[1].missing_end, 199);
}

#[test]
fn detect_gaps_ignores_zero_record_ids() {
    // A template-only decode returns record_id == 0 → should be skipped, not counted
    // as a huge gap.
    let make = |rid| {
        let mut e = Event::default();
        e.record_id = rid;
        e
    };
    let evs = vec![make(0), make(0), make(50), make(51), make(0)];
    let gaps = detect_gaps(&evs);
    assert!(gaps.is_empty());
}

#[test]
fn template_instance_returns_partial_event() {
    // Emit a header, an <Event> open, then a raw 0x0C — decoder should bail with
    // whatever it collected, not panic.
    let mut b = Vec::new();
    t_fragment_header(&mut b);
    t_open_element(&mut b, "Event");
    t_close_start(&mut b);
    b.push(0x0C); // TemplateInstance
    let ev = decode_binxml(&b).expect("partial decode");
    assert!(ev.xml.contains("template@"));
}
