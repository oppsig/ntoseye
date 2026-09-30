//! Pure, transport-packet-oriented decoding for classic KD over USB.
//!
//! A USB bulk-IN completion is deliberately kept as one observation.  This
//! module does not concatenate completions and does not require the serial
//! transport's optional `0xaa` byte.

pub const DATA_LEADER: u32 = 0x3030_3030;
pub const CONTROL_LEADER: u32 = 0x6969_6969;
pub const INITIAL_PACKET_ID: u32 = 0x8080_0000;
pub const SYNC_PACKET_ID: u32 = 0x0000_0800;
pub const TRAILER: u8 = 0xaa;

pub const KD_STATE_MANIPULATE: u16 = 2;
pub const KD_DEBUG_IO: u16 = 3;
pub const KD_ACKNOWLEDGE: u16 = 4;
pub const KD_RESEND: u16 = 5;
pub const KD_RESET: u16 = 6;
pub const KD_STATE_CHANGE64: u16 = 7;
pub const KD_CONTROL_REQUEST: u16 = 10;
pub const KD_FILE_IO: u16 = 11;
pub const DBGKD_LOAD_SYMBOLS_STATE_CHANGE: u32 = 0x3031;
pub const DBGKD_GET_VERSION_API: u32 = 0x3146;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Header {
    pub leader: u32,
    pub packet_type: u16,
    pub byte_count: u16,
    pub packet_id: u32,
    pub checksum: u32,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StateChange {
    pub new_state: u32,
    pub processor_level: u16,
    pub processor: u16,
    pub number_processors: u32,
    pub semantic: &'static str,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Manipulate {
    pub api_number: u32,
    pub processor_level: u16,
    pub processor: u16,
    pub return_status: u32,
    pub semantic: &'static str,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Classification {
    Empty,
    Name { name: Option<String> },
    Kd(KdPacket),
    Unknown,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KdPacket {
    pub header: Header,
    pub class: &'static str,
    pub payload_complete: bool,
    pub payload: Vec<u8>,
    pub checksum_valid: Option<bool>,
    pub trailer_present: bool,
    pub trailer_value: Option<u8>,
    pub extra_bytes: Vec<u8>,
    pub state_change: Option<StateChange>,
    pub manipulate: Option<Manipulate>,
}

fn u16le(bytes: &[u8], at: usize) -> Option<u16> {
    Some(u16::from_le_bytes(bytes.get(at..at + 2)?.try_into().ok()?))
}

fn u32le(bytes: &[u8], at: usize) -> Option<u32> {
    Some(u32::from_le_bytes(bytes.get(at..at + 4)?.try_into().ok()?))
}

pub fn checksum(bytes: &[u8]) -> u32 {
    bytes
        .iter()
        .fold(0u32, |sum, byte| sum.wrapping_add(u32::from(*byte)))
}

pub fn parse_header(bytes: &[u8]) -> Option<Header> {
    Some(Header {
        leader: u32le(bytes, 0)?,
        packet_type: u16le(bytes, 4)?,
        byte_count: u16le(bytes, 6)?,
        packet_id: u32le(bytes, 8)?,
        checksum: u32le(bytes, 12)?,
    })
}

pub fn packet_type_name(packet_type: u16) -> &'static str {
    match packet_type {
        KD_STATE_MANIPULATE => "KD_STATE_MANIPULATE",
        KD_DEBUG_IO => "KD_DEBUG_IO",
        KD_ACKNOWLEDGE => "KD_ACKNOWLEDGE",
        KD_RESEND => "KD_RESEND",
        KD_RESET => "KD_RESET",
        KD_STATE_CHANGE64 => "KD_STATE_CHANGE64",
        KD_CONTROL_REQUEST => "KD_CONTROL_REQUEST",
        KD_FILE_IO => "KD_FILE_IO",
        _ => "KD_UNKNOWN_TYPE",
    }
}

pub fn api_name(api: u32) -> &'static str {
    match api {
        DBGKD_GET_VERSION_API => "DbgKdGetVersionApi",
        0x3130 => "DbgKdReadVirtualMemoryApi",
        0x3131 => "DbgKdWriteVirtualMemoryApi",
        0x3136 => "DbgKdContinueApi",
        0x313c => "DbgKdContinueApi2",
        _ => "unknown-manipulate-api",
    }
}

pub fn classify_usb_transfer(bytes: &[u8]) -> Classification {
    if bytes.is_empty() {
        return Classification::Empty;
    }
    if bytes.starts_with(b"NAME") {
        let suffix = bytes.get(5..).unwrap_or_default();
        let name = suffix
            .iter()
            .position(|byte| *byte == 0)
            .and_then(|end| std::str::from_utf8(&suffix[..end]).ok())
            .filter(|name| bytes.starts_with(b"NAME=") && !name.is_empty() && name.len() <= 24)
            .map(ToOwned::to_owned);
        return Classification::Name { name };
    }
    let Some(header) = parse_header(bytes) else {
        return Classification::Unknown;
    };
    if header.leader != DATA_LEADER && header.leader != CONTROL_LEADER {
        return Classification::Unknown;
    }

    let declared_end = 16usize.saturating_add(header.byte_count as usize);
    let payload_complete = bytes.len() >= declared_end;
    let payload_end = bytes.len().min(declared_end);
    let payload = bytes[16..payload_end].to_vec();
    let tail = bytes.get(declared_end..).unwrap_or_default();
    let trailer_value = tail.first().copied();
    let trailer_present = header.leader == DATA_LEADER && trailer_value == Some(TRAILER);
    let extra_from = usize::from(trailer_present);
    let extra_bytes = tail.get(extra_from..).unwrap_or_default().to_vec();
    let checksum_valid = (header.leader == DATA_LEADER && payload_complete)
        .then(|| checksum(&payload) == header.checksum);

    let state_change =
        (header.packet_type == KD_STATE_CHANGE64 && payload.len() >= 12).then(|| {
            let new_state = u32le(&payload, 0).expect("length checked");
            StateChange {
                new_state,
                processor_level: u16le(&payload, 4).expect("length checked"),
                processor: u16le(&payload, 6).expect("length checked"),
                number_processors: u32le(&payload, 8).expect("length checked"),
                semantic: match new_state {
                    0x3030 => "DbgKdExceptionStateChange",
                    DBGKD_LOAD_SYMBOLS_STATE_CHANGE => "DbgKdLoadSymbolsStateChange",
                    0x3032 => "DbgKdCommandStringStateChange",
                    _ => "unknown-state-change",
                },
            }
        });
    let manipulate =
        (header.packet_type == KD_STATE_MANIPULATE && payload.len() >= 12).then(|| {
            let api_number = u32le(&payload, 0).expect("length checked");
            Manipulate {
                api_number,
                processor_level: u16le(&payload, 4).expect("length checked"),
                processor: u16le(&payload, 6).expect("length checked"),
                return_status: u32le(&payload, 8).expect("length checked"),
                semantic: api_name(api_number),
            }
        });

    Classification::Kd(KdPacket {
        header,
        class: if header.leader == DATA_LEADER {
            packet_type_name(header.packet_type)
        } else {
            match header.packet_type {
                KD_ACKNOWLEDGE => "KD_ACKNOWLEDGE",
                KD_RESEND => "KD_RESEND",
                KD_RESET => "KD_RESET",
                _ => "KD_UNKNOWN_CONTROL",
            }
        },
        payload_complete,
        payload,
        checksum_valid,
        trailer_present,
        trailer_value,
        extra_bytes,
        state_change,
        manipulate,
    })
}

pub fn acknowledge(packet_id: u32) -> [u8; 16] {
    control(KD_ACKNOWLEDGE, packet_id)
}

pub fn control(packet_type: u16, packet_id: u32) -> [u8; 16] {
    let mut bytes = [0u8; 16];
    bytes[0..4].copy_from_slice(&CONTROL_LEADER.to_le_bytes());
    bytes[4..6].copy_from_slice(&packet_type.to_le_bytes());
    bytes[8..12].copy_from_slice(&packet_id.to_le_bytes());
    bytes
}

/// Serialize the whitelisted GetVersion header+payload for offline analysis.
/// Whether an outgoing legacy KDUSB transfer must append the classic serial
/// trailer remains unverified. The live engine does not call this serializer.
pub fn get_version_query(packet_id: u32, processor: u16) -> Vec<u8> {
    let mut payload = vec![0u8; 56];
    payload[0..4].copy_from_slice(&DBGKD_GET_VERSION_API.to_le_bytes());
    payload[6..8].copy_from_slice(&processor.to_le_bytes());
    let header = Header {
        leader: DATA_LEADER,
        packet_type: KD_STATE_MANIPULATE,
        byte_count: payload.len() as u16,
        packet_id,
        checksum: checksum(&payload),
    };
    let mut bytes = Vec::with_capacity(16 + payload.len());
    bytes.extend_from_slice(&header.leader.to_le_bytes());
    bytes.extend_from_slice(&header.packet_type.to_le_bytes());
    bytes.extend_from_slice(&header.byte_count.to_le_bytes());
    bytes.extend_from_slice(&header.packet_id.to_le_bytes());
    bytes.extend_from_slice(&header.checksum.to_le_bytes());
    bytes.extend_from_slice(&payload);
    bytes
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PacketIdDisposition {
    FirstSync,
    Expected,
    Duplicate,
    OutOfSequence,
}

#[derive(Debug, Default)]
pub struct PacketIdTracker {
    expected: Option<u32>,
    last_accepted: Option<u32>,
}

impl PacketIdTracker {
    pub fn observe(&mut self, packet_id: u32) -> PacketIdDisposition {
        let base = packet_id & !SYNC_PACKET_ID;
        // Classic KD reuses IDs on every second *new* packet. Comparing
        // against a lifetime set incorrectly rejects the third packet.
        if self.last_accepted == Some(base) {
            return PacketIdDisposition::Duplicate;
        }
        let sync = packet_id & SYNC_PACKET_ID != 0;
        let disposition = if sync {
            PacketIdDisposition::FirstSync
        } else if self.expected.is_none() || self.expected == Some(base) {
            PacketIdDisposition::Expected
        } else {
            PacketIdDisposition::OutOfSequence
        };
        if disposition != PacketIdDisposition::OutOfSequence {
            self.expected = Some(base ^ 1);
            self.last_accepted = Some(base);
        }
        disposition
    }
}

/// The limits are applied to actual protocol operations, including the
/// authoritative initial ACK. A TX reservation is never retried automatically.
#[derive(Clone, Debug)]
pub struct Budgets {
    pub reads: usize,
    pub control_tx: usize,
    pub data_acks: usize,
    pub query_tx: usize,
    pub max_reads: usize,
    pub max_control_tx: usize,
    pub max_data_acks: usize,
    pub max_query_tx: usize,
    pub max_active_ms: u64,
}

impl Default for Budgets {
    fn default() -> Self {
        Self {
            reads: 0,
            control_tx: 0,
            data_acks: 0,
            query_tx: 0,
            max_reads: 64,
            max_control_tx: 16,
            max_data_acks: 16,
            max_query_tx: 1,
            max_active_ms: 60_000,
        }
    }
}

impl Budgets {
    pub fn reserve_read(&mut self, elapsed_ms: u64) -> Result<(), &'static str> {
        if elapsed_ms >= self.max_active_ms {
            return Err("ACTIVE_TIME_BUDGET_REACHED");
        }
        if self.reads >= self.max_reads {
            return Err("READ_BUDGET_REACHED");
        }
        self.reads += 1;
        Ok(())
    }

    pub fn reserve_ack(&mut self, elapsed_ms: u64) -> Result<(), &'static str> {
        if elapsed_ms >= self.max_active_ms {
            return Err("ACTIVE_TIME_BUDGET_REACHED");
        }
        if self.control_tx >= self.max_control_tx {
            return Err("CONTROL_TX_BUDGET_REACHED");
        }
        if self.data_acks >= self.max_data_acks {
            return Err("DATA_ACK_BUDGET_REACHED");
        }
        self.control_tx += 1;
        self.data_acks += 1;
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Decision {
    Receive(&'static str),
    Acknowledge {
        packet_id: u32,
        disposition: PacketIdDisposition,
    },
    Stop(&'static str),
}

/// Pure conversation policy, shared by USB execution and transcript replay.
/// The first ACK is for CB's retained header, whose entire payload is unavailable.
#[derive(Debug)]
pub struct Conversation {
    pub ids: PacketIdTracker,
    last_packet: Option<(u32, Vec<u8>)>,
    initial_retransmit: bool,
    timeouts: usize,
    duplicate_streak: usize,
    pub processor: u16,
}

impl Default for Conversation {
    fn default() -> Self {
        let mut ids = PacketIdTracker::default();
        ids.observe(INITIAL_PACKET_ID | SYNC_PACKET_ID);
        Self {
            ids,
            last_packet: None,
            initial_retransmit: true,
            timeouts: 0,
            duplicate_streak: 0,
            processor: 13,
        }
    }
}

impl Conversation {
    pub fn timeout(&mut self) -> Decision {
        self.timeouts += 1;
        if self.timeouts >= 4 {
            // Payload layout is defined, but host->target KDUSB trailer
            // framing is not yet verified by a public implementation/capture.
            Decision::Stop("SILENCE_QUERY_FRAMING_UNVERIFIED")
        } else {
            Decision::Receive("bounded receive-only opportunity before any query")
        }
    }

    pub fn receive(&mut self, class: &Classification, bytes: &[u8]) -> Decision {
        if matches!(class, Classification::Empty) {
            return Decision::Receive("USB ZLP is independently retained");
        }
        self.timeouts = 0;
        match class {
            Classification::Name { name } => {
                if name.as_deref().is_some_and(|n| n != "CLSA0102_USB") {
                    Decision::Stop("NAME_TARGET_IDENTITY_MISMATCH")
                } else {
                    Decision::Receive("NAME/NAME-like packet retained independently")
                }
            }
            Classification::Unknown => Decision::Stop("UNKNOWN_TRANSPORT_PACKET"),
            Classification::Empty => unreachable!(),
            Classification::Kd(p) if p.header.leader == CONTROL_LEADER => {
                if p.header.byte_count != 0 || p.header.checksum != 0 || !p.extra_bytes.is_empty() {
                    return Decision::Stop("MALFORMED_CONTROL_PACKET");
                }
                match p.header.packet_type {
                    KD_ACKNOWLEDGE => {
                        Decision::Receive("stray ACK classified; no query is in flight")
                    }
                    KD_RESET => Decision::Stop("TARGET_RESET_OBSERVED_NO_AUTOMATIC_RESPONSE"),
                    KD_RESEND => Decision::Stop("TARGET_RESEND_NO_VERIFIED_DATA_REQUEST_IN_FLIGHT"),
                    _ => Decision::Stop("UNKNOWN_KD_CONTROL"),
                }
            }
            Classification::Kd(p) => {
                if p.header.byte_count > 4000 {
                    return Decision::Stop("KD_PAYLOAD_OVER_LIMIT");
                }
                if !p.payload_complete {
                    return Decision::Stop("INCOMPLETE_USB_TRANSPORT_PACKET");
                }
                if p.checksum_valid != Some(true) {
                    return Decision::Stop("INVALID_CHECKSUM_NO_AUTOMATIC_RESEND");
                }
                if !p.extra_bytes.is_empty() {
                    return Decision::Stop("UNVERIFIED_BYTES_AFTER_KD_PAYLOAD");
                }
                let disposition = self.ids.observe(p.header.packet_id);
                if disposition == PacketIdDisposition::OutOfSequence {
                    return Decision::Stop("OUT_OF_SEQUENCE_PACKET_ID");
                }
                if disposition == PacketIdDisposition::Duplicate {
                    if let Some((id, prior)) = &self.last_packet {
                        if *id == (p.header.packet_id & !SYNC_PACKET_ID) && prior != &p.payload {
                            return Decision::Stop("SAME_PACKET_ID_DIFFERENT_PAYLOAD");
                        }
                    }
                    // CB's complete bytes are missing. A complete retransmit
                    // may validate its header/payload but is not ACKed again.
                    if self.initial_retransmit && self.last_packet.is_none() {
                        self.last_packet =
                            Some((p.header.packet_id & !SYNC_PACKET_ID, p.payload.clone()));
                    }
                    self.duplicate_streak += 1;
                    if self.duplicate_streak >= 2 {
                        return Decision::Stop("REPEATED_ALREADY_ACKNOWLEDGED_PACKET");
                    }
                    return Decision::Receive(
                        "duplicate/retransmission; previous ACK is not repeated",
                    );
                }
                self.duplicate_streak = 0;
                self.initial_retransmit = false;
                self.last_packet = Some((p.header.packet_id & !SYNC_PACKET_ID, p.payload.clone()));
                let _ = bytes; // Raw bytes belong to the recorder, not this state.
                if let Some(state) = &p.state_change {
                    self.processor = state.processor;
                }
                Decision::Acknowledge {
                    packet_id: p.header.packet_id,
                    disposition,
                }
            }
        }
    }

    pub fn after_ack(&self, class: &Classification) -> Option<&'static str> {
        let Classification::Kd(p) = class else {
            return None;
        };
        match p.header.packet_type {
            KD_FILE_IO | KD_DEBUG_IO | KD_CONTROL_REQUEST => {
                Some("UNEXPECTED_SEMANTIC_CLASS_PASSIVE_STOP")
            }
            KD_STATE_MANIPULATE => Some("UNSOLICITED_MANIPULATE_PASSIVE_STOP"),
            KD_STATE_CHANGE64 if p.state_change.is_some() => None,
            _ => Some("UNKNOWN_KD_SEMANTIC_PASSIVE_STOP"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn data(payload: &[u8], trailer: bool) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&DATA_LEADER.to_le_bytes());
        out.extend_from_slice(&KD_STATE_CHANGE64.to_le_bytes());
        out.extend_from_slice(&(payload.len() as u16).to_le_bytes());
        out.extend_from_slice(&0x8080_0800u32.to_le_bytes());
        out.extend_from_slice(&checksum(payload).to_le_bytes());
        out.extend_from_slice(payload);
        if trailer {
            out.push(TRAILER);
        }
        out
    }

    #[test]
    fn cb_shape_without_trailer_and_delayed_name() {
        let retained_prefix = hex::decode("3030303007004a0100088080524400003130000019000d00100000000000000040f050980ea7ffff05e02f9b07f8ffff5a0000000000000000000b2a07f8ffff").unwrap();
        assert_eq!(parse_header(&retained_prefix).unwrap().byte_count, 330);
        let mut payload = vec![0u8; 330];
        payload[..48].copy_from_slice(&retained_prefix[16..64]);
        let packet = data(&payload, false);
        assert_eq!(packet.len(), 346);
        let Classification::Kd(parsed) = classify_usb_transfer(&packet) else {
            panic!()
        };
        assert!(!parsed.trailer_present);
        assert_eq!(parsed.state_change.unwrap().processor, 13);
        assert_eq!(
            classify_usb_transfer(b"NAME=CLSA0102_USB\0\0"),
            Classification::Name {
                name: Some("CLSA0102_USB".into())
            }
        );
    }

    #[test]
    fn trailer_checksum_and_checksum_failure() {
        let payload = vec![7u8; 330];
        let no_trailer = data(&payload, false);
        let with_trailer = data(&payload, true);
        assert_eq!(no_trailer.len(), 346);
        assert_eq!(with_trailer.len(), 347);
        let Classification::Kd(ok) = classify_usb_transfer(&with_trailer) else {
            panic!()
        };
        assert_eq!(ok.checksum_valid, Some(true));
        assert!(ok.trailer_present);
        let mut bad = no_trailer;
        bad[20] ^= 1;
        let Classification::Kd(bad) = classify_usb_transfer(&bad) else {
            panic!()
        };
        assert_eq!(bad.checksum_valid, Some(false));
    }

    #[test]
    fn ack_and_query_are_byte_exact() {
        assert_eq!(
            hex::encode(acknowledge(0x8080_0800)),
            "69696969040000000008808000000000"
        );
        let query = get_version_query(INITIAL_PACKET_ID, 13);
        assert_eq!(query.len(), 72);
        assert_eq!(
            &hex::encode(&query)[..32],
            "30303030020038000000808084000000"
        );
        assert_eq!(&hex::encode(&query)[32..48], "4631000000000d00");
    }

    #[test]
    fn packet_ids_sync_duplicate_and_toggle() {
        let mut ids = PacketIdTracker::default();
        assert_eq!(ids.observe(0x8080_0800), PacketIdDisposition::FirstSync);
        assert_eq!(ids.observe(0x8080_0800), PacketIdDisposition::Duplicate);
        assert_eq!(ids.observe(0x8080_0001), PacketIdDisposition::Expected);
        assert_eq!(ids.observe(0x8080_0000), PacketIdDisposition::Expected);
        assert_eq!(ids.observe(0x8080_0001), PacketIdDisposition::Expected);
        assert_eq!(ids.observe(0x8080_0002), PacketIdDisposition::OutOfSequence);
    }

    #[test]
    fn control_unknown_and_multiple_are_independent() {
        let ack = acknowledge(INITIAL_PACKET_ID);
        let Classification::Kd(ack) = classify_usb_transfer(&ack) else {
            panic!()
        };
        assert_eq!(ack.class, "KD_ACKNOWLEDGE");
        assert_eq!(classify_usb_transfer(b"odd"), Classification::Unknown);
        let a = data(&vec![1; 330], false);
        let b = data(&vec![2; 330], true);
        assert!(matches!(classify_usb_transfer(&a), Classification::Kd(_)));
        assert!(matches!(classify_usb_transfer(&b), Classification::Kd(_)));
        assert_eq!(classify_usb_transfer(&[]), Classification::Empty);
    }

    fn with_id(mut packet: Vec<u8>, id: u32) -> Vec<u8> {
        packet[8..12].copy_from_slice(&id.to_le_bytes());
        packet
    }

    #[test]
    fn conversation_walks_sixteen_toggling_packets() {
        let mut conv = Conversation::default();
        for index in 0..16u32 {
            let mut payload = vec![0; 330];
            payload[..4].copy_from_slice(&DBGKD_LOAD_SYMBOLS_STATE_CHANGE.to_le_bytes());
            payload[32] = index as u8;
            let id = INITIAL_PACKET_ID | ((index + 1) & 1);
            let bytes = with_id(data(&payload, false), id);
            assert_eq!(
                conv.receive(&classify_usb_transfer(&bytes), &bytes),
                Decision::Acknowledge {
                    packet_id: id,
                    disposition: PacketIdDisposition::Expected
                }
            );
            assert!(matches!(
                conv.receive(&classify_usb_transfer(&bytes), &bytes),
                Decision::Receive(_)
            ));
        }
    }

    #[test]
    fn timeout_budget_and_name_interleaving() {
        let mut conv = Conversation::default();
        for _ in 0..3 {
            assert!(matches!(conv.timeout(), Decision::Receive(_)));
        }
        let name = b"NAME=CLSA0102_USB\0\0";
        assert!(matches!(
            conv.receive(&classify_usb_transfer(name), name),
            Decision::Receive(_)
        ));
        for _ in 0..3 {
            assert!(matches!(conv.timeout(), Decision::Receive(_)));
        }
        assert_eq!(
            conv.timeout(),
            Decision::Stop("SILENCE_QUERY_FRAMING_UNVERIFIED")
        );
        assert!(matches!(
            classify_usb_transfer(b"NAME?"),
            Classification::Name { name: None }
        ));
    }

    #[test]
    fn bounds_are_enforced_before_operations() {
        let mut budgets = Budgets::default();
        for _ in 0..64 {
            budgets.reserve_read(1).unwrap();
        }
        assert_eq!(budgets.reserve_read(1), Err("READ_BUDGET_REACHED"));
        for _ in 0..16 {
            budgets.reserve_ack(1).unwrap();
        }
        assert_eq!(budgets.reserve_ack(1), Err("CONTROL_TX_BUDGET_REACHED"));
        let mut budgets = Budgets::default();
        assert_eq!(
            budgets.reserve_read(60_000),
            Err("ACTIVE_TIME_BUDGET_REACHED")
        );
        assert_eq!(
            budgets.reserve_ack(60_000),
            Err("ACTIVE_TIME_BUDGET_REACHED")
        );
        assert_eq!(budgets.reads, 0);
        assert_eq!(budgets.control_tx, 0);
    }

    #[test]
    fn corrupt_packets_stop_without_ack_and_full_query_layout() {
        let mut conv = Conversation::default();
        let mut bad = with_id(data(&[1; 330], false), INITIAL_PACKET_ID ^ 1);
        bad[20] ^= 1;
        assert_eq!(
            conv.receive(&classify_usb_transfer(&bad), &bad),
            Decision::Stop("INVALID_CHECKSUM_NO_AUTOMATIC_RESEND")
        );
        let incomplete = &bad[..64];
        assert_eq!(
            conv.receive(&classify_usb_transfer(incomplete), incomplete),
            Decision::Stop("INCOMPLETE_USB_TRANSPORT_PACKET")
        );
        let mut ack = acknowledge(INITIAL_PACKET_ID).to_vec();
        ack.push(TRAILER);
        assert_eq!(
            conv.receive(&classify_usb_transfer(&ack), &ack),
            Decision::Stop("MALFORMED_CONTROL_PACKET")
        );
        let mut expected = hex::decode("303030300200380000008080840000004631000000000d00").unwrap();
        expected.resize(72, 0);
        assert_eq!(get_version_query(INITIAL_PACKET_ID, 13), expected);
    }

    #[test]
    fn duplicate_payload_conflict_and_reset_stop() {
        let mut conv = Conversation::default();
        let bytes = with_id(data(&[2; 330], false), INITIAL_PACKET_ID ^ 1);
        assert!(matches!(
            conv.receive(&classify_usb_transfer(&bytes), &bytes),
            Decision::Acknowledge { .. }
        ));
        let other = with_id(data(&[3; 330], false), INITIAL_PACKET_ID ^ 1);
        assert_eq!(
            conv.receive(&classify_usb_transfer(&other), &other),
            Decision::Stop("SAME_PACKET_ID_DIFFERENT_PAYLOAD")
        );
        let reset = control(KD_RESET, 0);
        assert_eq!(
            conv.receive(&classify_usb_transfer(&reset), &reset),
            Decision::Stop("TARGET_RESET_OBSERVED_NO_AUTOMATIC_RESPONSE")
        );
    }
}
