//! Conservative r2 policy. Each successful USB completion is a packet boundary.
//! The consumed r1 decoder is reused without reopening or changing its policy.
pub use crate::kdusb_discovery::{
    CONTROL_LEADER, Classification, DATA_LEADER, DBGKD_GET_VERSION_API,
    DBGKD_LOAD_SYMBOLS_STATE_CHANGE, INITIAL_PACKET_ID, KD_ACKNOWLEDGE, KD_DEBUG_IO, KD_FILE_IO,
    KD_RESEND, KD_RESET, KD_STATE_CHANGE64, KD_STATE_MANIPULATE, SYNC_PACKET_ID, acknowledge,
    checksum, classify_usb_transfer, control, get_version_query,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PacketIdDisposition {
    Expected,
    FirstSync,
    Duplicate,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Decision {
    Receive(&'static str),
    Acknowledge {
        packet_id: u32,
        disposition: PacketIdDisposition,
    },
    Retransmit(Vec<u8>),
    Stop(&'static str),
}

#[derive(Debug)]
pub struct Conversation {
    expected: u32,
    last_packet: Option<Vec<u8>>,
    duplicate_acks: usize,
    timeouts: usize,
    pending_data: Option<Vec<u8>>,
    requested_retransmits: usize,
    total_retransmits: usize,
    pub new_packets: usize,
}
impl Default for Conversation {
    fn default() -> Self {
        Self {
            expected: INITIAL_PACKET_ID ^ 1,
            last_packet: None,
            duplicate_acks: 0,
            timeouts: 0,
            pending_data: None,
            requested_retransmits: 0,
            total_retransmits: 0,
            new_packets: 0,
        }
    }
}
impl Conversation {
    /// Only a completed, source-verified host data submission can await ACK/RESEND.
    /// The live r2 engine never registers one: GetVersion framing is unresolved.
    pub fn verified_data_sent(&mut self, bytes: &[u8]) -> Result<(), &'static str> {
        match classify_usb_transfer(bytes) {
            Classification::Kd(p)
                if p.header.leader == DATA_LEADER
                    && p.header.packet_type == KD_STATE_MANIPULATE
                    && p.manipulate
                        .as_ref()
                        .is_some_and(|m| m.api_number == DBGKD_GET_VERSION_API)
                    && p.header.byte_count == 56
                    && p.payload_complete
                    && p.checksum_valid == Some(true)
                    && p.extra_bytes.is_empty() =>
            {
                self.pending_data = Some(bytes.to_vec());
                self.requested_retransmits = 0;
                Ok(())
            }
            _ => Err("UNVERIFIED_HOST_DATA_PACKET"),
        }
    }
    pub fn timeout(&mut self) -> Decision {
        self.timeouts += 1;
        if self.timeouts >= 4 {
            Decision::Stop("SILENCE_QUERY_FRAMING_UNVERIFIED")
        } else {
            Decision::Receive("bounded receive-only opportunity")
        }
    }
    pub fn receive(&mut self, class: &Classification, bytes: &[u8]) -> Decision {
        match class {
            Classification::Empty => return Decision::Receive("USB ZLP retained"),
            Classification::Unknown => return Decision::Stop("UNKNOWN_TRANSPORT_PACKET"),
            Classification::Name { name: Some(name) } if name == "CLSA0102_USB" => {
                self.timeouts = 0;
                return Decision::Receive("NAME retained independently");
            }
            Classification::Name { .. } => return Decision::Stop("AMBIGUOUS_OR_MISMATCHED_NAME"),
            _ => {}
        }
        self.timeouts = 0;
        let Classification::Kd(p) = class else {
            unreachable!()
        };
        if p.header.leader == CONTROL_LEADER {
            if p.header.byte_count != 0 || p.header.checksum != 0 || !p.extra_bytes.is_empty() {
                return Decision::Stop("MALFORMED_CONTROL_PACKET");
            }
            return match p.header.packet_type {
                KD_RESET => Decision::Stop("TARGET_RESET_NO_VERIFIED_RESPONSE"),
                KD_ACKNOWLEDGE => {
                    if let Some(last) = &self.pending_data {
                        let Classification::Kd(sent) = classify_usb_transfer(last) else {
                            unreachable!()
                        };
                        if (p.header.packet_id & !SYNC_PACKET_ID)
                            != (sent.header.packet_id & !SYNC_PACKET_ID)
                        {
                            return Decision::Stop("TARGET_ACK_WRONG_PACKET_ID");
                        }
                        self.pending_data = None;
                        Decision::Receive(
                            "matching ACK completes pending host data; independent stream",
                        )
                    } else {
                        Decision::Receive("stray target ACK; no host data pending")
                    }
                }
                KD_RESEND => {
                    // Classic RESEND has PacketId zero and retransmits pending DATA,
                    // not an ACK control packet (ReactOS kddll.h receive/send loop).
                    if p.header.packet_id != 0 {
                        return Decision::Stop("UNVERIFIED_RESEND_PACKET_ID");
                    }
                    if let Some(last) = &self.pending_data {
                        if self.requested_retransmits >= 1 || self.total_retransmits >= 2 {
                            Decision::Stop("REQUESTED_RETRANSMISSION_BUDGET_REACHED")
                        } else {
                            self.requested_retransmits += 1;
                            self.total_retransmits += 1;
                            Decision::Retransmit(last.clone())
                        }
                    } else {
                        Decision::Stop("TARGET_RESEND_NO_VERIFIED_DATA_IN_FLIGHT")
                    }
                }
                _ => Decision::Stop("UNKNOWN_KD_CONTROL"),
            };
        }
        if p.header.byte_count > 4000 {
            return Decision::Stop("KD_PAYLOAD_OVER_LIMIT");
        }
        if !p.payload_complete {
            return Decision::Stop("INCOMPLETE_USB_TRANSPORT_PACKET");
        }
        if p.checksum_valid != Some(true) {
            return Decision::Stop("INVALID_CHECKSUM_NO_VERIFIED_RESEND");
        }
        if !p.extra_bytes.is_empty() {
            return Decision::Stop("UNVERIFIED_BYTES_AFTER_PAYLOAD");
        }
        // Stop before any ACK of unmodeled semantics.
        if p.header.packet_type != KD_STATE_CHANGE64 {
            return Decision::Stop("UNMODELED_SEMANTIC_NO_RESPONSE");
        }
        let Some(state) = &p.state_change else {
            return Decision::Stop("INCOMPLETE_STATE_STRUCTURE");
        };
        if p.payload.len() < 240 {
            return Decision::Stop("INCOMPLETE_STATE_STRUCTURE");
        }
        if !matches!(state.new_state, 0x3030 | DBGKD_LOAD_SYMBOLS_STATE_CHANGE) {
            return Decision::Stop("UNMODELED_STATE_NO_RESPONSE");
        }
        let base = p.header.packet_id & !SYNC_PACKET_ID;
        if base != INITIAL_PACKET_ID && base != INITIAL_PACKET_ID ^ 1 {
            return Decision::Stop("OUT_OF_SEQUENCE_PACKET_ID");
        }
        // Compare the entire logical packet, normalizing only SYNC and trailer.
        let mut normalized = bytes[..16 + usize::from(p.header.byte_count)].to_vec();
        normalized[8..12].copy_from_slice(&base.to_le_bytes());
        let duplicate = if let Some(last) = &self.last_packet {
            let last_id = u32::from_le_bytes(last[8..12].try_into().unwrap());
            if last_id == base && last != &normalized {
                return Decision::Stop("SAME_PACKET_ID_DIFFERENT_PACKET");
            }
            last_id == base
        } else if base == INITIAL_PACKET_ID {
            // Only CB's header and prefix are retained; validate that prefix too.
            let prefix = hex::decode("3030303007004a0100088080524400003130000019000d00100000000000000040f050980ea7ffff05e02f9b07f8ffff5a0000000000000000000b2a07f8ffff").unwrap();
            let mut expected = prefix;
            expected[8..12].copy_from_slice(&base.to_le_bytes());
            if !normalized.starts_with(&expected) {
                return Decision::Stop("PREDECESSOR_RETRANSMISSION_PREFIX_MISMATCH");
            }
            true
        } else {
            false
        };
        if duplicate {
            if self.duplicate_acks >= 1 {
                return Decision::Stop("REPEATED_ALREADY_ACKNOWLEDGED_PACKET");
            }
            self.duplicate_acks += 1;
            self.last_packet = Some(normalized);
            return Decision::Acknowledge {
                packet_id: p.header.packet_id,
                disposition: PacketIdDisposition::Duplicate,
            };
        }
        if base != self.expected && p.header.packet_id & SYNC_PACKET_ID == 0 {
            return Decision::Stop("OUT_OF_SEQUENCE_PACKET_ID");
        }
        self.expected = base ^ 1;
        self.last_packet = Some(normalized);
        self.duplicate_acks = 0;
        self.new_packets += 1;
        Decision::Acknowledge {
            packet_id: p.header.packet_id,
            disposition: if p.header.packet_id & SYNC_PACKET_ID != 0 {
                PacketIdDisposition::FirstSync
            } else {
                PacketIdDisposition::Expected
            },
        }
    }
    pub fn after_ack(&self, _: &Classification) -> Option<&'static str> {
        None
    }
}

#[derive(Clone, Debug, Default)]
pub struct Budgets {
    pub reads: usize,
    pub control_tx: usize,
    pub data_acks: usize,
    pub query_tx: usize,
}
impl Budgets {
    pub fn reserve_read(&mut self, elapsed: u64) -> Result<(), &'static str> {
        if elapsed >= 60_000 {
            return Err("ACTIVE_TIME_BUDGET_REACHED");
        }
        if self.reads >= 64 {
            return Err("READ_BUDGET_REACHED");
        }
        self.reads += 1;
        Ok(())
    }
    pub fn reserve_control(&mut self, elapsed: u64, new_data: bool) -> Result<(), &'static str> {
        if elapsed >= 60_000 {
            return Err("ACTIVE_TIME_BUDGET_REACHED");
        }
        if self.control_tx >= 20 {
            return Err("CONTROL_TX_BUDGET_REACHED");
        }
        if new_data && self.data_acks >= 16 {
            return Err("NEW_DATA_ACK_BUDGET_REACHED");
        }
        self.control_tx += 1;
        self.data_acks += usize::from(new_data);
        Ok(())
    }
    pub fn reserve_query(&mut self, elapsed: u64) -> Result<(), &'static str> {
        if elapsed >= 60_000 {
            return Err("ACTIVE_TIME_BUDGET_REACHED");
        }
        if self.query_tx >= 1 {
            return Err("QUERY_BUDGET_REACHED");
        }
        self.query_tx += 1;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn data(id: u32, state: u32, marker: u8) -> Vec<u8> {
        let mut payload = vec![0; 330];
        payload[..4].copy_from_slice(&state.to_le_bytes());
        payload[32] = marker;
        let mut out = Vec::new();
        out.extend(DATA_LEADER.to_le_bytes());
        out.extend(KD_STATE_CHANGE64.to_le_bytes());
        out.extend(330u16.to_le_bytes());
        out.extend(id.to_le_bytes());
        out.extend(checksum(&payload).to_le_bytes());
        out.extend(payload);
        out
    }
    fn rx(c: &mut Conversation, b: &[u8]) -> Decision {
        c.receive(&classify_usb_transfer(b), b)
    }
    #[test]
    fn toggling_reuse_duplicate_once_and_sync() {
        let mut c = Conversation::default();
        for i in 0..16 {
            let id = INITIAL_PACKET_ID | ((i + 1) & 1);
            let b = data(id, 0x3031, i as u8);
            assert!(matches!(
                rx(&mut c, &b),
                Decision::Acknowledge {
                    disposition: PacketIdDisposition::Expected,
                    ..
                }
            ));
            assert!(matches!(
                rx(&mut c, &b),
                Decision::Acknowledge {
                    disposition: PacketIdDisposition::Duplicate,
                    ..
                }
            ));
        }
        let b = data(INITIAL_PACKET_ID, 0x3031, 15);
        assert!(matches!(
            rx(&mut c, &b),
            Decision::Stop("REPEATED_ALREADY_ACKNOWLEDGED_PACKET")
        ));
        assert_eq!(c.new_packets, 16);
        let mut c = Conversation::default();
        let b = data(INITIAL_PACKET_ID | SYNC_PACKET_ID | 1, 0x3031, 1);
        assert!(matches!(
            rx(&mut c, &b),
            Decision::Acknowledge {
                disposition: PacketIdDisposition::FirstSync,
                ..
            }
        ));
    }
    #[test]
    fn shapes_checksum_optional_trailer_and_name_order() {
        let mut c = Conversation::default();
        let b = data(INITIAL_PACKET_ID ^ 1, 0x3031, 1);
        assert_eq!(b.len(), 346);
        assert!(matches!(rx(&mut c, &b), Decision::Acknowledge { .. }));
        assert!(matches!(
            rx(&mut c, b"NAME=CLSA0102_USB\0\0"),
            Decision::Receive(_)
        ));
        let mut trailer = data(INITIAL_PACKET_ID, 0x3031, 2);
        trailer.push(0xaa);
        assert_eq!(trailer.len(), 347);
        assert!(matches!(rx(&mut c, &trailer), Decision::Acknowledge { .. }));
        trailer[25] ^= 1;
        assert_eq!(
            rx(&mut c, &trailer),
            Decision::Stop("INVALID_CHECKSUM_NO_VERIFIED_RESEND")
        );
        assert_eq!(
            rx(&mut c, &b[..64]),
            Decision::Stop("INCOMPLETE_USB_TRANSPORT_PACKET")
        );
    }
    #[test]
    fn unknown_semantics_never_ack() {
        for state in [0x3032, 0x9999] {
            let b = data(INITIAL_PACKET_ID ^ 1, state, 0);
            assert!(matches!(
                rx(&mut Conversation::default(), &b),
                Decision::Stop(_)
            ));
        }
        for ty in [KD_DEBUG_IO, KD_FILE_IO, KD_STATE_MANIPULATE, 99] {
            let mut b = data(INITIAL_PACKET_ID ^ 1, 0x3031, 0);
            b[4..6].copy_from_slice(&ty.to_le_bytes());
            assert_eq!(
                rx(&mut Conversation::default(), &b),
                Decision::Stop("UNMODELED_SEMANTIC_NO_RESPONSE")
            );
        }
        assert_eq!(
            rx(&mut Conversation::default(), b"unknown"),
            Decision::Stop("UNKNOWN_TRANSPORT_PACKET")
        );
    }
    #[test]
    fn control_ack_resend_reset_exact_last_data_only() {
        let mut c = Conversation::default();
        let resend = control(KD_RESEND, 0);
        assert_eq!(
            rx(&mut c, &resend),
            Decision::Stop("TARGET_RESEND_NO_VERIFIED_DATA_IN_FLIGHT")
        );
        assert!(matches!(
            rx(&mut c, &acknowledge(INITIAL_PACKET_ID)),
            Decision::Receive(_)
        ));
        let query = get_version_query(INITIAL_PACKET_ID, 13);
        c.verified_data_sent(&query).unwrap();
        assert_eq!(rx(&mut c, &resend), Decision::Retransmit(query.clone()));
        assert_eq!(
            rx(&mut c, &resend),
            Decision::Stop("REQUESTED_RETRANSMISSION_BUDGET_REACHED")
        );
        assert!(matches!(
            rx(&mut c, &acknowledge(INITIAL_PACKET_ID | SYNC_PACKET_ID)),
            Decision::Receive(_)
        ));
        assert_eq!(
            rx(&mut c, &resend),
            Decision::Stop("TARGET_RESEND_NO_VERIFIED_DATA_IN_FLIGHT")
        );
        assert_eq!(
            rx(&mut c, &control(KD_RESET, 0)),
            Decision::Stop("TARGET_RESET_NO_VERIFIED_RESPONSE")
        );
        assert!(
            c.verified_data_sent(&acknowledge(INITIAL_PACKET_ID))
                .is_err()
        );
        let mut bad = resend.to_vec();
        bad.push(0xaa);
        assert_eq!(rx(&mut c, &bad), Decision::Stop("MALFORMED_CONTROL_PACKET"));
    }
    #[test]
    fn all_budgets_and_timeout_stop() {
        let mut b = Budgets::default();
        b.reserve_control(0, false).unwrap();
        for _ in 0..16 {
            b.reserve_control(1, true).unwrap();
        }
        assert_eq!(
            b.reserve_control(1, true),
            Err("NEW_DATA_ACK_BUDGET_REACHED")
        );
        for _ in 0..3 {
            b.reserve_control(1, false).unwrap();
        }
        assert_eq!(
            b.reserve_control(1, false),
            Err("CONTROL_TX_BUDGET_REACHED")
        );
        for _ in 0..64 {
            b.reserve_read(1).unwrap();
        }
        assert_eq!(b.reserve_read(1), Err("READ_BUDGET_REACHED"));
        b.reserve_query(1).unwrap();
        assert_eq!(b.reserve_query(1), Err("QUERY_BUDGET_REACHED"));
        let mut b = Budgets::default();
        assert!(b.reserve_read(60000).is_err());
        assert!(b.reserve_control(60000, false).is_err());
        assert!(b.reserve_query(60000).is_err());
        assert_eq!((b.reads, b.control_tx, b.query_tx), (0, 0, 0));
        let mut c = Conversation::default();
        for _ in 0..3 {
            assert!(matches!(c.timeout(), Decision::Receive(_)));
        }
        assert_eq!(
            c.timeout(),
            Decision::Stop("SILENCE_QUERY_FRAMING_UNVERIFIED")
        );
    }
    #[test]
    fn ack_and_offline_getversion_exact_bytes() {
        assert_eq!(
            hex::encode(acknowledge(0x80800800)),
            "69696969040000000008808000000000"
        );
        let mut expected = hex::decode("303030300200380000008080840000004631000000000d00").unwrap();
        expected.resize(72, 0);
        assert_eq!(get_version_query(INITIAL_PACKET_ID, 13), expected);
    }
}
