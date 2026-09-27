//! Minimal classic-KDUSB break-in/release transaction.
//!
//! This is intentionally narrower than the normal KD backend connection path:
//! NAME discovery is handled by KdUsbStream::connect, then exactly one break-in
//! is sent, exactly one state-change is accepted/ACKed, and one AMD64
//! ContinueApi2 request is sent through strict one-shot framing.
//!
//! No RESET, RESEND repair, GetVersion, breakpoint cleanup, memory access, or
//! debugger session setup occurs here.

use std::fmt;
use std::io::{Read, Write};
use std::time::Duration;

use crate::kd::api;
use crate::kd::framing::{KdFraming, PACKET_TYPE_KD_STATE_CHANGE64};

use super::parse_state_change;

#[cfg(target_os = "linux")]
use super::kdusb::KdUsbStream;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MinimalBreakinReleaseStage {
    Discovery,
    Breakin,
    StateChange,
    Continue,
}

impl fmt::Display for MinimalBreakinReleaseStage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Discovery => "discovery",
            Self::Breakin => "breakin",
            Self::StateChange => "state-change",
            Self::Continue => "continue",
        })
    }
}

#[derive(Debug)]
pub struct MinimalBreakinReleaseFailure {
    pub stage: MinimalBreakinReleaseStage,
    pub target_may_be_halted: bool,
    pub message: String,
}

impl fmt::Display for MinimalBreakinReleaseFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} stage failed (target_may_be_halted={}): {}",
            self.stage, self.target_may_be_halted, self.message
        )
    }
}

impl std::error::Error for MinimalBreakinReleaseFailure {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MinimalBreakinReleaseReport {
    pub processor: u16,
    pub number_processors: u16,
    pub program_counter: u64,
    pub dr7: u64,
    pub dr7_from_control_report: bool,
    pub breakin_sent: bool,
    pub state_change_received: bool,
    pub continue_acked: bool,
}

fn failure(
    stage: MinimalBreakinReleaseStage,
    target_may_be_halted: bool,
    err: impl fmt::Display,
) -> MinimalBreakinReleaseFailure {
    MinimalBreakinReleaseFailure {
        stage,
        target_may_be_halted,
        message: err.to_string(),
    }
}

pub fn minimal_breakin_release_with_transport<T: Read + Write>(
    transport: T,
) -> Result<MinimalBreakinReleaseReport, MinimalBreakinReleaseFailure> {
    let mut framing = KdFraming::new(transport);

    framing
        .send_breakin()
        .map_err(|err| failure(MinimalBreakinReleaseStage::Breakin, false, err))?;

    // Once the break-in byte has been accepted by the host transport, be
    // conservative: the target may halt even if its response is lost.
    let packet = framing
        .recv_data_once()
        .map_err(|err| failure(MinimalBreakinReleaseStage::StateChange, true, err))?;
    if packet.packet_type != PACKET_TYPE_KD_STATE_CHANGE64 {
        return Err(failure(
            MinimalBreakinReleaseStage::StateChange,
            true,
            format!(
                "expected KD state-change packet type {}, got {}",
                PACKET_TYPE_KD_STATE_CHANGE64, packet.packet_type
            ),
        ));
    }

    let stop = parse_state_change(&packet.payload)
        .map_err(|err| failure(MinimalBreakinReleaseStage::StateChange, true, err))?;

    let dr7 = stop
        .control_report
        .as_ref()
        .and_then(|report| report.amd64_dr7());
    let dr7_from_control_report = dr7.is_some();
    let dr7 = dr7.unwrap_or(0);

    api::continue_api2_once(&mut framing, stop.processor, api::DBG_CONTINUE, false, dr7)
        .map_err(|err| failure(MinimalBreakinReleaseStage::Continue, true, err))?;

    Ok(MinimalBreakinReleaseReport {
        processor: stop.processor,
        number_processors: stop.number_processors,
        program_counter: stop.program_counter,
        dr7,
        dr7_from_control_report,
        breakin_sent: true,
        state_change_received: true,
        continue_acked: true,
    })
}

#[cfg(target_os = "linux")]
pub fn minimal_breakin_release_usb(
    target_name: &str,
    timeout: Duration,
) -> Result<MinimalBreakinReleaseReport, MinimalBreakinReleaseFailure> {
    let mut stream = KdUsbStream::connect(target_name)
        .map_err(|err| failure(MinimalBreakinReleaseStage::Discovery, false, err))?;
    stream.set_read_timeout(Some(timeout));
    minimal_breakin_release_with_transport(stream)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Cursor, Read, Write};

    use crate::kd::framing::{
        HEADER_SIZE, Header, INITIAL_PACKET_ID, PACKET_TYPE_KD_ACKNOWLEDGE, PACKET_TYPE_KD_RESEND,
        PACKET_TYPE_KD_STATE_MANIPULATE, SYNC_PACKET_ID, control_packet, data_packet,
    };

    struct Loopback {
        inbound: Cursor<Vec<u8>>,
        outbound: Vec<u8>,
    }

    impl Loopback {
        fn new(inbound: Vec<u8>) -> Self {
            Self {
                inbound: Cursor::new(inbound),
                outbound: Vec::new(),
            }
        }
    }

    impl Read for Loopback {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            self.inbound.read(buf)
        }
    }

    impl Write for Loopback {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.outbound.write(buf)
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    fn state_change_payload(pc: u64, dr7: u64) -> Vec<u8> {
        let mut payload = vec![0u8; 240];
        payload[0..4].copy_from_slice(&super::super::DBG_KD_EXCEPTION_STATE_CHANGE.to_le_bytes());
        payload[6..8].copy_from_slice(&0u16.to_le_bytes());
        payload[8..12].copy_from_slice(&1u32.to_le_bytes());
        payload[24..32].copy_from_slice(&pc.to_le_bytes());
        payload[32..36].copy_from_slice(&super::super::STATUS_BREAKPOINT.to_le_bytes());
        payload[super::super::CONTROL_REPORT_OFFSET + 8..super::super::CONTROL_REPORT_OFFSET + 16]
            .copy_from_slice(&dr7.to_le_bytes());
        payload
    }

    fn happy_inbound(pc: u64, dr7: u64) -> Vec<u8> {
        let mut inbound = data_packet(
            PACKET_TYPE_KD_STATE_CHANGE64,
            INITIAL_PACKET_ID | SYNC_PACKET_ID,
            &state_change_payload(pc, dr7),
        );
        inbound.extend(control_packet(
            PACKET_TYPE_KD_ACKNOWLEDGE,
            INITIAL_PACKET_ID,
        ));
        inbound
    }

    #[test]
    fn minimal_breakin_release_is_exactly_breakin_ack_continue() {
        let pc = 0xffff_f800_1234_5678;
        let dr7 = 0x400;
        let transport = Loopback::new(happy_inbound(pc, dr7));
        let mut framing = KdFraming::new(transport);

        framing.send_breakin().unwrap();
        let packet = framing.recv_data_once().unwrap();
        let stop = parse_state_change(&packet.payload).unwrap();
        let observed_dr7 = stop
            .control_report
            .as_ref()
            .and_then(|report| report.amd64_dr7())
            .unwrap();
        api::continue_api2_once(
            &mut framing,
            stop.processor,
            api::DBG_CONTINUE,
            false,
            observed_dr7,
        )
        .unwrap();

        let outbound = &framing.transport_ref().outbound;
        assert_eq!(outbound[0], crate::kd::framing::BREAKIN_BYTE);

        let ack_start = 1;
        let ack_end = ack_start + HEADER_SIZE;
        let ack: [u8; HEADER_SIZE] = outbound[ack_start..ack_end].try_into().unwrap();
        let ack = Header::decode(&ack);
        assert_eq!(ack.packet_type, PACKET_TYPE_KD_ACKNOWLEDGE);

        let continue_header: [u8; HEADER_SIZE] =
            outbound[ack_end..ack_end + HEADER_SIZE].try_into().unwrap();
        let continue_header = Header::decode(&continue_header);
        assert_eq!(continue_header.packet_type, PACKET_TYPE_KD_STATE_MANIPULATE);
        assert_eq!(continue_header.packet_id, INITIAL_PACKET_ID);

        let report =
            minimal_breakin_release_with_transport(Loopback::new(happy_inbound(pc, dr7))).unwrap();
        assert_eq!(report.program_counter, pc);
        assert_eq!(report.dr7, dr7);
        assert!(report.dr7_from_control_report);
        assert!(report.continue_acked);
    }

    #[test]
    fn continue_resend_is_reported_without_retransmission() {
        let pc = 0xffff_f800_1234_5678;
        let dr7 = 0x400;
        let mut inbound = data_packet(
            PACKET_TYPE_KD_STATE_CHANGE64,
            INITIAL_PACKET_ID | SYNC_PACKET_ID,
            &state_change_payload(pc, dr7),
        );
        inbound.extend(control_packet(PACKET_TYPE_KD_RESEND, 0));

        let err = minimal_breakin_release_with_transport(Loopback::new(inbound)).unwrap_err();
        assert_eq!(err.stage, MinimalBreakinReleaseStage::Continue);
        assert!(err.target_may_be_halted);
        assert!(err.message.contains("RESEND"));
    }

    #[test]
    fn bad_state_change_checksum_sends_no_resend_and_marks_halt_risk() {
        let mut packet = data_packet(
            PACKET_TYPE_KD_STATE_CHANGE64,
            INITIAL_PACKET_ID | SYNC_PACKET_ID,
            &state_change_payload(0xffff_f800_1234_5678, 0x400),
        );
        packet[12] ^= 0x01;

        let mut transport = Loopback::new(packet);
        let mut framing = KdFraming::new(&mut transport);
        framing.send_breakin().unwrap();
        let err = framing.recv_data_once().unwrap_err();
        assert!(err.to_string().contains("checksum mismatch"));
        drop(framing);
        assert_eq!(transport.outbound, vec![crate::kd::framing::BREAKIN_BYTE]);
    }
}
