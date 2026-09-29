//! Phase 3.44BU: dry-by-default, one-shot passive classic-KD packet observer.
//!
//! The only transmitted bytes in live mode are one ASCII `NAME?` bootstrap.
//! Received NAME bytes are consumed locally and at most one complete, validated
//! classic KD packet is retained.  No KD protocol packet is ever transmitted.

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("ntoseye-kdusb-passive-kd-first-packet-r1 is Linux-only");
    std::process::exit(2);
}

#[cfg(target_os = "linux")]
fn main() {
    std::process::exit(linux::run());
}

#[cfg(target_os = "linux")]
mod linux {
    use ntoseye::kd::file_io::{FileIoRequest, parse_file_io};
    use rusb::{Device, Direction, GlobalContext, TransferType};
    use std::time::Duration;

    const LIVE_FLAG: &str = "--execute-passive-first-kd-packet";
    const REQUIRED_TARGET: &str = "CLSA0102_USB";
    const HARDWARE_IDS: &[(u16, u16)] = &[
        (0x3495, 0x00e0),
        (0x0525, 0x127a),
        (0x046b, 0x0980),
        (0x045e, 0x062d),
    ];
    const INTERFACE_CLASS: u8 = 0xdc;
    const INTERFACE_SUBCLASS: u8 = 0x02;
    const INTERFACE_PROTOCOL: u8 = 0xff;
    const NAME_PROBE: &[u8; 5] = b"NAME?";
    const NAME_PREFIX: &[u8; 5] = b"NAME=";
    const NAME_RESPONSE_MAX: usize = 37;
    const TARGET_NAME_MAX: usize = 24;
    const MAX_NAME_TX: usize = 1;
    const MAX_USB_READ_CALLS: usize = 4;
    const USB_READ_REQUEST: usize = 4016;
    const PER_READ_TIMEOUT_MS: u64 = 1000;
    const MAX_COMPLETE_KD_PACKET_BYTES: usize = 4017;
    const MAX_USB_DEVICE_RESET_ATTEMPTS: usize = 0;
    const MAX_ENDPOINT_RECREATION_ATTEMPTS: usize = 0;
    const AUTOMATIC_NAME_RETRY: bool = false;
    const AUTOMATIC_READ_RESTART: bool = false;
    const MAX_KD_PAYLOAD_BYTES: usize = 4000;
    const KD_HEADER_SIZE: usize = 16;
    const DATA_PACKET_LEADER: u32 = 0x3030_3030;
    const CONTROL_PACKET_LEADER: u32 = 0x6969_6969;
    const PACKET_TRAILING_BYTE: u8 = 0xaa;
    const TIMEOUT: Duration = Duration::from_millis(PER_READ_TIMEOUT_MS);

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    struct KdHeader {
        leader: u32,
        packet_type: u16,
        byte_count: u16,
        packet_id: u32,
        checksum: u32,
    }

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum BootstrapKind {
        Name,
        KdPrefetch,
    }

    #[derive(Debug)]
    struct PacketSummary {
        header: KdHeader,
        total_bytes: usize,
        checksum_valid: bool,
        trailer_valid: Option<bool>,
        surplus_bytes: usize,
        packet: Vec<u8>,
    }

    #[derive(Debug)]
    struct ReadObservation {
        status: &'static str,
        len: usize,
        prefix_hex: String,
    }

    #[derive(Default)]
    struct Assembly {
        kind: Option<BootstrapKind>,
        name_target: Option<String>,
        pending: Vec<u8>,
        optional_nul_pending: bool,
        duplicate_names: usize,
        stream: Vec<u8>,
    }

    struct Candidate {
        device: Device<GlobalContext>,
        vendor: u16,
        product: u16,
        interface: u8,
        alternate_setting: u8,
        bulk_in: u8,
        bulk_out: u8,
        max_packet: u16,
    }

    struct LiveReport {
        result: &'static str,
        vendor: u16,
        product: u16,
        interface: u8,
        alternate_setting: u8,
        bulk_in: u8,
        bulk_out: u8,
        max_packet: u16,
        name_target: Option<String>,
        duplicate_names: usize,
        reads: Vec<ReadObservation>,
        nonempty_reads: usize,
        timeout_reads: usize,
        stream_bytes: usize,
        packet: Option<PacketSummary>,
        error: Option<String>,
        interface_released: bool,
        name_probe_sent: bool,
    }

    pub fn run() -> i32 {
        let args: Vec<String> = std::env::args().skip(1).collect();
        if args.is_empty() {
            print_dry_plan();
            return 0;
        }
        if args != [LIVE_FLAG, REQUIRED_TARGET] {
            eprintln!(
                "usage: ntoseye-kdusb-passive-kd-first-packet-r1 [{LIVE_FLAG} {REQUIRED_TARGET}]"
            );
            return 2;
        }

        let report = match observe(REQUIRED_TARGET) {
            Ok(report) => report,
            Err((class, error)) => {
                println!("PHASE344BU_RESULT={class}");
                println!("ERROR={error}");
                print_safety_markers(true, false);
                return 3;
            }
        };
        print_report(&report);
        if report.result == "PASSIVE_COMPLETE_KD_PACKET" {
            0
        } else {
            4
        }
    }

    fn print_dry_plan() {
        println!("NTOSEYE_KDUSB_PASSIVE_KD_FIRST_PACKET=READY");
        println!("DEFAULT_MODE=DRY_PLAN");
        println!("LIVE_FLAG={LIVE_FLAG} {REQUIRED_TARGET}");
        println!("MAX_NAME_TX={MAX_NAME_TX}");
        println!("MAX_USB_READ_CALLS={MAX_USB_READ_CALLS}");
        println!("USB_READ_REQUEST={USB_READ_REQUEST}");
        println!("PER_READ_TIMEOUT_MS={PER_READ_TIMEOUT_MS}");
        println!("MAX_COMPLETE_KD_PACKET_BYTES={MAX_COMPLETE_KD_PACKET_BYTES}");
        println!("MAX_USB_DEVICE_RESET_ATTEMPTS={MAX_USB_DEVICE_RESET_ATTEMPTS}");
        println!("MAX_ENDPOINT_RECREATION_ATTEMPTS={MAX_ENDPOINT_RECREATION_ATTEMPTS}");
        println!("AUTOMATIC_NAME_RETRY={AUTOMATIC_NAME_RETRY}");
        println!("AUTOMATIC_READ_RESTART={AUTOMATIC_READ_RESTART}");
        print_safety_markers(false, false);
    }

    fn print_safety_markers(live: bool, name_probe_sent: bool) {
        println!("LIVE_USB_ACTIVITY={live}");
        println!("NAME_PROBE_SENT={name_probe_sent}");
        println!("KD_PACKET_TX=false");
        println!("KD_ACK_TX=false");
        println!("KD_RESEND_TX=false");
        println!("KD_RESET_TX=false");
        println!("KD_FILE_IO_REPLY_TX=false");
        println!("BREAKIN_SENT=false");
        println!("DEBUGGER_SESSION=false");
        println!("TARGET_MEMORY_ACCESS=false");
        println!("USB_DEVICE_RESET=false");
        println!("ENDPOINT_RECREATION_EXECUTED=false");
        println!("PHASE340_CLEANUP_AUTHORIZED=false");
    }

    fn observe(expected: &str) -> Result<LiveReport, (&'static str, String)> {
        let candidates = candidates().map_err(|e| ("OTHER_TRANSPORT_FAULT", e))?;
        if candidates.len() != 1 {
            return Err((
                "IDENTITY_MISMATCH_ABORT",
                format!(
                    "expected exactly one supported dc/02/ff KDUSB interface, found {}",
                    candidates.len()
                ),
            ));
        }
        observe_candidate(
            candidates.into_iter().next().expect("one candidate"),
            expected,
        )
    }

    fn candidates() -> Result<Vec<Candidate>, String> {
        let devices = rusb::devices().map_err(|e| format!("enumerating USB devices: {e}"))?;
        let mut result = Vec::new();
        for device in devices.iter() {
            let descriptor = device
                .device_descriptor()
                .map_err(|e| format!("reading USB device descriptor: {e}"))?;
            if !HARDWARE_IDS.contains(&(descriptor.vendor_id(), descriptor.product_id())) {
                continue;
            }
            let config = device
                .active_config_descriptor()
                .map_err(|e| format!("reading active configuration: {e}"))?;
            for interface in config.interfaces() {
                for descriptor_if in interface.descriptors() {
                    if descriptor_if.class_code() != INTERFACE_CLASS
                        || descriptor_if.sub_class_code() != INTERFACE_SUBCLASS
                        || descriptor_if.protocol_code() != INTERFACE_PROTOCOL
                    {
                        continue;
                    }
                    let mut bulk_in = None;
                    let mut bulk_out = None;
                    for endpoint in descriptor_if.endpoint_descriptors() {
                        if endpoint.transfer_type() != TransferType::Bulk {
                            continue;
                        }
                        match endpoint.direction() {
                            Direction::In if bulk_in.is_none() => {
                                bulk_in = Some(endpoint.address())
                            }
                            Direction::Out if bulk_out.is_none() => {
                                bulk_out = Some((endpoint.address(), endpoint.max_packet_size()))
                            }
                            _ => {}
                        }
                    }
                    if let (Some(bulk_in), Some((bulk_out, max_packet))) = (bulk_in, bulk_out) {
                        result.push(Candidate {
                            device: device.clone(),
                            vendor: descriptor.vendor_id(),
                            product: descriptor.product_id(),
                            interface: descriptor_if.interface_number(),
                            alternate_setting: descriptor_if.setting_number(),
                            bulk_in,
                            bulk_out,
                            max_packet,
                        });
                    }
                }
            }
        }
        Ok(result)
    }

    fn observe_candidate(
        candidate: Candidate,
        expected: &str,
    ) -> Result<LiveReport, (&'static str, String)> {
        if candidate.alternate_setting != 0 {
            return Err((
                "IDENTITY_MISMATCH_ABORT",
                format!(
                    "alternate setting {} is not the admitted setting 0",
                    candidate.alternate_setting
                ),
            ));
        }
        let handle = candidate.device.open().map_err(|e| {
            (
                "OTHER_TRANSPORT_FAULT",
                format!("opening KDUSB device: {e}"),
            )
        })?;
        match handle.kernel_driver_active(candidate.interface) {
            Ok(true) => {
                return Err((
                    "IDENTITY_MISMATCH_ABORT",
                    "kernel driver is attached; refusing to detach it".to_string(),
                ));
            }
            Ok(false) | Err(rusb::Error::NotSupported) => {}
            Err(e) => {
                return Err((
                    "OTHER_TRANSPORT_FAULT",
                    format!("checking kernel-driver ownership: {e}"),
                ));
            }
        }
        handle
            .claim_interface(candidate.interface)
            .map_err(|e| ("OTHER_TRANSPORT_FAULT", format!("claiming interface: {e}")))?;

        let mut report = LiveReport {
            result: "OTHER_TRANSPORT_FAULT",
            vendor: candidate.vendor,
            product: candidate.product,
            interface: candidate.interface,
            alternate_setting: candidate.alternate_setting,
            bulk_in: candidate.bulk_in,
            bulk_out: candidate.bulk_out,
            max_packet: candidate.max_packet,
            name_target: None,
            duplicate_names: 0,
            reads: Vec::new(),
            nonempty_reads: 0,
            timeout_reads: 0,
            stream_bytes: 0,
            packet: None,
            error: None,
            interface_released: false,
            name_probe_sent: false,
        };

        match handle.write_bulk(candidate.bulk_out, NAME_PROBE, TIMEOUT) {
            Ok(written) if written == NAME_PROBE.len() => report.name_probe_sent = true,
            Ok(written) => {
                report.error = Some(format!("short NAME? write: {written}/{}", NAME_PROBE.len()));
            }
            Err(rusb::Error::Pipe | rusb::Error::Other) => {
                report.result = "PASSIVE_NAME_WRITE_EPROTO";
                report.error =
                    Some("NAME? bulk-OUT returned EPIPE/EPROTO-class failure".to_string());
            }
            Err(e) => {
                report.result = "OTHER_TRANSPORT_FAULT";
                report.error = Some(format!("NAME? bulk-OUT failed: {e}"));
            }
        }

        if report.error.is_none() {
            run_reads(&handle, &candidate, expected, &mut report);
        }

        match handle.release_interface(candidate.interface) {
            Ok(()) => report.interface_released = true,
            Err(e) => {
                report.result = "OTHER_TRANSPORT_FAULT";
                report.error = Some(format!("releasing interface: {e}"));
            }
        }
        Ok(report)
    }

    fn run_reads(
        handle: &rusb::DeviceHandle<GlobalContext>,
        candidate: &Candidate,
        expected: &str,
        report: &mut LiveReport,
    ) {
        let mut assembly = Assembly::default();
        for _ in 0..MAX_USB_READ_CALLS {
            let mut response = vec![0u8; USB_READ_REQUEST];
            let received = match handle.read_bulk(candidate.bulk_in, &mut response, TIMEOUT) {
                Ok(0) => {
                    report.reads.push(ReadObservation {
                        status: "ZLP",
                        len: 0,
                        prefix_hex: String::new(),
                    });
                    continue;
                }
                Ok(count) => count,
                Err(rusb::Error::Timeout) => {
                    report.timeout_reads += 1;
                    report.reads.push(ReadObservation {
                        status: "TIMEOUT",
                        len: 0,
                        prefix_hex: String::new(),
                    });
                    continue;
                }
                Err(rusb::Error::Pipe | rusb::Error::Other) => {
                    report.result = "PASSIVE_READ_EPROTO";
                    report.error = Some("bulk-IN returned EPIPE/EPROTO-class failure".to_string());
                    break;
                }
                Err(e) => {
                    report.result = "OTHER_TRANSPORT_FAULT";
                    report.error = Some(format!("bulk-IN failed: {e}"));
                    break;
                }
            };
            report.nonempty_reads += 1;
            report.reads.push(ReadObservation {
                status: "DATA",
                len: received,
                prefix_hex: hex::encode(&response[..received.min(64)]),
            });
            if let Err(e) = assembly.append(expected, &response[..received]) {
                report.result = if e.starts_with("identity mismatch:") {
                    "IDENTITY_MISMATCH_ABORT"
                } else {
                    "PASSIVE_FRAMING_INVALID"
                };
                report.error = Some(e);
                break;
            }
            match try_complete_packet(&assembly.stream) {
                Ok(Some(packet)) => {
                    report.result = "PASSIVE_COMPLETE_KD_PACKET";
                    report.packet = Some(packet);
                    break;
                }
                Ok(None) => {}
                Err(e) => {
                    report.result = "PASSIVE_FRAMING_INVALID";
                    report.error = Some(e);
                    break;
                }
            }
        }
        report.name_target = assembly.name_target;
        report.duplicate_names = assembly.duplicate_names;
        report.stream_bytes = assembly.stream.len();
        if report.packet.is_none() && report.error.is_none() {
            report.result = if report.name_target.is_some() && assembly.stream.is_empty() {
                "PASSIVE_NAME_ONLY_NO_KD_PACKET"
            } else {
                "PASSIVE_BOUNDED_TIMEOUT"
            };
        }
    }

    impl Assembly {
        fn append(&mut self, expected: &str, transfer: &[u8]) -> Result<(), String> {
            if self.kind == Some(BootstrapKind::KdPrefetch) {
                self.stream.extend_from_slice(transfer);
                return Ok(());
            }
            let mut transfer = transfer;
            if self.kind == Some(BootstrapKind::Name) && self.optional_nul_pending {
                if transfer.first() == Some(&0) {
                    transfer = &transfer[1..];
                }
                self.optional_nul_pending = false;
                if transfer.is_empty() {
                    return Ok(());
                }
            }
            if self.kind == Some(BootstrapKind::Name)
                && self.pending.is_empty()
                && self.stream.is_empty()
            {
                let n = transfer.len().min(NAME_PREFIX.len());
                if transfer[..n] == NAME_PREFIX[..n] {
                    self.pending.extend_from_slice(transfer);
                } else {
                    self.stream.extend_from_slice(transfer);
                    return Ok(());
                }
            } else {
                self.pending.extend_from_slice(transfer);
            }
            let n = self.pending.len().min(NAME_PREFIX.len());
            if self.pending[..n] != NAME_PREFIX[..n] {
                self.kind = Some(BootstrapKind::KdPrefetch);
                self.stream.append(&mut self.pending);
                return Ok(());
            }
            if self.pending.len() < NAME_PREFIX.len() {
                return Ok(());
            }
            let limit = self.pending.len().min(NAME_RESPONSE_MAX);
            let suffix = &self.pending[NAME_PREFIX.len()..limit];
            let Some(nul) = suffix.iter().position(|&b| b == 0) else {
                if self.pending.len() >= NAME_RESPONSE_MAX {
                    return Err("NAME response lacks NUL within 37 bytes".to_string());
                }
                return Ok(());
            };
            let name = &suffix[..nul];
            if name.is_empty() || name.len() > TARGET_NAME_MAX || !name.is_ascii() {
                return Err("invalid NAME target".to_string());
            }
            let target =
                std::str::from_utf8(name).map_err(|e| format!("invalid NAME UTF-8: {e}"))?;
            if target != expected {
                return Err(format!(
                    "identity mismatch: NAME target '{target}' != '{expected}'"
                ));
            }
            let logical_end = NAME_PREFIX.len() + nul + 1;
            let double_nul = self.pending.get(logical_end) == Some(&0);
            let consumed = logical_end + usize::from(double_nul);
            if self.kind == Some(BootstrapKind::Name) {
                self.duplicate_names += 1;
            }
            self.kind = Some(BootstrapKind::Name);
            self.name_target = Some(target.to_string());
            self.optional_nul_pending = !double_nul && consumed == self.pending.len();
            self.stream.extend_from_slice(&self.pending[consumed..]);
            self.pending.clear();
            Ok(())
        }
    }

    fn try_complete_packet(stream: &[u8]) -> Result<Option<PacketSummary>, String> {
        if stream.len() < KD_HEADER_SIZE {
            return Ok(None);
        }
        let header = parse_header(stream)?;
        let total_bytes = match header.leader {
            DATA_PACKET_LEADER => KD_HEADER_SIZE + usize::from(header.byte_count) + 1,
            CONTROL_PACKET_LEADER => KD_HEADER_SIZE,
            _ => unreachable!(),
        };
        if total_bytes > MAX_COMPLETE_KD_PACKET_BYTES {
            return Err(format!(
                "KD packet requires {total_bytes} bytes; hard maximum is {MAX_COMPLETE_KD_PACKET_BYTES}"
            ));
        }
        if stream.len() < total_bytes {
            return Ok(None);
        }
        let checksum_valid = checksum_valid(header, stream);
        if !checksum_valid {
            return Err(format!(
                "KD checksum mismatch: header=0x{:08x}",
                header.checksum
            ));
        }
        let trailer_valid = if header.leader == DATA_PACKET_LEADER {
            Some(stream[total_bytes - 1] == PACKET_TRAILING_BYTE)
        } else {
            None
        };
        if trailer_valid == Some(false) {
            return Err("KD data trailer is not 0xaa".to_string());
        }
        Ok(Some(PacketSummary {
            header,
            total_bytes,
            checksum_valid,
            trailer_valid,
            surplus_bytes: stream.len() - total_bytes,
            packet: stream[..total_bytes].to_vec(),
        }))
    }

    fn parse_header(stream: &[u8]) -> Result<KdHeader, String> {
        let header = KdHeader {
            leader: u32::from_le_bytes(stream[0..4].try_into().expect("fixed slice")),
            packet_type: u16::from_le_bytes(stream[4..6].try_into().expect("fixed slice")),
            byte_count: u16::from_le_bytes(stream[6..8].try_into().expect("fixed slice")),
            packet_id: u32::from_le_bytes(stream[8..12].try_into().expect("fixed slice")),
            checksum: u32::from_le_bytes(stream[12..16].try_into().expect("fixed slice")),
        };
        match header.leader {
            DATA_PACKET_LEADER
                if (1..=11).contains(&header.packet_type)
                    && usize::from(header.byte_count) <= MAX_KD_PAYLOAD_BYTES =>
            {
                Ok(header)
            }
            CONTROL_PACKET_LEADER
                if matches!(header.packet_type, 4..=6)
                    && header.byte_count == 0
                    && header.checksum == 0 =>
            {
                Ok(header)
            }
            _ => Err(format!(
                "invalid KD framing: leader=0x{:08x} type=0x{:04x} byte_count={} checksum=0x{:08x}",
                header.leader, header.packet_type, header.byte_count, header.checksum
            )),
        }
    }

    fn checksum_valid(header: KdHeader, stream: &[u8]) -> bool {
        if header.leader == CONTROL_PACKET_LEADER {
            return header.byte_count == 0 && header.checksum == 0;
        }
        let end = KD_HEADER_SIZE + usize::from(header.byte_count);
        stream[KD_HEADER_SIZE..end]
            .iter()
            .fold(0u32, |sum, &b| sum.wrapping_add(u32::from(b)))
            == header.checksum
    }

    fn packet_label(packet_type: u16) -> &'static str {
        match packet_type {
            0x0001 => "KD_STATE_CHANGE32",
            0x0002 => "KD_STATE_MANIPULATE",
            0x0003 => "KD_DEBUG_IO",
            0x0004 => "KD_ACKNOWLEDGE",
            0x0005 => "KD_RESEND",
            0x0006 => "KD_RESET",
            0x0007 => "KD_STATE_CHANGE64",
            0x000b => "KD_FILE_IO",
            _ => "KD_KNOWN_DATA_TYPE",
        }
    }

    fn file_io_api(payload: &[u8]) -> Option<&'static str> {
        match parse_file_io(payload).ok()? {
            FileIoRequest::Create { .. } => Some("CREATE_FILE"),
            FileIoRequest::Read { .. } => Some("READ_FILE"),
            FileIoRequest::Write { .. } => Some("WRITE_FILE"),
            FileIoRequest::Close { .. } => Some("CLOSE_FILE"),
            FileIoRequest::Unknown { .. } => Some("UNKNOWN"),
        }
    }

    fn print_report(report: &LiveReport) {
        println!("PHASE344BU_RESULT={}", report.result);
        println!("VID_PID={:04x}:{:04x}", report.vendor, report.product);
        println!("INTERFACE={}", report.interface);
        println!("ALTERNATE_SETTING={}", report.alternate_setting);
        println!("BULK_OUT=0x{:02x}", report.bulk_out);
        println!("BULK_IN=0x{:02x}", report.bulk_in);
        println!("MAX_PACKET={}", report.max_packet);
        println!("NAME_SEEN={}", report.name_target.is_some());
        println!(
            "NAME_TARGET={}",
            report.name_target.as_deref().unwrap_or("NA")
        );
        println!("DUPLICATE_NAME_REPLIES={}", report.duplicate_names);
        println!("READ_CALLS_USED={}", report.reads.len());
        println!("NONEMPTY_READS={}", report.nonempty_reads);
        println!("TIMEOUT_READS={}", report.timeout_reads);
        for index in 0..MAX_USB_READ_CALLS {
            if let Some(read) = report.reads.get(index) {
                println!("RX{}_STATUS={}", index + 1, read.status);
                println!("RX{}_LEN={}", index + 1, read.len);
                println!("RX{}_PREFIX_HEX={}", index + 1, read.prefix_hex);
            } else {
                println!("RX{}_STATUS=NA", index + 1);
                println!("RX{}_LEN=NA", index + 1);
                println!("RX{}_PREFIX_HEX=NA", index + 1);
            }
        }
        if let Some(packet) = &report.packet {
            println!("KD_PACKET_HEX={}", hex::encode(&packet.packet));
            println!("KD_PACKET_TOTAL_BYTES={}", packet.total_bytes);
            println!("KD_LEADER=0x{:08x}", packet.header.leader);
            println!("KD_PACKET_TYPE=0x{:04x}", packet.header.packet_type);
            println!(
                "KD_PACKET_SEMANTIC={}",
                packet_label(packet.header.packet_type)
            );
            if packet.header.packet_type == 0x000b {
                let payload_end = KD_HEADER_SIZE + usize::from(packet.header.byte_count);
                println!(
                    "KD_FILE_IO_API={}",
                    file_io_api(&packet.packet[KD_HEADER_SIZE..payload_end]).unwrap_or("UNDECODED")
                );
            }
            println!("KD_BYTE_COUNT={}", packet.header.byte_count);
            println!("KD_PACKET_ID=0x{:08x}", packet.header.packet_id);
            println!("KD_CHECKSUM=0x{:08x}", packet.header.checksum);
            println!("KD_CHECKSUM_VALID={}", packet.checksum_valid);
            match packet.trailer_valid {
                Some(value) => println!("KD_TRAILER_VALID={value}"),
                None => println!("KD_TRAILER_VALID=NA"),
            }
            println!("KD_STREAM_SURPLUS_BYTES={}", packet.surplus_bytes);
        } else {
            println!("KD_PACKET_HEX=NA");
            println!("KD_PACKET_TOTAL_BYTES=0");
            println!("KD_CHECKSUM_VALID=false");
            println!("KD_TRAILER_VALID=NA");
            println!("KD_STREAM_SURPLUS_BYTES={}", report.stream_bytes);
        }
        println!("INTERFACE_RELEASED={}", report.interface_released);
        if let Some(error) = &report.error {
            println!("ERROR={error}");
        }
        print_safety_markers(true, report.name_probe_sent);
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        fn data_packet(packet_type: u16, payload: &[u8]) -> Vec<u8> {
            let checksum = payload
                .iter()
                .fold(0u32, |s, &b| s.wrapping_add(u32::from(b)));
            let mut bytes = Vec::new();
            bytes.extend_from_slice(&DATA_PACKET_LEADER.to_le_bytes());
            bytes.extend_from_slice(&packet_type.to_le_bytes());
            bytes.extend_from_slice(&(payload.len() as u16).to_le_bytes());
            bytes.extend_from_slice(&0x8080_0000u32.to_le_bytes());
            bytes.extend_from_slice(&checksum.to_le_bytes());
            bytes.extend_from_slice(payload);
            bytes.push(PACKET_TRAILING_BYTE);
            bytes
        }

        #[test]
        fn consumes_exact_name_and_preserves_split_packet() {
            let packet = data_packet(0x000b, b"file");
            let mut assembly = Assembly::default();
            assembly
                .append(REQUIRED_TARGET, b"NAME=CLSA0102_USB\0\0")
                .unwrap();
            assembly.append(REQUIRED_TARGET, &packet[..8]).unwrap();
            assert!(try_complete_packet(&assembly.stream).unwrap().is_none());
            assembly.append(REQUIRED_TARGET, &packet[8..]).unwrap();
            let summary = try_complete_packet(&assembly.stream).unwrap().unwrap();
            assert_eq!(summary.packet, packet);
            assert_eq!(packet_label(summary.header.packet_type), "KD_FILE_IO");
        }

        #[test]
        fn direct_control_packet_is_complete_at_sixteen_bytes() {
            let mut packet = Vec::new();
            packet.extend_from_slice(&CONTROL_PACKET_LEADER.to_le_bytes());
            packet.extend_from_slice(&4u16.to_le_bytes());
            packet.extend_from_slice(&0u16.to_le_bytes());
            packet.extend_from_slice(&0x8080_0000u32.to_le_bytes());
            packet.extend_from_slice(&0u32.to_le_bytes());
            let summary = try_complete_packet(&packet).unwrap().unwrap();
            assert_eq!(summary.total_bytes, 16);
            assert_eq!(summary.trailer_valid, None);
        }

        #[test]
        fn rejects_bad_checksum_and_bad_trailer() {
            let mut bad_checksum = data_packet(3, b"abc");
            bad_checksum[12] ^= 1;
            assert!(try_complete_packet(&bad_checksum).is_err());
            let mut bad_trailer = data_packet(3, b"abc");
            *bad_trailer.last_mut().unwrap() = 0;
            assert!(try_complete_packet(&bad_trailer).is_err());
        }

        #[test]
        fn retains_only_one_packet_and_counts_surplus() {
            let packet = data_packet(3, b"one");
            let mut stream = packet.clone();
            stream.extend_from_slice(&data_packet(3, b"two"));
            let summary = try_complete_packet(&stream).unwrap().unwrap();
            assert_eq!(summary.packet, packet);
            assert!(summary.surplus_bytes > 0);
        }

        #[test]
        fn wrong_name_is_identity_mismatch() {
            let mut assembly = Assembly::default();
            let error = assembly
                .append(REQUIRED_TARGET, b"NAME=OTHER\0\0")
                .unwrap_err();
            assert!(error.starts_with("identity mismatch:"));
        }

        #[test]
        fn maximum_data_packet_is_4017_bytes() {
            let packet = data_packet(3, &vec![1; MAX_KD_PAYLOAD_BYTES]);
            let summary = try_complete_packet(&packet).unwrap().unwrap();
            assert_eq!(summary.total_bytes, MAX_COMPLETE_KD_PACKET_BYTES);
        }

        #[test]
        fn existing_read_only_file_io_parser_classifies_api() {
            let mut payload = vec![0u8; 64];
            payload[..4].copy_from_slice(&0x0000_3431u32.to_le_bytes());
            assert_eq!(file_io_api(&payload), Some("READ_FILE"));
        }
    }
}
