//! Bounded passive classic-KDUSB first-packet observer (v5).
//!
//! Sends only the recovered five-byte NAME? bootstrap probe, then performs at
//! most four bulk-IN read calls. The first non-empty transfer may be either
//! NAME=<target> or KD framing. NAME bytes are consumed locally; any trailing
//! bytes and later transfers are assembled as a byte stream until one complete
//! KD packet is available. No KD ACK/RESEND/RESET, break-in, debugger request,
//! or target-memory request is ever transmitted.

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("ntoseye-kdusb-passive-packet-observer is supported only on Linux hosts");
    std::process::exit(2);
}

#[cfg(target_os = "linux")]
fn main() {
    if let Err(err) = linux::run() {
        eprintln!("KDUSB_PASSIVE_PACKET_OBSERVER=FAIL");
        eprintln!("ERROR={err}");
        std::process::exit(2);
    }
}

#[cfg(target_os = "linux")]
mod linux {
    use rusb::{Device, Direction, GlobalContext, TransferType};
    use std::time::Duration;

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
    const USB_READ_REQUEST: usize = 0x0fb0;
    const MAX_USB_READ_CALLS: usize = 4;
    const KD_PACKET_MAX: usize = 4000;
    const KD_HEADER_SIZE: usize = 16;
    const DATA_PACKET_LEADER: u32 = 0x3030_3030;
    const CONTROL_PACKET_LEADER: u32 = 0x6969_6969;
    const PACKET_TRAILING_BYTE: u8 = 0xaa;
    const TIMEOUT: Duration = Duration::from_secs(1);

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    struct KdHeader {
        leader: u32,
        packet_type: u16,
        byte_count: u16,
        packet_id: u32,
        checksum: u32,
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum BootstrapKind {
        Name,
        KdPrefetch,
    }

    impl BootstrapKind {
        fn as_str(self) -> &'static str {
            match self {
                Self::Name => "NAME",
                Self::KdPrefetch => "KD_PREFETCH",
            }
        }
    }

    struct PacketSummary {
        header: KdHeader,
        required_stream_bytes: usize,
        checksum_valid: bool,
        trailer_valid: Option<bool>,
        surplus_bytes: usize,
    }

    struct ReadObservation {
        status: &'static str,
        len: usize,
        prefix_hex: String,
    }

    struct ProbeReport {
        vendor: u16,
        product: u16,
        interface: u8,
        alternate_setting: u8,
        bulk_in: u8,
        bulk_out: u8,
        max_packet: u16,
        bootstrap_kind: BootstrapKind,
        name_target: Option<String>,
        read_calls_used: usize,
        nonempty_reads: usize,
        timeout_reads: usize,
        reads: Vec<ReadObservation>,
        packet: PacketSummary,
        stream_prefix_hex: String,
    }

    pub fn run() -> Result<(), String> {
        let mut args = std::env::args();
        let program = args
            .next()
            .unwrap_or_else(|| "ntoseye-kdusb-passive-packet-observer".to_string());
        let expected = args
            .next()
            .ok_or_else(|| format!("usage: {program} <TARGET_NAME>"))?;
        if args.next().is_some() {
            return Err(format!("usage: {program} <TARGET_NAME>"));
        }
        validate_target_name(&expected)?;

        let report = probe(&expected)?;

        println!("KDUSB_PASSIVE_PACKET_OBSERVER=PASS");
        println!("VID_PID={:04x}:{:04x}", report.vendor, report.product);
        println!("INTERFACE={}", report.interface);
        println!("ALTERNATE_SETTING={}", report.alternate_setting);
        println!("BULK_OUT=0x{:02x}", report.bulk_out);
        println!("BULK_IN=0x{:02x}", report.bulk_in);
        println!("MAX_PACKET={}", report.max_packet);
        println!("PROBE_TX_LEN={}", NAME_PROBE.len());
        println!("PROBE_TX_HEX={}", hex::encode(NAME_PROBE));
        println!("USB_RX_REQUEST_LEN={USB_READ_REQUEST}");
        println!("MAX_USB_READ_CALLS={MAX_USB_READ_CALLS}");
        println!("READ_CALLS_USED={}", report.read_calls_used);
        println!("NONEMPTY_READS={}", report.nonempty_reads);
        println!("TIMEOUT_READS={}", report.timeout_reads);
        println!("BOOTSTRAP_KIND={}", report.bootstrap_kind.as_str());
        println!("NAME_SEEN={}", report.name_target.is_some());
        println!(
            "NAME_TARGET={}",
            report.name_target.as_deref().unwrap_or("NA")
        );

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

        println!("KD_LEADER=0x{:08x}", report.packet.header.leader);
        println!("KD_PACKET_TYPE=0x{:04x}", report.packet.header.packet_type);
        println!("KD_BYTE_COUNT={}", report.packet.header.byte_count);
        println!("KD_PACKET_ID=0x{:08x}", report.packet.header.packet_id);
        println!("KD_CHECKSUM=0x{:08x}", report.packet.header.checksum);
        println!(
            "KD_REQUIRED_STREAM_BYTES={}",
            report.packet.required_stream_bytes
        );
        println!("KD_CHECKSUM_VALID={}", report.packet.checksum_valid);
        match report.packet.trailer_valid {
            Some(valid) => println!("KD_TRAILER_VALID={valid}"),
            None => println!("KD_TRAILER_VALID=NA"),
        }
        println!("KD_PACKET_COMPLETE=true");
        println!("KD_STREAM_SURPLUS_BYTES={}", report.packet.surplus_bytes);
        println!("KD_STREAM_PREFIX_HEX={}", report.stream_prefix_hex);
        println!("INTERFACE_RELEASED=true");
        println!("USB_CONTROL_TRANSFER=false");
        println!("KD_PACKET_TX=false");
        println!("KD_ACK_TX=false");
        println!("KD_RESEND_TX=false");
        println!("KD_RESET_TX=false");
        println!("KD_FILE_IO_REPLY_TX=false");
        println!("BREAKIN_SENT=false");
        println!("DEBUGGER_SESSION=false");
        println!("TARGET_MEMORY_ACCESS=false");
        Ok(())
    }

    fn validate_target_name(target: &str) -> Result<(), String> {
        let valid = !target.is_empty()
            && target.len() <= TARGET_NAME_MAX
            && target
                .bytes()
                .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit() || matches!(b, b'-' | b'_'));
        if valid {
            Ok(())
        } else {
            Err("target name must be 1..=24 bytes using A-Z, 0-9, '-' or '_'".to_string())
        }
    }

    fn probe(expected: &str) -> Result<ProbeReport, String> {
        let devices = rusb::devices().map_err(|err| format!("enumerating USB devices: {err}"))?;
        let mut saw_interface = false;
        let mut last_error = None;

        for device in devices.iter() {
            let descriptor = match device.device_descriptor() {
                Ok(value) => value,
                Err(err) => {
                    last_error = Some(format!("reading USB device descriptor: {err}"));
                    continue;
                }
            };
            if !HARDWARE_IDS.contains(&(descriptor.vendor_id(), descriptor.product_id())) {
                continue;
            }

            let config = match device.active_config_descriptor() {
                Ok(value) => value,
                Err(err) => {
                    last_error = Some(format!("reading active USB configuration: {err}"));
                    continue;
                }
            };

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
                                bulk_in = Some(endpoint.address());
                            }
                            Direction::Out if bulk_out.is_none() => {
                                bulk_out = Some((endpoint.address(), endpoint.max_packet_size()));
                            }
                            _ => {}
                        }
                    }

                    let (Some(bulk_in), Some((bulk_out, max_packet))) = (bulk_in, bulk_out) else {
                        continue;
                    };

                    saw_interface = true;
                    match probe_candidate(
                        &device,
                        descriptor.vendor_id(),
                        descriptor.product_id(),
                        descriptor_if.interface_number(),
                        descriptor_if.setting_number(),
                        bulk_in,
                        bulk_out,
                        max_packet,
                        expected,
                    ) {
                        Ok(Some(report)) => return Ok(report),
                        Ok(None) => {}
                        Err(err) => last_error = Some(err),
                    }
                }
            }
        }

        if let Some(err) = last_error {
            Err(err)
        } else if saw_interface {
            Err(format!(
                "classic KDUSB interface found, but NAME target did not match '{expected}'"
            ))
        } else {
            Err("no supported classic KDUSB dc/02/ff interface found".to_string())
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn probe_candidate(
        device: &Device<GlobalContext>,
        vendor: u16,
        product: u16,
        interface: u8,
        alternate_setting: u8,
        bulk_in: u8,
        bulk_out: u8,
        max_packet: u16,
        expected: &str,
    ) -> Result<Option<ProbeReport>, String> {
        let handle = device
            .open()
            .map_err(|err| format!("opening classic KDUSB device: {err}"))?;

        match handle.kernel_driver_active(interface) {
            Ok(true) => {
                return Err(format!(
                    "KDUSB interface {interface} has a kernel driver; refusing to detach it"
                ));
            }
            Ok(false) | Err(rusb::Error::NotSupported) => {}
            Err(err) => {
                return Err(format!(
                    "checking KDUSB interface kernel-driver ownership: {err}"
                ));
            }
        }

        handle
            .claim_interface(interface)
            .map_err(|err| format!("claiming KDUSB interface {interface}: {err}"))?;

        let transfer_result = (|| -> Result<Option<ProbeReport>, String> {
            if alternate_setting != 0 {
                handle
                    .set_alternate_setting(interface, alternate_setting)
                    .map_err(|err| {
                        format!(
                            "selecting KDUSB alternate setting {alternate_setting} on interface {interface}: {err}"
                        )
                    })?;
            }

            let written = handle
                .write_bulk(bulk_out, NAME_PROBE, TIMEOUT)
                .map_err(|err| format!("sending KDUSB NAME? probe: {err}"))?;
            if written != NAME_PROBE.len() {
                return Err(format!(
                    "short KDUSB NAME? probe: wrote {written} of {} bytes",
                    NAME_PROBE.len()
                ));
            }

            let mut reads = Vec::new();
            let mut stream = Vec::new();
            let mut bootstrap_pending = Vec::new();
            let mut bootstrap_kind = None;
            let mut name_target = None;
            let mut name_optional_nul_pending = false;
            let mut nonempty_reads = 0usize;
            let mut timeout_reads = 0usize;

            for read_index in 0..MAX_USB_READ_CALLS {
                let mut response = vec![0u8; USB_READ_REQUEST];
                let (status, received) = match handle.read_bulk(bulk_in, &mut response, TIMEOUT) {
                    Ok(0) => ("ZLP", 0),
                    Ok(count) => ("DATA", count),
                    Err(rusb::Error::Timeout) => {
                        timeout_reads += 1;
                        ("TIMEOUT", 0)
                    }
                    Err(err) => {
                        return Err(format!(
                            "reading KDUSB passive transfer {} of {}: {err}",
                            read_index + 1,
                            MAX_USB_READ_CALLS
                        ));
                    }
                };

                let prefix_len = received.min(64);
                reads.push(ReadObservation {
                    status,
                    len: received,
                    prefix_hex: hex::encode(&response[..prefix_len]),
                });

                if received == 0 {
                    continue;
                }
                nonempty_reads += 1;

                let transfer = &response[..received];
                append_bootstrap_transfer(
                    expected,
                    transfer,
                    &mut bootstrap_kind,
                    &mut name_target,
                    &mut bootstrap_pending,
                    &mut name_optional_nul_pending,
                    &mut stream,
                )?;

                if let Some(packet) = try_complete_packet(&stream)? {
                    let stream_prefix_len = stream.len().min(64);
                    return Ok(Some(ProbeReport {
                        vendor,
                        product,
                        interface,
                        alternate_setting,
                        bulk_in,
                        bulk_out,
                        max_packet,
                        bootstrap_kind: bootstrap_kind.ok_or_else(|| {
                            "internal error: bootstrap kind missing after packet assembly"
                                .to_string()
                        })?,
                        name_target,
                        read_calls_used: read_index + 1,
                        nonempty_reads,
                        timeout_reads,
                        reads,
                        packet,
                        stream_prefix_hex: hex::encode(&stream[..stream_prefix_len]),
                    }));
                }
            }

            Err(format!(
                "no complete KD packet within {MAX_USB_READ_CALLS} bounded bulk-IN read calls; NAME_SEEN={}; TIMEOUT_READS={timeout_reads}; KD_STREAM_BYTES={}",
                name_target.is_some(),
                stream.len()
            ))
        })();

        let release_result = handle
            .release_interface(interface)
            .map_err(|err| format!("releasing KDUSB interface {interface}: {err}"));

        match (transfer_result, release_result) {
            (Ok(report), Ok(())) => Ok(report),
            (Err(err), Ok(())) => Err(err),
            (Ok(_), Err(release)) => Err(release),
            (Err(err), Err(release)) => Err(format!("{err}; additionally {release}")),
        }
    }

    fn append_bootstrap_transfer(
        expected: &str,
        transfer: &[u8],
        bootstrap_kind: &mut Option<BootstrapKind>,
        name_target: &mut Option<String>,
        bootstrap_pending: &mut Vec<u8>,
        name_optional_nul_pending: &mut bool,
        stream: &mut Vec<u8>,
    ) -> Result<(), String> {
        match bootstrap_kind {
            Some(BootstrapKind::KdPrefetch) => {
                stream.extend_from_slice(transfer);
                return Ok(());
            }
            Some(BootstrapKind::Name) => {
                if *name_optional_nul_pending {
                    if transfer.first() == Some(&0) {
                        stream.extend_from_slice(&transfer[1..]);
                    } else {
                        stream.extend_from_slice(transfer);
                    }
                    *name_optional_nul_pending = false;
                } else {
                    stream.extend_from_slice(transfer);
                }
                return Ok(());
            }
            None => {}
        }

        bootstrap_pending.extend_from_slice(transfer);

        let compare_len = bootstrap_pending.len().min(NAME_PREFIX.len());
        if bootstrap_pending[..compare_len] != NAME_PREFIX[..compare_len] {
            *bootstrap_kind = Some(BootstrapKind::KdPrefetch);
            stream.extend_from_slice(bootstrap_pending);
            bootstrap_pending.clear();
            return Ok(());
        }

        if bootstrap_pending.len() < NAME_PREFIX.len() {
            return Ok(());
        }

        let limit = bootstrap_pending.len().min(NAME_RESPONSE_MAX);
        let suffix = &bootstrap_pending[NAME_PREFIX.len()..limit];
        let Some(nul) = suffix.iter().position(|&byte| byte == 0) else {
            if bootstrap_pending.len() >= NAME_RESPONSE_MAX {
                return Err(
                    "KDUSB NAME response is not NUL terminated within 37 bytes".to_string()
                );
            }
            return Ok(());
        };

        let name = &suffix[..nul];
        if name.is_empty() {
            return Err("KDUSB target name is empty".to_string());
        }
        if name.len() > TARGET_NAME_MAX {
            return Err(format!(
                "KDUSB target name is {} bytes (maximum {})",
                name.len(),
                TARGET_NAME_MAX
            ));
        }

        let target = std::str::from_utf8(name)
            .map_err(|err| format!("KDUSB target name is not UTF-8/ASCII: {err}"))?;
        if target != expected {
            return Err(format!(
                "KDUSB NAME reply target '{target}' did not match expected '{expected}'"
            ));
        }

        let logical_end = NAME_PREFIX.len() + nul + 1;
        let has_second_nul = bootstrap_pending.get(logical_end) == Some(&0);
        let consumed = if has_second_nul {
            logical_end + 1
        } else {
            logical_end
        };

        *bootstrap_kind = Some(BootstrapKind::Name);
        *name_target = Some(target.to_string());
        *name_optional_nul_pending =
            !has_second_nul && consumed == bootstrap_pending.len();

        stream.extend_from_slice(&bootstrap_pending[consumed..]);
        bootstrap_pending.clear();
        Ok(())
    }

    fn parse_name_transfer(transfer: &[u8]) -> Result<(&str, usize), String> {
        if !transfer.starts_with(NAME_PREFIX) {
            return Err("KDUSB bootstrap transfer is missing NAME= prefix".to_string());
        }

        let limit = transfer.len().min(NAME_RESPONSE_MAX);
        let suffix = &transfer[NAME_PREFIX.len()..limit];
        let nul = suffix.iter().position(|&byte| byte == 0).ok_or_else(|| {
            "KDUSB NAME response is not NUL terminated within 37 bytes".to_string()
        })?;
        let name = &suffix[..nul];
        if name.is_empty() {
            return Err("KDUSB target name is empty".to_string());
        }
        if name.len() > TARGET_NAME_MAX {
            return Err(format!(
                "KDUSB target name is {} bytes (maximum {})",
                name.len(),
                TARGET_NAME_MAX
            ));
        }
        let target = std::str::from_utf8(name)
            .map_err(|err| format!("KDUSB target name is not UTF-8/ASCII: {err}"))?;

        let logical_end = NAME_PREFIX.len() + nul + 1;
        let consumed = if transfer.get(logical_end) == Some(&0) {
            logical_end + 1
        } else {
            logical_end
        };
        Ok((target, consumed))
    }

    fn try_complete_packet(stream: &[u8]) -> Result<Option<PacketSummary>, String> {
        if stream.len() < KD_HEADER_SIZE {
            return Ok(None);
        }

        let header = parse_plausible_kd_header(stream)?;
        let required_stream_bytes = kd_required_stream_bytes(header);
        if stream.len() < required_stream_bytes {
            return Ok(None);
        }

        let checksum_valid = kd_checksum_valid(header, stream);
        if !checksum_valid {
            return Err(format!(
                "complete KD packet checksum mismatch: header=0x{:08x}",
                header.checksum
            ));
        }

        let trailer_valid = kd_trailer_valid(header, stream);
        if trailer_valid == Some(false) {
            return Err("complete KD data packet trailer is not 0xAA".to_string());
        }

        Ok(Some(PacketSummary {
            header,
            required_stream_bytes,
            checksum_valid,
            trailer_valid,
            surplus_bytes: stream.len() - required_stream_bytes,
        }))
    }

    fn parse_plausible_kd_header(response: &[u8]) -> Result<KdHeader, String> {
        if response.len() < KD_HEADER_SIZE {
            return Err(format!(
                "KD stream has only {} bytes; need {} for header",
                response.len(),
                KD_HEADER_SIZE
            ));
        }

        let header = KdHeader {
            leader: u32::from_le_bytes(response[0..4].try_into().expect("fixed header slice")),
            packet_type: u16::from_le_bytes(response[4..6].try_into().expect("fixed header slice")),
            byte_count: u16::from_le_bytes(response[6..8].try_into().expect("fixed header slice")),
            packet_id: u32::from_le_bytes(response[8..12].try_into().expect("fixed header slice")),
            checksum: u32::from_le_bytes(response[12..16].try_into().expect("fixed header slice")),
        };

        let plausible = match header.leader {
            DATA_PACKET_LEADER => {
                (1..=11).contains(&header.packet_type)
                    && usize::from(header.byte_count) <= KD_PACKET_MAX
            }
            CONTROL_PACKET_LEADER => {
                matches!(header.packet_type, 4..=6)
                    && header.byte_count == 0
                    && header.checksum == 0
            }
            _ => false,
        };

        if plausible {
            Ok(header)
        } else {
            Err(format!(
                "stream does not begin with plausible KD framing (leader={:#010x}, type={}, byte_count={})",
                header.leader, header.packet_type, header.byte_count
            ))
        }
    }

    fn kd_required_stream_bytes(header: KdHeader) -> usize {
        match header.leader {
            DATA_PACKET_LEADER => KD_HEADER_SIZE + usize::from(header.byte_count) + 1,
            CONTROL_PACKET_LEADER => KD_HEADER_SIZE,
            _ => unreachable!("header was already classified as plausible"),
        }
    }

    fn kd_checksum_valid(header: KdHeader, packet: &[u8]) -> bool {
        if header.leader == CONTROL_PACKET_LEADER {
            return header.byte_count == 0
                && header.checksum == 0
                && packet.len() >= KD_HEADER_SIZE;
        }

        let payload_end = KD_HEADER_SIZE + usize::from(header.byte_count);
        if packet.len() < payload_end {
            return false;
        }
        packet[KD_HEADER_SIZE..payload_end]
            .iter()
            .fold(0u32, |sum, &byte| sum.wrapping_add(u32::from(byte)))
            == header.checksum
    }

    fn kd_trailer_valid(header: KdHeader, packet: &[u8]) -> Option<bool> {
        if header.leader != DATA_PACKET_LEADER {
            return None;
        }

        let trailer_index = KD_HEADER_SIZE + usize::from(header.byte_count);
        packet
            .get(trailer_index)
            .map(|&byte| byte == PACKET_TRAILING_BYTE)
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        fn synthetic_data_packet(payload: &[u8]) -> Vec<u8> {
            let checksum = payload
                .iter()
                .fold(0u32, |sum, &byte| sum.wrapping_add(u32::from(byte)));
            let header = KdHeader {
                leader: DATA_PACKET_LEADER,
                packet_type: 3,
                byte_count: payload.len() as u16,
                packet_id: 0x8080_0000,
                checksum,
            };

            let mut packet = Vec::new();
            packet.extend_from_slice(&header.leader.to_le_bytes());
            packet.extend_from_slice(&header.packet_type.to_le_bytes());
            packet.extend_from_slice(&header.byte_count.to_le_bytes());
            packet.extend_from_slice(&header.packet_id.to_le_bytes());
            packet.extend_from_slice(&header.checksum.to_le_bytes());
            packet.extend_from_slice(payload);
            packet.push(PACKET_TRAILING_BYTE);
            packet
        }

        #[test]
        fn exact_name_reply_consumes_double_nul() {
            let reply = b"NAME=CLSA0102_USB\0\0";
            let (target, consumed) = parse_name_transfer(reply).unwrap();
            assert_eq!(target, "CLSA0102_USB");
            assert_eq!(consumed, reply.len());
        }

        #[test]
        fn name_on_second_read_after_empty_first_read_is_accepted() {
            let mut kind = None;
            let mut name = None;
            let mut pending = Vec::new();
            let mut optional_nul = false;
            let mut stream = Vec::new();

            append_bootstrap_transfer(
                "CLSA0102_USB",
                b"NAME=CLSA0102_USB\0\0",
                &mut kind,
                &mut name,
                &mut pending,
                &mut optional_nul,
                &mut stream,
            )
            .unwrap();

            assert_eq!(kind, Some(BootstrapKind::Name));
            assert_eq!(name.as_deref(), Some("CLSA0102_USB"));
            assert!(stream.is_empty());
        }

        #[test]
        fn name_then_split_packet_completes_within_three_reads() {
            let packet = synthetic_data_packet(b"abc");
            let split = packet.len() - 1;
            let mut kind = None;
            let mut name = None;
            let mut pending = Vec::new();
            let mut optional_nul = false;
            let mut stream = Vec::new();

            append_bootstrap_transfer(
                "CLSA0102_USB",
                b"NAME=CLSA0102_USB\0\0",
                &mut kind,
                &mut name,
                &mut pending,
                &mut optional_nul,
                &mut stream,
            )
            .unwrap();
            assert!(stream.is_empty());
            assert_eq!(kind, Some(BootstrapKind::Name));

            append_bootstrap_transfer(
                "CLSA0102_USB",
                &packet[..split],
                &mut kind,
                &mut name,
                &mut pending,
                &mut optional_nul,
                &mut stream,
            )
            .unwrap();
            assert!(try_complete_packet(&stream).unwrap().is_none());

            append_bootstrap_transfer(
                "CLSA0102_USB",
                &packet[split..],
                &mut kind,
                &mut name,
                &mut pending,
                &mut optional_nul,
                &mut stream,
            )
            .unwrap();
            let summary = try_complete_packet(&stream).unwrap().unwrap();
            assert!(summary.checksum_valid);
            assert_eq!(summary.trailer_valid, Some(true));
        }

        #[test]
        fn direct_prefetch_split_packet_completes_in_two_reads() {
            let packet = synthetic_data_packet(b"xyz");
            let split = packet.len() - 1;
            let mut kind = None;
            let mut name = None;
            let mut pending = Vec::new();
            let mut optional_nul = false;
            let mut stream = Vec::new();

            append_bootstrap_transfer(
                "CLSA0102_USB",
                &packet[..split],
                &mut kind,
                &mut name,
                &mut pending,
                &mut optional_nul,
                &mut stream,
            )
            .unwrap();
            assert_eq!(kind, Some(BootstrapKind::KdPrefetch));
            assert!(try_complete_packet(&stream).unwrap().is_none());

            append_bootstrap_transfer(
                "CLSA0102_USB",
                &packet[split..],
                &mut kind,
                &mut name,
                &mut pending,
                &mut optional_nul,
                &mut stream,
            )
            .unwrap();
            assert!(try_complete_packet(&stream).unwrap().is_some());
        }

        #[test]
        fn name_reply_preserves_trailing_kd_stream_bytes() {
            let packet = synthetic_data_packet(b"tail");
            let mut transfer = b"NAME=CLSA0102_USB\0\0".to_vec();
            transfer.extend_from_slice(&packet);

            let mut kind = None;
            let mut name = None;
            let mut pending = Vec::new();
            let mut optional_nul = false;
            let mut stream = Vec::new();
            append_bootstrap_transfer(
                "CLSA0102_USB",
                &transfer,
                &mut kind,
                &mut name,
                &mut pending,
                &mut optional_nul,
                &mut stream,
            )
            .unwrap();

            assert_eq!(stream, packet);
            assert!(try_complete_packet(&stream).unwrap().is_some());
        }

        #[test]
        fn wrong_name_is_rejected() {
            let mut kind = None;
            let mut name = None;
            let mut pending = Vec::new();
            let mut optional_nul = false;
            let mut stream = Vec::new();
            assert!(append_bootstrap_transfer(
                "CLSA0102_USB",
                b"NAME=OTHER\0\0",
                &mut kind,
                &mut name,
                &mut pending,
                &mut optional_nul,
                &mut stream,
            )
            .is_err());
        }

        #[test]
        fn split_name_prefix_is_buffered_before_classification() {
            let mut kind = None;
            let mut name = None;
            let mut pending = Vec::new();
            let mut optional_nul = false;
            let mut stream = Vec::new();

            append_bootstrap_transfer(
                "CLSA0102_USB",
                b"NAME",
                &mut kind,
                &mut name,
                &mut pending,
                &mut optional_nul,
                &mut stream,
            )
            .unwrap();

            assert_eq!(kind, None);
            assert_eq!(pending, b"NAME");
            assert!(stream.is_empty());

            append_bootstrap_transfer(
                "CLSA0102_USB",
                b"=CLSA0102_USB\0\0",
                &mut kind,
                &mut name,
                &mut pending,
                &mut optional_nul,
                &mut stream,
            )
            .unwrap();

            assert_eq!(kind, Some(BootstrapKind::Name));
            assert_eq!(name.as_deref(), Some("CLSA0102_USB"));
            assert!(pending.is_empty());
            assert!(!optional_nul);
            assert!(stream.is_empty());
        }

        #[test]
        fn split_optional_second_nul_is_consumed_before_kd_stream() {
            let packet = synthetic_data_packet(b"next");
            let mut kind = None;
            let mut name = None;
            let mut pending = Vec::new();
            let mut optional_nul = false;
            let mut stream = Vec::new();

            append_bootstrap_transfer(
                "CLSA0102_USB",
                b"NAME=CLSA0102_USB\0",
                &mut kind,
                &mut name,
                &mut pending,
                &mut optional_nul,
                &mut stream,
            )
            .unwrap();

            assert_eq!(kind, Some(BootstrapKind::Name));
            assert!(optional_nul);
            assert!(stream.is_empty());

            let mut next = vec![0];
            next.extend_from_slice(&packet);
            append_bootstrap_transfer(
                "CLSA0102_USB",
                &next,
                &mut kind,
                &mut name,
                &mut pending,
                &mut optional_nul,
                &mut stream,
            )
            .unwrap();

            assert!(!optional_nul);
            assert_eq!(stream, packet);
            assert!(try_complete_packet(&stream).unwrap().is_some());
        }

        #[test]
        fn observed_live_file_io_header_is_plausible() {
            let observed = hex::decode(
                "303030300b00920000088080a0110000303400000000000089001200800000000100000001000000000000000000000000000000000000000000000000000000",
            )
            .unwrap();
            let header = parse_plausible_kd_header(&observed).unwrap();
            assert_eq!(header.leader, DATA_PACKET_LEADER);
            assert_eq!(header.packet_type, 11);
            assert_eq!(header.byte_count, 146);
            assert_eq!(header.packet_id, 0x8080_0800);
            assert_eq!(header.checksum, 0x0000_11a0);
            assert_eq!(kd_required_stream_bytes(header), 163);
        }
    }
}
