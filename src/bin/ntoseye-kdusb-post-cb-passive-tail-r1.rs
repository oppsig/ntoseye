//! Phase 3.44CD: passive post-CB KDUSB tail/retransmission characterization.
//!
//! Dry by default. Live mode performs only bounded bulk-IN reads. It never
//! sends NAME?, KD packets, USB control writes, resets, configuration changes,
//! or endpoint recovery operations.

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("ntoseye-kdusb-post-cb-passive-tail-r1 is Linux-only");
    std::process::exit(2);
}

#[cfg(target_os = "linux")]
fn main() {
    std::process::exit(linux::run());
}

#[cfg(target_os = "linux")]
mod linux {
    use rusb::{Device, Direction, GlobalContext, TransferType};
    use std::time::Duration;

    const LIVE_FLAG: &str = "--execute-post-cb-passive-tail";
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

    const DATA_PACKET_LEADER: u32 = 0x3030_3030;
    const CONTROL_PACKET_LEADER: u32 = 0x6969_6969;
    const PACKET_TRAILING_BYTE: u8 = 0xaa;
    const KD_HEADER_SIZE: usize = 16;
    const MAX_KD_PAYLOAD_BYTES: usize = 4000;
    const MAX_COMPLETE_KD_PACKET_BYTES: usize = 4017;

    const CB_PACKET_TYPE: u16 = 7;
    const CB_BYTE_COUNT: u16 = 330;
    const CB_PACKET_ID: u32 = 0x8080_0800;
    const CB_CHECKSUM: u32 = 0x0000_4452;
    const CB_NEW_STATE: u32 = 0x0000_3031;

    const MAX_READS: usize = 4;
    const USB_READ_REQUEST: usize = 4016;
    const PER_READ_TIMEOUT_MS: u64 = 1000;
    const TIMEOUT: Duration = Duration::from_millis(PER_READ_TIMEOUT_MS);

    #[derive(Clone)]
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

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    struct KdHeader {
        leader: u32,
        packet_type: u16,
        byte_count: u16,
        packet_id: u32,
        checksum: u32,
    }

    #[derive(Debug)]
    struct ReadObservation {
        status: &'static str,
        len: usize,
        bytes: Vec<u8>,
    }

    #[derive(Debug)]
    struct PacketCandidate {
        offset: usize,
        header: KdHeader,
        expected_total: usize,
        available: usize,
        complete: bool,
        checksum_valid: Option<bool>,
        trailer_valid: Option<bool>,
        cb_header_match: bool,
        new_state: Option<u32>,
        processor_level: Option<u16>,
        processor: Option<u16>,
        number_processors: Option<u32>,
        thread: Option<u64>,
        program_counter: Option<u64>,
    }

    struct LiveReport {
        result: String,
        vendor: u16,
        product: u16,
        interface: u8,
        alternate_setting: u8,
        bulk_in: u8,
        bulk_out: u8,
        max_packet: u16,
        reads: Vec<ReadObservation>,
        stream: Vec<u8>,
        leading_bytes: Vec<u8>,
        packets: Vec<PacketCandidate>,
        error: Option<String>,
        interface_released: bool,
    }

    pub fn run() -> i32 {
        let args: Vec<String> = std::env::args().skip(1).collect();
        if args.is_empty() {
            print_dry_plan();
            return 0;
        }
        if args != [LIVE_FLAG, REQUIRED_TARGET] {
            eprintln!(
                "usage: ntoseye-kdusb-post-cb-passive-tail-r1 [{LIVE_FLAG} {REQUIRED_TARGET}]"
            );
            return 2;
        }

        let report = match observe() {
            Ok(report) => report,
            Err((class, error)) => {
                println!("PHASE344CD_RESULT={class}");
                println!("ERROR={error}");
                print_safety(true);
                return 3;
            }
        };

        print_report(&report);
        match report.result.as_str() {
            "LEADING_TRAILER_THEN_CB_RETRANSMIT"
            | "CB_STATE_CHANGE_RETRANSMIT_COMPLETE"
            | "CB_STATE_CHANGE_RETRANSMIT_INCOMPLETE"
            | "LEADING_TRAILER_ONLY"
            | "OTHER_KD_PACKET"
            | "NO_DATA_AFTER_CB"
            | "UNCLASSIFIED_PASSIVE_DATA" => 0,
            _ => 4,
        }
    }

    fn print_dry_plan() {
        println!("NTOSEYE_KDUSB_POST_CB_PASSIVE_TAIL=READY");
        println!("DEFAULT_MODE=DRY_PLAN");
        println!("LIVE_FLAG={LIVE_FLAG} {REQUIRED_TARGET}");
        println!("MAX_BULK_IN_READS={MAX_READS}");
        println!("USB_READ_REQUEST={USB_READ_REQUEST}");
        println!("PER_READ_TIMEOUT_MS={PER_READ_TIMEOUT_MS}");
        println!("CB_EXPECTED_LEADER=0x{DATA_PACKET_LEADER:08x}");
        println!("CB_EXPECTED_PACKET_TYPE=0x{CB_PACKET_TYPE:04x}");
        println!("CB_EXPECTED_BYTE_COUNT={CB_BYTE_COUNT}");
        println!("CB_EXPECTED_PACKET_ID=0x{CB_PACKET_ID:08x}");
        println!("CB_EXPECTED_CHECKSUM=0x{CB_CHECKSUM:08x}");
        println!("CB_EXPECTED_NEW_STATE=0x{CB_NEW_STATE:08x}");
        println!("USB_WRITE_TX=0");
        println!("NAME_PROBE_SENT=false");
        println!("KD_PACKET_TX=false");
        println!("USB_DEVICE_RESET=false");
        println!("SET_CONFIGURATION_TX=false");
        println!("ENDPOINT_RECREATION_EXECUTED=false");
        println!("TARGET_REBOOT=false");
        println!("PHASE340_CLEANUP_AUTHORIZED=false");
    }

    fn print_safety(live: bool) {
        println!("LIVE_USB_ACTIVITY={live}");
        println!("USB_WRITE_TX=0");
        println!("NAME_PROBE_SENT=false");
        println!("KD_PACKET_TX=false");
        println!("KD_ACK_TX=false");
        println!("KD_RESEND_TX=false");
        println!("KD_RESET_TX=false");
        println!("BREAKIN_SENT=false");
        println!("TARGET_MEMORY_ACCESS=false");
        println!("USB_DEVICE_RESET=false");
        println!("SET_CONFIGURATION_TX=false");
        println!("ENDPOINT_RECREATION_EXECUTED=false");
        println!("TARGET_REBOOT=false");
        println!("PHASE340_CLEANUP_AUTHORIZED=false");
    }

    fn observe() -> Result<LiveReport, (&'static str, String)> {
        let mut found = candidates().map_err(|e| ("OTHER_TRANSPORT_FAULT", e))?;
        if found.len() != 1 {
            return Err((
                "IDENTITY_MISMATCH_ABORT",
                format!(
                    "expected exactly one supported dc/02/ff KDUSB interface, found {}",
                    found.len()
                ),
            ));
        }
        observe_candidate(found.remove(0))
    }

    fn candidates() -> Result<Vec<Candidate>, String> {
        let devices = rusb::devices().map_err(|e| format!("enumerating USB devices: {e}"))?;
        let mut result = Vec::new();

        for device in devices.iter() {
            let dd = device
                .device_descriptor()
                .map_err(|e| format!("reading USB device descriptor: {e}"))?;
            if !HARDWARE_IDS.contains(&(dd.vendor_id(), dd.product_id())) {
                continue;
            }

            let config = device
                .active_config_descriptor()
                .map_err(|e| format!("reading active configuration: {e}"))?;

            for interface in config.interfaces() {
                for id in interface.descriptors() {
                    if (id.class_code(), id.sub_class_code(), id.protocol_code())
                        != (INTERFACE_CLASS, INTERFACE_SUBCLASS, INTERFACE_PROTOCOL)
                    {
                        continue;
                    }

                    let (mut bin, mut bout) = (None, None);
                    for ep in id.endpoint_descriptors() {
                        if ep.transfer_type() != TransferType::Bulk {
                            continue;
                        }
                        match ep.direction() {
                            Direction::In if bin.is_none() => bin = Some(ep.address()),
                            Direction::Out if bout.is_none() => {
                                bout = Some((ep.address(), ep.max_packet_size()))
                            }
                            _ => {}
                        }
                    }

                    if let (Some(bulk_in), Some((bulk_out, max_packet))) = (bin, bout) {
                        result.push(Candidate {
                            device: device.clone(),
                            vendor: dd.vendor_id(),
                            product: dd.product_id(),
                            interface: id.interface_number(),
                            alternate_setting: id.setting_number(),
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

    fn observe_candidate(c: Candidate) -> Result<LiveReport, (&'static str, String)> {
        if c.alternate_setting != 0 {
            return Err((
                "IDENTITY_MISMATCH_ABORT",
                format!(
                    "alternate setting {} is not admitted setting 0",
                    c.alternate_setting
                ),
            ));
        }

        let handle = c.device.open().map_err(|e| {
            (
                "OTHER_TRANSPORT_FAULT",
                format!("opening KDUSB device: {e}"),
            )
        })?;

        match handle.kernel_driver_active(c.interface) {
            Ok(true) => {
                return Err((
                    "IDENTITY_MISMATCH_ABORT",
                    "kernel driver attached; refusing detach".into(),
                ));
            }
            Ok(false) | Err(rusb::Error::NotSupported) => {}
            Err(e) => {
                return Err((
                    "OTHER_TRANSPORT_FAULT",
                    format!("checking kernel driver: {e}"),
                ));
            }
        }

        handle
            .claim_interface(c.interface)
            .map_err(|e| ("OTHER_TRANSPORT_FAULT", format!("claiming interface: {e}")))?;

        let mut report = LiveReport {
            result: "OTHER_TRANSPORT_FAULT".into(),
            vendor: c.vendor,
            product: c.product,
            interface: c.interface,
            alternate_setting: c.alternate_setting,
            bulk_in: c.bulk_in,
            bulk_out: c.bulk_out,
            max_packet: c.max_packet,
            reads: Vec::new(),
            stream: Vec::new(),
            leading_bytes: Vec::new(),
            packets: Vec::new(),
            error: None,
            interface_released: false,
        };

        for _ in 0..MAX_READS {
            let mut buf = vec![0u8; USB_READ_REQUEST];
            match handle.read_bulk(c.bulk_in, &mut buf, TIMEOUT) {
                Ok(n) => {
                    buf.truncate(n);
                    report.stream.extend_from_slice(&buf);
                    report.reads.push(ReadObservation {
                        status: if n == 0 { "ZLP" } else { "DATA" },
                        len: n,
                        bytes: buf,
                    });
                }
                Err(rusb::Error::Timeout) => report.reads.push(ReadObservation {
                    status: "TIMEOUT",
                    len: 0,
                    bytes: Vec::new(),
                }),
                Err(rusb::Error::Pipe | rusb::Error::Other) => {
                    report.result = "READ_EPROTO".into();
                    report.error = Some("bulk-IN EPROTO-class failure".into());
                    break;
                }
                Err(e) => {
                    report.result = "OTHER_TRANSPORT_FAULT".into();
                    report.error = Some(format!("bulk-IN failed: {e}"));
                    break;
                }
            }
        }

        if report.error.is_none() {
            analyze_stream(&mut report);
        }

        match handle.release_interface(c.interface) {
            Ok(()) => report.interface_released = true,
            Err(e) => {
                report.result = "OTHER_TRANSPORT_FAULT".into();
                report.error = Some(format!("releasing interface: {e}"));
            }
        }

        Ok(report)
    }

    fn parse_header(s: &[u8]) -> Option<KdHeader> {
        if s.len() < KD_HEADER_SIZE {
            return None;
        }
        let leader = u32::from_le_bytes(s[0..4].try_into().ok()?);
        if leader != DATA_PACKET_LEADER && leader != CONTROL_PACKET_LEADER {
            return None;
        }
        Some(KdHeader {
            leader,
            packet_type: u16::from_le_bytes(s[4..6].try_into().ok()?),
            byte_count: u16::from_le_bytes(s[6..8].try_into().ok()?),
            packet_id: u32::from_le_bytes(s[8..12].try_into().ok()?),
            checksum: u32::from_le_bytes(s[12..16].try_into().ok()?),
        })
    }

    fn find_first_leader(stream: &[u8], from: usize) -> Option<usize> {
        (from..stream.len().saturating_sub(3)).find(|&i| {
            matches!(
                u32::from_le_bytes(stream[i..i + 4].try_into().unwrap()),
                DATA_PACKET_LEADER | CONTROL_PACKET_LEADER
            )
        })
    }

    fn checksum_valid(header: KdHeader, packet: &[u8]) -> Option<bool> {
        if header.leader == CONTROL_PACKET_LEADER {
            return Some(header.byte_count == 0 && header.checksum == 0);
        }

        let payload_end = KD_HEADER_SIZE + usize::from(header.byte_count);
        if packet.len() < payload_end {
            return None;
        }

        let calculated = packet[KD_HEADER_SIZE..payload_end]
            .iter()
            .fold(0u32, |sum, &b| sum.wrapping_add(u32::from(b)));
        Some(calculated == header.checksum)
    }

    fn decode_state_change(
        packet: &[u8],
        header: KdHeader,
    ) -> (
        Option<u32>,
        Option<u16>,
        Option<u16>,
        Option<u32>,
        Option<u64>,
        Option<u64>,
    ) {
        if header.packet_type != 7 || packet.len() < KD_HEADER_SIZE + 32 {
            return (None, None, None, None, None, None);
        }

        let p = &packet[KD_HEADER_SIZE..];
        (
            Some(u32::from_le_bytes(p[0..4].try_into().unwrap())),
            Some(u16::from_le_bytes(p[4..6].try_into().unwrap())),
            Some(u16::from_le_bytes(p[6..8].try_into().unwrap())),
            Some(u32::from_le_bytes(p[8..12].try_into().unwrap())),
            Some(u64::from_le_bytes(p[16..24].try_into().unwrap())),
            Some(u64::from_le_bytes(p[24..32].try_into().unwrap())),
        )
    }

    fn analyze_stream(report: &mut LiveReport) {
        if report.stream.is_empty() {
            report.result = "NO_DATA_AFTER_CB".into();
            return;
        }

        let Some(first_leader) = find_first_leader(&report.stream, 0) else {
            report.leading_bytes = report.stream.clone();
            report.result = if report.leading_bytes.iter().all(|&b| b == PACKET_TRAILING_BYTE) {
                "LEADING_TRAILER_ONLY".into()
            } else {
                "UNCLASSIFIED_PASSIVE_DATA".into()
            };
            return;
        };

        report.leading_bytes = report.stream[..first_leader].to_vec();

        let mut cursor = first_leader;
        while let Some(offset) = find_first_leader(&report.stream, cursor) {
            let Some(header) = parse_header(&report.stream[offset..]) else {
                break;
            };

            if header.leader == DATA_PACKET_LEADER
                && usize::from(header.byte_count) > MAX_KD_PAYLOAD_BYTES
            {
                cursor = offset + 1;
                continue;
            }

            let expected_total = if header.leader == DATA_PACKET_LEADER {
                KD_HEADER_SIZE + usize::from(header.byte_count) + 1
            } else {
                KD_HEADER_SIZE
            };
            if expected_total > MAX_COMPLETE_KD_PACKET_BYTES {
                cursor = offset + 1;
                continue;
            }

            let available = report.stream.len() - offset;
            let complete = available >= expected_total;
            let packet_end = offset + available.min(expected_total);
            let packet = &report.stream[offset..packet_end];

            let checksum = if complete {
                checksum_valid(header, packet)
            } else {
                None
            };
            let trailer = if header.leader == DATA_PACKET_LEADER && complete {
                Some(packet[expected_total - 1] == PACKET_TRAILING_BYTE)
            } else {
                None
            };

            let (
                new_state,
                processor_level,
                processor,
                number_processors,
                thread,
                program_counter,
            ) = decode_state_change(packet, header);

            let cb_header_match = header.leader == DATA_PACKET_LEADER
                && header.packet_type == CB_PACKET_TYPE
                && header.byte_count == CB_BYTE_COUNT
                && header.packet_id == CB_PACKET_ID
                && header.checksum == CB_CHECKSUM;

            report.packets.push(PacketCandidate {
                offset,
                header,
                expected_total,
                available,
                complete,
                checksum_valid: checksum,
                trailer_valid: trailer,
                cb_header_match,
                new_state,
                processor_level,
                processor,
                number_processors,
                thread,
                program_counter,
            });

            if !complete {
                break;
            }
            cursor = offset + expected_total;
        }

        let leading_trailer = !report.leading_bytes.is_empty()
            && report.leading_bytes.iter().all(|&b| b == PACKET_TRAILING_BYTE);
        let cb_complete = report.packets.iter().any(|p| {
            p.cb_header_match
                && p.complete
                && p.checksum_valid == Some(true)
                && p.trailer_valid == Some(true)
        });
        let cb_incomplete = report
            .packets
            .iter()
            .any(|p| p.cb_header_match && !p.complete);
        let any_complete_valid = report.packets.iter().any(|p| {
            p.complete
                && p.checksum_valid == Some(true)
                && (p.header.leader == CONTROL_PACKET_LEADER
                    || p.trailer_valid == Some(true))
        });

        report.result = if leading_trailer && cb_complete {
            "LEADING_TRAILER_THEN_CB_RETRANSMIT".into()
        } else if cb_complete {
            "CB_STATE_CHANGE_RETRANSMIT_COMPLETE".into()
        } else if cb_incomplete {
            "CB_STATE_CHANGE_RETRANSMIT_INCOMPLETE".into()
        } else if leading_trailer && report.packets.is_empty() {
            "LEADING_TRAILER_ONLY".into()
        } else if any_complete_valid {
            "OTHER_KD_PACKET".into()
        } else {
            "UNCLASSIFIED_PASSIVE_DATA".into()
        };
    }

    fn state_label(value: u32) -> &'static str {
        match value {
            0x3030 => "DbgKdExceptionStateChange",
            0x3031 => "DbgKdLoadSymbolsStateChange",
            0x3032 => "DbgKdCommandStringStateChange",
            _ => "UNKNOWN_STATE_CHANGE",
        }
    }

    fn print_report(r: &LiveReport) {
        println!("PHASE344CD_RESULT={}", r.result);
        println!("VID_PID={:04x}:{:04x}", r.vendor, r.product);
        println!("INTERFACE={}", r.interface);
        println!("ALTERNATE_SETTING={}", r.alternate_setting);
        println!("BULK_OUT=0x{:02x}", r.bulk_out);
        println!("BULK_IN=0x{:02x}", r.bulk_in);
        println!("MAX_PACKET={}", r.max_packet);
        println!("READ_CALLS_USED={}", r.reads.len());
        println!(
            "NONEMPTY_READS={}",
            r.reads.iter().filter(|x| x.status == "DATA").count()
        );
        println!(
            "TIMEOUT_READS={}",
            r.reads.iter().filter(|x| x.status == "TIMEOUT").count()
        );

        for i in 0..MAX_READS {
            if let Some(read) = r.reads.get(i) {
                println!("RX{}_STATUS={}", i + 1, read.status);
                println!("RX{}_LEN={}", i + 1, read.len);
                println!(
                    "RX{}_HEX={}",
                    i + 1,
                    if read.bytes.is_empty() {
                        "NA".into()
                    } else {
                        hex::encode(&read.bytes)
                    }
                );
            } else {
                println!("RX{}_STATUS=NA", i + 1);
                println!("RX{}_LEN=NA", i + 1);
                println!("RX{}_HEX=NA", i + 1);
            }
        }

        println!(
            "LEADING_BYTES_HEX={}",
            if r.leading_bytes.is_empty() {
                "NA".into()
            } else {
                hex::encode(&r.leading_bytes)
            }
        );
        println!(
            "LEADING_BYTES_ALL_AA={}",
            !r.leading_bytes.is_empty()
                && r.leading_bytes.iter().all(|&b| b == PACKET_TRAILING_BYTE)
        );
        println!("KD_PACKET_CANDIDATES={}", r.packets.len());

        for (i, p) in r.packets.iter().enumerate() {
            let n = i + 1;
            println!("KD{n}_OFFSET={}", p.offset);
            println!("KD{n}_LEADER=0x{:08x}", p.header.leader);
            println!("KD{n}_TYPE=0x{:04x}", p.header.packet_type);
            println!("KD{n}_BYTE_COUNT={}", p.header.byte_count);
            println!("KD{n}_PACKET_ID=0x{:08x}", p.header.packet_id);
            println!("KD{n}_CHECKSUM=0x{:08x}", p.header.checksum);
            println!("KD{n}_EXPECTED_TOTAL={}", p.expected_total);
            println!("KD{n}_AVAILABLE={}", p.available);
            println!("KD{n}_COMPLETE={}", p.complete);
            println!(
                "KD{n}_CHECKSUM_VALID={}",
                p.checksum_valid
                    .map(|v| v.to_string())
                    .unwrap_or_else(|| "NA".into())
            );
            println!(
                "KD{n}_TRAILER_VALID={}",
                p.trailer_valid
                    .map(|v| v.to_string())
                    .unwrap_or_else(|| "NA".into())
            );
            println!("KD{n}_CB_HEADER_MATCH={}", p.cb_header_match);
            if let Some(state) = p.new_state {
                println!("KD{n}_NEW_STATE=0x{state:08x}");
                println!("KD{n}_NEW_STATE_SEMANTIC={}", state_label(state));
            } else {
                println!("KD{n}_NEW_STATE=NA");
                println!("KD{n}_NEW_STATE_SEMANTIC=NA");
            }
            println!(
                "KD{n}_PROCESSOR_LEVEL={}",
                p.processor_level
                    .map(|v| v.to_string())
                    .unwrap_or_else(|| "NA".into())
            );
            println!(
                "KD{n}_PROCESSOR={}",
                p.processor
                    .map(|v| v.to_string())
                    .unwrap_or_else(|| "NA".into())
            );
            println!(
                "KD{n}_NUMBER_PROCESSORS={}",
                p.number_processors
                    .map(|v| v.to_string())
                    .unwrap_or_else(|| "NA".into())
            );
            println!(
                "KD{n}_THREAD={}",
                p.thread
                    .map(|v| format!("0x{v:016x}"))
                    .unwrap_or_else(|| "NA".into())
            );
            println!(
                "KD{n}_PROGRAM_COUNTER={}",
                p.program_counter
                    .map(|v| format!("0x{v:016x}"))
                    .unwrap_or_else(|| "NA".into())
            );
        }

        println!("INTERFACE_RELEASED={}", r.interface_released);
        if let Some(e) = &r.error {
            println!("ERROR={e}");
        }
        print_safety(true);
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        fn header(packet_type: u16, byte_count: u16, packet_id: u32, checksum: u32) -> Vec<u8> {
            let mut v = Vec::new();
            v.extend_from_slice(&DATA_PACKET_LEADER.to_le_bytes());
            v.extend_from_slice(&packet_type.to_le_bytes());
            v.extend_from_slice(&byte_count.to_le_bytes());
            v.extend_from_slice(&packet_id.to_le_bytes());
            v.extend_from_slice(&checksum.to_le_bytes());
            v
        }

        fn cb_payload() -> Vec<u8> {
            let mut p = vec![0u8; usize::from(CB_BYTE_COUNT)];
            p[0..4].copy_from_slice(&CB_NEW_STATE.to_le_bytes());
            p[4..6].copy_from_slice(&0x19u16.to_le_bytes());
            p[6..8].copy_from_slice(&13u16.to_le_bytes());
            p[8..12].copy_from_slice(&16u32.to_le_bytes());
            p[16..24].copy_from_slice(&0xffff_a70e_9850_f040u64.to_le_bytes());
            p[24..32].copy_from_slice(&0xffff_f807_9b2f_e005u64.to_le_bytes());

            let mut sum = p.iter().fold(0u32, |s, &b| s.wrapping_add(u32::from(b)));
            let target = CB_CHECKSUM;
            let mut i = 32usize;
            while sum < target {
                let add = (target - sum).min(255) as u8;
                p[i] = add;
                sum += u32::from(add);
                i += 1;
            }
            assert_eq!(sum, target);
            p
        }

        fn cb_packet() -> Vec<u8> {
            let p = cb_payload();
            let mut v = header(CB_PACKET_TYPE, CB_BYTE_COUNT, CB_PACKET_ID, CB_CHECKSUM);
            v.extend_from_slice(&p);
            v.push(PACKET_TRAILING_BYTE);
            v
        }

        fn dummy(stream: Vec<u8>) -> LiveReport {
            LiveReport {
                result: String::new(),
                vendor: 0x3495,
                product: 0x00e0,
                interface: 0,
                alternate_setting: 0,
                bulk_in: 0x81,
                bulk_out: 0x01,
                max_packet: 64,
                reads: Vec::new(),
                stream,
                leading_bytes: Vec::new(),
                packets: Vec::new(),
                error: None,
                interface_released: false,
            }
        }

        #[test]
        fn cb_header_arithmetic_matches_observed_read() {
            assert_eq!(KD_HEADER_SIZE + usize::from(CB_BYTE_COUNT), 346);
            assert_eq!(KD_HEADER_SIZE + usize::from(CB_BYTE_COUNT) + 1, 347);
        }

        #[test]
        fn leading_trailer_then_complete_retransmit() {
            let mut stream = vec![PACKET_TRAILING_BYTE];
            stream.extend_from_slice(&cb_packet());
            let mut r = dummy(stream);
            analyze_stream(&mut r);
            assert_eq!(r.result, "LEADING_TRAILER_THEN_CB_RETRANSMIT");
            assert_eq!(r.leading_bytes, vec![PACKET_TRAILING_BYTE]);
            assert_eq!(r.packets.len(), 1);
            assert!(r.packets[0].cb_header_match);
            assert_eq!(r.packets[0].new_state, Some(CB_NEW_STATE));
            assert_eq!(r.packets[0].processor, Some(13));
            assert_eq!(r.packets[0].number_processors, Some(16));
        }

        #[test]
        fn complete_cb_retransmit_at_zero() {
            let mut r = dummy(cb_packet());
            analyze_stream(&mut r);
            assert_eq!(r.result, "CB_STATE_CHANGE_RETRANSMIT_COMPLETE");
            assert!(r.packets[0].complete);
            assert_eq!(r.packets[0].checksum_valid, Some(true));
            assert_eq!(r.packets[0].trailer_valid, Some(true));
        }

        #[test]
        fn incomplete_cb_retransmit_without_trailer() {
            let mut p = cb_packet();
            p.pop();
            let mut r = dummy(p);
            analyze_stream(&mut r);
            assert_eq!(r.result, "CB_STATE_CHANGE_RETRANSMIT_INCOMPLETE");
            assert_eq!(r.packets[0].available, 346);
            assert_eq!(r.packets[0].expected_total, 347);
        }

        #[test]
        fn trailer_only_is_distinct() {
            let mut r = dummy(vec![0xaa]);
            analyze_stream(&mut r);
            assert_eq!(r.result, "LEADING_TRAILER_ONLY");
        }

        #[test]
        fn no_data_is_distinct() {
            let mut r = dummy(Vec::new());
            analyze_stream(&mut r);
            assert_eq!(r.result, "NO_DATA_AFTER_CB");
        }

        #[test]
        fn no_write_api_is_needed_by_design() {
            assert_eq!(MAX_READS, 4);
            assert_eq!(USB_READ_REQUEST, 4016);
        }
    }
}
