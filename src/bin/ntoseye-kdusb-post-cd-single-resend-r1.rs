//! Phase 3.44CE: one exact KD RESEND followed by bounded receive capture.
//!
//! Dry by default. Live mode sends exactly one classic KD control RESEND packet
//! (packet id zero), then performs up to four bulk-IN reads. It sends no NAME,
//! ACK, RESET, data, break-in, USB control, or recovery operation.

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("ntoseye-kdusb-post-cd-single-resend-r1 is Linux-only");
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

    const LIVE_FLAG: &str = "--execute-post-cd-single-resend";
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
    const PACKET_TYPE_KD_RESEND: u16 = 5;
    const PACKET_TRAILING_BYTE: u8 = 0xaa;
    const KD_HEADER_SIZE: usize = 16;
    const MAX_KD_PAYLOAD_BYTES: usize = 4000;

    const OBSERVED_PACKET_TYPE: u16 = 7;
    const OBSERVED_BYTE_COUNT: u16 = 330;
    const OBSERVED_PACKET_ID: u32 = 0x8080_0800;
    const OBSERVED_CHECKSUM: u32 = 0x0000_4452;
    const OBSERVED_NEW_STATE: u32 = 0x0000_3031;

    const KD_RESEND_PACKET: [u8; 16] = [
        0x69, 0x69, 0x69, 0x69, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00,
    ];

    const MAX_RESEND_TX: usize = 1;
    const MAX_READS: usize = 4;
    const USB_READ_REQUEST: usize = 4016;
    const PER_IO_TIMEOUT_MS: u64 = 1000;
    const TIMEOUT: Duration = Duration::from_millis(PER_IO_TIMEOUT_MS);

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
        bytes: Vec<u8>,
    }

    #[derive(Debug)]
    struct PacketAnalysis {
        header: KdHeader,
        header_match: bool,
        payload_complete: bool,
        checksum_valid: Option<bool>,
        payload_end: usize,
        trailer_present: bool,
        trailer_valid: Option<bool>,
        extra_bytes: Vec<u8>,
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
        resend_sent: bool,
        reads: Vec<ReadObservation>,
        analysis_read_index: Option<usize>,
        packet: Option<PacketAnalysis>,
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
                "usage: ntoseye-kdusb-post-cd-single-resend-r1 [{LIVE_FLAG} {REQUIRED_TARGET}]"
            );
            return 2;
        }

        let report = match observe() {
            Ok(r) => r,
            Err((class, error)) => {
                println!("PHASE344CE_RESULT={class}");
                println!("ERROR={error}");
                print_safety(true, false);
                return 3;
            }
        };

        print_report(&report);
        match report.result.as_str() {
            "RESEND_RETRANSMIT_VALID_NO_TRAILER"
            | "RESEND_RETRANSMIT_VALID_WITH_TRAILER"
            | "RESEND_RETRANSMIT_CHECKSUM_INVALID"
            | "RESEND_RETRANSMIT_INCOMPLETE"
            | "RESEND_OTHER_KD_PACKET"
            | "RESEND_NAME_REPLY"
            | "RESEND_UNCLASSIFIED_DATA"
            | "NO_REPLY_AFTER_RESEND" => 0,
            _ => 4,
        }
    }

    fn print_dry_plan() {
        println!("NTOSEYE_KDUSB_POST_CD_SINGLE_RESEND=READY");
        println!("DEFAULT_MODE=DRY_PLAN");
        println!("LIVE_FLAG={LIVE_FLAG} {REQUIRED_TARGET}");
        println!("MAX_KD_RESEND_TX={MAX_RESEND_TX}");
        println!("KD_RESEND_HEX={}", hex::encode(KD_RESEND_PACKET));
        println!("MAX_BULK_IN_READS={MAX_READS}");
        println!("USB_READ_REQUEST={USB_READ_REQUEST}");
        println!("PER_IO_TIMEOUT_MS={PER_IO_TIMEOUT_MS}");
        println!("EXPECTED_PACKET_TYPE=0x{OBSERVED_PACKET_TYPE:04x}");
        println!("EXPECTED_BYTE_COUNT={OBSERVED_BYTE_COUNT}");
        println!("EXPECTED_PACKET_ID=0x{OBSERVED_PACKET_ID:08x}");
        println!("EXPECTED_CHECKSUM=0x{OBSERVED_CHECKSUM:08x}");
        println!("EXPECTED_NEW_STATE=0x{OBSERVED_NEW_STATE:08x}");
        println!("NAME_PROBE_SENT=false");
        println!("KD_ACK_TX=false");
        println!("KD_RESET_TX=false");
        println!("KD_DATA_TX=false");
        println!("BREAKIN_SENT=false");
        println!("USB_DEVICE_RESET=false");
        println!("SET_CONFIGURATION_TX=false");
        println!("ENDPOINT_RECREATION_EXECUTED=false");
        println!("TARGET_REBOOT=false");
        println!("PHASE340_CLEANUP_AUTHORIZED=false");
    }

    fn print_safety(live: bool, resend: bool) {
        println!("LIVE_USB_ACTIVITY={live}");
        println!("KD_RESEND_TX={resend}");
        println!("NAME_PROBE_SENT=false");
        println!("KD_ACK_TX=false");
        println!("KD_RESET_TX=false");
        println!("KD_DATA_TX=false");
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
            resend_sent: false,
            reads: Vec::new(),
            analysis_read_index: None,
            packet: None,
            error: None,
            interface_released: false,
        };

        match handle.write_bulk(c.bulk_out, &KD_RESEND_PACKET, TIMEOUT) {
            Ok(n) if n == KD_RESEND_PACKET.len() => report.resend_sent = true,
            Ok(n) => {
                report.result = "OTHER_TRANSPORT_FAULT".into();
                report.error = Some(format!("short RESEND write: {n}/16"));
            }
            Err(rusb::Error::Pipe | rusb::Error::Other) => {
                report.result = "RESEND_WRITE_EPROTO".into();
                report.error = Some("RESEND bulk-OUT EPROTO-class failure".into());
            }
            Err(e) => {
                report.result = "OTHER_TRANSPORT_FAULT".into();
                report.error = Some(format!("RESEND bulk-OUT failed: {e}"));
            }
        }

        if report.error.is_none() {
            for _ in 0..MAX_READS {
                let mut buf = vec![0u8; USB_READ_REQUEST];
                match handle.read_bulk(c.bulk_in, &mut buf, TIMEOUT) {
                    Ok(n) => {
                        buf.truncate(n);
                        report.reads.push(ReadObservation {
                            status: if n == 0 { "ZLP" } else { "DATA" },
                            bytes: buf,
                        });
                    }
                    Err(rusb::Error::Timeout) => report.reads.push(ReadObservation {
                        status: "TIMEOUT",
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
        }

        if report.error.is_none() {
            classify(&mut report);
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

    fn parse_header(bytes: &[u8]) -> Option<KdHeader> {
        if bytes.len() < KD_HEADER_SIZE {
            return None;
        }
        let leader = u32::from_le_bytes(bytes[0..4].try_into().ok()?);
        if leader != DATA_PACKET_LEADER && leader != CONTROL_PACKET_LEADER {
            return None;
        }
        Some(KdHeader {
            leader,
            packet_type: u16::from_le_bytes(bytes[4..6].try_into().ok()?),
            byte_count: u16::from_le_bytes(bytes[6..8].try_into().ok()?),
            packet_id: u32::from_le_bytes(bytes[8..12].try_into().ok()?),
            checksum: u32::from_le_bytes(bytes[12..16].try_into().ok()?),
        })
    }

    fn analyze_packet(bytes: &[u8]) -> Option<PacketAnalysis> {
        let header = parse_header(bytes)?;
        if header.leader == DATA_PACKET_LEADER
            && usize::from(header.byte_count) > MAX_KD_PAYLOAD_BYTES
        {
            return None;
        }

        let payload_end = if header.leader == DATA_PACKET_LEADER {
            KD_HEADER_SIZE + usize::from(header.byte_count)
        } else {
            KD_HEADER_SIZE
        };
        let payload_complete = bytes.len() >= payload_end;

        let checksum_valid = if !payload_complete {
            None
        } else if header.leader == CONTROL_PACKET_LEADER {
            Some(header.byte_count == 0 && header.checksum == 0)
        } else {
            let calculated = bytes[KD_HEADER_SIZE..payload_end]
                .iter()
                .fold(0u32, |sum, &b| sum.wrapping_add(u32::from(b)));
            Some(calculated == header.checksum)
        };

        let (trailer_present, trailer_valid, extra_start) =
            if header.leader == DATA_PACKET_LEADER && payload_complete && bytes.len() > payload_end
            {
                (
                    true,
                    Some(bytes[payload_end] == PACKET_TRAILING_BYTE),
                    payload_end + 1,
                )
            } else {
                (false, None, payload_end.min(bytes.len()))
            };

        let extra_bytes = if bytes.len() > extra_start {
            bytes[extra_start..].to_vec()
        } else {
            Vec::new()
        };

        let mut new_state = None;
        let mut processor_level = None;
        let mut processor = None;
        let mut number_processors = None;
        let mut thread = None;
        let mut program_counter = None;

        if header.packet_type == 7 && bytes.len() >= KD_HEADER_SIZE + 32 {
            let p = &bytes[KD_HEADER_SIZE..];
            new_state = Some(u32::from_le_bytes(p[0..4].try_into().unwrap()));
            processor_level = Some(u16::from_le_bytes(p[4..6].try_into().unwrap()));
            processor = Some(u16::from_le_bytes(p[6..8].try_into().unwrap()));
            number_processors = Some(u32::from_le_bytes(p[8..12].try_into().unwrap()));
            thread = Some(u64::from_le_bytes(p[16..24].try_into().unwrap()));
            program_counter = Some(u64::from_le_bytes(p[24..32].try_into().unwrap()));
        }

        Some(PacketAnalysis {
            header,
            header_match: header.leader == DATA_PACKET_LEADER
                && header.packet_type == OBSERVED_PACKET_TYPE
                && header.byte_count == OBSERVED_BYTE_COUNT
                && header.packet_id == OBSERVED_PACKET_ID
                && header.checksum == OBSERVED_CHECKSUM,
            payload_complete,
            checksum_valid,
            payload_end,
            trailer_present,
            trailer_valid,
            extra_bytes,
            new_state,
            processor_level,
            processor,
            number_processors,
            thread,
            program_counter,
        })
    }

    fn classify(report: &mut LiveReport) {
        let Some((index, read)) = report
            .reads
            .iter()
            .enumerate()
            .find(|(_, r)| r.status == "DATA" && !r.bytes.is_empty())
        else {
            report.result = "NO_REPLY_AFTER_RESEND".into();
            return;
        };

        report.analysis_read_index = Some(index + 1);

        if read.bytes == b"NAME=CLSA0102_USB\0\0" {
            report.result = "RESEND_NAME_REPLY".into();
            return;
        }

        let Some(packet) = analyze_packet(&read.bytes) else {
            report.result = "RESEND_UNCLASSIFIED_DATA".into();
            return;
        };

        let result = if packet.header_match {
            if !packet.payload_complete {
                "RESEND_RETRANSMIT_INCOMPLETE"
            } else if packet.checksum_valid != Some(true) {
                "RESEND_RETRANSMIT_CHECKSUM_INVALID"
            } else if packet.trailer_present {
                if packet.trailer_valid == Some(true) {
                    "RESEND_RETRANSMIT_VALID_WITH_TRAILER"
                } else {
                    "RESEND_RETRANSMIT_CHECKSUM_INVALID"
                }
            } else {
                "RESEND_RETRANSMIT_VALID_NO_TRAILER"
            }
        } else {
            "RESEND_OTHER_KD_PACKET"
        };

        report.packet = Some(packet);
        report.result = result.into();
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
        println!("PHASE344CE_RESULT={}", r.result);
        println!("VID_PID={:04x}:{:04x}", r.vendor, r.product);
        println!("INTERFACE={}", r.interface);
        println!("ALTERNATE_SETTING={}", r.alternate_setting);
        println!("BULK_OUT=0x{:02x}", r.bulk_out);
        println!("BULK_IN=0x{:02x}", r.bulk_in);
        println!("MAX_PACKET={}", r.max_packet);
        println!("RESEND_SENT={}", r.resend_sent);
        println!("RESEND_HEX={}", hex::encode(KD_RESEND_PACKET));
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
                println!("RX{}_LEN={}", i + 1, read.bytes.len());
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
            "ANALYSIS_READ_INDEX={}",
            r.analysis_read_index
                .map(|v| v.to_string())
                .unwrap_or_else(|| "NA".into())
        );

        if let Some(p) = &r.packet {
            println!("KD_LEADER=0x{:08x}", p.header.leader);
            println!("KD_TYPE=0x{:04x}", p.header.packet_type);
            println!("KD_BYTE_COUNT={}", p.header.byte_count);
            println!("KD_PACKET_ID=0x{:08x}", p.header.packet_id);
            println!("KD_CHECKSUM=0x{:08x}", p.header.checksum);
            println!("KD_HEADER_MATCH={}", p.header_match);
            println!("KD_PAYLOAD_END={}", p.payload_end);
            println!("KD_PAYLOAD_COMPLETE={}", p.payload_complete);
            println!(
                "KD_CHECKSUM_VALID={}",
                p.checksum_valid
                    .map(|v| v.to_string())
                    .unwrap_or_else(|| "NA".into())
            );
            println!("KD_TRAILER_PRESENT={}", p.trailer_present);
            println!(
                "KD_TRAILER_VALID={}",
                p.trailer_valid
                    .map(|v| v.to_string())
                    .unwrap_or_else(|| "NA".into())
            );
            println!(
                "KD_EXTRA_BYTES_HEX={}",
                if p.extra_bytes.is_empty() {
                    "NA".into()
                } else {
                    hex::encode(&p.extra_bytes)
                }
            );
            if let Some(state) = p.new_state {
                println!("KD_NEW_STATE=0x{state:08x}");
                println!("KD_NEW_STATE_SEMANTIC={}", state_label(state));
            } else {
                println!("KD_NEW_STATE=NA");
                println!("KD_NEW_STATE_SEMANTIC=NA");
            }
            println!(
                "KD_PROCESSOR_LEVEL={}",
                p.processor_level
                    .map(|v| v.to_string())
                    .unwrap_or_else(|| "NA".into())
            );
            println!(
                "KD_PROCESSOR={}",
                p.processor
                    .map(|v| v.to_string())
                    .unwrap_or_else(|| "NA".into())
            );
            println!(
                "KD_NUMBER_PROCESSORS={}",
                p.number_processors
                    .map(|v| v.to_string())
                    .unwrap_or_else(|| "NA".into())
            );
            println!(
                "KD_THREAD={}",
                p.thread
                    .map(|v| format!("0x{v:016x}"))
                    .unwrap_or_else(|| "NA".into())
            );
            println!(
                "KD_PROGRAM_COUNTER={}",
                p.program_counter
                    .map(|v| format!("0x{v:016x}"))
                    .unwrap_or_else(|| "NA".into())
            );
        }

        println!("INTERFACE_RELEASED={}", r.interface_released);
        if let Some(e) = &r.error {
            println!("ERROR={e}");
        }
        print_safety(true, r.resend_sent);
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        fn observed_payload() -> Vec<u8> {
            let mut p = vec![0u8; usize::from(OBSERVED_BYTE_COUNT)];
            p[0..4].copy_from_slice(&OBSERVED_NEW_STATE.to_le_bytes());
            p[4..6].copy_from_slice(&0x19u16.to_le_bytes());
            p[6..8].copy_from_slice(&13u16.to_le_bytes());
            p[8..12].copy_from_slice(&16u32.to_le_bytes());
            p[16..24].copy_from_slice(&0xffff_a70e_9850_f040u64.to_le_bytes());
            p[24..32].copy_from_slice(&0xffff_f807_9b2f_e005u64.to_le_bytes());

            let mut sum = p.iter().fold(0u32, |s, &b| s.wrapping_add(u32::from(b)));
            let mut i = 32usize;
            while sum < OBSERVED_CHECKSUM {
                let add = (OBSERVED_CHECKSUM - sum).min(255) as u8;
                p[i] = add;
                sum += u32::from(add);
                i += 1;
            }
            assert_eq!(sum, OBSERVED_CHECKSUM);
            p
        }

        fn observed_packet(with_trailer: bool) -> Vec<u8> {
            let payload = observed_payload();
            let mut v = Vec::new();
            v.extend_from_slice(&DATA_PACKET_LEADER.to_le_bytes());
            v.extend_from_slice(&OBSERVED_PACKET_TYPE.to_le_bytes());
            v.extend_from_slice(&OBSERVED_BYTE_COUNT.to_le_bytes());
            v.extend_from_slice(&OBSERVED_PACKET_ID.to_le_bytes());
            v.extend_from_slice(&OBSERVED_CHECKSUM.to_le_bytes());
            v.extend_from_slice(&payload);
            if with_trailer {
                v.push(PACKET_TRAILING_BYTE);
            }
            v
        }

        fn report_with(bytes: Vec<u8>) -> LiveReport {
            LiveReport {
                result: String::new(),
                vendor: 0x3495,
                product: 0x00e0,
                interface: 0,
                alternate_setting: 0,
                bulk_in: 0x81,
                bulk_out: 0x01,
                max_packet: 64,
                resend_sent: true,
                reads: vec![ReadObservation {
                    status: "DATA",
                    bytes,
                }],
                analysis_read_index: None,
                packet: None,
                error: None,
                interface_released: false,
            }
        }

        #[test]
        fn resend_packet_is_exact() {
            assert_eq!(
                hex::encode(KD_RESEND_PACKET),
                "69696969050000000000000000000000"
            );
        }

        #[test]
        fn observed_shape_is_346_without_trailer() {
            assert_eq!(KD_HEADER_SIZE + usize::from(OBSERVED_BYTE_COUNT), 346);
            assert_eq!(observed_packet(false).len(), 346);
        }

        #[test]
        fn valid_no_trailer_is_accepted() {
            let mut r = report_with(observed_packet(false));
            classify(&mut r);
            assert_eq!(r.result, "RESEND_RETRANSMIT_VALID_NO_TRAILER");
            let p = r.packet.unwrap();
            assert_eq!(p.checksum_valid, Some(true));
            assert!(!p.trailer_present);
            assert_eq!(p.new_state, Some(OBSERVED_NEW_STATE));
        }

        #[test]
        fn valid_with_trailer_is_accepted() {
            let mut r = report_with(observed_packet(true));
            classify(&mut r);
            assert_eq!(r.result, "RESEND_RETRANSMIT_VALID_WITH_TRAILER");
            let p = r.packet.unwrap();
            assert_eq!(p.trailer_valid, Some(true));
        }

        #[test]
        fn checksum_failure_is_distinct() {
            let mut bytes = observed_packet(false);
            bytes[40] ^= 0x01;
            let mut r = report_with(bytes);
            classify(&mut r);
            assert_eq!(r.result, "RESEND_RETRANSMIT_CHECKSUM_INVALID");
        }

        #[test]
        fn incomplete_is_distinct() {
            let mut bytes = observed_packet(false);
            bytes.truncate(100);
            let mut r = report_with(bytes);
            classify(&mut r);
            assert_eq!(r.result, "RESEND_RETRANSMIT_INCOMPLETE");
        }

        #[test]
        fn name_reply_is_distinct() {
            let mut r = report_with(b"NAME=CLSA0102_USB\0\0".to_vec());
            classify(&mut r);
            assert_eq!(r.result, "RESEND_NAME_REPLY");
        }

        #[test]
        fn no_reply_is_distinct() {
            let mut r = report_with(Vec::new());
            r.reads[0].status = "TIMEOUT";
            classify(&mut r);
            assert_eq!(r.result, "NO_REPLY_AFTER_RESEND");
        }
    }
}
