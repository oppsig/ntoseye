//! Phase 3.44CF: one exact KD ACK for the observed sync packet, then bounded reads.
//!
//! Dry by default. Live mode sends exactly one classic KD ACK control packet
//! with PacketId 0x80800800, then performs up to four bulk-IN reads.

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("ntoseye-kdusb-post-ce-single-ack-r1 is Linux-only");
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

    const LIVE_FLAG: &str = "--execute-post-ce-single-ack";
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
    const OBSERVED_PACKET_TYPE: u16 = 7;
    const OBSERVED_BYTE_COUNT: u16 = 330;
    const OBSERVED_PACKET_ID: u32 = 0x8080_0800;
    const OBSERVED_CHECKSUM: u32 = 0x0000_4452;

    const KD_ACK_PACKET: [u8; 16] = [
        0x69, 0x69, 0x69, 0x69, 0x04, 0x00, 0x00, 0x00, 0x00, 0x08, 0x80, 0x80, 0x00, 0x00, 0x00,
        0x00,
    ];

    const MAX_ACK_TX: usize = 1;
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

    struct LiveReport {
        result: String,
        vendor: u16,
        product: u16,
        interface: u8,
        alternate_setting: u8,
        bulk_in: u8,
        bulk_out: u8,
        max_packet: u16,
        ack_sent: bool,
        reads: Vec<ReadObservation>,
        first_data_index: Option<usize>,
        first_header: Option<KdHeader>,
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
                "usage: ntoseye-kdusb-post-ce-single-ack-r1 [{LIVE_FLAG} {REQUIRED_TARGET}]"
            );
            return 2;
        }

        let report = match observe() {
            Ok(r) => r,
            Err((class, error)) => {
                println!("PHASE344CF_RESULT={class}");
                println!("ERROR={error}");
                print_safety(true, false);
                return 3;
            }
        };

        print_report(&report);
        match report.result.as_str() {
            "ACK_SAME_PACKET_RETRANSMIT"
            | "ACK_NEXT_KD_DATA_PACKET"
            | "ACK_CONTROL_PACKET"
            | "ACK_NAME_REPLY"
            | "ACK_UNCLASSIFIED_DATA"
            | "NO_REPLY_AFTER_ACK" => 0,
            _ => 4,
        }
    }

    fn print_dry_plan() {
        println!("NTOSEYE_KDUSB_POST_CE_SINGLE_ACK=READY");
        println!("DEFAULT_MODE=DRY_PLAN");
        println!("LIVE_FLAG={LIVE_FLAG} {REQUIRED_TARGET}");
        println!("MAX_KD_ACK_TX={MAX_ACK_TX}");
        println!("KD_ACK_PACKET_ID=0x{OBSERVED_PACKET_ID:08x}");
        println!("KD_ACK_HEX={}", hex::encode(KD_ACK_PACKET));
        println!("MAX_BULK_IN_READS={MAX_READS}");
        println!("USB_READ_REQUEST={USB_READ_REQUEST}");
        println!("PER_IO_TIMEOUT_MS={PER_IO_TIMEOUT_MS}");
        println!("NAME_PROBE_SENT=false");
        println!("KD_RESEND_TX=false");
        println!("KD_RESET_TX=false");
        println!("KD_DATA_TX=false");
        println!("BREAKIN_SENT=false");
        println!("USB_DEVICE_RESET=false");
        println!("SET_CONFIGURATION_TX=false");
        println!("ENDPOINT_RECREATION_EXECUTED=false");
        println!("TARGET_REBOOT=false");
        println!("PHASE340_CLEANUP_AUTHORIZED=false");
    }

    fn print_safety(live: bool, ack: bool) {
        println!("LIVE_USB_ACTIVITY={live}");
        println!("USB_WRITE_TX={}", if ack { 1 } else { 0 });
        println!("KD_ACK_TX={ack}");
        println!("NAME_PROBE_SENT=false");
        println!("KD_RESEND_TX=false");
        println!("KD_RESET_TX=false");
        println!("KD_DATA_TX=false");
        println!("BREAKIN_SENT=false");
        println!("TARGET_MEMORY_ACCESS=false");
        println!("USB_DEVICE_RESET=false");
        println!("SET_CONFIGURATION_TX=false");
        println!("ENDPOINT_RECREATION_EXECUTED=false");
        println!("HOST_REBOOT=false");
        println!("TARGET_REBOOT=false");
        println!("AUTOMATIC_COMPLETE_EXPERIMENT_RETRY=false");
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
            ack_sent: false,
            reads: Vec::new(),
            first_data_index: None,
            first_header: None,
            error: None,
            interface_released: false,
        };

        match handle.write_bulk(c.bulk_out, &KD_ACK_PACKET, TIMEOUT) {
            Ok(n) if n == KD_ACK_PACKET.len() => report.ack_sent = true,
            Ok(n) => {
                report.result = "OTHER_TRANSPORT_FAULT".into();
                report.error = Some(format!("short ACK write: {n}/16"));
            }
            Err(rusb::Error::Pipe | rusb::Error::Other) => {
                report.result = "ACK_WRITE_EPROTO".into();
                report.error = Some("ACK bulk-OUT EPROTO-class failure".into());
            }
            Err(e) => {
                report.result = "OTHER_TRANSPORT_FAULT".into();
                report.error = Some(format!("ACK bulk-OUT failed: {e}"));
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
        if bytes.len() < 16 {
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

    fn classify(report: &mut LiveReport) {
        let Some((index, read)) = report
            .reads
            .iter()
            .enumerate()
            .find(|(_, r)| r.status == "DATA" && !r.bytes.is_empty())
        else {
            report.result = "NO_REPLY_AFTER_ACK".into();
            return;
        };

        report.first_data_index = Some(index + 1);

        if read.bytes == b"NAME=CLSA0102_USB\0\0" {
            report.result = "ACK_NAME_REPLY".into();
            return;
        }

        let Some(header) = parse_header(&read.bytes) else {
            report.result = "ACK_UNCLASSIFIED_DATA".into();
            return;
        };
        report.first_header = Some(header);

        report.result = if header.leader == CONTROL_PACKET_LEADER {
            "ACK_CONTROL_PACKET".into()
        } else if header.packet_type == OBSERVED_PACKET_TYPE
            && header.byte_count == OBSERVED_BYTE_COUNT
            && header.packet_id == OBSERVED_PACKET_ID
            && header.checksum == OBSERVED_CHECKSUM
        {
            "ACK_SAME_PACKET_RETRANSMIT".into()
        } else {
            "ACK_NEXT_KD_DATA_PACKET".into()
        };
    }

    fn print_report(r: &LiveReport) {
        println!("PHASE344CF_RESULT={}", r.result);
        println!("VID_PID={:04x}:{:04x}", r.vendor, r.product);
        println!("INTERFACE={}", r.interface);
        println!("ALTERNATE_SETTING={}", r.alternate_setting);
        println!("BULK_OUT=0x{:02x}", r.bulk_out);
        println!("BULK_IN=0x{:02x}", r.bulk_in);
        println!("MAX_PACKET={}", r.max_packet);
        println!("ACK_SENT={}", r.ack_sent);
        println!("ACK_PACKET_ID=0x{OBSERVED_PACKET_ID:08x}");
        println!("ACK_HEX={}", hex::encode(KD_ACK_PACKET));
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
            "FIRST_DATA_READ_INDEX={}",
            r.first_data_index
                .map(|v| v.to_string())
                .unwrap_or_else(|| "NA".into())
        );

        if let Some(h) = r.first_header {
            println!("KD_LEADER=0x{:08x}", h.leader);
            println!("KD_TYPE=0x{:04x}", h.packet_type);
            println!("KD_BYTE_COUNT={}", h.byte_count);
            println!("KD_PACKET_ID=0x{:08x}", h.packet_id);
            println!("KD_CHECKSUM=0x{:08x}", h.checksum);
        }

        println!("INTERFACE_RELEASED={}", r.interface_released);
        if let Some(e) = &r.error {
            println!("ERROR={e}");
        }
        print_safety(true, r.ack_sent);
    }

    #[cfg(test)]
    mod tests {
        use super::*;

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
                ack_sent: true,
                reads: vec![ReadObservation {
                    status: "DATA",
                    bytes,
                }],
                first_data_index: None,
                first_header: None,
                error: None,
                interface_released: false,
            }
        }

        fn header(packet_type: u16, byte_count: u16, packet_id: u32, checksum: u32) -> Vec<u8> {
            let mut v = Vec::new();
            v.extend_from_slice(&DATA_PACKET_LEADER.to_le_bytes());
            v.extend_from_slice(&packet_type.to_le_bytes());
            v.extend_from_slice(&byte_count.to_le_bytes());
            v.extend_from_slice(&packet_id.to_le_bytes());
            v.extend_from_slice(&checksum.to_le_bytes());
            v
        }

        #[test]
        fn ack_packet_is_exact() {
            assert_eq!(
                hex::encode(KD_ACK_PACKET),
                "69696969040000000008808000000000"
            );
        }

        #[test]
        fn same_packet_is_distinct() {
            let mut r = report_with(header(
                OBSERVED_PACKET_TYPE,
                OBSERVED_BYTE_COUNT,
                OBSERVED_PACKET_ID,
                OBSERVED_CHECKSUM,
            ));
            classify(&mut r);
            assert_eq!(r.result, "ACK_SAME_PACKET_RETRANSMIT");
        }

        #[test]
        fn next_data_packet_is_distinct() {
            let mut r = report_with(header(2, 0, 0x8080_0001, 0));
            classify(&mut r);
            assert_eq!(r.result, "ACK_NEXT_KD_DATA_PACKET");
        }

        #[test]
        fn control_packet_is_distinct() {
            let mut bytes = Vec::new();
            bytes.extend_from_slice(&CONTROL_PACKET_LEADER.to_le_bytes());
            bytes.extend_from_slice(&4u16.to_le_bytes());
            bytes.extend_from_slice(&0u16.to_le_bytes());
            bytes.extend_from_slice(&OBSERVED_PACKET_ID.to_le_bytes());
            bytes.extend_from_slice(&0u32.to_le_bytes());
            let mut r = report_with(bytes);
            classify(&mut r);
            assert_eq!(r.result, "ACK_CONTROL_PACKET");
        }

        #[test]
        fn no_reply_is_distinct() {
            let mut r = report_with(Vec::new());
            r.reads[0].status = "TIMEOUT";
            classify(&mut r);
            assert_eq!(r.result, "NO_REPLY_AFTER_ACK");
        }
    }
}
