//! One-shot classic KDUSB bootstrap observer.
//!
//! Default mode preserves the original NAME?-only identity probe semantics.
//! With `--accept-kd-prefetch`, the first non-empty bulk-IN transfer may
//! instead be a plausible KD packet header from an already-active target.
//! With `--complete-kd-prefetch-tail`, an incomplete prefetched KD packet
//! may consume exactly one additional non-empty bulk-IN transfer so its
//! checksum/trailer boundary can be validated. The observer never sends a KD
//! ACK/RESEND/RESET packet, break-in byte, or debugger request.

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("ntoseye-kdusb-name-probe is supported only on Linux hosts");
    std::process::exit(2);
}

#[cfg(target_os = "linux")]
fn main() {
    if let Err(err) = linux::run() {
        eprintln!("KDUSB_NAME_PROBE=FAIL");
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
    const KD_PACKET_MAX: usize = 4000;
    const KD_HEADER_SIZE: usize = 16;
    const DATA_PACKET_LEADER: u32 = 0x3030_3030;
    const CONTROL_PACKET_LEADER: u32 = 0x6969_6969;
    const TIMEOUT: Duration = Duration::from_secs(1);

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    struct KdHeader {
        leader: u32,
        packet_type: u16,
        byte_count: u16,
        packet_id: u32,
        checksum: u32,
    }

    enum BootstrapObservation {
        Name {
            reply: Vec<u8>,
            usb_rx_len: usize,
            trailing_rx_len: usize,
            target_name: String,
        },
        KdPrefetch {
            header: KdHeader,
            usb_rx_len: usize,
            raw_prefix_hex: String,
            required_stream_bytes: usize,
            tail_observation_performed: bool,
            tail_usb_rx_len: usize,
            tail_prefix_hex: String,
            tail_extra_rx_len: usize,
            packet_complete_after_tail: bool,
            checksum_valid: bool,
            trailer_valid: Option<bool>,
        },
    }

    struct ProbeReport {
        vendor: u16,
        product: u16,
        interface: u8,
        alternate_setting: u8,
        bulk_in: u8,
        bulk_out: u8,
        max_packet: u16,
        observation: BootstrapObservation,
    }

    pub fn run() -> Result<(), String> {
        let mut args = std::env::args();
        let program = args
            .next()
            .unwrap_or_else(|| "ntoseye-kdusb-name-probe".to_string());
        let usage = || {
            format!(
                "usage: {program} <TARGET_NAME> [--accept-kd-prefetch] [--complete-kd-prefetch-tail]"
            )
        };
        let expected = args.next().ok_or_else(&usage)?;

        let mut accept_kd_prefetch = false;
        let mut complete_kd_prefetch_tail = false;
        for arg in args {
            match arg.as_str() {
                "--accept-kd-prefetch" if !accept_kd_prefetch => accept_kd_prefetch = true,
                "--complete-kd-prefetch-tail" if !complete_kd_prefetch_tail => {
                    complete_kd_prefetch_tail = true;
                    accept_kd_prefetch = true;
                }
                _ => return Err(usage()),
            }
        }

        validate_target_name(&expected)?;
        let report = probe(
            &expected,
            accept_kd_prefetch,
            complete_kd_prefetch_tail,
        )?;

        println!("KDUSB_NAME_PROBE=PASS");
        println!("VID_PID={:04x}:{:04x}", report.vendor, report.product);
        println!("INTERFACE={}", report.interface);
        println!("ALTERNATE_SETTING={}", report.alternate_setting);
        println!("BULK_OUT=0x{:02x}", report.bulk_out);
        println!("BULK_IN=0x{:02x}", report.bulk_in);
        println!("MAX_PACKET={}", report.max_packet);
        println!("PROBE_TX_LEN={}", NAME_PROBE.len());
        println!("PROBE_TX_HEX={}", hex::encode(NAME_PROBE));
        println!("USB_RX_REQUEST_LEN={USB_READ_REQUEST}");

        match report.observation {
            BootstrapObservation::Name {
                reply,
                usb_rx_len,
                trailing_rx_len,
                target_name,
            } => {
                println!("BOOTSTRAP_KIND=NAME");
                println!("USB_RX_TRANSFER_LEN={usb_rx_len}");
                println!("REPLY_RX_LEN={}", reply.len());
                println!("REPLY_RX_HEX={}", hex::encode(&reply));
                println!("TRAILING_RX_LEN={trailing_rx_len}");
                println!("REPLY_TARGET={target_name}");
                println!("KD_PREFETCH=false");
            }
            BootstrapObservation::KdPrefetch {
                header,
                usb_rx_len,
                raw_prefix_hex,
                required_stream_bytes,
                tail_observation_performed,
                tail_usb_rx_len,
                tail_prefix_hex,
                tail_extra_rx_len,
                packet_complete_after_tail,
                checksum_valid,
                trailer_valid,
            } => {
                println!("BOOTSTRAP_KIND=KD_PREFETCH");
                println!("USB_RX_TRANSFER_LEN={usb_rx_len}");
                println!("KD_PREFETCH=true");
                println!("KD_LEADER=0x{:08x}", header.leader);
                println!("KD_PACKET_TYPE=0x{:04x}", header.packet_type);
                println!("KD_BYTE_COUNT={}", header.byte_count);
                println!("KD_PACKET_ID=0x{:08x}", header.packet_id);
                println!("KD_CHECKSUM=0x{:08x}", header.checksum);
                println!("KD_REQUIRED_STREAM_BYTES={required_stream_bytes}");
                println!(
                    "KD_PACKET_COMPLETE_IN_FIRST_TRANSFER={}",
                    usb_rx_len >= required_stream_bytes
                );
                println!("KD_CHECKSUM_VALID={checksum_valid}");
                println!("TAIL_OBSERVATION_PERFORMED={tail_observation_performed}");
                println!("TAIL_USB_RX_TRANSFER_LEN={tail_usb_rx_len}");
                println!("TAIL_RX_PREFIX_HEX={tail_prefix_hex}");
                println!("TAIL_EXTRA_RX_LEN={tail_extra_rx_len}");
                println!("KD_PACKET_COMPLETE_AFTER_TAIL_OBSERVATION={packet_complete_after_tail}");
                match trailer_valid {
                    Some(valid) => println!("KD_TRAILER_VALID={valid}"),
                    None => println!("KD_TRAILER_VALID=NA"),
                }
                println!("RAW_RX_PREFIX_HEX={raw_prefix_hex}");
            }
        }

        println!("INTERFACE_RELEASED=true");
        println!("USB_CONTROL_TRANSFER=false");
        println!("KD_PACKET_TX=false");
        println!("KD_ACK_TX=false");
        println!("KD_RESEND_TX=false");
        println!("KD_RESET_TX=false");
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

    fn probe(
        expected: &str,
        accept_kd_prefetch: bool,
        complete_kd_prefetch_tail: bool,
    ) -> Result<ProbeReport, String> {
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
                        accept_kd_prefetch,
                        complete_kd_prefetch_tail,
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
                "classic KDUSB interface found, but bootstrap did not match target '{expected}'"
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
        accept_kd_prefetch: bool,
        complete_kd_prefetch_tail: bool,
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

            let mut response = vec![0u8; USB_READ_REQUEST];
            let received = loop {
                let count = handle
                    .read_bulk(bulk_in, &mut response, TIMEOUT)
                    .map_err(|err| format!("reading KDUSB bootstrap transfer: {err}"))?;
                if count != 0 {
                    break count;
                }
            };
            let transfer = &response[..received];
            let raw_prefix_len = received.min(64);
            let raw_prefix_hex = hex::encode(&transfer[..raw_prefix_len]);

            let observation = if transfer.starts_with(NAME_PREFIX) {
                let limit = received.min(NAME_RESPONSE_MAX);
                let suffix = &transfer[NAME_PREFIX.len()..limit];
                let nul = suffix.iter().position(|&byte| byte == 0).ok_or_else(|| {
                    format!(
                        "KDUSB NAME response is not NUL terminated within {NAME_RESPONSE_MAX} bytes; USB_RX_TRANSFER_LEN={received}; RAW_RX_PREFIX_HEX={raw_prefix_hex}"
                    )
                })?;
                let logical_end = NAME_PREFIX.len() + nul + 1;
                let consumed = if transfer.get(logical_end) == Some(&0) {
                    logical_end + 1
                } else {
                    logical_end
                };
                let reply = transfer[..consumed].to_vec();
                let target_name = parse_name_response(&reply)?.to_string();
                if target_name != expected {
                    return Ok(None);
                }

                BootstrapObservation::Name {
                    reply,
                    usb_rx_len: received,
                    trailing_rx_len: received - consumed,
                    target_name,
                }
            } else if accept_kd_prefetch {
                let header = parse_plausible_kd_header(transfer).map_err(|err| {
                    format!(
                        "{err}; USB_RX_TRANSFER_LEN={received}; RAW_RX_PREFIX_HEX={raw_prefix_hex}"
                    )
                })?;

                let required_stream_bytes = kd_required_stream_bytes(header);
                let mut packet_prefix = transfer.to_vec();
                let mut tail_observation_performed = false;
                let mut tail_usb_rx_len = 0usize;
                let mut tail_prefix_hex = String::new();
                let mut tail_extra_rx_len = 0usize;

                if complete_kd_prefetch_tail && packet_prefix.len() < required_stream_bytes {
                    tail_observation_performed = true;
                    let mut tail = vec![0u8; USB_READ_REQUEST];
                    tail_usb_rx_len = loop {
                        let count = handle
                            .read_bulk(bulk_in, &mut tail, TIMEOUT)
                            .map_err(|err| format!("reading KDUSB prefetched packet tail: {err}"))?;
                        if count != 0 {
                            break count;
                        }
                    };

                    let tail_prefix_len = tail_usb_rx_len.min(64);
                    tail_prefix_hex = hex::encode(&tail[..tail_prefix_len]);
                    let missing = required_stream_bytes - packet_prefix.len();
                    if tail_usb_rx_len < missing {
                        return Err(format!(
                            "second KDUSB bulk-IN transfer still does not complete prefetched KD packet: need {missing} bytes, received {tail_usb_rx_len}"
                        ));
                    }

                    packet_prefix.extend_from_slice(&tail[..missing]);
                    tail_extra_rx_len = tail_usb_rx_len - missing;
                }

                let packet_complete_after_tail = packet_prefix.len() >= required_stream_bytes;
                let checksum_valid = kd_checksum_valid(header, &packet_prefix);
                let trailer_valid = kd_trailer_valid(header, &packet_prefix);

                if complete_kd_prefetch_tail {
                    if !packet_complete_after_tail {
                        return Err("prefetched KD packet remains incomplete after bounded tail observation".to_string());
                    }
                    if !checksum_valid {
                        return Err("prefetched KD packet checksum does not match header".to_string());
                    }
                    if trailer_valid == Some(false) {
                        return Err("prefetched KD data packet trailer is not 0xAA".to_string());
                    }
                }

                BootstrapObservation::KdPrefetch {
                    header,
                    usb_rx_len: received,
                    raw_prefix_hex,
                    required_stream_bytes,
                    tail_observation_performed,
                    tail_usb_rx_len,
                    tail_prefix_hex,
                    tail_extra_rx_len,
                    packet_complete_after_tail,
                    checksum_valid,
                    trailer_valid,
                }
            } else {
                return Err(format!(
                    "KDUSB NAME response is missing NAME= prefix; USB_RX_TRANSFER_LEN={received}; RAW_RX_PREFIX_LEN={raw_prefix_len}; RAW_RX_PREFIX_HEX={raw_prefix_hex}"
                ));
            };

            Ok(Some(ProbeReport {
                vendor,
                product,
                interface,
                alternate_setting,
                bulk_in,
                bulk_out,
                max_packet,
                observation,
            }))
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

    fn parse_plausible_kd_header(response: &[u8]) -> Result<KdHeader, String> {
        if response.len() < KD_HEADER_SIZE {
            return Err(format!(
                "KDUSB bootstrap transfer is neither NAME= nor a complete KD header ({} bytes)",
                response.len()
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
                "KDUSB bootstrap transfer is neither NAME= nor plausible KD framing (leader={:#010x}, type={}, byte_count={})",
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
            return header.byte_count == 0 && header.checksum == 0 && packet.len() >= KD_HEADER_SIZE;
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
        packet.get(trailer_index).map(|&byte| byte == 0xaa)
    }

    fn parse_name_response(response: &[u8]) -> Result<&str, String> {
        if response.len() < NAME_PREFIX.len() || response.len() > NAME_RESPONSE_MAX {
            return Err(format!(
                "KDUSB NAME response has invalid length {} (expected {}..={})",
                response.len(),
                NAME_PREFIX.len(),
                NAME_RESPONSE_MAX
            ));
        }
        if !response.starts_with(NAME_PREFIX) {
            return Err("KDUSB NAME response is missing NAME= prefix".to_string());
        }

        let suffix = &response[NAME_PREFIX.len()..];
        let nul = suffix
            .iter()
            .position(|&byte| byte == 0)
            .ok_or_else(|| "KDUSB NAME response is not NUL terminated".to_string())?;
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
        std::str::from_utf8(name)
            .map_err(|err| format!("KDUSB target name is not UTF-8/ASCII: {err}"))
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn exact_clsa0102_reply_parses() {
            let reply = b"NAME=CLSA0102_USB\0\0";
            assert_eq!(parse_name_response(reply).unwrap(), "CLSA0102_USB");
        }

        #[test]
        fn observed_live_file_io_header_is_accepted_as_kd_prefetch() {
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
        }

        #[test]
        fn observed_prefetch_requires_one_trailer_byte() {
            let mut observed = hex::decode(
                "303030300b00920000088080a0110000303400000000000089001200800000000100000001000000000000000000000000000000000000000000000000000000",
            )
            .unwrap();
            observed.resize(162, 0);
            let header = parse_plausible_kd_header(&observed).unwrap();
            assert_eq!(kd_required_stream_bytes(header), 163);
            assert!(!kd_trailer_valid(header, &observed).unwrap_or(false));
            observed.push(0xaa);
            assert_eq!(kd_trailer_valid(header, &observed), Some(true));
        }

        #[test]
        fn checksum_validator_accepts_synthetic_data_packet() {
            let payload = b"abc";
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
            packet.push(0xaa);
            assert!(kd_checksum_valid(header, &packet));
            assert_eq!(kd_trailer_valid(header, &packet), Some(true));
        }

        #[test]
        fn random_non_name_non_kd_transfer_is_rejected() {
            assert!(parse_plausible_kd_header(&[0x55; 32]).is_err());
        }

        #[test]
        fn target_validation_matches_windows_limit() {
            assert!(validate_target_name("CLSA0102_USB").is_ok());
            assert!(validate_target_name(&"A".repeat(24)).is_ok());
            assert!(validate_target_name(&"A".repeat(25)).is_err());
            assert!(validate_target_name("lowercase").is_err());
        }
    }
}
