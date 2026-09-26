//! One-shot classic KDUSB NAME? identity probe.
//!
//! This binary is deliberately narrower than the ntoseye KDUSB backend:
//! it opens one supported classic-KDUSB interface, claims it, sends exactly
//! the five-byte ASCII probe "NAME?", reads one NAME= reply, releases the
//! interface, and exits. It never constructs KD framing, sends a break-in,
//! starts a debugger session, or accesses target memory.

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
    const TIMEOUT: Duration = Duration::from_secs(1);

    struct ProbeReport {
        vendor: u16,
        product: u16,
        interface: u8,
        alternate_setting: u8,
        bulk_in: u8,
        bulk_out: u8,
        max_packet: u16,
        reply: Vec<u8>,
        usb_rx_len: usize,
        trailing_rx_len: usize,
        target_name: String,
    }

    pub fn run() -> Result<(), String> {
        let mut args = std::env::args();
        let program = args
            .next()
            .unwrap_or_else(|| "ntoseye-kdusb-name-probe".to_string());
        let expected = args
            .next()
            .ok_or_else(|| format!("usage: {program} <TARGET_NAME>"))?;
        if args.next().is_some() {
            return Err(format!("usage: {program} <TARGET_NAME>"));
        }
        validate_target_name(&expected)?;

        let report = probe(&expected)?;

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
        println!("USB_RX_TRANSFER_LEN={}", report.usb_rx_len);
        println!("REPLY_RX_LEN={}", report.reply.len());
        println!("REPLY_RX_HEX={}", hex::encode(&report.reply));
        println!("TRAILING_RX_LEN={}", report.trailing_rx_len);
        println!("REPLY_TARGET={}", report.target_name);
        println!("INTERFACE_RELEASED=true");
        println!("USB_CONTROL_TRANSFER=false");
        println!("KD_PACKET_TRAFFIC=false");
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
                "classic KDUSB interface found, but NAME= reply did not match '{expected}'"
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

            // USB2DBG posts a 4016-byte USB receive and presents the result as
            // a byte stream to its caller. A raw libusb buffer sized only to
            // the <=37-byte logical NAME reply can overflow when the device
            // completes a larger USB transfer. Match the recovered Windows
            // receive quantum, then validate only the logical NAME response.
            let mut response = vec![0u8; USB_READ_REQUEST];
            let received = handle
                .read_bulk(bulk_in, &mut response, TIMEOUT)
                .map_err(|err| format!("reading KDUSB NAME= reply: {err}"))?;

            let logical_len = NAME_PREFIX.len() + expected.len() + 2;
            if logical_len > NAME_RESPONSE_MAX {
                return Err(format!(
                    "expected NAME reply length {logical_len} exceeds logical maximum {NAME_RESPONSE_MAX}"
                ));
            }
            if received < logical_len {
                return Err(format!(
                    "short KDUSB NAME= reply: received {received} bytes, need at least {logical_len}"
                ));
            }

            let reply = response[..logical_len].to_vec();
            let target_name = parse_name_response(&reply)?.to_string();

            if target_name != expected || reply[logical_len - 2..] != [0, 0] {
                return Ok(None);
            }

            Ok(Some(ProbeReport {
                vendor,
                product,
                interface,
                alternate_setting,
                bulk_in,
                bulk_out,
                max_packet,
                reply,
                usb_rx_len: received,
                trailing_rx_len: received - logical_len,
                target_name,
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
        fn target_validation_matches_windows_limit() {
            assert!(validate_target_name("CLSA0102_USB").is_ok());
            assert!(validate_target_name(&"A".repeat(24)).is_ok());
            assert!(validate_target_name(&"A".repeat(25)).is_err());
            assert!(validate_target_name("lowercase").is_err());
        }
    }
}
