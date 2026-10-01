#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("ntoseye-kdusb-same-configuration-r1 is Linux-only");
    std::process::exit(2);
}

#[cfg(target_os = "linux")]
fn main() {
    use std::process::ExitCode;
    match linux::run() {
        Ok(()) => {}
        Err((code, error)) => {
            eprintln!("{error}");
            std::process::exit(code);
        }
    }
}

#[cfg(target_os = "linux")]
mod linux {
    use ntoseye::kd::kdusb::{
        KDUSB_BULK_IN, KDUSB_BULK_OUT, KDUSB_INTERFACE_ALT_SETTING, KDUSB_INTERFACE_CLASS,
        KDUSB_INTERFACE_PROTOCOL, KDUSB_INTERFACE_SUBCLASS, KDUSB_MAX_PACKET, KDUSB_PRODUCT_ID,
        KDUSB_VENDOR_ID,
    };
    use rusb::{Device, Direction, GlobalContext, TransferType};

    const AUTH_FLAG: &str = "--authorize-live-same-configuration-reapply";
    const TARGET_FLAG: &str = "--target";
    const ADMITTED_TARGET: &str = "CLSA0102_USB";
    const EXPECTED_BUS: u8 = 6;
    const EXPECTED_PORTS: &[u8] = &[1];
    const EXPECTED_CONFIGURATION: u8 = 1;
    const EXPECTED_INTERFACE: u8 = 0;

    #[derive(Clone, Debug, PartialEq, Eq)]
    struct Identity {
        bus: u8,
        address: u8,
        ports: Vec<u8>,
        configuration: u8,
        interface: u8,
        alternate_setting: u8,
        bulk_in: u8,
        bulk_out: u8,
        input_mps: u16,
        output_mps: u16,
    }

    struct Candidate {
        device: Device<GlobalContext>,
        identity: Identity,
    }

    fn usage() -> &'static str {
        "usage: ntoseye-kdusb-same-configuration-r1 --authorize-live-same-configuration-reapply --target CLSA0102_USB"
    }

    fn parse_args() -> Result<(), String> {
        let mut args = std::env::args().skip(1);
        let mut authorized = false;
        let mut target = None;

        while let Some(arg) = args.next() {
            match arg.as_str() {
                AUTH_FLAG => authorized = true,
                TARGET_FLAG => {
                    target = Some(
                        args.next()
                            .ok_or_else(|| format!("{TARGET_FLAG} requires a value"))?,
                    );
                }
                "-h" | "--help" => return Err(usage().into()),
                other => return Err(format!("unknown argument: {other}\n{}", usage())),
            }
        }

        if !authorized {
            return Err(format!(
                "live same-configuration reapply is not authorized; pass {AUTH_FLAG} explicitly"
            ));
        }
        let target = target.ok_or_else(|| format!("{TARGET_FLAG} is required"))?;
        if target != ADMITTED_TARGET {
            return Err(format!(
                "target must be exact admitted name {ADMITTED_TARGET:?}, got {target:?}"
            ));
        }
        Ok(())
    }

    fn physical_path(identity: &Identity) -> String {
        let suffix = identity
            .ports
            .iter()
            .map(u8::to_string)
            .collect::<Vec<_>>()
            .join(".");
        format!("{}-{suffix}", identity.bus)
    }

    fn discover() -> Result<Candidate, String> {
        let devices = rusb::devices().map_err(|err| format!("enumerating USB devices: {err}"))?;
        let mut candidates = Vec::new();

        for device in devices.iter() {
            let descriptor = match device.device_descriptor() {
                Ok(descriptor) => descriptor,
                Err(_) => continue,
            };
            if descriptor.vendor_id() != KDUSB_VENDOR_ID
                || descriptor.product_id() != KDUSB_PRODUCT_ID
            {
                continue;
            }

            let bus = device.bus_number();
            let address = device.address();
            let ports = device
                .port_numbers()
                .map_err(|err| format!("reading KDUSB port path: {err}"))?;
            let config = device
                .active_config_descriptor()
                .map_err(|err| format!("reading active KDUSB configuration descriptor: {err}"))?;

            for interface in config.interfaces() {
                for descriptor_if in interface.descriptors() {
                    if descriptor_if.setting_number() != KDUSB_INTERFACE_ALT_SETTING
                        || descriptor_if.class_code() != KDUSB_INTERFACE_CLASS
                        || descriptor_if.sub_class_code() != KDUSB_INTERFACE_SUBCLASS
                        || descriptor_if.protocol_code() != KDUSB_INTERFACE_PROTOCOL
                    {
                        continue;
                    }

                    let mut input = None;
                    let mut output = None;
                    let mut duplicate_bulk = false;

                    for endpoint in descriptor_if.endpoint_descriptors() {
                        if endpoint.transfer_type() != TransferType::Bulk {
                            continue;
                        }
                        match endpoint.direction() {
                            Direction::In => {
                                if input
                                    .replace((endpoint.address(), endpoint.max_packet_size()))
                                    .is_some()
                                {
                                    duplicate_bulk = true;
                                }
                            }
                            Direction::Out => {
                                if output
                                    .replace((endpoint.address(), endpoint.max_packet_size()))
                                    .is_some()
                                {
                                    duplicate_bulk = true;
                                }
                            }
                        }
                    }

                    if duplicate_bulk {
                        return Err("KDUSB interface has duplicate bulk endpoints".into());
                    }

                    let (Some((bulk_in, input_mps)), Some((bulk_out, output_mps))) =
                        (input, output)
                    else {
                        continue;
                    };

                    let identity = Identity {
                        bus,
                        address,
                        ports: ports.clone(),
                        configuration: config.number(),
                        interface: descriptor_if.interface_number(),
                        alternate_setting: descriptor_if.setting_number(),
                        bulk_in,
                        bulk_out,
                        input_mps,
                        output_mps,
                    };

                    if identity.bus == EXPECTED_BUS
                        && identity.ports.as_slice() == EXPECTED_PORTS
                        && identity.configuration == EXPECTED_CONFIGURATION
                        && identity.interface == EXPECTED_INTERFACE
                        && identity.alternate_setting == KDUSB_INTERFACE_ALT_SETTING
                        && identity.bulk_in == KDUSB_BULK_IN
                        && identity.bulk_out == KDUSB_BULK_OUT
                        && usize::from(identity.input_mps) == KDUSB_MAX_PACKET
                        && usize::from(identity.output_mps) == KDUSB_MAX_PACKET
                    {
                        candidates.push(Candidate {
                            device: device.clone(),
                            identity,
                        });
                    }
                }
            }
        }

        match candidates.len() {
            1 => Ok(candidates.pop().expect("length checked")),
            0 => Err("no exact admitted KDUSB candidate found on physical path 6-1".into()),
            count => Err(format!(
                "{count} exact admitted KDUSB candidates found; refusing ambiguous operation"
            )),
        }
    }

    fn print_identity(prefix: &str, identity: &Identity) {
        println!("{prefix}_BUS={}", identity.bus);
        println!("{prefix}_ADDRESS={}", identity.address);
        println!("{prefix}_PHYSICAL_PATH={}", physical_path(identity));
        println!("{prefix}_CONFIGURATION={}", identity.configuration);
        println!("{prefix}_INTERFACE={}", identity.interface);
        println!("{prefix}_ALT_SETTING={}", identity.alternate_setting);
        println!("{prefix}_BULK_IN=0x{:02x}", identity.bulk_in);
        println!("{prefix}_BULK_OUT=0x{:02x}", identity.bulk_out);
        println!("{prefix}_INPUT_MPS={}", identity.input_mps);
        println!("{prefix}_OUTPUT_MPS={}", identity.output_mps);
    }

    fn print_policy() {
        println!("TARGET_NAME={ADMITTED_TARGET}");
        println!("EXPECTED_VID_PID=3495:00e0");
        println!("EXPECTED_PHYSICAL_PATH=6-1");
        println!("EXPECTED_CONFIGURATION=1");
        println!("EXPECTED_INTERFACE=0");
        println!("EXPECTED_ALT_SETTING=0");
        println!("EXPECTED_ENDPOINTS=81/01");
        println!("EXPECTED_MAX_PACKET=1024");
        println!("SET_CONFIGURATION_CURRENT_MAX=1");
        println!("CONFIGURATION_VALUE_CHANGED=false");
        println!("INTERFACE_CLAIM=false");
        println!("KERNEL_DRIVER_DETACH=false");
        println!("ALTERNATE_SETTING_CHANGE=false");
        println!("CLEAR_HALT=false");
        println!("USB_DEVICE_RESET=false");
        println!("NAME_PROBE=false");
        println!("KD_PACKET_TX=false");
        println!("BREAKIN=false");
        println!("GETVERSION=false");
        println!("BACKEND_ATTACH=false");
        println!("AUTOMATIC_RETRY=false");
    }

    pub fn run() -> Result<(), (i32, String)> {
        parse_args().map_err(|error| (2, format!("FAIL_KDUSB_SAME_CONFIG_ARGS={error}")))?;

        println!("PHASE349G_MODE=ONE_SHOT_SAME_CONFIGURATION_REAPPLY");
        print_policy();

        let before_candidate =
            discover().map_err(|error| (1, format!("FAIL_KDUSB_DISCOVERY_BEFORE={error}")))?;
        let before = before_candidate.identity.clone();
        print_identity("BEFORE", &before);

        let handle = before_candidate
            .device
            .open()
            .map_err(|err| (1, format!("FAIL_KDUSB_OPEN_UNCLAIMED={err}")))?;

        match handle.kernel_driver_active(before.interface) {
            Ok(true) => {
                return Err((
                    1,
                    format!(
                        "FAIL_KDUSB_KERNEL_DRIVER=interface {} has a kernel driver; refusing detach",
                        before.interface
                    ),
                ));
            }
            Ok(false) | Err(rusb::Error::NotSupported) => {}
            Err(err) => {
                return Err((
                    1,
                    format!("FAIL_KDUSB_KERNEL_DRIVER_CHECK={err}"),
                ));
            }
        }

        let active = handle
            .active_configuration()
            .map_err(|err| (1, format!("FAIL_KDUSB_ACTIVE_CONFIGURATION_READ={err}")))?;
        if active != EXPECTED_CONFIGURATION || active != before.configuration {
            return Err((
                1,
                format!(
                    "FAIL_KDUSB_ACTIVE_CONFIGURATION_MISMATCH=active={active} descriptor={}",
                    before.configuration
                ),
            ));
        }

        println!("LIVE_SAME_CONFIGURATION_REAPPLY_AUTHORIZED=true");
        println!("SET_CONFIGURATION_CURRENT_VALUE={active}");

        handle
            .set_active_configuration(active)
            .map_err(|err| (1, format!("FAIL_KDUSB_SAME_CONFIGURATION_REAPPLY={err}")))?;

        drop(handle);

        let after_candidate =
            discover().map_err(|error| (1, format!("FAIL_KDUSB_DISCOVERY_AFTER={error}")))?;
        let after = after_candidate.identity;
        print_identity("AFTER", &after);

        if before != after {
            return Err((
                1,
                format!(
                    "FAIL_KDUSB_IDENTITY_CHANGED=before={before:?} after={after:?}"
                ),
            ));
        }

        println!("PASS_KDUSB_SAME_CONFIGURATION_REAPPLY=true");
        println!("PASS_KDUSB_IDENTITY_STABLE=true");
        println!("PASS_KDUSB_BUS_ADDRESS_STABLE=true");
        println!("PASS_KDUSB_PHYSICAL_PATH_STABLE=true");
        println!("PASS_KDUSB_ENDPOINT_TOPOLOGY_STABLE=true");
        println!("NAME_PROBE_EXECUTED=false");
        println!("USB_DEVICE_RESET_EXECUTED=false");
        println!("INTERFACE_CLAIM_EXECUTED=false");
        Ok(())
    }
}
