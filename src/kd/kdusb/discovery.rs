//! Evidence-bounded Linux discovery for classic USB2DBG.
//!
//! This opener denies discovery until independent admission exists. Its
//! dormant implementation is deliberately narrow: exact VID/PID, interface
//! class/subclass/protocol, alternate setting zero, and the recovered bulk
//! endpoints. It never changes USB configuration, selects an alternate
//! setting, detaches a kernel driver, resets a device, or sends KD break-in.

use std::io;
use std::sync::Arc;
use std::time::Duration;

use rusb::{Direction, GlobalContext, TransferType};

use super::{BulkEndpoints, KdUsbStream, TARGET_NAME_MAX};

pub const KDUSB_VENDOR_ID: u16 = 0x3495;
pub const KDUSB_PRODUCT_ID: u16 = 0x00e0;
pub const KDUSB_INTERFACE_CLASS: u8 = 0xdc;
pub const KDUSB_INTERFACE_SUBCLASS: u8 = 0x02;
pub const KDUSB_INTERFACE_PROTOCOL: u8 = 0xff;
pub const KDUSB_INTERFACE_ALT_SETTING: u8 = 0;
pub const KDUSB_BULK_IN: u8 = 0x81;
pub const KDUSB_BULK_OUT: u8 = 0x01;
pub const KDUSB_MAX_PACKET: usize = 1024;

pub type LinuxKdUsbStream = KdUsbStream<rusb::DeviceHandle<GlobalContext>>;

/// Preserve discovery context and the typed rusb source through io::Error.
#[derive(Debug)]
pub struct DiscoveryFailure {
    pub stage: &'static str,
    pub error: rusb::Error,
}

impl std::fmt::Display for DiscoveryFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.stage, self.error)
    }
}

impl std::error::Error for DiscoveryFailure {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.error)
    }
}

pub(super) fn usb_error(context: &'static str, err: rusb::Error) -> io::Error {
    let kind = match err {
        rusb::Error::Access => io::ErrorKind::PermissionDenied,
        rusb::Error::Busy => io::ErrorKind::WouldBlock,
        rusb::Error::Interrupted => io::ErrorKind::Interrupted,
        rusb::Error::InvalidParam => io::ErrorKind::InvalidInput,
        rusb::Error::NoDevice => io::ErrorKind::NotConnected,
        rusb::Error::NotFound => io::ErrorKind::NotFound,
        rusb::Error::Overflow => io::ErrorKind::InvalidData,
        rusb::Error::Pipe => io::ErrorKind::BrokenPipe,
        rusb::Error::Timeout => io::ErrorKind::TimedOut,
        _ => io::ErrorKind::Other,
    };
    io::Error::new(kind, DiscoveryFailure { stage: context, error: err })
}

// No public constructor or production issuer: identity is not authorization.
pub(super) struct DiscoveryAdmission {
    _private: (),
}

pub(super) fn discovery_admission() -> io::Result<DiscoveryAdmission> {
    Err(io::Error::new(io::ErrorKind::PermissionDenied,
        "KDUSB discovery/claim/NAME requires independent admission; unavailable"))
}

// Passive inspection may continue, but must retain its first failure. Device
// removal is terminal even before claim and cannot be hidden by another device.
pub(super) fn record_passive_error(first: &mut Option<io::Error>, error: io::Error)
    -> io::Result<()> {
    if error.get_ref().and_then(|e| e.downcast_ref::<DiscoveryFailure>())
        .is_some_and(|e| e.error == rusb::Error::NoDevice) {
        return Err(error);
    }
    first.get_or_insert(error);
    Ok(())
}

fn validate_target_name(target_name: &str) -> io::Result<()> {
    let bytes = target_name.as_bytes();
    if bytes.is_empty()
        || bytes.len() > TARGET_NAME_MAX
        || !bytes.is_ascii()
        || bytes.contains(&0)
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "KDUSB target name must be 1..=24 non-NUL ASCII bytes",
        ));
    }
    Ok(())
}

/// Fail closed until independent discovery admission is implemented.
///
/// The signature is preserved, but valid requests now return PermissionDenied
/// before enumeration. The dormant opener inspects configuration without
/// changing it and stops at the first open/ownership/claim/NAME error.
pub fn connect_named(target_name: &str, timeout: Duration) -> io::Result<LinuxKdUsbStream> {
    validate_target_name(target_name)?;
    if timeout.is_zero() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "KDUSB discovery timeout must be nonzero",
        ));
    }

    let _admission = discovery_admission()?;
    let devices = rusb::devices().map_err(|err| usb_error("enumerating USB devices", err))?;
    let mut saw_device = false;
    let mut first_passive_error = None;

    for device in devices.iter() {
        let descriptor = match device.device_descriptor() {
            Ok(descriptor) => descriptor,
            Err(err) => {
                record_passive_error(&mut first_passive_error,
                    usb_error("reading USB device descriptor", err))?;
                continue;
            }
        };
        if descriptor.vendor_id() != KDUSB_VENDOR_ID
            || descriptor.product_id() != KDUSB_PRODUCT_ID
        {
            continue;
        }
        saw_device = true;

        let config = match device.active_config_descriptor() {
            Ok(config) => config,
            Err(err) => {
                record_passive_error(&mut first_passive_error,
                    usb_error("reading active USB configuration", err))?;
                continue;
            }
        };

        for interface in config.interfaces() {
            for descriptor in interface.descriptors() {
                if descriptor.setting_number() != KDUSB_INTERFACE_ALT_SETTING
                    || descriptor.class_code() != KDUSB_INTERFACE_CLASS
                    || descriptor.sub_class_code() != KDUSB_INTERFACE_SUBCLASS
                    || descriptor.protocol_code() != KDUSB_INTERFACE_PROTOCOL
                {
                    continue;
                }

                let mut input = None;
                let mut output = None;
                let mut duplicate_bulk = false;

                for endpoint in descriptor.endpoint_descriptors() {
                    if endpoint.transfer_type() != TransferType::Bulk {
                        continue;
                    }
                    match endpoint.direction() {
                        Direction::In => {
                            if input.replace((endpoint.address(), endpoint.max_packet_size())).is_some()
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
                    record_passive_error(&mut first_passive_error, io::Error::new(
                        io::ErrorKind::InvalidData,
                        "KDUSB interface has multiple bulk endpoints in one direction",
                    ))?;
                    continue;
                }

                let (Some((input_address, input_mps)), Some((output_address, output_mps))) =
                    (input, output)
                else {
                    continue;
                };

                if input_address != KDUSB_BULK_IN
                    || output_address != KDUSB_BULK_OUT
                    || usize::from(input_mps) != KDUSB_MAX_PACKET
                    || usize::from(output_mps) != KDUSB_MAX_PACKET
                {
                    record_passive_error(&mut first_passive_error, io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!(
                            "KDUSB endpoint topology differs from admitted 81/01 max-packet 1024: in={input_address:#04x}/{input_mps}, out={output_address:#04x}/{output_mps}"
                        ),
                    ))?;
                    continue;
                }

                // Crossing from passive inspection to device access consumes
                // the candidate attempt: no later candidate may replace faults.
                let handle = device.open()
                    .map_err(|err| usb_error("opening classic KDUSB device", err))?;

                match handle.kernel_driver_active(descriptor.interface_number()) {
                    Ok(true) => {
                        return Err(io::Error::new(
                            io::ErrorKind::PermissionDenied,
                            format!(
                                "KDUSB interface {} has a kernel driver; refusing to detach it",
                                descriptor.interface_number()
                            ),
                        ));
                    }
                    Ok(false) | Err(rusb::Error::NotSupported) => {}
                    Err(err) => {
                        return Err(usb_error(
                            "checking KDUSB kernel-driver ownership",
                            err,
                        ));
                    }
                }

                handle.claim_interface(descriptor.interface_number())
                    .map_err(|err| usb_error("claiming KDUSB interface", err))?;

                let endpoints = BulkEndpoints {
                    input: input_address,
                    output: output_address,
                    max_packet: KDUSB_MAX_PACKET,
                };
                let mut stream = KdUsbStream::new(Arc::new(handle), endpoints, timeout)?;

                stream.probe_name(target_name.as_bytes())?;
                return Ok(stream);
            }
        }
    }

    if let Some(err) = first_passive_error {
        return Err(err);
    }

    Err(io::Error::new(
        io::ErrorKind::NotFound,
        if saw_device {
            "classic KDUSB device found, but admitted interface topology was not present".to_string()
        } else {
            "admitted classic KDUSB device 3495:00e0 was not found".to_string()
        },
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn target_name_validation_is_bounded_ascii() {
        for valid in ["A", "CLSA0102_USB", "debug-1", "A B"] {
            assert!(validate_target_name(valid).is_ok(), "{valid:?}");
        }
        for invalid in ["", "på", &"A".repeat(25)] {
            assert!(validate_target_name(invalid).is_err(), "{invalid:?}");
        }
    }

    #[test]
    fn admitted_topology_constants_are_exact() {
        assert_eq!((KDUSB_VENDOR_ID, KDUSB_PRODUCT_ID), (0x3495, 0x00e0));
        assert_eq!(
            (
                KDUSB_INTERFACE_CLASS,
                KDUSB_INTERFACE_SUBCLASS,
                KDUSB_INTERFACE_PROTOCOL,
            ),
            (0xdc, 0x02, 0xff)
        );
        assert_eq!(KDUSB_INTERFACE_ALT_SETTING, 0);
        assert_eq!((KDUSB_BULK_IN, KDUSB_BULK_OUT), (0x81, 0x01));
        assert_eq!(KDUSB_MAX_PACKET, 1024);
    }
}
