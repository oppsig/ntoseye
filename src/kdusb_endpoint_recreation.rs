//! One-shot Linux KDUSB endpoint recreation by reapplying the active USB
//! configuration.  This module deliberately exposes no USB device-reset API.

use crate::kdusb_probe::{DeviceSelection, TransportFault};
use std::time::Duration;

/// Minimal transport surface used by the bounded validation state machine.
pub trait EndpointRecreationBackend {
    /// Discover and open exactly one KDUSB candidate without claiming it.
    fn discover_unclaimed(&mut self) -> Result<DeviceSelection, TransportFault>;
    /// Reapply the already-active configuration exactly once.
    fn reapply_current_configuration(
        &mut self,
        expected: &DeviceSelection,
    ) -> Result<(), TransportFault>;
    /// Rediscover, validate, and claim the same interface after the operation.
    fn acquire_after_recreation(
        &mut self,
        expected: &DeviceSelection,
    ) -> Result<DeviceSelection, TransportFault>;
    fn write_name(
        &mut self,
        endpoint: u8,
        payload: &[u8],
        timeout: Duration,
    ) -> Result<usize, TransportFault>;
    fn read_name(
        &mut self,
        endpoint: u8,
        response: &mut [u8],
        timeout: Duration,
    ) -> Result<usize, TransportFault>;
    fn release(&mut self) -> Result<(), TransportFault>;
}

#[cfg(target_os = "linux")]
pub mod linux {
    use super::*;
    use crate::kdusb_probe::linux::{RusbProbeBackend, classify_rusb_error};
    use rusb::{DeviceHandle, GlobalContext};

    pub struct RusbEndpointRecreationBackend {
        handle: Option<DeviceHandle<GlobalContext>>,
        claimed_interface: Option<u8>,
        original_bus: Option<u8>,
        original_address: Option<u8>,
    }

    impl Default for RusbEndpointRecreationBackend {
        fn default() -> Self {
            Self::new()
        }
    }

    impl RusbEndpointRecreationBackend {
        pub const fn new() -> Self {
            Self {
                handle: None,
                claimed_interface: None,
                original_bus: None,
                original_address: None,
            }
        }

        fn ensure_no_kernel_driver(
            handle: &DeviceHandle<GlobalContext>,
            interface: u8,
        ) -> Result<(), TransportFault> {
            match handle.kernel_driver_active(interface) {
                Ok(false) | Err(rusb::Error::NotSupported) => Ok(()),
                Ok(true) => Err(TransportFault::recovery(
                    "kernel-driver-check",
                    format!("interface {interface} has a kernel driver; refusing detach"),
                )),
                Err(err) => Err(classify_rusb_error("kernel-driver-check", err)),
            }
        }

        fn matching_candidate(
            expected: Option<&DeviceSelection>,
        ) -> Result<crate::kdusb_probe::linux::Candidate, TransportFault> {
            let expected_port = expected.map(|selection| selection.port_path.as_slice());
            let mut candidates = RusbProbeBackend::candidates(expected_port)?;
            if let Some(expected) = expected {
                candidates.retain(|candidate| candidate.selection == *expected);
            }
            match candidates.len() {
                0 => Err(TransportFault::recovery(
                    "descriptor-identity",
                    "no exact KDUSB dc/02/ff bulk endpoint identity found",
                )),
                1 => Ok(candidates.pop().expect("length checked")),
                count => Err(TransportFault::recovery(
                    "descriptor-identity",
                    format!("{count} candidates found; refusing ambiguous operation"),
                )),
            }
        }
    }

    impl EndpointRecreationBackend for RusbEndpointRecreationBackend {
        fn discover_unclaimed(&mut self) -> Result<DeviceSelection, TransportFault> {
            let candidate = Self::matching_candidate(None)?;
            candidate.selection.validate()?;
            if candidate.selection.alternate_setting != 0 {
                return Err(TransportFault::recovery(
                    "validate-selection",
                    "same-configuration recreation resets interfaces to altsetting zero",
                ));
            }
            let handle = candidate
                .device
                .open()
                .map_err(|err| classify_rusb_error("open-unclaimed", err))?;
            Self::ensure_no_kernel_driver(&handle, candidate.selection.interface)?;
            let active = handle
                .active_configuration()
                .map_err(|err| classify_rusb_error("get-active-configuration", err))?;
            if active != candidate.selection.configuration {
                return Err(TransportFault::recovery(
                    "get-active-configuration",
                    format!(
                        "descriptor configuration {} differs from active configuration {active}",
                        candidate.selection.configuration
                    ),
                ));
            }
            self.original_bus = Some(candidate.device.bus_number());
            self.original_address = Some(candidate.device.address());
            self.handle = Some(handle);
            Ok(candidate.selection)
        }

        fn reapply_current_configuration(
            &mut self,
            expected: &DeviceSelection,
        ) -> Result<(), TransportFault> {
            let handle = self.handle.as_ref().ok_or_else(|| {
                TransportFault::recovery("same-configuration-reapply", "no unclaimed handle")
            })?;
            let active = handle
                .active_configuration()
                .map_err(|err| classify_rusb_error("get-active-configuration", err))?;
            if active != expected.configuration {
                return Err(TransportFault::recovery(
                    "same-configuration-reapply",
                    "active configuration changed before the operation",
                ));
            }
            handle
                .set_active_configuration(active)
                .map_err(|err| classify_rusb_error("same-configuration-reapply", err))
        }

        fn acquire_after_recreation(
            &mut self,
            expected: &DeviceSelection,
        ) -> Result<DeviceSelection, TransportFault> {
            self.handle = None;
            let candidate = Self::matching_candidate(Some(expected))?;
            if (
                Some(candidate.device.bus_number()),
                Some(candidate.device.address()),
            ) != (self.original_bus, self.original_address)
            {
                return Err(TransportFault::recovery(
                    "stable-usb-address",
                    "bus/address changed; refusing possible re-enumeration before NAME",
                ));
            }
            let handle = candidate
                .device
                .open()
                .map_err(|err| classify_rusb_error("reopen-after-recreation", err))?;
            Self::ensure_no_kernel_driver(&handle, expected.interface)?;
            handle
                .claim_interface(expected.interface)
                .map_err(|err| classify_rusb_error("claim-after-recreation", err))?;
            self.claimed_interface = Some(expected.interface);
            self.handle = Some(handle);
            Ok(candidate.selection)
        }

        fn write_name(
            &mut self,
            endpoint: u8,
            payload: &[u8],
            timeout: Duration,
        ) -> Result<usize, TransportFault> {
            self.handle
                .as_ref()
                .ok_or_else(|| TransportFault::recovery("post-operation-name-write", "no handle"))?
                .write_bulk(endpoint, payload, timeout)
                .map_err(|err| classify_rusb_error("post-operation-name-write", err))
        }

        fn read_name(
            &mut self,
            endpoint: u8,
            response: &mut [u8],
            timeout: Duration,
        ) -> Result<usize, TransportFault> {
            self.handle
                .as_ref()
                .ok_or_else(|| TransportFault::recovery("post-operation-name-read", "no handle"))?
                .read_bulk(endpoint, response, timeout)
                .map_err(|err| classify_rusb_error("post-operation-name-read", err))
        }

        fn release(&mut self) -> Result<(), TransportFault> {
            if let (Some(handle), Some(interface)) =
                (self.handle.as_ref(), self.claimed_interface.take())
            {
                handle
                    .release_interface(interface)
                    .map_err(|err| classify_rusb_error("release-interface", err))?;
            }
            self.handle = None;
            self.original_bus = None;
            self.original_address = None;
            Ok(())
        }
    }
}
