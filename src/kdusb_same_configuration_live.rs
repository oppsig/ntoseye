//! Two-stage, one-shot same-configuration live transport primitives.
//!
//! Stage 1 opens without claiming, reapplies the current configuration once,
//! closes, and rediscovers without transmitting bulk data. Stage 2 is a
//! separate process invocation. This module deliberately exposes no reset or
//! alternate-setting operation.

use crate::kdusb_probe::{DeviceSelection, TransportFault};
use std::time::Duration;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LiveIdentity {
    pub selection: DeviceSelection,
    pub bus: u8,
    pub address: u8,
    pub physical_path: String,
}

pub trait SameConfigurationLiveBackend {
    fn reapply_only(&mut self) -> Result<(LiveIdentity, LiveIdentity), TransportFault>;
    fn acquire_exact(&mut self, expected: &LiveIdentity) -> Result<LiveIdentity, TransportFault>;
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

    pub struct RusbSameConfigurationLiveBackend {
        handle: Option<DeviceHandle<GlobalContext>>,
        claimed_interface: Option<u8>,
    }

    impl Default for RusbSameConfigurationLiveBackend {
        fn default() -> Self {
            Self::new()
        }
    }

    impl RusbSameConfigurationLiveBackend {
        pub const fn new() -> Self {
            Self {
                handle: None,
                claimed_interface: None,
            }
        }

        fn physical_path(bus: u8, ports: &[u8]) -> String {
            let suffix = ports
                .iter()
                .map(u8::to_string)
                .collect::<Vec<_>>()
                .join(".");
            format!("{bus}-{suffix}")
        }

        fn identity(candidate: &crate::kdusb_probe::linux::Candidate) -> LiveIdentity {
            let bus = candidate.device.bus_number();
            LiveIdentity {
                selection: candidate.selection.clone(),
                bus,
                address: candidate.device.address(),
                physical_path: Self::physical_path(bus, &candidate.selection.port_path),
            }
        }

        fn admitted(candidate: &crate::kdusb_probe::linux::Candidate) -> bool {
            let identity = Self::identity(candidate);
            let selection = &identity.selection;
            selection.vendor == crate::kdusb_probe::KDUSB_VENDOR_ID
                && selection.product == crate::kdusb_probe::KDUSB_PRODUCT_ID
                && identity.physical_path == "6-1"
                && selection.configuration == 1
                && selection.interface == 0
                && selection.alternate_setting == 0
                && selection.bulk_out == 0x01
                && selection.bulk_in == 0x81
                && selection.transfer_type == "bulk"
                && selection.max_packet > 0
        }

        fn unique(
            expected: Option<&LiveIdentity>,
        ) -> Result<crate::kdusb_probe::linux::Candidate, TransportFault> {
            let expected_ports = expected.map(|value| value.selection.port_path.as_slice());
            let mut candidates = RusbProbeBackend::candidates(expected_ports)?;
            candidates.retain(Self::admitted);
            if let Some(expected) = expected {
                candidates.retain(|candidate| Self::identity(candidate) == *expected);
            }
            match candidates.len() {
                0 => Err(TransportFault::recovery(
                    "descriptor-identity",
                    "no exact KDUSB identity found",
                )),
                1 => Ok(candidates.pop().expect("length checked")),
                count => Err(TransportFault::recovery(
                    "descriptor-identity",
                    format!("{count} candidates found; refusing ambiguous operation"),
                )),
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
                Err(error) => Err(classify_rusb_error("kernel-driver-check", error)),
            }
        }
    }

    impl SameConfigurationLiveBackend for RusbSameConfigurationLiveBackend {
        fn reapply_only(&mut self) -> Result<(LiveIdentity, LiveIdentity), TransportFault> {
            let before_candidate = Self::unique(None)?;
            before_candidate.selection.validate()?;
            let before = Self::identity(&before_candidate);
            let handle = before_candidate
                .device
                .open()
                .map_err(|error| classify_rusb_error("stage1-open-unclaimed", error))?;
            Self::ensure_no_kernel_driver(&handle, before.selection.interface)?;
            let active = handle
                .active_configuration()
                .map_err(|error| classify_rusb_error("stage1-get-active-configuration", error))?;
            if active != before.selection.configuration {
                return Err(TransportFault::recovery(
                    "stage1-active-configuration",
                    "active and descriptor configuration differ",
                ));
            }
            // The sole endpoint-recreation attempt. No interface is claimed.
            handle
                .set_active_configuration(active)
                .map_err(|error| classify_rusb_error("stage1-same-configuration-reapply", error))?;
            drop(handle);
            let after_candidate = Self::unique(Some(&before))?;
            let after = Self::identity(&after_candidate);
            Ok((before, after))
        }

        fn acquire_exact(
            &mut self,
            expected: &LiveIdentity,
        ) -> Result<LiveIdentity, TransportFault> {
            let candidate = Self::unique(Some(expected))?;
            let actual = Self::identity(&candidate);
            let handle = candidate
                .device
                .open()
                .map_err(|error| classify_rusb_error("stage2-open", error))?;
            Self::ensure_no_kernel_driver(&handle, expected.selection.interface)?;
            handle
                .claim_interface(expected.selection.interface)
                .map_err(|error| classify_rusb_error("stage2-claim-interface", error))?;
            self.claimed_interface = Some(expected.selection.interface);
            self.handle = Some(handle);
            Ok(actual)
        }

        fn write_name(
            &mut self,
            endpoint: u8,
            payload: &[u8],
            timeout: Duration,
        ) -> Result<usize, TransportFault> {
            self.handle
                .as_ref()
                .ok_or_else(|| TransportFault::recovery("stage2-name-write", "no claimed handle"))?
                .write_bulk(endpoint, payload, timeout)
                .map_err(|error| classify_rusb_error("stage2-name-write", error))
        }

        fn read_name(
            &mut self,
            endpoint: u8,
            response: &mut [u8],
            timeout: Duration,
        ) -> Result<usize, TransportFault> {
            self.handle
                .as_ref()
                .ok_or_else(|| TransportFault::recovery("stage2-name-read", "no claimed handle"))?
                .read_bulk(endpoint, response, timeout)
                .map_err(|error| classify_rusb_error("stage2-name-read", error))
        }

        fn release(&mut self) -> Result<(), TransportFault> {
            if let (Some(handle), Some(interface)) =
                (self.handle.as_ref(), self.claimed_interface.take())
            {
                handle
                    .release_interface(interface)
                    .map_err(|error| classify_rusb_error("stage2-release-interface", error))?;
            }
            self.handle = None;
            Ok(())
        }
    }
}
