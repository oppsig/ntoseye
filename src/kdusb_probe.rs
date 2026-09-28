//! Bounded classic-KDUSB NAME discovery and transport-fault recovery policy.
//!
//! The default policy is intentionally one-shot: one exact `NAME?` bulk OUT,
//! bounded bulk-IN reads, and no recovery. State-changing recovery is exposed
//! separately and stops before a second NAME bootstrap.

use std::fmt;
use std::time::Duration;

pub const KDUSB_VENDOR_ID: u16 = 0x3495;
pub const KDUSB_PRODUCT_ID: u16 = 0x00e0;
pub const KDUSB_HARDWARE_IDS: &[(u16, u16)] = &[
    (0x3495, 0x00e0),
    (0x0525, 0x127a),
    (0x046b, 0x0980),
    (0x045e, 0x062d),
];
pub const INTERFACE_CLASS: u8 = 0xdc;
pub const INTERFACE_SUBCLASS: u8 = 0x02;
pub const INTERFACE_PROTOCOL: u8 = 0xff;
pub const NAME_PROBE: &[u8; 5] = b"NAME?";
pub const NAME_PREFIX: &[u8; 5] = b"NAME=";
pub const NAME_RESPONSE_MAX: usize = 37;
pub const TARGET_NAME_MAX: usize = 24;
pub const USB_READ_REQUEST: usize = 0x0fb0;
pub const TRANSFER_TIMEOUT: Duration = Duration::from_secs(1);
pub const MAX_DISCOVERY_READS: usize = 4;
pub const MAX_NAME_TX: usize = 1;
pub const MAX_RECOVERY_ATTEMPTS: usize = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransportFaultKind {
    Timeout,
    Stall,
    NoDevice,
    Access,
    /// libusb's Linux usbfs backend collapsed the kernel errno into
    /// LIBUSB_ERROR_IO. This includes the observed kernel -EPROTO, but rusb
    /// cannot recover the underlying errno.
    LinuxUsbfsIo,
    /// A backend/test seam that retains a raw Linux EPROTO classification.
    LinuxEproto,
    GenericIo,
    RecoveryFailure,
}

impl TransportFaultKind {
    pub const fn marker(self) -> &'static str {
        match self {
            Self::Timeout => "TIMEOUT",
            Self::Stall => "STALL",
            Self::NoDevice => "NO_DEVICE",
            Self::Access => "ACCESS",
            Self::LinuxUsbfsIo => "LINUX_USBFS_IO_EPROTO_POSSIBLE",
            Self::LinuxEproto => "LINUX_EPROTO",
            Self::GenericIo => "GENERIC_IO",
            Self::RecoveryFailure => "RECOVERY_FAILURE",
        }
    }

    const fn permits_reset_recovery(self) -> bool {
        matches!(self, Self::LinuxUsbfsIo | Self::LinuxEproto)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransportFault {
    pub kind: TransportFaultKind,
    pub operation: &'static str,
    pub raw_libusb: Option<i32>,
    pub raw_os_errno: Option<i32>,
    pub detail: String,
}

impl TransportFault {
    pub fn new(
        kind: TransportFaultKind,
        operation: &'static str,
        raw_libusb: Option<i32>,
        raw_os_errno: Option<i32>,
        detail: impl Into<String>,
    ) -> Self {
        Self {
            kind,
            operation,
            raw_libusb,
            raw_os_errno,
            detail: detail.into(),
        }
    }

    pub fn recovery(operation: &'static str, detail: impl Into<String>) -> Self {
        Self::new(
            TransportFaultKind::RecoveryFailure,
            operation,
            None,
            None,
            detail,
        )
    }
}

impl fmt::Display for TransportFault {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "TRANSPORT_FAULT={} OPERATION={} RAW_LIBUSB={} RAW_OS_ERRNO={} DETAIL={}",
            self.kind.marker(),
            self.operation,
            self.raw_libusb
                .map_or_else(|| "unavailable".to_string(), |value| value.to_string()),
            self.raw_os_errno
                .map_or_else(|| "unavailable".to_string(), |value| value.to_string()),
            self.detail
        )
    }
}

impl std::error::Error for TransportFault {}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum RecoveryPolicy {
    #[default]
    None,
    /// Explicitly represented because this does not replace an xHCI endpoint.
    ReopenHandle,
    ResetAndReacquire,
}

impl RecoveryPolicy {
    pub const fn marker(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::ReopenHandle => "reopen-handle-unsupported",
            Self::ResetAndReacquire => "reset-and-reacquire",
        }
    }

    pub fn parse(value: &str) -> Result<Self, String> {
        match value {
            "none" => Ok(Self::None),
            "reopen-handle" => Ok(Self::ReopenHandle),
            "reset-and-reacquire" => Ok(Self::ResetAndReacquire),
            _ => Err(format!(
                "unknown recovery policy '{value}': expected none, reopen-handle, or reset-and-reacquire"
            )),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceSelection {
    pub vendor: u16,
    pub product: u16,
    pub configuration: u8,
    pub interface: u8,
    pub alternate_setting: u8,
    pub bulk_in: u8,
    pub bulk_out: u8,
    pub transfer_type: &'static str,
    pub max_packet: u16,
    pub port_path: Vec<u8>,
}

impl DeviceSelection {
    pub fn validate(&self) -> Result<(), TransportFault> {
        if !KDUSB_HARDWARE_IDS.contains(&(self.vendor, self.product)) {
            return Err(TransportFault::new(
                TransportFaultKind::GenericIo,
                "validate-selection",
                None,
                None,
                format!(
                    "unsupported KDUSB identity {:04x}:{:04x}",
                    self.vendor, self.product
                ),
            ));
        }
        if self.transfer_type != "bulk" || self.bulk_in & 0x80 == 0 || self.bulk_out & 0x80 != 0 {
            return Err(TransportFault::new(
                TransportFaultKind::GenericIo,
                "validate-selection",
                None,
                None,
                "descriptor selection is not one bulk-IN and one bulk-OUT endpoint",
            ));
        }
        if self.max_packet == 0 {
            return Err(TransportFault::new(
                TransportFaultKind::GenericIo,
                "validate-selection",
                None,
                None,
                "bulk-OUT maximum packet size is zero",
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProbeReport {
    pub selection: DeviceSelection,
    pub reply: Vec<u8>,
    pub usb_rx_len: usize,
    pub usb_rx_transfers: usize,
    pub usb_rx_read_calls: usize,
    pub prelude: Vec<u8>,
    pub postlude: Vec<u8>,
    pub target_name: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProbeOutcome {
    Success(ProbeReport),
    /// Recovery finished and a matching interface was reacquired. No second
    /// NAME was transmitted.
    RecoveredAwaitingBootstrap {
        original_fault: TransportFault,
        selection: DeviceSelection,
        recovery_attempts: usize,
    },
}

pub trait ProbeBackend {
    fn acquire(&mut self) -> Result<DeviceSelection, TransportFault>;
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
    fn reset_and_reacquire(
        &mut self,
        expected: &DeviceSelection,
    ) -> Result<DeviceSelection, TransportFault>;
    fn release(&mut self) -> Result<(), TransportFault>;
}

pub fn validate_target_name(target: &str) -> Result<(), String> {
    let valid = !target.is_empty()
        && target.len() <= TARGET_NAME_MAX
        && target.bytes().all(|byte| {
            byte.is_ascii_uppercase() || byte.is_ascii_digit() || matches!(byte, b'-' | b'_')
        });
    if valid {
        Ok(())
    } else {
        Err("target name must be 1..=24 bytes using A-Z, 0-9, '-' or '_'".to_string())
    }
}

pub fn parse_name_response(response: &[u8]) -> Result<&str, String> {
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
    std::str::from_utf8(name).map_err(|err| format!("KDUSB target name is not UTF-8/ASCII: {err}"))
}

fn terminal_with_release<B: ProbeBackend, T>(
    backend: &mut B,
    result: Result<T, TransportFault>,
) -> Result<T, TransportFault> {
    let release = backend.release();
    match (result, release) {
        (Ok(value), Ok(())) => Ok(value),
        (Err(primary), Ok(())) => Err(primary),
        (Ok(_), Err(release)) => Err(release),
        (Err(primary), Err(release)) => Err(TransportFault::recovery(
            "release-after-failure",
            format!("{primary}; additionally {release}"),
        )),
    }
}

pub fn run_probe<B: ProbeBackend>(
    backend: &mut B,
    expected: &str,
    policy: RecoveryPolicy,
) -> Result<ProbeOutcome, TransportFault> {
    validate_target_name(expected).map_err(|detail| {
        TransportFault::new(
            TransportFaultKind::GenericIo,
            "validate-target-name",
            None,
            None,
            detail,
        )
    })?;

    let selection = backend.acquire()?;
    if let Err(fault) = selection.validate() {
        return terminal_with_release(backend, Err(fault));
    }

    let written = match backend.write_name(selection.bulk_out, NAME_PROBE, TRANSFER_TIMEOUT) {
        Ok(written) => written,
        Err(fault) => {
            let recoverable = fault.kind.permits_reset_recovery();
            match policy {
                RecoveryPolicy::None => return terminal_with_release(backend, Err(fault)),
                RecoveryPolicy::ReopenHandle => {
                    return terminal_with_release(
                        backend,
                        Err(TransportFault::recovery(
                            "reopen-handle",
                            "unsupported: closing/reopening a usbfs handle does not replace the xHCI endpoint object",
                        )),
                    );
                }
                RecoveryPolicy::ResetAndReacquire if recoverable => {
                    let reacquired = match backend.reset_and_reacquire(&selection) {
                        Ok(reacquired) => reacquired,
                        Err(recovery) => {
                            return terminal_with_release(
                                backend,
                                Err(TransportFault::recovery(
                                    "reset-and-reacquire",
                                    format!("original fault: {fault}; recovery: {recovery}"),
                                )),
                            );
                        }
                    };
                    if let Err(invalid) = reacquired.validate() {
                        return terminal_with_release(backend, Err(invalid));
                    }
                    return terminal_with_release(
                        backend,
                        Ok(ProbeOutcome::RecoveredAwaitingBootstrap {
                            original_fault: fault,
                            selection: reacquired,
                            recovery_attempts: MAX_RECOVERY_ATTEMPTS,
                        }),
                    );
                }
                RecoveryPolicy::ResetAndReacquire => {
                    return terminal_with_release(backend, Err(fault));
                }
            }
        }
    };
    if written != NAME_PROBE.len() {
        return terminal_with_release(
            backend,
            Err(TransportFault::new(
                TransportFaultKind::GenericIo,
                "name-write",
                None,
                None,
                format!(
                    "short KDUSB NAME? probe: wrote {written} of {} bytes",
                    NAME_PROBE.len()
                ),
            )),
        );
    }

    let logical_len = NAME_PREFIX.len() + expected.len() + 2;
    if logical_len > NAME_RESPONSE_MAX {
        return terminal_with_release(
            backend,
            Err(TransportFault::new(
                TransportFaultKind::GenericIo,
                "name-read",
                None,
                None,
                format!("expected NAME reply length {logical_len} exceeds {NAME_RESPONSE_MAX}"),
            )),
        );
    }
    let mut needle = Vec::with_capacity(logical_len);
    needle.extend_from_slice(NAME_PREFIX);
    needle.extend_from_slice(expected.as_bytes());
    needle.extend_from_slice(&[0, 0]);

    let mut stream = Vec::new();
    let mut transfers = 0usize;
    let mut read_calls = 0usize;
    for _ in 0..MAX_DISCOVERY_READS {
        let mut response = vec![0u8; USB_READ_REQUEST];
        read_calls += 1;
        let received = match backend.read_name(selection.bulk_in, &mut response, TRANSFER_TIMEOUT) {
            Ok(received) => received,
            Err(fault) => return terminal_with_release(backend, Err(fault)),
        };
        if received > response.len() {
            return terminal_with_release(
                backend,
                Err(TransportFault::new(
                    TransportFaultKind::GenericIo,
                    "name-read",
                    None,
                    None,
                    "backend returned more bytes than requested",
                )),
            );
        }
        if received == 0 {
            continue;
        }
        transfers += 1;
        stream.extend_from_slice(&response[..received]);
        if let Some(start) = stream
            .windows(needle.len())
            .position(|window| window == needle.as_slice())
        {
            let end = start + needle.len();
            let reply = stream[start..end].to_vec();
            let target_name = parse_name_response(&reply)
                .map_err(|detail| {
                    TransportFault::new(
                        TransportFaultKind::GenericIo,
                        "parse-name-reply",
                        None,
                        None,
                        detail,
                    )
                })?
                .to_string();
            let report = ProbeReport {
                selection,
                reply,
                usb_rx_len: stream.len(),
                usb_rx_transfers: transfers,
                usb_rx_read_calls: read_calls,
                prelude: stream[..start].to_vec(),
                postlude: stream[end..].to_vec(),
                target_name,
            };
            return terminal_with_release(backend, Ok(ProbeOutcome::Success(report)));
        }
    }

    let prefix_len = stream.len().min(64);
    terminal_with_release(
        backend,
        Err(TransportFault::new(
            TransportFaultKind::GenericIo,
            "name-read",
            None,
            None,
            format!(
                "NAME response not found after {read_calls} reads; RAW_RX_PREFIX_HEX={}",
                hex::encode(&stream[..prefix_len])
            ),
        )),
    )
}

pub fn recovery_plan(policy: RecoveryPolicy) -> Vec<String> {
    let mut lines = vec![
        format!("RECOVERY_POLICY={}", policy.marker()),
        format!("MAX_RECOVERY_ATTEMPTS={MAX_RECOVERY_ATTEMPTS}"),
        format!("MAX_NAME_TX={MAX_NAME_TX}"),
        "AUTOMATIC_NAME_RETRY=false".to_string(),
        "LIVE_USB_OPEN=false".to_string(),
        "LIVE_USB_TX=false".to_string(),
        "REAL_USB_RESET=false".to_string(),
    ];
    match policy {
        RecoveryPolicy::None => {
            lines.push("PLAN_STEP_1=terminate-with-structured-fault".to_string())
        }
        RecoveryPolicy::ReopenHandle => lines.push(
            "PLAN_STEP_1=unsupported-do-not-execute-handle-reopen-does-not-replace-xhci-endpoint"
                .to_string(),
        ),
        RecoveryPolicy::ResetAndReacquire => lines.extend([
            "PLAN_STEP_1=release-claimed-interface".to_string(),
            "PLAN_STEP_2=single-libusb-device-reset".to_string(),
            "PLAN_STEP_3=close-stale-handle".to_string(),
            "PLAN_STEP_4=wait-for-same-usb-port-path".to_string(),
            "PLAN_STEP_5=rediscover-expected-vid-pid".to_string(),
            "PLAN_STEP_6=verify-dc-02-ff-and-bulk-endpoints".to_string(),
            "PLAN_STEP_7=reclaim-interface".to_string(),
            "PLAN_STEP_8=stop-before-post-recovery-name-bootstrap".to_string(),
        ]),
    }
    lines
}

#[cfg(target_os = "linux")]
pub mod linux {
    use super::*;
    use rusb::{Device, DeviceHandle, Direction, GlobalContext, TransferType};
    use std::thread;

    const REDISCOVERY_POLLS: usize = 20;
    const REDISCOVERY_INTERVAL: Duration = Duration::from_millis(250);

    struct Candidate {
        device: Device<GlobalContext>,
        selection: DeviceSelection,
    }

    pub struct RusbProbeBackend {
        handle: Option<DeviceHandle<GlobalContext>>,
        selection: Option<DeviceSelection>,
        claimed_interface: Option<u8>,
    }

    impl Default for RusbProbeBackend {
        fn default() -> Self {
            Self::new()
        }
    }

    impl RusbProbeBackend {
        pub const fn new() -> Self {
            Self {
                handle: None,
                selection: None,
                claimed_interface: None,
            }
        }

        fn candidates(expected_port: Option<&[u8]>) -> Result<Vec<Candidate>, TransportFault> {
            let devices = rusb::devices().map_err(|err| classify_rusb_error("enumerate", err))?;
            let mut candidates = Vec::new();
            for device in devices.iter() {
                let descriptor = match device.device_descriptor() {
                    Ok(descriptor) => descriptor,
                    Err(_) => continue,
                };
                if !KDUSB_HARDWARE_IDS.contains(&(descriptor.vendor_id(), descriptor.product_id()))
                {
                    continue;
                }
                let port_path = match device.port_numbers() {
                    Ok(path) => path,
                    Err(_) => continue,
                };
                if expected_port.is_some_and(|expected| expected != port_path.as_slice()) {
                    continue;
                }
                let config = match device.active_config_descriptor() {
                    Ok(config) => config,
                    Err(_) => continue,
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
                                    bulk_out =
                                        Some((endpoint.address(), endpoint.max_packet_size()));
                                }
                                _ => {}
                            }
                        }
                        if let (Some(bulk_in), Some((bulk_out, max_packet))) = (bulk_in, bulk_out) {
                            candidates.push(Candidate {
                                device: device.clone(),
                                selection: DeviceSelection {
                                    vendor: descriptor.vendor_id(),
                                    product: descriptor.product_id(),
                                    configuration: config.number(),
                                    interface: descriptor_if.interface_number(),
                                    alternate_setting: descriptor_if.setting_number(),
                                    bulk_in,
                                    bulk_out,
                                    transfer_type: "bulk",
                                    max_packet,
                                    port_path: port_path.clone(),
                                },
                            });
                        }
                    }
                }
            }
            Ok(candidates)
        }

        fn open_candidate(
            &mut self,
            candidate: Candidate,
        ) -> Result<DeviceSelection, TransportFault> {
            let handle = candidate
                .device
                .open()
                .map_err(|err| classify_rusb_error("open", err))?;
            let interface = candidate.selection.interface;
            match handle.kernel_driver_active(interface) {
                Ok(true) => {
                    return Err(TransportFault::new(
                        TransportFaultKind::Access,
                        "kernel-driver-check",
                        None,
                        None,
                        format!("interface {interface} has a kernel driver; refusing detach"),
                    ));
                }
                Ok(false) | Err(rusb::Error::NotSupported) => {}
                Err(err) => return Err(classify_rusb_error("kernel-driver-check", err)),
            }
            handle
                .claim_interface(interface)
                .map_err(|err| classify_rusb_error("claim-interface", err))?;
            if candidate.selection.alternate_setting != 0 {
                handle
                    .set_alternate_setting(interface, candidate.selection.alternate_setting)
                    .map_err(|err| classify_rusb_error("set-alternate-setting", err))?;
            }
            self.claimed_interface = Some(interface);
            self.selection = Some(candidate.selection.clone());
            self.handle = Some(handle);
            Ok(candidate.selection)
        }

        fn release_current(&mut self) -> Result<(), TransportFault> {
            let Some(handle) = self.handle.as_ref() else {
                self.claimed_interface = None;
                return Ok(());
            };
            if let Some(interface) = self.claimed_interface.take() {
                handle
                    .release_interface(interface)
                    .map_err(|err| classify_rusb_error("release-interface", err))?;
            }
            Ok(())
        }
    }

    impl ProbeBackend for RusbProbeBackend {
        fn acquire(&mut self) -> Result<DeviceSelection, TransportFault> {
            let mut candidates = Self::candidates(None)?;
            match candidates.len() {
                0 => Err(TransportFault::new(
                    TransportFaultKind::NoDevice,
                    "discover",
                    None,
                    None,
                    "no supported classic KDUSB dc/02/ff interface found",
                )),
                1 => self.open_candidate(candidates.pop().expect("length checked")),
                count => Err(TransportFault::new(
                    TransportFaultKind::GenericIo,
                    "discover",
                    None,
                    None,
                    format!("{count} candidates found; refusing ambiguous NAME probing"),
                )),
            }
        }

        fn write_name(
            &mut self,
            endpoint: u8,
            payload: &[u8],
            timeout: Duration,
        ) -> Result<usize, TransportFault> {
            self.handle
                .as_ref()
                .ok_or_else(|| TransportFault::recovery("name-write", "no acquired handle"))?
                .write_bulk(endpoint, payload, timeout)
                .map_err(|err| classify_rusb_error("name-write", err))
        }

        fn read_name(
            &mut self,
            endpoint: u8,
            response: &mut [u8],
            timeout: Duration,
        ) -> Result<usize, TransportFault> {
            self.handle
                .as_ref()
                .ok_or_else(|| TransportFault::recovery("name-read", "no acquired handle"))?
                .read_bulk(endpoint, response, timeout)
                .map_err(|err| classify_rusb_error("name-read", err))
        }

        fn reset_and_reacquire(
            &mut self,
            expected: &DeviceSelection,
        ) -> Result<DeviceSelection, TransportFault> {
            self.release_current()?;
            let handle = self
                .handle
                .take()
                .ok_or_else(|| TransportFault::recovery("device-reset", "no acquired handle"))?;
            match handle.reset() {
                Ok(()) | Err(rusb::Error::NotFound) | Err(rusb::Error::NoDevice) => {}
                Err(err) => return Err(classify_rusb_error("device-reset", err)),
            }
            drop(handle);
            self.selection = None;

            for _ in 0..REDISCOVERY_POLLS {
                let mut matches = Self::candidates(Some(&expected.port_path))?
                    .into_iter()
                    .filter(|candidate| {
                        candidate.selection.vendor == expected.vendor
                            && candidate.selection.product == expected.product
                    })
                    .collect::<Vec<_>>();
                match matches.len() {
                    1 => return self.open_candidate(matches.pop().expect("length checked")),
                    0 => thread::sleep(REDISCOVERY_INTERVAL),
                    count => {
                        return Err(TransportFault::recovery(
                            "rediscover",
                            format!("{count} matching interfaces appeared on the same port path"),
                        ));
                    }
                }
            }
            Err(TransportFault::recovery(
                "rediscover",
                format!(
                    "{:04x}:{:04x} did not reappear on port path {:?} within {} ms",
                    expected.vendor,
                    expected.product,
                    expected.port_path,
                    REDISCOVERY_POLLS * REDISCOVERY_INTERVAL.as_millis() as usize
                ),
            ))
        }

        fn release(&mut self) -> Result<(), TransportFault> {
            self.release_current()?;
            self.handle = None;
            self.selection = None;
            Ok(())
        }
    }

    pub fn classify_rusb_error(operation: &'static str, err: rusb::Error) -> TransportFault {
        let (kind, raw) = match err {
            rusb::Error::Timeout => (TransportFaultKind::Timeout, -7),
            rusb::Error::Pipe => (TransportFaultKind::Stall, -9),
            rusb::Error::NoDevice => (TransportFaultKind::NoDevice, -4),
            rusb::Error::Access => (TransportFaultKind::Access, -3),
            rusb::Error::Io => (TransportFaultKind::LinuxUsbfsIo, -1),
            rusb::Error::InvalidParam => (TransportFaultKind::GenericIo, -2),
            rusb::Error::NotFound => (TransportFaultKind::GenericIo, -5),
            rusb::Error::Busy => (TransportFaultKind::GenericIo, -6),
            rusb::Error::Overflow => (TransportFaultKind::GenericIo, -8),
            rusb::Error::Interrupted => (TransportFaultKind::GenericIo, -10),
            rusb::Error::NoMem => (TransportFaultKind::GenericIo, -11),
            rusb::Error::NotSupported => (TransportFaultKind::GenericIo, -12),
            rusb::Error::BadDescriptor | rusb::Error::Other => (TransportFaultKind::GenericIo, -99),
        };
        TransportFault::new(
            kind,
            operation,
            Some(raw),
            None,
            format!("{err}; rusb/libusb does not expose the underlying Linux usbfs errno"),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;

    #[derive(Default)]
    struct MockBackend {
        writes: Vec<(u8, Vec<u8>, Duration)>,
        reads: VecDeque<Result<Vec<u8>, TransportFault>>,
        recoveries: usize,
        releases: usize,
        events: Vec<&'static str>,
        write_fault: Option<TransportFault>,
        recovery_fault: Option<TransportFault>,
    }

    fn selection() -> DeviceSelection {
        DeviceSelection {
            vendor: KDUSB_VENDOR_ID,
            product: KDUSB_PRODUCT_ID,
            configuration: 1,
            interface: 0,
            alternate_setting: 0,
            bulk_in: 0x81,
            bulk_out: 0x01,
            transfer_type: "bulk",
            max_packet: 1024,
            port_path: vec![1],
        }
    }

    fn fault(kind: TransportFaultKind) -> TransportFault {
        TransportFault::new(kind, "name-write", Some(-1), Some(71), "mock")
    }

    impl ProbeBackend for MockBackend {
        fn acquire(&mut self) -> Result<DeviceSelection, TransportFault> {
            self.events.push("acquire");
            Ok(selection())
        }

        fn write_name(
            &mut self,
            endpoint: u8,
            payload: &[u8],
            timeout: Duration,
        ) -> Result<usize, TransportFault> {
            self.events.push("write-name");
            self.writes.push((endpoint, payload.to_vec(), timeout));
            if let Some(fault) = self.write_fault.take() {
                Err(fault)
            } else {
                Ok(payload.len())
            }
        }

        fn read_name(
            &mut self,
            endpoint: u8,
            response: &mut [u8],
            timeout: Duration,
        ) -> Result<usize, TransportFault> {
            self.events.push("read-name");
            assert_eq!(endpoint, 0x81);
            assert_eq!(response.len(), USB_READ_REQUEST);
            assert_eq!(timeout, TRANSFER_TIMEOUT);
            match self.reads.pop_front().expect("mock read") {
                Ok(bytes) => {
                    response[..bytes.len()].copy_from_slice(&bytes);
                    Ok(bytes.len())
                }
                Err(fault) => Err(fault),
            }
        }

        fn reset_and_reacquire(
            &mut self,
            _expected: &DeviceSelection,
        ) -> Result<DeviceSelection, TransportFault> {
            self.events.push("reset-and-reacquire");
            self.recoveries += 1;
            if let Some(fault) = self.recovery_fault.take() {
                Err(fault)
            } else {
                self.events.push("reacquired");
                Ok(selection())
            }
        }

        fn release(&mut self) -> Result<(), TransportFault> {
            self.events.push("release");
            self.releases += 1;
            Ok(())
        }
    }

    #[test]
    fn defaults_and_first_transfer_match_recovered_contract() {
        assert_eq!(RecoveryPolicy::default(), RecoveryPolicy::None);
        let mut backend = MockBackend::default();
        backend
            .reads
            .push_back(Ok(b"NAME=CLSA0102_USB\0\0".to_vec()));
        let result = run_probe(&mut backend, "CLSA0102_USB", RecoveryPolicy::None).unwrap();
        assert!(matches!(result, ProbeOutcome::Success(_)));
        assert_eq!(
            backend.writes,
            vec![(0x01, b"NAME?".to_vec(), Duration::from_secs(1))]
        );
        assert_eq!(backend.recoveries, 0);
        assert_eq!(backend.releases, 1);
        let selected = selection();
        assert_eq!(selected.configuration, 1);
        assert_eq!(selected.interface, 0);
        assert_eq!(selected.alternate_setting, 0);
        assert_eq!(selected.transfer_type, "bulk");
        assert_eq!(selected.max_packet, 1024);
        assert_eq!(
            (INTERFACE_CLASS, INTERFACE_SUBCLASS, INTERFACE_PROTOCOL),
            (0xdc, 0x02, 0xff)
        );
    }

    #[test]
    fn name_eproto_none_is_terminal_and_never_resubmits() {
        let mut backend = MockBackend {
            write_fault: Some(fault(TransportFaultKind::LinuxEproto)),
            ..MockBackend::default()
        };
        let error = run_probe(&mut backend, "CLSA0102_USB", RecoveryPolicy::None).unwrap_err();
        assert_eq!(error.kind, TransportFaultKind::LinuxEproto);
        assert_eq!(backend.writes.len(), 1);
        assert_eq!(backend.recoveries, 0);
    }

    #[test]
    fn name_eproto_reset_policy_performs_exactly_one_recovery_and_no_retry() {
        let mut backend = MockBackend {
            write_fault: Some(fault(TransportFaultKind::LinuxEproto)),
            ..MockBackend::default()
        };
        let outcome = run_probe(
            &mut backend,
            "CLSA0102_USB",
            RecoveryPolicy::ResetAndReacquire,
        )
        .unwrap();
        assert!(matches!(
            outcome,
            ProbeOutcome::RecoveredAwaitingBootstrap {
                recovery_attempts: 1,
                ..
            }
        ));
        assert_eq!(backend.writes.len(), 1);
        assert_eq!(backend.recoveries, 1);
        assert_eq!(
            backend.events,
            [
                "acquire",
                "write-name",
                "reset-and-reacquire",
                "reacquired",
                "release"
            ]
        );
    }

    #[test]
    fn recovery_failure_is_terminal_without_loop() {
        let mut backend = MockBackend {
            write_fault: Some(fault(TransportFaultKind::LinuxEproto)),
            recovery_fault: Some(TransportFault::recovery("device-reset", "failed")),
            ..MockBackend::default()
        };
        let error = run_probe(
            &mut backend,
            "CLSA0102_USB",
            RecoveryPolicy::ResetAndReacquire,
        )
        .unwrap_err();
        assert_eq!(error.kind, TransportFaultKind::RecoveryFailure);
        assert_eq!(backend.writes.len(), 1);
        assert_eq!(backend.recoveries, MAX_RECOVERY_ATTEMPTS);
    }

    #[test]
    fn timeout_and_disconnect_do_not_take_eproto_recovery_path() {
        for kind in [TransportFaultKind::Timeout, TransportFaultKind::NoDevice] {
            let mut backend = MockBackend {
                write_fault: Some(fault(kind)),
                ..MockBackend::default()
            };
            let error = run_probe(
                &mut backend,
                "CLSA0102_USB",
                RecoveryPolicy::ResetAndReacquire,
            )
            .unwrap_err();
            assert_eq!(error.kind, kind);
            assert_eq!(backend.recoveries, 0);
            assert_eq!(backend.writes.len(), 1);
        }
    }

    #[test]
    fn queued_bytes_are_preserved_around_name_reply() {
        let mut payload = b"queued".to_vec();
        payload.extend_from_slice(b"NAME=CLSA0102_USB\0\0tail");
        let mut backend = MockBackend::default();
        backend.reads.push_back(Ok(payload));
        let ProbeOutcome::Success(report) =
            run_probe(&mut backend, "CLSA0102_USB", RecoveryPolicy::None).unwrap()
        else {
            panic!("expected success");
        };
        assert_eq!(report.prelude, b"queued");
        assert_eq!(report.postlude, b"tail");
    }

    #[test]
    fn dry_plan_is_non_live_and_stops_before_second_name() {
        let plan = recovery_plan(RecoveryPolicy::ResetAndReacquire).join("\n");
        assert!(plan.contains("MAX_RECOVERY_ATTEMPTS=1"));
        assert!(plan.contains("MAX_NAME_TX=1"));
        assert!(plan.contains("LIVE_USB_OPEN=false"));
        assert!(plan.contains("LIVE_USB_TX=false"));
        assert!(plan.contains("REAL_USB_RESET=false"));
        assert!(plan.contains("stop-before-post-recovery-name-bootstrap"));
    }

    #[test]
    fn reopen_policy_is_explicitly_rejected() {
        let mut backend = MockBackend {
            write_fault: Some(fault(TransportFaultKind::LinuxEproto)),
            ..MockBackend::default()
        };
        let error =
            run_probe(&mut backend, "CLSA0102_USB", RecoveryPolicy::ReopenHandle).unwrap_err();
        assert_eq!(error.kind, TransportFaultKind::RecoveryFailure);
        assert_eq!(backend.recoveries, 0);
        assert_eq!(backend.writes.len(), 1);
    }
}
