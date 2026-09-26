//! Classic KDUSB transport constants and wire-contract helpers.
//!
//! These helpers are intentionally pure: no USB device is opened or claimed.
//! They encode the transport contract recovered from Windows USB2DBG host
//! driver and the matching target-side KDUSB transport.

use std::io;

use super::framing::{CONTROL_PACKET_LEADER, DATA_PACKET_LEADER, Header, PACKET_MAX_SIZE};

pub(crate) const KDUSB_VENDOR_ID: u16 = 0x3495;
pub(crate) const KDUSB_PRODUCT_ID: u16 = 0x00e0;
pub(crate) const KDUSB_HARDWARE_IDS: &[(u16, u16)] = &[
    (0x3495, 0x00e0),
    (0x0525, 0x127a),
    (0x046b, 0x0980),
    (0x045e, 0x062d),
];

pub(crate) const KDUSB_INTERFACE_CLASS: u8 = 0xdc;
pub(crate) const KDUSB_INTERFACE_SUBCLASS: u8 = 0x02;
pub(crate) const KDUSB_INTERFACE_PROTOCOL: u8 = 0xff;

pub(crate) const NAME_PROBE: &[u8; 5] = b"NAME?";
pub(crate) const NAME_RESPONSE_PREFIX: &[u8; 5] = b"NAME=";
pub(crate) const NAME_RESPONSE_MIN: usize = 5;
pub(crate) const NAME_RESPONSE_MAX: usize = 37;
pub(crate) const TARGET_NAME_MAX: usize = 24;

pub(crate) const USB_READ_REQUEST: usize = 0x0fb0;
pub(crate) const USB3_WRITE_CHUNK: usize = 0x1000;

#[derive(Debug, Clone, PartialEq, Eq)]
enum BootstrapTransfer {
    NameMatch { consumed: usize },
    NameMismatch { actual: String },
    KdPrefetch,
}

/// Classify the first non-empty bulk-IN transfer after NAME?.
///
/// A live target can already have a KD packet queued when userspace claims the
/// interface. In that case the transfer is not a failed NAME handshake: it is
/// debugger traffic that must be preserved for KdFraming instead of discarded.
fn classify_bootstrap_transfer(response: &[u8], expected: &str) -> io::Result<BootstrapTransfer> {
    if response.starts_with(NAME_RESPONSE_PREFIX) {
        let limit = response.len().min(NAME_RESPONSE_MAX);
        let suffix = &response[NAME_RESPONSE_PREFIX.len()..limit];
        let nul = suffix.iter().position(|&byte| byte == 0).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "KDUSB NAME response is not NUL terminated within the recovered maximum",
            )
        })?;

        let logical_end = NAME_RESPONSE_PREFIX.len() + nul + 1;
        let actual = parse_name_response(&response[..logical_end])?.to_string();

        // The recovered target emits a second zero byte. The Windows parser
        // only requires the first terminator, so consume the second when it is
        // present and preserve anything after it as debugger stream data.
        let consumed = if response.get(logical_end) == Some(&0) {
            logical_end + 1
        } else {
            logical_end
        };

        return Ok(if actual == expected {
            BootstrapTransfer::NameMatch { consumed }
        } else {
            BootstrapTransfer::NameMismatch { actual }
        });
    }

    let Some(header) = Header::peek(response) else {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "KDUSB bootstrap transfer is neither NAME= nor a complete KD header ({} bytes)",
                response.len()
            ),
        ));
    };

    let plausible = match header.leader {
        DATA_PACKET_LEADER => {
            (1..=11).contains(&header.packet_type)
                && usize::from(header.byte_count) <= PACKET_MAX_SIZE
        }
        CONTROL_PACKET_LEADER => {
            matches!(header.packet_type, 4..=6) && header.byte_count == 0 && header.checksum == 0
        }
        _ => false,
    };

    if plausible {
        Ok(BootstrapTransfer::KdPrefetch)
    } else {
        Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "KDUSB bootstrap transfer is neither NAME= nor plausible KD framing (leader={:#010x}, type={}, byte_count={})",
                header.leader, header.packet_type, header.byte_count
            ),
        ))
    }
}

/// Parse the USB2DBG bootstrap reply and return its target name.
///
/// The Windows host accepts 5..=37 bytes, requires NAME=, and passes the
/// suffix to RtlInitAnsiString, so a NUL terminator must be present. The
/// target implementation sends two trailing zero bytes; only the first is
/// semantically required by the host parser.
pub(crate) fn parse_name_response(response: &[u8]) -> io::Result<&str> {
    if !(NAME_RESPONSE_MIN..=NAME_RESPONSE_MAX).contains(&response.len()) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "KDUSB NAME response has invalid length {} (expected {}..={})",
                response.len(),
                NAME_RESPONSE_MIN,
                NAME_RESPONSE_MAX
            ),
        ));
    }
    if !response.starts_with(NAME_RESPONSE_PREFIX) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "KDUSB NAME response is missing NAME= prefix",
        ));
    }

    let suffix = &response[NAME_RESPONSE_PREFIX.len()..];
    let nul = suffix.iter().position(|&byte| byte == 0).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "KDUSB NAME response is not NUL terminated",
        )
    })?;
    let name = &suffix[..nul];
    if name.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "KDUSB target name is empty",
        ));
    }
    if name.len() > TARGET_NAME_MAX {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "KDUSB target name is {} bytes (maximum {})",
                name.len(),
                TARGET_NAME_MAX
            ),
        ));
    }
    std::str::from_utf8(name).map_err(|err| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("KDUSB target name is not UTF-8/ASCII: {err}"),
        )
    })
}

/// Validate a NAME reply against the target name requested by the operator.
pub(crate) fn name_response_matches(response: &[u8], expected: &str) -> io::Result<bool> {
    Ok(parse_name_response(response)? == expected)
}

/// USB3 OUT transfer lengths for one logical byte-stream write.
///
/// Windows USB2DBG limits USB3 body URBs to 4096 bytes. If a non-empty logical
/// write ends exactly on the endpoint maximum packet size, it submits an
/// additional zero-length transfer (ZLP).
pub(crate) fn usb3_write_plan(len: usize, max_packet: usize) -> io::Result<Vec<usize>> {
    if max_packet == 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "KDUSB max packet size cannot be zero",
        ));
    }

    let mut remaining = len;
    let mut chunks = Vec::new();
    while remaining != 0 {
        let chunk = remaining.min(USB3_WRITE_CHUNK);
        chunks.push(chunk);
        remaining -= chunk;
    }
    if len != 0 && len % max_packet == 0 {
        chunks.push(0);
    }
    Ok(chunks)
}

pub(crate) trait BulkIo: Send + Sync {
    fn read_bulk(
        &self,
        endpoint: u8,
        buf: &mut [u8],
        timeout: std::time::Duration,
    ) -> io::Result<usize>;

    fn write_bulk(
        &self,
        endpoint: u8,
        buf: &[u8],
        timeout: std::time::Duration,
    ) -> io::Result<usize>;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct BulkEndpoints {
    pub(crate) input: u8,
    pub(crate) output: u8,
    pub(crate) max_packet: usize,
}

/// Byte-stream adapter between KD framing and a bulk-I/O implementation.
///
/// Reads always request the recovered 4016-byte USB receive quantum and buffer
/// surplus bytes so tiny std::io::Read calls cannot truncate a USB transfer.
///
/// Writes accumulate until flush. This is important because KdFraming writes a
/// data packet as header, payload and trailer calls followed by one flush; the
/// USB2DBG write/ZLP rule applies to that complete logical write.
pub(crate) struct KdUsbStreamCore<I: BulkIo> {
    io: std::sync::Arc<I>,
    endpoints: BulkEndpoints,
    read_timeout: Option<std::time::Duration>,
    write_timeout: std::time::Duration,
    rx: std::collections::VecDeque<u8>,
    tx: Vec<u8>,
    write_lock: std::sync::Arc<std::sync::Mutex<()>>,
}

impl<I: BulkIo> KdUsbStreamCore<I> {
    pub(crate) fn new(io: I, endpoints: BulkEndpoints) -> io::Result<Self> {
        Self::new_with_rx(io, endpoints, Vec::<u8>::new())
    }

    fn new_with_rx(
        io: I,
        endpoints: BulkEndpoints,
        prefetched: impl IntoIterator<Item = u8>,
    ) -> io::Result<Self> {
        if endpoints.input & 0x80 == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "KDUSB bulk-IN endpoint has OUT direction",
            ));
        }
        if endpoints.output & 0x80 != 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "KDUSB bulk-OUT endpoint has IN direction",
            ));
        }
        if endpoints.max_packet == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "KDUSB max packet size cannot be zero",
            ));
        }

        Ok(Self {
            io: std::sync::Arc::new(io),
            endpoints,
            read_timeout: None,
            write_timeout: std::time::Duration::from_secs(1),
            rx: prefetched.into_iter().collect(),
            tx: Vec::new(),
            write_lock: std::sync::Arc::new(std::sync::Mutex::new(())),
        })
    }

    pub(crate) fn try_clone(&self) -> io::Result<Self> {
        Ok(Self {
            io: self.io.clone(),
            endpoints: self.endpoints,
            read_timeout: self.read_timeout,
            write_timeout: self.write_timeout,
            rx: std::collections::VecDeque::new(),
            tx: Vec::new(),
            write_lock: self.write_lock.clone(),
        })
    }

    pub(crate) fn set_read_timeout(&mut self, timeout: Option<std::time::Duration>) {
        self.read_timeout = timeout;
    }

    pub(crate) fn set_write_timeout(&mut self, timeout: std::time::Duration) {
        self.write_timeout = timeout;
    }

    fn libusb_timeout(timeout: Option<std::time::Duration>) -> std::time::Duration {
        // libusb interprets zero as an infinite timeout.
        timeout.unwrap_or(std::time::Duration::ZERO)
    }

    fn drain_rx(&mut self, output: &mut [u8]) -> usize {
        let count = output.len().min(self.rx.len());
        for byte in output.iter_mut().take(count) {
            *byte = self.rx.pop_front().expect("count bounded by rx length");
        }
        count
    }
}

impl<I: BulkIo> std::io::Read for KdUsbStreamCore<I> {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        if output.is_empty() {
            return Ok(0);
        }

        let buffered = self.drain_rx(output);
        if buffered != 0 {
            return Ok(buffered);
        }

        let mut transfer = vec![0u8; USB_READ_REQUEST];
        loop {
            let count = self.io.read_bulk(
                self.endpoints.input,
                &mut transfer,
                Self::libusb_timeout(self.read_timeout),
            )?;
            if count == 0 {
                // A USB ZLP is not an EOF on the debugger byte stream.
                continue;
            }
            if count > transfer.len() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "KDUSB bulk read returned more bytes than requested",
                ));
            }

            let direct = output.len().min(count);
            output[..direct].copy_from_slice(&transfer[..direct]);
            self.rx.extend(&transfer[direct..count]);
            return Ok(direct);
        }
    }
}

impl<I: BulkIo> std::io::Write for KdUsbStreamCore<I> {
    fn write(&mut self, input: &[u8]) -> io::Result<usize> {
        self.tx.extend_from_slice(input);
        Ok(input.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        if self.tx.is_empty() {
            return Ok(());
        }

        let logical = std::mem::take(&mut self.tx);
        let plan = usb3_write_plan(logical.len(), self.endpoints.max_packet)?;
        let _guard = self
            .write_lock
            .lock()
            .map_err(|_| io::Error::other("KDUSB write lock poisoned"))?;

        let mut offset = 0usize;
        for count in plan {
            let end = offset + count;
            let chunk = &logical[offset..end];
            let written = self
                .io
                .write_bulk(self.endpoints.output, chunk, self.write_timeout)?;
            if written != count {
                return Err(io::Error::new(
                    io::ErrorKind::WriteZero,
                    format!("KDUSB bulk write accepted {written} of {count} bytes"),
                ));
            }
            offset = end;
        }
        debug_assert_eq!(offset, logical.len());
        Ok(())
    }
}

#[cfg(target_os = "linux")]
mod linux {
    use super::*;
    use rusb::{Device, DeviceHandle, Direction, GlobalContext, TransferType};
    use std::time::Duration;

    const DISCOVERY_TIMEOUT: Duration = Duration::from_secs(1);

    pub struct KdUsbStream {
        inner: KdUsbStreamCore<RusbBulkIo>,
    }

    struct RusbBulkIo {
        handle: DeviceHandle<GlobalContext>,
    }

    impl BulkIo for RusbBulkIo {
        fn read_bulk(&self, endpoint: u8, buf: &mut [u8], timeout: Duration) -> io::Result<usize> {
            self.handle
                .read_bulk(endpoint, buf, timeout)
                .map_err(|err| usb_error("KDUSB bulk read", err))
        }

        fn write_bulk(&self, endpoint: u8, buf: &[u8], timeout: Duration) -> io::Result<usize> {
            self.handle
                .write_bulk(endpoint, buf, timeout)
                .map_err(|err| usb_error("KDUSB bulk write", err))
        }
    }

    impl KdUsbStream {
        pub(crate) fn connect(target_name: &str) -> io::Result<Self> {
            validate_requested_target_name(target_name)?;
            let (io, endpoints, prefetched) = open_named_device(target_name)?;
            Ok(Self {
                inner: KdUsbStreamCore::new_with_rx(io, endpoints, prefetched)?,
            })
        }

        pub(crate) fn try_clone(&self) -> io::Result<Self> {
            Ok(Self {
                inner: self.inner.try_clone()?,
            })
        }

        pub(crate) fn set_read_timeout(&mut self, timeout: Option<Duration>) {
            self.inner.set_read_timeout(timeout);
        }
    }

    impl std::io::Read for KdUsbStream {
        fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
            self.inner.read(output)
        }
    }

    impl std::io::Write for KdUsbStream {
        fn write(&mut self, input: &[u8]) -> io::Result<usize> {
            self.inner.write(input)
        }

        fn flush(&mut self) -> io::Result<()> {
            self.inner.flush()
        }
    }

    fn validate_requested_target_name(target_name: &str) -> io::Result<()> {
        let valid = !target_name.is_empty()
            && target_name.len() <= TARGET_NAME_MAX
            && target_name
                .bytes()
                .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit() || matches!(b, b'-' | b'_'));

        if valid {
            Ok(())
        } else {
            Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "KDUSB target name must be 1..=24 bytes using A-Z, 0-9, '-' or '_'",
            ))
        }
    }

    fn is_known_hardware_id(vendor: u16, product: u16) -> bool {
        KDUSB_HARDWARE_IDS.contains(&(vendor, product))
    }

    enum ProbeOutcome {
        Named { io: RusbBulkIo, prefetched: Vec<u8> },
        KdPrefetch { io: RusbBulkIo, prefetched: Vec<u8> },
    }

    fn open_named_device(target_name: &str) -> io::Result<(RusbBulkIo, BulkEndpoints, Vec<u8>)> {
        let devices = rusb::devices().map_err(|err| usb_error("enumerating USB devices", err))?;
        let mut saw_interface = false;
        let mut last_error = None;
        let mut kd_fallback = None;
        let mut kd_fallback_count = 0usize;

        for device in devices.iter() {
            let descriptor = match device.device_descriptor() {
                Ok(descriptor) => descriptor,
                Err(err) => {
                    last_error = Some(usb_error("reading USB device descriptor", err));
                    continue;
                }
            };

            if !is_known_hardware_id(descriptor.vendor_id(), descriptor.product_id()) {
                continue;
            }

            let config = match device.active_config_descriptor() {
                Ok(config) => config,
                Err(err) => {
                    last_error = Some(usb_error("reading active USB configuration", err));
                    continue;
                }
            };

            for interface in config.interfaces() {
                for descriptor in interface.descriptors() {
                    if descriptor.class_code() != KDUSB_INTERFACE_CLASS
                        || descriptor.sub_class_code() != KDUSB_INTERFACE_SUBCLASS
                        || descriptor.protocol_code() != KDUSB_INTERFACE_PROTOCOL
                    {
                        continue;
                    }

                    let mut input = None;
                    let mut output = None;

                    for endpoint in descriptor.endpoint_descriptors() {
                        if endpoint.transfer_type() != TransferType::Bulk {
                            continue;
                        }
                        match endpoint.direction() {
                            Direction::In if input.is_none() => {
                                input = Some(endpoint.address());
                            }
                            Direction::Out if output.is_none() => {
                                output = Some((
                                    endpoint.address(),
                                    usize::from(endpoint.max_packet_size()),
                                ));
                            }
                            _ => {}
                        }
                    }

                    let (Some(input), Some((output, max_packet))) = (input, output) else {
                        continue;
                    };

                    saw_interface = true;
                    let endpoints = BulkEndpoints {
                        input,
                        output,
                        max_packet,
                    };

                    match open_and_probe(
                        &device,
                        descriptor.interface_number(),
                        descriptor.setting_number(),
                        endpoints,
                        target_name,
                    ) {
                        Ok(Some(ProbeOutcome::Named { io, prefetched })) => {
                            return Ok((io, endpoints, prefetched));
                        }
                        Ok(Some(ProbeOutcome::KdPrefetch { io, prefetched })) => {
                            kd_fallback_count += 1;
                            if kd_fallback.is_none() {
                                kd_fallback = Some((io, endpoints, prefetched));
                            }
                        }
                        Ok(None) => {}
                        Err(err) => last_error = Some(err),
                    }
                }
            }
        }

        // A live Windows target may already be transmitting KD before it can
        // answer the out-of-band NAME? query. If exactly one supported KDUSB
        // interface proves itself by emitting plausible KD framing, select it
        // and replay those bytes into KdFraming. Never guess when more than one
        // such device exists because the requested target name is then
        // ambiguous.
        if kd_fallback_count == 1 {
            return Ok(kd_fallback.expect("single KD fallback must be retained"));
        }
        if kd_fallback_count > 1 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "{kd_fallback_count} active classic KDUSB devices emitted KD traffic before NAME=; target '{target_name}' is ambiguous"
                ),
            ));
        }

        if let Some(err) = last_error {
            return Err(err);
        }

        Err(io::Error::new(
            io::ErrorKind::NotFound,
            if saw_interface {
                format!(
                    "classic KDUSB device found, but target '{target_name}' did not match NAME?"
                )
            } else {
                "no supported classic KDUSB interface found".to_string()
            },
        ))
    }

    fn open_and_probe(
        device: &Device<GlobalContext>,
        interface: u8,
        alternate_setting: u8,
        endpoints: BulkEndpoints,
        target_name: &str,
    ) -> io::Result<Option<ProbeOutcome>> {
        let handle = device
            .open()
            .map_err(|err| usb_error("opening classic KDUSB device", err))?;

        match handle.kernel_driver_active(interface) {
            Ok(true) => {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    format!(
                        "KDUSB interface {interface} already has a kernel driver; refusing to detach it"
                    ),
                ));
            }
            Ok(false) | Err(rusb::Error::NotSupported) => {}
            Err(err) => {
                return Err(usb_error(
                    "checking KDUSB interface kernel-driver ownership",
                    err,
                ));
            }
        }

        handle
            .claim_interface(interface)
            .map_err(|err| usb_error("claiming KDUSB interface", err))?;

        if alternate_setting != 0 {
            handle
                .set_alternate_setting(interface, alternate_setting)
                .map_err(|err| usb_error("selecting KDUSB alternate setting", err))?;
        }

        let written = handle
            .write_bulk(endpoints.output, NAME_PROBE, DISCOVERY_TIMEOUT)
            .map_err(|err| usb_error("sending KDUSB NAME? probe", err))?;
        if written != NAME_PROBE.len() {
            return Err(io::Error::new(
                io::ErrorKind::WriteZero,
                format!(
                    "short KDUSB NAME? probe: wrote {written} of {} bytes",
                    NAME_PROBE.len()
                ),
            ));
        }

        // Match USB2DBG's recovered 4016-byte receive request. The previous
        // <=37-byte buffer could overflow before userspace had a chance to
        // classify a live KD packet that raced the NAME= reply.
        let mut response = vec![0u8; USB_READ_REQUEST];
        let received = loop {
            let count = handle
                .read_bulk(endpoints.input, &mut response, DISCOVERY_TIMEOUT)
                .map_err(|err| usb_error("reading KDUSB bootstrap transfer", err))?;
            if count != 0 {
                break count;
            }
        };
        let transfer = &response[..received];

        match classify_bootstrap_transfer(transfer, target_name)? {
            BootstrapTransfer::NameMatch { consumed } => Ok(Some(ProbeOutcome::Named {
                io: RusbBulkIo { handle },
                prefetched: transfer[consumed..].to_vec(),
            })),
            BootstrapTransfer::NameMismatch { .. } => Ok(None),
            BootstrapTransfer::KdPrefetch => Ok(Some(ProbeOutcome::KdPrefetch {
                io: RusbBulkIo { handle },
                prefetched: transfer.to_vec(),
            })),
        }
    }

    fn usb_error(context: &str, err: rusb::Error) -> io::Error {
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
        io::Error::new(kind, format!("{context}: {err}"))
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn target_name_matches_windows_target_parser() {
            for valid in ["A", "CLSA0102_USB", "DEBUG-1", "A0"] {
                assert!(validate_requested_target_name(valid).is_ok(), "{valid}");
            }
            for invalid in ["", "lower", "BAD.NAME", "A+B", &"A".repeat(25)] {
                assert!(
                    validate_requested_target_name(invalid).is_err(),
                    "{invalid}"
                );
            }
        }

        #[test]
        fn inf_hardware_ids_are_recognised() {
            for &(vendor, product) in KDUSB_HARDWARE_IDS {
                assert!(is_known_hardware_id(vendor, product));
            }
            assert!(!is_known_hardware_id(0xffff, 0xffff));
        }
    }
}

#[cfg(target_os = "linux")]
pub(crate) use linux::KdUsbStream;

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;
    use std::io::{Read, Write};
    use std::sync::Mutex;
    use std::time::Duration;

    #[derive(Default)]
    struct MockBulkIo {
        reads: Mutex<VecDeque<Vec<u8>>>,
        writes: Mutex<Vec<Vec<u8>>>,
        read_requests: Mutex<Vec<(u8, usize, Duration)>>,
        write_requests: Mutex<Vec<(u8, usize, Duration)>>,
    }

    impl MockBulkIo {
        fn with_reads(reads: impl IntoIterator<Item = Vec<u8>>) -> Self {
            Self {
                reads: Mutex::new(reads.into_iter().collect()),
                ..Self::default()
            }
        }
    }

    impl BulkIo for MockBulkIo {
        fn read_bulk(&self, endpoint: u8, buf: &mut [u8], timeout: Duration) -> io::Result<usize> {
            self.read_requests
                .lock()
                .unwrap()
                .push((endpoint, buf.len(), timeout));
            let bytes = self
                .reads
                .lock()
                .unwrap()
                .pop_front()
                .ok_or_else(|| io::Error::new(io::ErrorKind::TimedOut, "mock read timeout"))?;
            if bytes.len() > buf.len() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "mock transfer exceeds supplied buffer",
                ));
            }
            buf[..bytes.len()].copy_from_slice(&bytes);
            Ok(bytes.len())
        }

        fn write_bulk(&self, endpoint: u8, buf: &[u8], timeout: Duration) -> io::Result<usize> {
            self.write_requests
                .lock()
                .unwrap()
                .push((endpoint, buf.len(), timeout));
            self.writes.lock().unwrap().push(buf.to_vec());
            Ok(buf.len())
        }
    }

    fn test_endpoints() -> BulkEndpoints {
        BulkEndpoints {
            input: 0x81,
            output: 0x01,
            max_packet: 1024,
        }
    }

    const CLSA0102_REPLY: &[u8] = b"NAME=CLSA0102_USB\0\0";

    #[test]
    fn stream_replays_prefetched_kd_bytes_before_new_usb_reads() {
        let io = MockBulkIo::with_reads([b"later".to_vec()]);
        let mut stream =
            KdUsbStreamCore::new_with_rx(io, test_endpoints(), b"early".iter().copied()).unwrap();

        let mut first = [0u8; 5];
        stream.read_exact(&mut first).unwrap();
        assert_eq!(&first, b"early");
        assert!(stream.io.read_requests.lock().unwrap().is_empty());

        let mut second = [0u8; 5];
        stream.read_exact(&mut second).unwrap();
        assert_eq!(&second, b"later");
        assert_eq!(stream.io.read_requests.lock().unwrap().len(), 1);
    }

    #[test]
    fn bootstrap_name_match_preserves_trailing_stream_bytes() {
        let mut transfer = CLSA0102_REPLY.to_vec();
        transfer.extend_from_slice(b"KD");
        assert_eq!(
            classify_bootstrap_transfer(&transfer, "CLSA0102_USB").unwrap(),
            BootstrapTransfer::NameMatch {
                consumed: CLSA0102_REPLY.len()
            }
        );
    }

    #[test]
    fn bootstrap_name_mismatch_is_not_silently_accepted() {
        assert_eq!(
            classify_bootstrap_transfer(CLSA0102_REPLY, "OTHER").unwrap(),
            BootstrapTransfer::NameMismatch {
                actual: "CLSA0102_USB".to_string()
            }
        );
    }

    #[test]
    fn observed_live_file_io_header_is_classified_as_kd_prefetch() {
        let observed = hex::decode(
            "303030300b00920000088080a0110000303400000000000089001200800000000100000001000000000000000000000000000000000000000000000000000000",
        )
        .unwrap();
        assert_eq!(
            classify_bootstrap_transfer(&observed, "CLSA0102_USB").unwrap(),
            BootstrapTransfer::KdPrefetch
        );
    }

    #[test]
    fn stream_buffers_surplus_bulk_read_bytes() {
        let io = MockBulkIo::with_reads([b"abcdefghij".to_vec()]);
        let mut stream = KdUsbStreamCore::new(io, test_endpoints()).unwrap();
        stream.set_read_timeout(Some(Duration::from_millis(250)));

        let mut first = [0u8; 1];
        assert_eq!(stream.read(&mut first).unwrap(), 1);
        assert_eq!(&first, b"a");

        let mut rest = [0u8; 9];
        assert_eq!(stream.read(&mut rest).unwrap(), 9);
        assert_eq!(&rest, b"bcdefghij");

        let requests = stream.io.read_requests.lock().unwrap();
        assert_eq!(
            requests.as_slice(),
            &[(0x81, USB_READ_REQUEST, Duration::from_millis(250))]
        );
    }

    #[test]
    fn stream_ignores_usb_zlp_on_read() {
        let io = MockBulkIo::with_reads([Vec::new(), b"x".to_vec()]);
        let mut stream = KdUsbStreamCore::new(io, test_endpoints()).unwrap();
        let mut byte = [0u8; 1];
        assert_eq!(stream.read(&mut byte).unwrap(), 1);
        assert_eq!(byte[0], b'x');
        assert_eq!(stream.io.read_requests.lock().unwrap().len(), 2);
    }

    #[test]
    fn flush_coalesces_kd_header_payload_and_trailer() {
        let io = MockBulkIo::default();
        let mut stream = KdUsbStreamCore::new(io, test_endpoints()).unwrap();

        stream.write_all(&[0x30; 16]).unwrap();
        stream.write_all(&vec![0x5a; 1024]).unwrap();
        stream.write_all(&[0xaa]).unwrap();

        assert!(stream.io.writes.lock().unwrap().is_empty());
        stream.flush().unwrap();

        let writes = stream.io.writes.lock().unwrap();
        assert_eq!(writes.len(), 1);
        assert_eq!(writes[0].len(), 16 + 1024 + 1);
        assert_eq!(&writes[0][..16], &[0x30; 16]);
        assert_eq!(writes[0][16], 0x5a);
        assert_eq!(*writes[0].last().unwrap(), 0xaa);
    }

    #[test]
    fn flush_applies_chunking_and_zlp_to_whole_logical_write() {
        let io = MockBulkIo::default();
        let mut stream = KdUsbStreamCore::new(io, test_endpoints()).unwrap();

        stream.write_all(&vec![0x11; 8192]).unwrap();
        stream.flush().unwrap();

        let writes = stream.io.writes.lock().unwrap();
        assert_eq!(
            writes.iter().map(Vec::len).collect::<Vec<_>>(),
            vec![4096, 4096, 0]
        );
    }

    #[test]
    fn clone_has_independent_buffers_but_shared_bulk_handle() {
        let io = MockBulkIo::default();
        let mut stream = KdUsbStreamCore::new(io, test_endpoints()).unwrap();
        let mut breakin = stream.try_clone().unwrap();

        stream.write_all(b"packet").unwrap();
        breakin
            .write_all(&[crate::kd::framing::BREAKIN_BYTE])
            .unwrap();
        breakin.flush().unwrap();
        stream.flush().unwrap();

        let writes = stream.io.writes.lock().unwrap();
        assert_eq!(
            writes.as_slice(),
            &[vec![crate::kd::framing::BREAKIN_BYTE], b"packet".to_vec()]
        );
    }

    #[test]
    fn stream_validates_endpoint_directions_and_packet_size() {
        assert!(
            KdUsbStreamCore::new(
                MockBulkIo::default(),
                BulkEndpoints {
                    input: 0x01,
                    output: 0x02,
                    max_packet: 1024,
                },
            )
            .is_err()
        );
        assert!(
            KdUsbStreamCore::new(
                MockBulkIo::default(),
                BulkEndpoints {
                    input: 0x81,
                    output: 0x82,
                    max_packet: 1024,
                },
            )
            .is_err()
        );
        assert!(
            KdUsbStreamCore::new(
                MockBulkIo::default(),
                BulkEndpoints {
                    input: 0x81,
                    output: 0x01,
                    max_packet: 0,
                },
            )
            .is_err()
        );
    }

    #[test]
    fn recovered_constants_match_classic_kdusb_contract() {
        assert_eq!(KDUSB_VENDOR_ID, 0x3495);
        assert_eq!(KDUSB_PRODUCT_ID, 0x00e0);
        assert_eq!(
            (
                KDUSB_INTERFACE_CLASS,
                KDUSB_INTERFACE_SUBCLASS,
                KDUSB_INTERFACE_PROTOCOL
            ),
            (0xdc, 0x02, 0xff)
        );
        assert_eq!(NAME_PROBE, b"NAME?");
        assert_eq!(USB_READ_REQUEST, 4016);
        assert_eq!(USB3_WRITE_CHUNK, 4096);
    }

    #[test]
    fn parses_exact_clsa0102_fixture() {
        assert_eq!(CLSA0102_REPLY.len(), 19);
        assert_eq!(parse_name_response(CLSA0102_REPLY).unwrap(), "CLSA0102_USB");
        assert!(name_response_matches(CLSA0102_REPLY, "CLSA0102_USB").unwrap());
        assert!(!name_response_matches(CLSA0102_REPLY, "OTHER").unwrap());
    }

    #[test]
    fn name_reply_requires_prefix_and_nul() {
        assert!(parse_name_response(b"NOPE=CLSA0102_USB\0\0").is_err());
        assert!(parse_name_response(b"NAME=CLSA0102_USB").is_err());
        assert!(parse_name_response(b"NAME=\0").is_err());
    }

    #[test]
    fn name_reply_enforces_recovered_length_bounds() {
        assert!(parse_name_response(b"NAME").is_err());

        let mut too_long = b"NAME=".to_vec();
        too_long.extend_from_slice(&[b'A'; 32]);
        too_long.push(0);
        assert_eq!(too_long.len(), 38);
        assert!(parse_name_response(&too_long).is_err());
    }

    #[test]
    fn target_name_enforces_target_side_24_byte_limit() {
        let mut response = b"NAME=".to_vec();
        response.extend_from_slice(&[b'A'; TARGET_NAME_MAX]);
        response.extend_from_slice(&[0, 0]);
        assert_eq!(
            parse_name_response(&response).unwrap().len(),
            TARGET_NAME_MAX
        );

        let mut too_long_name = b"NAME=".to_vec();
        too_long_name.extend_from_slice(&[b'A'; TARGET_NAME_MAX + 1]);
        too_long_name.push(0);
        assert!(parse_name_response(&too_long_name).is_err());
    }

    #[test]
    fn write_plan_reproduces_usb3_chunk_and_zlp_rules() {
        assert_eq!(usb3_write_plan(0, 1024).unwrap(), Vec::<usize>::new());
        assert_eq!(usb3_write_plan(1, 1024).unwrap(), vec![1]);
        assert_eq!(usb3_write_plan(1023, 1024).unwrap(), vec![1023]);
        assert_eq!(usb3_write_plan(1024, 1024).unwrap(), vec![1024, 0]);
        assert_eq!(usb3_write_plan(4095, 1024).unwrap(), vec![4095]);
        assert_eq!(usb3_write_plan(4096, 1024).unwrap(), vec![4096, 0]);
        assert_eq!(usb3_write_plan(4097, 1024).unwrap(), vec![4096, 1]);
        assert_eq!(usb3_write_plan(8192, 1024).unwrap(), vec![4096, 4096, 0]);
        assert!(usb3_write_plan(1, 0).is_err());
    }

    #[test]
    fn kd_max_packet_can_span_usb_receive_requests() {
        // KdFraming allows 4000 payload bytes, plus 16-byte header and the
        // 0xAA trailer. The USB stream must tolerate a packet crossing one
        // 4016-byte bulk-IN request boundary by one byte.
        assert_eq!(crate::kd::framing::PACKET_MAX_SIZE + 16 + 1, 4017);
        assert_eq!(USB_READ_REQUEST, 4016);
    }
}
