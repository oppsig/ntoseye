//! Experimental classic KDUSB transport foundation (Linux).
//!
//! Complete USB transfers are classified before adapting them to `KdFraming`.
//! No discovery/open/claim API or debugger backend activation is provided.
//! Outbound DATA is adapted at this USB boundary: generic `KdFraming` keeps
//! its serial-compatible trailing 0xaa internally, while KDUSB strips exactly
//! that byte before bulk OUT. See `docs/kdusb.md` for evidence and limits.

use std::collections::VecDeque;
use std::io::{self, Read, Write};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use super::framing::{
    BREAKIN_BYTE, CONTROL_PACKET_LEADER, HEADER_SIZE, Header, PACKET_MAX_SIZE,
    PACKET_TRAILING_BYTE, PACKET_TYPE_KD_ACKNOWLEDGE, PACKET_TYPE_KD_RESEND,
    PACKET_TYPE_KD_RESET,
};

// Independently recovered USB2DBG/target wire constants, not copied driver code.
// USB2DBG.SYS SHA256 3074ae7f9375ed50149fc3ba8b913f54ae85532177acfab12982ba83c135ec0c.
pub const NAME_PROBE: &[u8; 5] = b"NAME?";
pub const RECEIVE_QUANTUM: usize = 4016;
pub const USB3_WRITE_CHUNK: usize = 4096;
pub const TARGET_NAME_MAX: usize = 24;
const NAME_PREFIX: &[u8; 5] = b"NAME=";
const NAME_MAX: usize = NAME_PREFIX.len() + TARGET_NAME_MAX + 2;
// One extra byte accommodates a maximum-size packet with a tolerated trailer.
pub const RECEIVE_CAPACITY: usize = RECEIVE_QUANTUM + 1;

mod discovery;
pub use discovery::{
    KDUSB_BULK_IN, KDUSB_BULK_OUT, KDUSB_INTERFACE_ALT_SETTING, KDUSB_INTERFACE_CLASS,
    KDUSB_INTERFACE_PROTOCOL, KDUSB_INTERFACE_SUBCLASS, KDUSB_MAX_PACKET, KDUSB_PRODUCT_ID,
    KDUSB_VENDOR_ID, LinuxKdUsbStream, connect_named,
};

/// A whole completion's shape. Checksums and packet IDs remain `KdFraming`'s job.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PacketShape {
    Data { payload_len: usize, trailer: bool },
    Control,
}

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

/// Classify one complete KD USB transfer; never concatenate incomplete packets.
pub fn classify_transfer(bytes: &[u8]) -> io::Result<PacketShape> {
    let header = Header::peek(bytes).ok_or_else(|| invalid("incomplete KDUSB header"))?;
    if header.is_data() {
        let payload_len = usize::from(header.byte_count);
        if payload_len > PACKET_MAX_SIZE {
            return Err(invalid("KDUSB payload exceeds KD maximum"));
        }
        let body_len = HEADER_SIZE + payload_len;
        let trailer = match bytes.len() {
            len if len == body_len => false,
            len if len == body_len + 1 && bytes[body_len] == PACKET_TRAILING_BYTE => true,
            _ => return Err(invalid("incomplete or unrecognized KDUSB data transfer")),
        };
        Ok(PacketShape::Data {
            payload_len,
            trailer,
        })
    } else if header.leader == CONTROL_PACKET_LEADER
        && bytes.len() == HEADER_SIZE
        && header.byte_count == 0
        && header.checksum == 0
        && matches!(
            header.packet_type,
            PACKET_TYPE_KD_ACKNOWLEDGE | PACKET_TYPE_KD_RESEND | PACKET_TYPE_KD_RESET
        )
    {
        Ok(PacketShape::Control)
    } else {
        Err(invalid("unrecognized KDUSB control transfer"))
    }
}

/// Parse the target's exact two-NUL NAME reply. Names remain ANSI bytes.
pub fn parse_name(bytes: &[u8]) -> io::Result<&[u8]> {
    let name = bytes
        .strip_prefix(NAME_PREFIX)
        .and_then(|suffix| suffix.strip_suffix(&[0, 0]))
        .ok_or_else(|| invalid("invalid KDUSB NAME envelope"))?;
    if name.is_empty() || name.len() > TARGET_NAME_MAX || name.contains(&0) {
        return Err(invalid("invalid KDUSB target name"));
    }
    Ok(name)
}

/// One successful bulk read returns one completion, including a possible ZLP.
/// Implementations must report overflow, never silently truncate a transfer.
pub trait BulkIo: Send + Sync {
    fn read_bulk(&self, endpoint: u8, bytes: &mut [u8], timeout: Duration) -> io::Result<usize>;
    fn write_bulk(&self, endpoint: u8, bytes: &[u8], timeout: Duration) -> io::Result<usize>;
}

/// Adapter for a handle opened and claimed by a separate, admitted caller.
/// This module itself never enumerates, opens, claims, detaches or selects alt settings.
impl<C: rusb::UsbContext> BulkIo for rusb::DeviceHandle<C> {
    fn read_bulk(&self, endpoint: u8, bytes: &mut [u8], timeout: Duration) -> io::Result<usize> {
        if endpoint & 0x80 == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "not an IN endpoint",
            ));
        }
        bulk_transfer(self, endpoint, bytes, timeout)
    }

    fn write_bulk(&self, endpoint: u8, bytes: &[u8], timeout: Duration) -> io::Result<usize> {
        if endpoint & 0x80 != 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "not an OUT endpoint",
            ));
        }
        bulk_transfer(self, endpoint, &mut bytes.to_vec(), timeout)
    }
}

// rusb's convenience bulk methods turn timeout/interruption with partial bytes
// into Ok(n). Keep the libusb status so incomplete completions cannot look like
// successful transfer boundaries. No interface state is manipulated here.
fn bulk_transfer<C: rusb::UsbContext>(
    handle: &rusb::DeviceHandle<C>,
    endpoint: u8,
    bytes: &mut [u8],
    timeout: Duration,
) -> io::Result<usize> {
    let len = i32::try_from(bytes.len())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "bulk buffer too large"))?;
    let timeout_ms = usb_timeout_ms(timeout)?;
    let mut transferred = 0;
    // SAFETY: the borrowed handle stays alive; the mutable slice is valid for
    // len bytes throughout this synchronous call. libusb does not retain either
    // pointer. OUT uses an owned copy, including a valid zero-length ZLP buffer.
    let status = unsafe {
        rusb::ffi::libusb_bulk_transfer(
            handle.as_raw(),
            endpoint,
            bytes.as_mut_ptr(),
            len,
            &mut transferred,
            timeout_ms,
        )
    };
    bulk_completion(status, transferred, bytes, endpoint)
}

// Pure completion adapter, also exercised without a libusb handle in unit tests.
fn bulk_completion(
    status: i32,
    transferred: i32,
    bytes: &[u8],
    endpoint: u8,
) -> io::Result<usize> {
    bulk_result(status, transferred, bytes.len()).map_err(|mut error| {
        if let Some(fault) = error.get_mut().and_then(|e| e.downcast_mut::<BulkFailure>()) {
            fault.endpoint = Some(endpoint);
            if endpoint & 0x80 != 0 {
                // Keep only the reported valid prefix; do not parse a failed completion.
                let count = usize::try_from(transferred).unwrap_or(0).min(bytes.len());
                fault.partial.extend_from_slice(&bytes[..count]);
            }
        }
        error
    })
}

fn usb_timeout_ms(timeout: Duration) -> io::Result<u32> {
    // libusb timeout 0 means infinite; round sub-millisecond budgets UP.
    let ms = timeout.as_nanos().div_ceil(1_000_000);
    u32::try_from(ms).ok().filter(|ms| *ms != 0).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "bulk timeout outside finite libusb range",
        )
    })
}

/// Raw libusb completion; Io does not identify errno -71 or xHCI code4.
#[derive(Debug)]
pub struct BulkFailure {
    pub status: i32,
    pub error: rusb::Error,
    pub transferred: i32,
    pub requested: usize,
    pub endpoint: Option<u8>,
    pub partial: Vec<u8>,
}

impl std::fmt::Display for BulkFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "libusb {:?} (status {}), actual {} of {}, endpoint {:?}",
            self.error, self.status, self.transferred, self.requested, self.endpoint)
    }
}

impl std::error::Error for BulkFailure {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.error)
    }
}

/// Lossless first-failure wrapper shared across stream clones.
#[derive(Debug, Clone)]
pub struct TransportFailure {
    pub stage: &'static str,
    pub endpoint: u8,
    pub requested: usize,
    pub original: Arc<io::Error>,
}

impl std::fmt::Display for TransportFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "KDUSB {} endpoint {:#04x}, requested {}: {}",
            self.stage, self.endpoint, self.requested, self.original)
    }
}

impl std::error::Error for TransportFailure {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(self.original.as_ref())
    }
}

pub(crate) fn is_terminal_error(error: &io::Error) -> bool {
    error.get_ref().is_some_and(|e| e.is::<TransportFailure>())
}

#[derive(Default)]
struct SessionState {
    name_started: bool,
    packet_io_admitted: bool,
    terminal: Option<TransportFailure>,
}

impl SessionState {
    fn check(&self) -> io::Result<()> {
        match &self.terminal {
            Some(fault) => Err(io::Error::new(fault.original.kind(), fault.clone())),
            None => Ok(()),
        }
    }

    fn fail(&mut self, stage: &'static str, endpoint: u8,
        requested: usize, original: io::Error) -> io::Error {
        let fault = self.terminal.get_or_insert_with(|| TransportFailure {
            stage, endpoint, requested, original: Arc::new(original),
        });
        io::Error::new(fault.original.kind(), fault.clone())
    }
}

fn bulk_result(status: i32, transferred: i32, capacity: usize) -> io::Result<usize> {
    use rusb::constants::*;
    if status != 0 {
        let kind = match status {
            LIBUSB_ERROR_TIMEOUT if transferred == 0 => io::ErrorKind::TimedOut,
            LIBUSB_ERROR_NO_DEVICE => io::ErrorKind::NotConnected,
            LIBUSB_ERROR_PIPE => io::ErrorKind::BrokenPipe,
            LIBUSB_ERROR_ACCESS => io::ErrorKind::PermissionDenied,
            LIBUSB_ERROR_OVERFLOW => io::ErrorKind::InvalidData,
            // Partial timed-out/interrupted transfers must not be normalized.
            LIBUSB_ERROR_TIMEOUT | LIBUSB_ERROR_INTERRUPTED => io::ErrorKind::InvalidData,
            _ => io::ErrorKind::Other,
        };
        let error = match status {
            LIBUSB_ERROR_IO => rusb::Error::Io,
            LIBUSB_ERROR_INVALID_PARAM => rusb::Error::InvalidParam,
            LIBUSB_ERROR_ACCESS => rusb::Error::Access,
            LIBUSB_ERROR_NO_DEVICE => rusb::Error::NoDevice,
            LIBUSB_ERROR_NOT_FOUND => rusb::Error::NotFound,
            LIBUSB_ERROR_BUSY => rusb::Error::Busy,
            LIBUSB_ERROR_TIMEOUT => rusb::Error::Timeout,
            LIBUSB_ERROR_OVERFLOW => rusb::Error::Overflow,
            LIBUSB_ERROR_PIPE => rusb::Error::Pipe,
            LIBUSB_ERROR_INTERRUPTED => rusb::Error::Interrupted,
            LIBUSB_ERROR_NO_MEM => rusb::Error::NoMem,
            LIBUSB_ERROR_NOT_SUPPORTED => rusb::Error::NotSupported,
            _ => rusb::Error::Other,
        };
        return Err(io::Error::new(kind, BulkFailure {
            status, error, transferred, requested: capacity,
            endpoint: None, partial: Vec::new(),
        }));
    }
    usize::try_from(transferred)
        .ok()
        .filter(|n| *n <= capacity)
        .ok_or_else(|| invalid("invalid bulk completion length"))
}

#[derive(Debug, Clone, Copy)]
pub struct BulkEndpoints {
    pub input: u8,
    pub output: u8,
    pub max_packet: usize,
}

/// Recovered USB3 logical-write chunk/ZLP rule; independent of KD DATA framing.
pub fn usb3_write_plan(len: usize, max_packet: usize) -> io::Result<Vec<usize>> {
    if max_packet == 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "zero max packet",
        ));
    }
    let mut plan = vec![USB3_WRITE_CHUNK; len / USB3_WRITE_CHUNK];
    if !len.is_multiple_of(USB3_WRITE_CHUNK) {
        plan.push(len % USB3_WRITE_CHUNK);
    }
    if len != 0 && len.is_multiple_of(max_packet) {
        plan.push(0);
    }
    Ok(plan)
}

#[derive(Default)]
struct ReceiveState {
    pending: VecDeque<u8>,
    name_fragment: Vec<u8>,
    names: VecDeque<Vec<u8>>,
}

impl ReceiveState {
    fn ingest(&mut self, transfer: &[u8]) -> io::Result<()> {
        if transfer.is_empty() {
            return Ok(());
        }
        // NAME is only recognized at a transfer boundary, never inside KD payload.
        if !self.name_fragment.is_empty()
            || transfer.starts_with(NAME_PREFIX)
            || NAME_PREFIX.starts_with(transfer)
        {
            self.name_fragment.extend_from_slice(transfer);
            let bytes = &self.name_fragment;
            if !(bytes.starts_with(NAME_PREFIX) || NAME_PREFIX.starts_with(bytes)) {
                return Err(invalid("invalid split KDUSB NAME prefix"));
            }
            if let Some(end) = bytes.windows(2).position(|b| b == [0, 0]) {
                let end = end + 2;
                if end > NAME_MAX {
                    return Err(invalid("oversized KDUSB NAME reply"));
                }
                let name = parse_name(&bytes[..end])?.to_vec();
                if self.names.len() == 16 {
                    return Err(invalid("too many unconsumed KDUSB NAME replies"));
                }
                let tail = self.name_fragment.split_off(end);
                self.name_fragment.clear();
                self.names.push_back(name);
                // A NAME envelope may precede a complete prefetched KD packet.
                if let Err(error) = self.ingest(&tail) {
                    self.name_fragment = tail; // retain rejected extra bytes for diagnosis
                    return Err(error);
                }
            } else if bytes.len() > NAME_MAX {
                return Err(invalid("oversized KDUSB NAME reply"));
            }
            return Ok(());
        }
        let shape = classify_transfer(transfer)?;
        self.pending.extend(transfer);
        if matches!(shape, PacketShape::Data { trailer: false, .. }) {
            // Internal normalization only. Never send this byte back onto USB.
            self.pending.push_back(PACKET_TRAILING_BYTE);
        }
        Ok(())
    }
}

/// Boundary-aware adapter for existing KD framing.
/// Inbound trailer-less USB DATA gets one synthetic 0xaa for `KdFraming`.
/// Outbound DATA must contain that internal trailer and loses it before bulk OUT.
/// CONTROL is unchanged; break-in remains gated.
/// Clones share unread bytes and a logical-write lock; write staging is per clone.
pub struct KdUsbStream<I: BulkIo> {
    io: Arc<I>,
    endpoints: BulkEndpoints,
    receive: Arc<Mutex<ReceiveState>>,
    write_lock: Arc<Mutex<()>>,
    timeout: Duration,
    transmit: Vec<u8>,
    write_failed: Arc<Mutex<bool>>,
    session: Arc<Mutex<SessionState>>,
}

impl<I: BulkIo> KdUsbStream<I> {
    pub fn new(io: Arc<I>, endpoints: BulkEndpoints, timeout: Duration) -> io::Result<Self> {
        if endpoints.input & 0x80 == 0
            || endpoints.output & 0x80 != 0
            || endpoints.input & 0x0f == 0
            || endpoints.output & 0x0f == 0
            || endpoints.max_packet == 0
            || timeout.is_zero()
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid bulk parameters",
            ));
        }
        Ok(Self {
            io,
            endpoints,
            receive: Arc::new(Mutex::new(ReceiveState::default())),
            write_lock: Arc::new(Mutex::new(())),
            timeout,
            transmit: Vec::new(),
            write_failed: Arc::new(Mutex::new(false)),
            session: Arc::new(Mutex::new(SessionState::default())),
        })
    }

    pub fn try_clone(&self) -> io::Result<Self> {
        Ok(Self {
            io: Arc::clone(&self.io),
            endpoints: self.endpoints,
            receive: Arc::clone(&self.receive),
            write_lock: Arc::clone(&self.write_lock),
            timeout: self.timeout,
            transmit: Vec::new(),
            write_failed: Arc::clone(&self.write_failed),
            session: Arc::clone(&self.session),
        })
    }

    pub fn set_read_timeout(&mut self, timeout: Duration) -> io::Result<()> {
        if timeout.is_zero() {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "zero timeout"));
        }
        self.timeout = timeout;
        Ok(())
    }

    pub fn take_name(&self) -> io::Result<Option<Vec<u8>>> {
        Ok(self
            .receive
            .lock()
            .map_err(|_| io::Error::other("receive lock poisoned"))?
            .names
            .pop_front())
    }

    /// Diagnostic snapshot remains available after a terminal fault; no USB IO.
    /// Pending bytes include framing's synthetic trailer, fragments are unchanged.
    pub fn retained_receive(&self) -> io::Result<(Vec<u8>, Vec<u8>)> {
        let receive = self.receive.lock()
            .map_err(|_| io::Error::other("receive lock poisoned"))?;
        Ok((receive.pending.iter().copied().collect(), receive.name_fragment.clone()))
    }

    /// Enable pure packet fixtures only. Production admission stays unavailable
    /// until a separate, evidence-backed session authorization is implemented.
    #[cfg(test)]
    fn admit_packet_io(&mut self) -> io::Result<()> {
        let mut session = self.session.lock()
            .map_err(|_| io::Error::other("session lock poisoned"))?;
        session.check()?;
        session.packet_io_admitted = true;
        Ok(())
    }

    /// One NAME OUT and at most one 4016-byte IN per shared stream generation.
    /// An incomplete reply or KD prefetch is retained, never retried here.
    pub(crate) fn probe_name(&mut self, expected: &[u8]) -> io::Result<()> {
        if expected.is_empty() || expected.len() > TARGET_NAME_MAX
            || !expected.is_ascii() || expected.contains(&0) {
            return Err(io::Error::new(io::ErrorKind::InvalidInput,
                "KDUSB target name must be 1..=24 non-NUL ASCII bytes"));
        }
        let mut session = self.session.lock()
            .map_err(|_| io::Error::other("session lock poisoned"))?;
        session.check()?;
        if session.name_started {
            return Err(io::Error::new(io::ErrorKind::PermissionDenied,
                "KDUSB NAME budget consumed; no automatic retry"));
        }
        session.name_started = true;
        let written = self.io.write_bulk(self.endpoints.output, NAME_PROBE, self.timeout)
            .map_err(|err| session.fail("NAME OUT", self.endpoints.output, 5, err))?;
        if written != NAME_PROBE.len() {
            return Err(session.fail("NAME OUT", self.endpoints.output, 5,
                io::Error::new(io::ErrorKind::WriteZero,
                    format!("short NAME OUT: actual {written} of 5; no suffix resend"))));
        }
        let mut transfer = [0u8; RECEIVE_QUANTUM];
        let len = self.io.read_bulk(self.endpoints.input, &mut transfer, self.timeout)
            .map_err(|err| session.fail("NAME IN", self.endpoints.input, RECEIVE_QUANTUM, err))?;
        let bytes = transfer.get(..len).ok_or_else(|| session.fail(
            "NAME IN", self.endpoints.input, RECEIVE_QUANTUM, invalid("bulk read overflow")))?;
        let mut receive = self.receive.lock()
            .map_err(|_| io::Error::other("receive lock poisoned"))?;
        receive.ingest(bytes).map_err(|err| session.fail(
            "NAME parse", self.endpoints.input, RECEIVE_QUANTUM, err))?;
        match receive.names.pop_front() {
            Some(name) if name == expected => Ok(()),
            Some(name) => Err(session.fail("NAME identity", self.endpoints.input,
                RECEIVE_QUANTUM, io::Error::new(io::ErrorKind::InvalidData,
                    format!("NAME identity mismatch: expected {expected:?}, got {name:?}; stop")))),
            None => Err(session.fail("NAME incomplete", self.endpoints.input,
                RECEIVE_QUANTUM, io::Error::new(io::ErrorKind::UnexpectedEof,
                    "one IN consumed; NAME prefix/KD prefetch retained; identity unverified"))),
        }
    }

}

impl<I: BulkIo> Read for KdUsbStream<I> {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        if output.is_empty() {
            return Ok(0);
        }
        let mut session = self.session.lock()
            .map_err(|_| io::Error::other("session lock poisoned"))?;
        session.check()?;
        if !session.packet_io_admitted {
            return Err(io::Error::new(io::ErrorKind::PermissionDenied,
                "KDUSB packet input requires separate explicit admission"));
        }
        let mut receive = self
            .receive
            .lock()
            .map_err(|_| io::Error::other("receive lock poisoned"))?;
        let start = Instant::now();
        while receive.pending.is_empty() {
            let remaining = self
                .timeout
                .checked_sub(start.elapsed())
                .filter(|t| !t.is_zero())
                .ok_or_else(|| session.fail("KD IN", self.endpoints.input, RECEIVE_CAPACITY,
                    io::Error::new(io::ErrorKind::TimedOut, "KDUSB receive deadline")))?;
            let mut transfer = [0u8; RECEIVE_CAPACITY];
            let len = self
                .io
                .read_bulk(self.endpoints.input, &mut transfer, remaining)
                .map_err(|err| session.fail("KD IN", self.endpoints.input, RECEIVE_CAPACITY, err))?;
            let bytes = transfer.get(..len).ok_or_else(|| session.fail(
                "KD IN", self.endpoints.input, RECEIVE_CAPACITY, invalid("bulk read overflow")))?;
            receive.ingest(bytes).map_err(|err| session.fail(
                "KD parse", self.endpoints.input, RECEIVE_CAPACITY, err))?;
        }
        let count = output.len().min(receive.pending.len());
        for byte in &mut output[..count] {
            *byte = receive
                .pending
                .pop_front()
                .expect("count bounded by pending length");
        }
        Ok(count)
    }
}

impl<I: BulkIo> Write for KdUsbStream<I> {
    fn write(&mut self, input: &[u8]) -> io::Result<usize> {
        let session = self.session.lock()
            .map_err(|_| io::Error::other("session lock poisoned"))?;
        session.check()?;
        if !session.packet_io_admitted {
            return Err(io::Error::new(io::ErrorKind::PermissionDenied,
                "KDUSB packet output requires separate explicit admission"));
        }
        // Generic KdFraming emits DATA as header + payload + 0xaa. Stage one
        // complete logical packet so this adapter can strip that internal-only
        // trailer atomically before the first bulk OUT.
        let max_staged = HEADER_SIZE + PACKET_MAX_SIZE + 1;
        if self.transmit.len() + input.len() > max_staged {
            self.transmit.clear();
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "KDUSB logical write exceeds maximum KD DATA packet",
            ));
        }
        self.transmit.extend_from_slice(input);
        Ok(input.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        let mut session = self.session.lock()
            .map_err(|_| io::Error::other("session lock poisoned"))?;
        session.check()?;
        if self.transmit.is_empty() {
            return Ok(());
        }
        if !session.packet_io_admitted {
            return Err(io::Error::new(io::ErrorKind::PermissionDenied,
                "KDUSB packet flush requires separate explicit admission"));
        }

        let mut wire = std::mem::take(&mut self.transmit);
        if wire.as_slice() == [BREAKIN_BYTE] {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "KDUSB break-in output is not yet admitted",
            ));
        }

        match classify_transfer(&wire)? {
            PacketShape::Control => {}
            PacketShape::Data { trailer: true, .. } => {
                let trailer = wire.pop();
                debug_assert_eq!(trailer, Some(PACKET_TRAILING_BYTE));
                if !matches!(
                    classify_transfer(&wire)?,
                    PacketShape::Data { trailer: false, .. }
                ) {
                    return Err(invalid("KDUSB DATA trailer normalization failed"));
                }
            }
            PacketShape::Data { trailer: false, .. } => {
                return Err(invalid(
                    "KDUSB internal DATA write is missing KdFraming trailer",
                ));
            }
        }

        let _lock = self
            .write_lock
            .lock()
            .map_err(|_| io::Error::other("write lock poisoned"))?;
        let mut failed = self
            .write_failed
            .lock()
            .map_err(|_| io::Error::other("write state poisoned"))?;
        if *failed {
            return Err(io::Error::other("KDUSB output failed; reopen required"));
        }
        let mut offset = 0;
        for len in usb3_write_plan(wire.len(), self.endpoints.max_packet)? {
            match self.io.write_bulk(
                self.endpoints.output,
                &wire[offset..offset + len],
                self.timeout,
            ) {
                Ok(written) if written == len => offset += len,
                result => {
                    *failed = true;
                    let error = match result {
                        Err(error) => error,
                        Ok(actual) => io::Error::new(io::ErrorKind::WriteZero,
                            format!("short KDUSB write: actual {actual} of {len}; no retry")),
                    };
                    return Err(session.fail("KD OUT", self.endpoints.output, len, error));
                }
            }
        }
        Ok(())
    }
}

// Inline the historical pure tests so the bounded probe expectations and new
// offline cases remain in the two admitted top-level KD modules.
#[cfg(test)]
mod tests {
    use super::*;
    use crate::kd::framing::{
        INITIAL_PACKET_ID, KdFraming, PACKET_TYPE_KD_STATE_CHANGE64, PACKET_TYPE_KD_STATE_MANIPULATE,
        SYNC_PACKET_ID,
    };

    #[derive(Default)]
    struct FakeBulk {
        reads: Mutex<VecDeque<Vec<u8>>>,
        writes: Mutex<Vec<Vec<u8>>>,
        capacities: Mutex<Vec<usize>>,
        short_write: bool,
    }

    impl BulkIo for FakeBulk {
        fn read_bulk(&self, endpoint: u8, bytes: &mut [u8], timeout: Duration) -> io::Result<usize> {
            assert_eq!(endpoint, 0x81);
            assert!(!timeout.is_zero());
            self.capacities.lock().unwrap().push(bytes.len());
            let transfer = self
                .reads
                .lock()
                .unwrap()
                .pop_front()
                .ok_or_else(|| io::Error::new(io::ErrorKind::TimedOut, "fake idle"))?;
            if transfer.len() > bytes.len() {
                return Err(invalid("fake overflow"));
            }
            bytes[..transfer.len()].copy_from_slice(&transfer);
            Ok(transfer.len())
        }
        fn write_bulk(&self, endpoint: u8, bytes: &[u8], _: Duration) -> io::Result<usize> {
            assert_eq!(endpoint, 0x01);
            self.writes.lock().unwrap().push(bytes.to_vec());
            Ok(if self.short_write {
                bytes.len().saturating_sub(1)
            } else {
                bytes.len()
            })
        }
    }

    fn stream(reads: Vec<Vec<u8>>) -> KdUsbStream<FakeBulk> {
        let io = Arc::new(FakeBulk {
            reads: Mutex::new(reads.into()),
            ..Default::default()
        });
        let mut stream = KdUsbStream::new(
            io,
            BulkEndpoints {
                input: 0x81,
                output: 0x01,
                max_packet: 1024,
            },
            Duration::from_secs(1),
        )
        .unwrap();
        stream.admit_packet_io().unwrap(); // explicit admission for pure packet fixtures
        stream
    }

    fn data(id: u32, payload: &[u8], trailer: bool) -> Vec<u8> {
        let mut bytes = Header::data(PACKET_TYPE_KD_STATE_CHANGE64, id, payload)
            .encode()
            .to_vec();
        bytes.extend_from_slice(payload);
        if trailer {
            bytes.push(PACKET_TRAILING_BYTE);
        }
        bytes
    }

    #[test]
    fn cb_shape_is_346_bytes_without_trailer_and_does_not_consume_next_transfer() {
        // Structurally equivalent fixture, NOT the missing captured payload.
        let payload = vec![0x35; 330];
        let bytes = data(INITIAL_PACKET_ID | SYNC_PACKET_ID, &payload, false);
        assert_eq!(bytes.len(), 346);
        assert_eq!(
            classify_transfer(&bytes).unwrap(),
            PacketShape::Data {
                payload_len: 330,
                trailer: false
            }
        );
        let mut kd = KdFraming::new(stream(vec![
            bytes,
            data(INITIAL_PACKET_ID ^ 1, b"next", false),
        ]));
        assert_eq!(kd.recv_data().unwrap().payload, payload);
        assert_eq!(kd.recv_data().unwrap().payload, b"next");
        let writes = kd.transport_ref().io.writes.lock().unwrap();
        assert_eq!(writes.len(), 2);
        assert!(
            writes
                .iter()
                .all(|b| Header::peek(b).unwrap().packet_type == PACKET_TYPE_KD_ACKNOWLEDGE)
        );
    }

    #[test]
    fn retained_prefix_is_incomplete_not_an_invented_checksum_valid_packet() {
        // Retained 64-byte prefix; reported completion length 346. No full payload exists.
        let bytes = hex::decode("3030303007004a0100088080524400003130000019000d00100000000000000040f050980ea7ffff05e02f9b07f8ffff5a0000000000000000000b2a07f8ffff").unwrap();
        assert_eq!(bytes.len(), 64);
        let header = Header::peek(&bytes).unwrap();
        assert!(header.is_data());
        assert_eq!(header.packet_type, 7);
        assert_eq!(header.byte_count, 330);
        assert_eq!(header.packet_id, 0x80800800);
        assert_eq!(header.checksum, 0x4452);
        assert_eq!(HEADER_SIZE + usize::from(header.byte_count), 346);
        assert!(classify_transfer(&bytes).is_err());
    }

    #[test]
    fn tolerates_only_an_exact_in_transfer_aa_trailer() {
        let bytes = data(INITIAL_PACKET_ID, &vec![0x35; 330], true);
        assert_eq!(bytes.len(), 347);
        assert_eq!(
            classify_transfer(&bytes).unwrap(),
            PacketShape::Data {
                payload_len: 330,
                trailer: true
            }
        );
        let mut kd = KdFraming::new(stream(vec![bytes.clone()]));
        assert_eq!(kd.recv_data().unwrap().payload.len(), 330);
        let mut wrong = bytes;
        *wrong.last_mut().unwrap() = 0xbb;
        assert!(classify_transfer(&wrong).is_err());
    }

    #[test]
    fn control_is_exactly_sixteen_bytes_and_ack_bytes_are_preserved() {
        let ack = Header::control(PACKET_TYPE_KD_ACKNOWLEDGE, 0x80800800).encode();
        assert_eq!(hex::encode(ack), "69696969040000000008808000000000");
        assert_eq!(classify_transfer(&ack).unwrap(), PacketShape::Control);
        let mut s = stream(vec![ack.to_vec()]);
        let mut received = [0; 16];
        s.read_exact(&mut received).unwrap();
        assert_eq!(received, ack);
        s.write_all(&ack[..4]).unwrap();
        s.write_all(&ack[4..]).unwrap();
        assert!(s.io.writes.lock().unwrap().is_empty());
        s.flush().unwrap();
        assert_eq!(*s.io.writes.lock().unwrap(), vec![ack.to_vec()]);
        assert!(classify_transfer(&ack[..15]).is_err());
        assert!(classify_transfer(&[ack.as_slice(), &[0xaa]].concat()).is_err());
        assert_eq!(
            hex::encode(Header::control(PACKET_TYPE_KD_RESEND, 0).encode()),
            "69696969050000000000000000000000"
        );
    }

    #[test]
    fn name_probe_retains_prefetch_and_stops_at_one_in() {
        let packet = data(INITIAL_PACKET_ID, b"prefetched-before-name", false);
        let mut s = stream(vec![packet.clone(), b"NAME=CLSA0102_USB\0\0".to_vec()]);
        assert_eq!(s.probe_name(b"CLSA0102_USB").unwrap_err().kind(), io::ErrorKind::UnexpectedEof);
        let mut expected = packet;
        expected.push(PACKET_TRAILING_BYTE);
        assert_eq!(s.receive.lock().unwrap().pending.iter().copied().collect::<Vec<_>>(), expected);
        assert_eq!(*s.io.capacities.lock().unwrap(), vec![RECEIVE_QUANTUM]);
        assert!(s.probe_name(b"CLSA0102_USB").is_err());
        assert_eq!(*s.io.writes.lock().unwrap(), vec![NAME_PROBE.to_vec()]);
    }

    #[test]
    fn name_probe_retains_split_prefix_without_second_in() {
        let mut s = stream(vec![b"NAME=CLSA".to_vec(), b"0102_USB\0\0".to_vec()]);
        assert!(s.probe_name(b"CLSA0102_USB").is_err());
        assert_eq!(s.receive.lock().unwrap().name_fragment, b"NAME=CLSA");
        assert_eq!(*s.io.capacities.lock().unwrap(), vec![RECEIVE_QUANTUM]);
    }

    #[test]
    fn delayed_name_preserves_entire_pre_name_data_packet() {
        let payload = vec![0x72; 330];
        let mut kd = KdFraming::new(stream(vec![
            data(INITIAL_PACKET_ID, &payload, false),
            b"NAME=TEST_TARGET\0\0".to_vec(),
            data(INITIAL_PACKET_ID ^ 1, b"second", false),
        ]));
        assert_eq!(kd.recv_data().unwrap().payload, payload);
        assert_eq!(kd.transport_ref().take_name().unwrap(), None);
        assert_eq!(kd.recv_data().unwrap().payload, b"second");
        assert_eq!(
            kd.transport_ref().take_name().unwrap().unwrap(),
            b"TEST_TARGET"
        );
    }

    #[test]
    fn split_name_at_every_byte_boundary() {
        let name = b"NAME=TEST_TARGET\0\0";
        for split in 1..name.len() {
            let mut s = stream(vec![
                name[..split].to_vec(),
                name[split..].to_vec(),
                data(INITIAL_PACKET_ID, b"data", false),
            ]);
            let mut kd = KdFraming::new(&mut s);
            assert_eq!(kd.recv_data().unwrap().payload, b"data");
            assert_eq!(s.take_name().unwrap().unwrap(), b"TEST_TARGET");
        }
    }

    #[test]
    fn one_byte_name_reads_and_zlp_do_not_return_fake_eof() {
        let mut reads: Vec<Vec<u8>> = b"NAME=TEST\0\0".iter().map(|b| vec![*b]).collect();
        reads.insert(3, vec![]);
        reads.insert(0, vec![]);
        reads.push(data(INITIAL_PACKET_ID, b"ok", false));
        let mut kd = KdFraming::new(stream(reads));
        assert_eq!(kd.recv_data().unwrap().payload, b"ok");
        assert_eq!(kd.transport_ref().take_name().unwrap().unwrap(), b"TEST");
    }

    #[test]
    fn zlp_only_returns_timeout_and_empty_read_has_no_io() {
        let mut s = stream(vec![vec![], vec![]]);
        assert_eq!(s.read(&mut []).unwrap(), 0);
        assert!(s.io.capacities.lock().unwrap().is_empty());
        assert_eq!(
            s.read(&mut [0]).unwrap_err().kind(),
            io::ErrorKind::TimedOut
        );
    }

    #[test]
    fn tiny_reads_keep_normalized_transfer_boundary() {
        let bytes = data(INITIAL_PACKET_ID, b"whole", false);
        let mut expected = bytes.clone();
        expected.push(0xaa);
        let mut s = stream(vec![bytes]);
        let mut actual = vec![];
        for _ in 0..expected.len() {
            let mut byte = [0];
            assert_eq!(s.read(&mut byte).unwrap(), 1);
            actual.push(byte[0]);
        }
        assert_eq!(actual, expected);
        assert_eq!(*s.io.capacities.lock().unwrap(), vec![RECEIVE_CAPACITY]);
    }

    #[test]
    fn name_like_payload_is_never_discarded_as_discovery() {
        let payload = b"prefixNAME=TEST\0\0suffix";
        let mut kd = KdFraming::new(stream(vec![data(INITIAL_PACKET_ID, payload, false)]));
        assert_eq!(kd.recv_data().unwrap().payload, payload);
        assert_eq!(kd.transport_ref().take_name().unwrap(), None);
    }

    #[test]
    fn maximum_payload_around_4016_quantum() {
        for len in [3999, 4000] {
            for trailer in [false, true] {
                let bytes = data(INITIAL_PACKET_ID, &vec![0x11; len], trailer);
                assert_eq!(bytes.len(), HEADER_SIZE + len + usize::from(trailer));
                let mut kd = KdFraming::new(stream(vec![bytes]));
                assert_eq!(kd.recv_data().unwrap().payload.len(), len);
            }
        }
        assert_eq!(HEADER_SIZE + PACKET_MAX_SIZE, RECEIVE_QUANTUM);
        assert!(classify_transfer(&data(INITIAL_PACKET_ID, &vec![0; 4001], false)).is_err());
    }

    #[test]
    fn incomplete_or_coalesced_transfers_fail_closed() {
        let bytes = data(INITIAL_PACKET_ID, b"whole", false);
        for transfer in [
            bytes[..10].to_vec(),
            bytes[..18].to_vec(),
            [bytes.clone(), bytes].concat(),
        ] {
            let mut s = stream(vec![transfer]);
            assert_eq!(
                s.read(&mut [0]).unwrap_err().kind(),
                io::ErrorKind::InvalidData
            );
            assert!(s.io.writes.lock().unwrap().is_empty());
        }
    }

    #[test]
    fn checksums_remain_validated_by_existing_framing() {
        let mut bad = data(INITIAL_PACKET_ID, b"bad", false);
        bad[16] ^= 1;
        let mut kd = KdFraming::new(stream(vec![bad, data(INITIAL_PACKET_ID, b"good", false)]));
        assert_eq!(kd.recv_data().unwrap().payload, b"good");
        let writes = kd.transport_ref().io.writes.lock().unwrap();
        assert_eq!(
            writes[0],
            Header::control(PACKET_TYPE_KD_RESEND, 0).encode()
        );
        assert_eq!(
            writes[1],
            Header::control(PACKET_TYPE_KD_ACKNOWLEDGE, INITIAL_PACKET_ID).encode()
        );
    }

    #[test]
    fn clones_share_unread_data_and_have_independent_write_staging() {
        let mut s = stream(vec![data(INITIAL_PACKET_ID, b"payload", false)]);
        let mut first = [0];
        s.read_exact(&mut first).unwrap();
        let mut clone = s.try_clone().unwrap();
        assert!(Arc::ptr_eq(&s.write_lock, &clone.write_lock));
        let mut rest = vec![0; 16 + 7];
        clone.read_exact(&mut rest).unwrap();
        assert_eq!(rest.last(), Some(&0xaa));
        assert_eq!(s.io.capacities.lock().unwrap().len(), 1);
        let a = Header::control(PACKET_TYPE_KD_ACKNOWLEDGE, 1).encode();
        let b = Header::control(PACKET_TYPE_KD_ACKNOWLEDGE, 2).encode();
        s.write_all(&a[..8]).unwrap();
        clone.write_all(&b).unwrap();
        clone.flush().unwrap();
        s.write_all(&a[8..]).unwrap();
        s.flush().unwrap();
        assert_eq!(*s.io.writes.lock().unwrap(), vec![b.to_vec(), a.to_vec()]);
    }

    #[test]
    fn concurrent_clones_do_not_interleave_control_and_zlp() {
        let mut s = stream(vec![]);
        // Exercise a 16-byte max-packet fake endpoint so each CONTROL needs a ZLP.
        s.endpoints.max_packet = 16;
        let start = Arc::new(std::sync::Barrier::new(3));
        let threads: Vec<_> = (1..=2)
            .map(|id| {
                let mut clone = s.try_clone().unwrap();
                let start = Arc::clone(&start);
                std::thread::spawn(move || {
                    start.wait();
                    for _ in 0..32 {
                        clone
                            .write_all(&Header::control(PACKET_TYPE_KD_ACKNOWLEDGE, id).encode())
                            .unwrap();
                        clone.flush().unwrap();
                    }
                })
            })
            .collect();
        start.wait();
        for thread in threads {
            thread.join().unwrap();
        }
        let writes = s.io.writes.lock().unwrap();
        assert_eq!(writes.len(), 128);
        for pair in writes.chunks_exact(2) {
            assert_eq!(pair[0].len(), 16);
            assert!(pair[1].is_empty());
        }
    }

    #[test]
    fn outbound_data_strips_internal_trailer_before_usb() {
        let payload = [0x35; 56];
        let ack = Header::control(PACKET_TYPE_KD_ACKNOWLEDGE, INITIAL_PACKET_ID)
            .encode()
            .to_vec();
        let mut kd = KdFraming::new(stream(vec![ack]));

        kd.send_data(PACKET_TYPE_KD_STATE_MANIPULATE, &payload)
            .unwrap();

        let mut expected =
            Header::data(PACKET_TYPE_KD_STATE_MANIPULATE, INITIAL_PACKET_ID, &payload)
                .encode()
                .to_vec();
        expected.extend_from_slice(&payload);
        assert_eq!(expected.len(), 72);

        let writes = kd.transport_ref().io.writes.lock().unwrap();
        assert_eq!(*writes, vec![expected]);
        assert_ne!(writes[0].last(), Some(&PACKET_TRAILING_BYTE));
    }

    #[test]
    fn usb_data_uses_wire_length_for_zlp_after_trailer_strip() {
        // 16-byte header + 1008-byte payload = one exact 1024-byte USB transfer.
        // Generic KdFraming stages 1025 bytes including its internal 0xaa; the USB
        // adapter strips it first, so the recovered USB2DBG ZLP rule applies to 1024.
        let payload = vec![0x41; 1008];
        let ack = Header::control(PACKET_TYPE_KD_ACKNOWLEDGE, INITIAL_PACKET_ID)
            .encode()
            .to_vec();
        let mut kd = KdFraming::new(stream(vec![ack]));

        kd.send_data(PACKET_TYPE_KD_STATE_MANIPULATE, &payload)
            .unwrap();

        let writes = kd.transport_ref().io.writes.lock().unwrap();
        assert_eq!(writes.len(), 2);
        assert_eq!(writes[0].len(), 1024);
        assert!(writes[1].is_empty());
        assert_ne!(writes[0].last(), Some(&PACKET_TRAILING_BYTE));
    }

    #[test]
    fn direct_trailerless_data_and_breakin_remain_rejected_at_internal_boundary() {
        let mut s = stream(vec![]);
        let bare = data(INITIAL_PACKET_ID, b"payload", false);
        s.write_all(&bare).unwrap();
        assert_eq!(s.flush().unwrap_err().kind(), io::ErrorKind::InvalidData);
        assert!(s.io.writes.lock().unwrap().is_empty());

        s.write_all(&[BREAKIN_BYTE]).unwrap();
        assert_eq!(s.flush().unwrap_err().kind(), io::ErrorKind::Unsupported);
        assert!(s.io.writes.lock().unwrap().is_empty());
    }

    #[test]
    fn short_write_is_not_replayed_by_this_stream_or_its_clone() {
        let mut s = stream(vec![]);
        Arc::get_mut(&mut s.io).unwrap().short_write = true;
        let mut clone = s.try_clone().unwrap();
        let ack = Header::control(PACKET_TYPE_KD_ACKNOWLEDGE, INITIAL_PACKET_ID).encode();
        s.write_all(&ack).unwrap();
        assert_eq!(s.flush().unwrap_err().kind(), io::ErrorKind::WriteZero);
        assert!(clone.write_all(&ack).is_err());
        assert!(clone.flush().is_err());
        assert_eq!(s.io.writes.lock().unwrap().len(), 1);
    }

    #[test]
    fn write_plan_is_independent_of_outbound_data_trailer() {
        for (len, expected) in [
            (0, vec![]),
            (1, vec![1]),
            (1024, vec![1024, 0]),
            (4096, vec![4096, 0]),
            (4097, vec![4096, 1]),
            (8192, vec![4096, 4096, 0]),
        ] {
            assert_eq!(usb3_write_plan(len, 1024).unwrap(), expected);
        }
        assert!(usb3_write_plan(1, 0).is_err());
    }

    #[test]
    fn name_validation_and_bounded_timeout() {
        for name in [
            b"NAME=\0\0".as_slice(),
            b"NAME=TEST\0",
            b"NAME=bad\0inside\0\0",
        ] {
            assert!(parse_name(name).is_err());
        }
        assert!(parse_name(&[b"NAME=".as_slice(), &[b'X'; 25], &[0, 0]].concat()).is_err());
        let mut s = stream(vec![]);
        assert!(s.set_read_timeout(Duration::ZERO).is_err());
        s.set_read_timeout(Duration::from_millis(20)).unwrap();
        assert_eq!(s.timeout, Duration::from_millis(20));
    }

    #[test]
    fn libusb_timeouts_never_round_to_infinite_or_wrap() {
        assert_eq!(usb_timeout_ms(Duration::from_nanos(1)).unwrap(), 1);
        assert_eq!(usb_timeout_ms(Duration::from_micros(1500)).unwrap(), 2);
        assert_eq!(usb_timeout_ms(Duration::from_millis(20)).unwrap(), 20);
        assert!(usb_timeout_ms(Duration::ZERO).is_err());
        assert!(usb_timeout_ms(Duration::from_millis(u64::from(u32::MAX) + 1)).is_err());
    }

    #[test]
    fn partial_libusb_errors_never_become_successful_transfer_boundaries() {
        use rusb::constants::*;
        assert_eq!(bulk_result(0, 346, 4017).unwrap(), 346);
        assert_eq!(bulk_result(0, 0, 4017).unwrap(), 0);
        assert!(bulk_result(0, -1, 4017).is_err());
        assert!(bulk_result(0, 4018, 4017).is_err());
        assert_eq!(
            bulk_result(LIBUSB_ERROR_TIMEOUT, 0, 4017)
                .unwrap_err()
                .kind(),
            io::ErrorKind::TimedOut
        );
        assert_eq!(
            bulk_result(LIBUSB_ERROR_TIMEOUT, 346, 4017)
                .unwrap_err()
                .kind(),
            io::ErrorKind::InvalidData
        );
        assert_eq!(
            bulk_result(LIBUSB_ERROR_INTERRUPTED, 346, 4017)
                .unwrap_err()
                .kind(),
            io::ErrorKind::InvalidData
        );
        assert_eq!(
            bulk_result(LIBUSB_ERROR_OVERFLOW, 346, 4017)
                .unwrap_err()
                .kind(),
            io::ErrorKind::InvalidData
        );
    }

    #[test]
    fn r39_short_out_prevents_in_and_preserves_one_submit_across_clones() {
        let mut s = stream(vec![]);
        let fake = Arc::get_mut(&mut s.io).unwrap();
        fake.short_write = true;
        let first = s.probe_name(b"TEST").unwrap_err();
        assert_eq!(first.kind(), io::ErrorKind::WriteZero);
        let mut clone = s.try_clone().unwrap();
        let later = clone.probe_name(b"TEST").unwrap_err();
        let a = first.get_ref().unwrap().downcast_ref::<TransportFailure>().unwrap();
        let b = later.get_ref().unwrap().downcast_ref::<TransportFailure>().unwrap();
        assert!(Arc::ptr_eq(&a.original, &b.original));
        assert_eq!(*s.io.writes.lock().unwrap(), vec![NAME_PROBE.to_vec()]);
        assert!(s.io.capacities.lock().unwrap().is_empty());
    }

    #[test]
    fn r39_exact_short_name_and_extra_kd_bytes_are_preserved() {
        let mut bytes = b"NAME=CLSA0102_USB\0\0".to_vec();
        assert_eq!(bytes.len(), 19);
        let packet = Header::data(0x000b, INITIAL_PACKET_ID, b"file-io-prefetch").encode();
        bytes.extend_from_slice(&packet);
        bytes.extend_from_slice(b"file-io-prefetch");
        let mut s = stream(vec![bytes]);
        s.probe_name(b"CLSA0102_USB").unwrap();
        let count = s.receive.lock().unwrap().pending.len();
        assert_eq!(count, HEADER_SIZE + b"file-io-prefetch".len() + 1);
        assert!(s.probe_name(b"CLSA0102_USB").is_err());
        assert_eq!(*s.io.capacities.lock().unwrap(), vec![4016]);
        assert_eq!(*s.io.writes.lock().unwrap(), vec![NAME_PROBE.to_vec()]);
    }

    #[test]
    fn r39_raw_error_types_survive_io_and_kd_wrapping() {
        use rusb::constants::*;
        for (status, raw) in [
            (LIBUSB_ERROR_PIPE, rusb::Error::Pipe),
            (LIBUSB_ERROR_TIMEOUT, rusb::Error::Timeout),
            (LIBUSB_ERROR_IO, rusb::Error::Io),
            (LIBUSB_ERROR_NO_DEVICE, rusb::Error::NoDevice),
        ] {
            let error = bulk_result(status, 0, 4016).unwrap_err();
            let mut session = SessionState::default();
            let error = session.fail("NAME IN", 0x81, 4016, error);
            let wrapped = crate::error::Error::from(error);
            let crate::error::Error::Io(error) = wrapped else { panic!("lost IO error") };
            let fault = error.get_ref().unwrap().downcast_ref::<TransportFailure>().unwrap();
            let bulk = fault.original.get_ref().unwrap().downcast_ref::<BulkFailure>().unwrap();
            assert_eq!(bulk.error, raw);
            assert_eq!(bulk.status, status);
            assert_eq!((fault.stage, fault.endpoint, fault.requested), ("NAME IN", 0x81, 4016));
        }
    }

    #[test]
    fn r39_terminal_framing_timeout_does_not_retry_or_emit_reset_ack() {
        let mut kd = KdFraming::new(stream(vec![]));
        let error = kd.send_data(PACKET_TYPE_KD_STATE_MANIPULATE, b"data").unwrap_err();
        assert!(matches!(error, crate::error::Error::Io(_)));
        assert_eq!(kd.transport_ref().io.writes.lock().unwrap().len(), 1);
        assert_eq!(kd.transport_ref().io.capacities.lock().unwrap().len(), 1);
        assert!(kd.send_reset().is_err());
        assert_eq!(kd.transport_ref().io.writes.lock().unwrap().len(), 1);
    }

    #[test]
    fn r39_default_packet_output_is_blocked() {
        let mut s = stream(vec![]);
        s.session.lock().unwrap().packet_io_admitted = false;
        for packet in [PACKET_TYPE_KD_ACKNOWLEDGE, PACKET_TYPE_KD_RESET] {
            assert!(s.write_all(&Header::control(packet, 0).encode()).is_err());
        }
        assert!(s.io.writes.lock().unwrap().is_empty());
        assert!(s.read(&mut [0]).is_err());
        assert!(s.io.capacities.lock().unwrap().is_empty());
    }

    #[test]
    fn r39_complete_19_byte_name_is_short_success() {
        let mut s = stream(vec![b"NAME=CLSA0102_USB\0\0".to_vec()]);
        s.probe_name(b"CLSA0102_USB").unwrap();
        assert_eq!(*s.io.capacities.lock().unwrap(), vec![4016]);
        assert_eq!(*s.io.writes.lock().unwrap(), vec![NAME_PROBE.to_vec()]);
    }

    #[test]
    fn r39_cleanup_failure_cannot_replace_first_fault() {
        let mut session = SessionState::default();
        let first = session.fail("NAME OUT", 0x01, 5,
            bulk_result(rusb::constants::LIBUSB_ERROR_IO, 0, 5).unwrap_err());
        let later = session.fail("cleanup", 0, 0, io::Error::other("release failed"));
        let first = first.get_ref().unwrap().downcast_ref::<TransportFailure>().unwrap();
        let later = later.get_ref().unwrap().downcast_ref::<TransportFailure>().unwrap();
        assert!(Arc::ptr_eq(&first.original, &later.original));
        assert_eq!((later.stage, later.endpoint, later.requested), ("NAME OUT", 0x01, 5));
    }

    fn unadmitted<I: BulkIo>(io: Arc<I>) -> KdUsbStream<I> {
        KdUsbStream::new(io, BulkEndpoints {
            input: 0x81, output: 0x01, max_packet: 1024,
        }, Duration::from_secs(1)).unwrap()
    }

    #[test]
    fn r40_name_success_does_not_admit_packets_or_refresh_clone_budget() {
        let io = Arc::new(FakeBulk {
            reads: Mutex::new(vec![b"NAME=CLSA0102_USB\0\0".to_vec()].into()),
            ..Default::default()
        });
        let mut s = unadmitted(Arc::clone(&io));
        let mut clone = s.try_clone().unwrap();
        assert!(Arc::ptr_eq(&s.session, &clone.session));
        s.probe_name(b"CLSA0102_USB").unwrap();
        assert_eq!(clone.probe_name(b"CLSA0102_USB").unwrap_err().kind(),
            io::ErrorKind::PermissionDenied);
        assert_eq!(clone.read(&mut [0]).unwrap_err().kind(), io::ErrorKind::PermissionDenied);
        assert_eq!(clone.write(&Header::control(PACKET_TYPE_KD_RESET, 0).encode())
            .unwrap_err().kind(), io::ErrorKind::PermissionDenied);
        clone.flush().unwrap(); // Empty staging has no submission.
        assert_eq!(*io.writes.lock().unwrap(), vec![NAME_PROBE.to_vec()]);
        assert_eq!(*io.capacities.lock().unwrap(), vec![4016]);
        assert!(!clone.session.lock().unwrap().packet_io_admitted);

        // Default admission also denies delivery of complete prefetched KD data.
        let packet = data(INITIAL_PACKET_ID, b"prefetch", false);
        let io = Arc::new(FakeBulk {
            reads: Mutex::new(vec![
                [b"NAME=CLSA0102_USB\0\0".as_slice(), &packet].concat()
            ].into()), ..Default::default()
        });
        let mut s = unadmitted(Arc::clone(&io));
        s.probe_name(b"CLSA0102_USB").unwrap();
        let snapshot = s.retained_receive().unwrap();
        assert_eq!(snapshot.0, [packet, vec![PACKET_TRAILING_BYTE]].concat());
        assert_eq!(s.read(&mut [0]).unwrap_err().kind(), io::ErrorKind::PermissionDenied);
        assert_eq!(s.retained_receive().unwrap(), snapshot);

        // Model staged data whose earlier test-only admission is withdrawn.
        s.admit_packet_io().unwrap();
        s.write_all(&Header::control(PACKET_TYPE_KD_ACKNOWLEDGE, 0).encode()).unwrap();
        s.session.lock().unwrap().packet_io_admitted = false;
        assert_eq!(s.flush().unwrap_err().kind(), io::ErrorKind::PermissionDenied);
        assert_eq!(*io.writes.lock().unwrap(), vec![NAME_PROBE.to_vec()]);
        assert_eq!(*io.capacities.lock().unwrap(), vec![4016]);
    }

    struct FaultBulk {
        out_actual: Option<usize>,
        out_status: i32,
        in_status: i32,
        partial: Vec<u8>,
        writes: Mutex<Vec<Vec<u8>>>,
        capacities: Mutex<Vec<usize>>,
    }

    impl BulkIo for FaultBulk {
        fn read_bulk(&self, endpoint: u8, bytes: &mut [u8], _: Duration) -> io::Result<usize> {
            assert_eq!(endpoint, 0x81);
            self.capacities.lock().unwrap().push(bytes.len());
            bytes[..self.partial.len()].copy_from_slice(&self.partial);
            bulk_completion(self.in_status, self.partial.len() as i32, bytes, endpoint)
        }

        fn write_bulk(&self, endpoint: u8, bytes: &[u8], _: Duration) -> io::Result<usize> {
            assert_eq!(endpoint, 0x01);
            self.writes.lock().unwrap().push(bytes.to_vec());
            bulk_completion(self.out_status, self.out_actual.unwrap_or(bytes.len()) as i32,
                bytes, endpoint)
        }
    }

    fn fault_io(out_actual: Option<usize>, out_status: i32, in_status: i32,
        partial: &[u8]) -> Arc<FaultBulk> {
        Arc::new(FaultBulk {
            out_actual, out_status, in_status, partial: partial.to_vec(),
            writes: Mutex::new(Vec::new()), capacities: Mutex::new(Vec::new()),
        })
    }

    #[test]
    fn r40_zero_short_and_failed_name_out_never_submit_in() {
        use rusb::constants::*;
        for (actual, status) in [(Some(0), 0), (Some(4), 0),
            (Some(0), LIBUSB_ERROR_PIPE), (Some(0), LIBUSB_ERROR_NO_DEVICE),
            (Some(2), LIBUSB_ERROR_TIMEOUT)] {
            let io = fault_io(actual, status, LIBUSB_ERROR_TIMEOUT, &[]);
            let mut s = unadmitted(Arc::clone(&io));
            let first = s.probe_name(b"TEST").unwrap_err();
            let fault = first.get_ref().unwrap().downcast_ref::<TransportFailure>().unwrap();
            assert_eq!((fault.stage, fault.endpoint, fault.requested), ("NAME OUT", 1, 5));
            if status != 0 {
                let bulk = fault.original.get_ref().unwrap().downcast_ref::<BulkFailure>().unwrap();
                assert_eq!((bulk.status, bulk.transferred, bulk.requested, bulk.endpoint),
                    (status, actual.unwrap() as i32, 5, Some(1)));
                assert!(bulk.partial.is_empty());
            }
            let mut clone = s.try_clone().unwrap();
            let later = clone.probe_name(b"TEST").unwrap_err();
            let later = later.get_ref().unwrap().downcast_ref::<TransportFailure>().unwrap();
            assert!(Arc::ptr_eq(&fault.original, &later.original));
            assert!(clone.admit_packet_io().is_err());
            assert_eq!(*io.writes.lock().unwrap(), vec![NAME_PROBE.to_vec()]);
            assert!(io.capacities.lock().unwrap().is_empty());
        }
    }

    #[test]
    fn r40_partial_name_in_preserves_raw_prefix_and_first_fault_across_clones() {
        use rusb::constants::*;
        for status in [LIBUSB_ERROR_TIMEOUT, LIBUSB_ERROR_INTERRUPTED,
            LIBUSB_ERROR_PIPE, LIBUSB_ERROR_IO, LIBUSB_ERROR_NO_DEVICE] {
            let prefix = b"NAME=CLSA";
            let io = fault_io(None, 0, status, prefix);
            let mut s = unadmitted(Arc::clone(&io));
            let first = s.probe_name(b"CLSA0102_USB").unwrap_err();
            let fault = first.get_ref().unwrap().downcast_ref::<TransportFailure>().unwrap();
            let bulk = fault.original.get_ref().unwrap().downcast_ref::<BulkFailure>().unwrap();
            assert_eq!((fault.stage, fault.endpoint, fault.requested), ("NAME IN", 0x81, 4016));
            assert_eq!((bulk.status, bulk.transferred, bulk.requested, bulk.endpoint),
                (status, prefix.len() as i32, 4016, Some(0x81)));
            assert_eq!(bulk.partial, prefix);
            assert_eq!(s.retained_receive().unwrap(), (vec![], vec![]));
            let mut clone = s.try_clone().unwrap();
            for later in [clone.read(&mut [0]).unwrap_err(),
                clone.write(&[0]).unwrap_err(), clone.flush().unwrap_err(),
                clone.probe_name(b"CLSA0102_USB").unwrap_err()] {
                let later = later.get_ref().unwrap().downcast_ref::<TransportFailure>().unwrap();
                assert!(Arc::ptr_eq(&fault.original, &later.original));
            }
            assert_eq!(*io.writes.lock().unwrap(), vec![NAME_PROBE.to_vec()]);
            assert_eq!(*io.capacities.lock().unwrap(), vec![4016]);
        }
    }

    #[test]
    fn r40_terminal_framing_faults_emit_no_secondary_packet() {
        use rusb::constants::*;
        for status in [LIBUSB_ERROR_TIMEOUT, LIBUSB_ERROR_PIPE, LIBUSB_ERROR_IO,
            LIBUSB_ERROR_NO_DEVICE, LIBUSB_ERROR_INTERRUPTED] {
            let io = fault_io(None, 0, status, &[]);
            let mut s = unadmitted(Arc::clone(&io));
            s.admit_packet_io().unwrap();
            let mut kd = KdFraming::new(s);
            let error = kd.send_data(PACKET_TYPE_KD_STATE_MANIPULATE, b"data").unwrap_err();
            let crate::error::Error::Io(error) = error else { panic!("lost IO error") };
            assert!(is_terminal_error(&error));
            assert!(kd.send_reset().is_err());
            assert!(kd.recv_data().is_err());
            let writes = io.writes.lock().unwrap();
            assert_eq!(writes.len(), 1);
            assert!(Header::peek(&writes[0]).unwrap().is_data());
            assert_eq!(*io.capacities.lock().unwrap(), vec![4017]);
        }
    }

    #[test]
    fn r40_first_two_nuls_reject_tail_and_preserve_it_without_io_retry() {
        let mut receive = ReceiveState::default();
        let invalid_tail = b"bad-tail";
        let bytes = [b"NAME=CLSA0102_USB\0\0".as_slice(), invalid_tail].concat();
        assert!(receive.ingest(&bytes).is_err());
        assert_eq!(receive.names.pop_front().unwrap(), b"CLSA0102_USB");
        assert_eq!(receive.name_fragment, invalid_tail);
        assert!(receive.pending.is_empty());

        let io = Arc::new(FakeBulk {
            reads: Mutex::new(vec![bytes].into()), ..Default::default()
        });
        let mut s = unadmitted(Arc::clone(&io));
        let error = s.probe_name(b"CLSA0102_USB").unwrap_err();
        let fault = error.get_ref().unwrap().downcast_ref::<TransportFailure>().unwrap();
        assert_eq!(fault.stage, "NAME parse");
        assert_eq!(s.retained_receive().unwrap(), (vec![], invalid_tail.to_vec()));
        assert!(s.try_clone().unwrap().probe_name(b"CLSA0102_USB").is_err());
        assert_eq!(io.writes.lock().unwrap().len(), 1);
        assert_eq!(*io.capacities.lock().unwrap(), vec![4016]);
    }

    #[test]
    fn r40_blocking_callbacks_observe_session_and_receive_lock_ownership() {
        struct InspectBulk {
            session: Arc<Mutex<SessionState>>,
            receive: Arc<Mutex<ReceiveState>>,
            observations: Mutex<Vec<(bool, bool)>>,
        }
        impl BulkIo for InspectBulk {
            fn read_bulk(&self, _: u8, bytes: &mut [u8], _: Duration) -> io::Result<usize> {
                let mut observations = self.observations.lock().unwrap();
                observations.push((
                    matches!(self.session.try_lock(), Err(std::sync::TryLockError::WouldBlock)),
                    matches!(self.receive.try_lock(), Err(std::sync::TryLockError::WouldBlock)),
                ));
                let transfer = if observations.len() == 1 {
                    b"NAME=TEST\0\0".to_vec()
                } else {
                    data(INITIAL_PACKET_ID, b"ok", false)
                };
                bytes[..transfer.len()].copy_from_slice(&transfer);
                Ok(transfer.len())
            }
            fn write_bulk(&self, _: u8, bytes: &[u8], _: Duration) -> io::Result<usize> {
                assert!(matches!(self.session.try_lock(),
                    Err(std::sync::TryLockError::WouldBlock)));
                Ok(bytes.len())
            }
        }
        let session = Arc::new(Mutex::new(SessionState::default()));
        let receive = Arc::new(Mutex::new(ReceiveState::default()));
        let io = Arc::new(InspectBulk {
            session: Arc::clone(&session), receive: Arc::clone(&receive),
            observations: Mutex::new(vec![]),
        });
        let mut s = unadmitted(Arc::clone(&io));
        s.session = session;
        s.receive = receive;
        s.probe_name(b"TEST").unwrap();
        s.admit_packet_io().unwrap();
        assert_eq!(s.read(&mut [0]).unwrap(), 1);
        let observations = io.observations.lock().unwrap();
        assert_eq!(observations.len(), 2);
        assert_eq!(observations[0], (true, false));
        assert!(observations[1..].iter().all(|pair| *pair == (true, true)));
    }

    #[test]
    fn r40_poisoned_session_blocks_all_submissions() {
        let io = Arc::new(FakeBulk::default());
        let mut s = unadmitted(Arc::clone(&io));
        let session = Arc::clone(&s.session);
        assert!(std::thread::spawn(move || {
            let _guard = session.lock().unwrap();
            panic!("pure fixture poisons session");
        }).join().is_err());
        assert!(s.probe_name(b"TEST").is_err());
        assert!(s.read(&mut [0]).is_err());
        assert!(s.write(&[0]).is_err());
        assert!(s.flush().is_err());
        assert!(s.try_clone().unwrap().admit_packet_io().is_err());
        assert!(io.writes.lock().unwrap().is_empty());
        assert!(io.capacities.lock().unwrap().is_empty());
    }

    #[test]
    fn r40_unmarked_framing_timeout_keeps_historical_retry_budget() {
        #[derive(Default)]
        struct PlainTimeout {
            writes: Vec<Vec<u8>>,
            flushes: usize,
            reads: usize,
        }
        impl Read for PlainTimeout {
            fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
                self.reads += 1;
                Err(io::Error::new(io::ErrorKind::TimedOut, "pure generic timeout"))
            }
        }
        impl Write for PlainTimeout {
            fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
                self.writes.push(bytes.to_vec());
                Ok(bytes.len())
            }
            fn flush(&mut self) -> io::Result<()> {
                self.flushes += 1;
                Ok(())
            }
        }
        let mut kd = KdFraming::new(PlainTimeout::default());
        assert!(matches!(kd.send_data(PACKET_TYPE_KD_STATE_MANIPULATE, b"data"),
            Err(crate::error::Error::KdSendExhausted(_))));
        let io = kd.transport_ref();
        assert_eq!((io.flushes, io.reads, io.writes.len()), (5, 5, 15));
        for write in io.writes.chunks_exact(3) {
            let header = Header::peek(&write[0]).unwrap();
            assert!(header.is_data());
            assert_eq!(header.packet_id, INITIAL_PACKET_ID);
            assert_eq!(write[1], b"data");
            assert_eq!(write[2], [PACKET_TRAILING_BYTE]);
        }
    }
}
