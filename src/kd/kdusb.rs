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
    bulk_result(status, transferred, bytes.len())
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

fn bulk_result(status: i32, transferred: i32, capacity: usize) -> io::Result<usize> {
    use rusb::constants::*;
    if status != 0 {
        let kind = match status {
            LIBUSB_ERROR_TIMEOUT if transferred == 0 => io::ErrorKind::TimedOut,
            LIBUSB_ERROR_NO_DEVICE => io::ErrorKind::NotConnected,
            LIBUSB_ERROR_ACCESS => io::ErrorKind::PermissionDenied,
            LIBUSB_ERROR_OVERFLOW => io::ErrorKind::InvalidData,
            // Partial timed-out/interrupted transfers must not be normalized.
            LIBUSB_ERROR_TIMEOUT | LIBUSB_ERROR_INTERRUPTED => io::ErrorKind::InvalidData,
            _ => io::ErrorKind::Other,
        };
        return Err(io::Error::new(
            kind,
            format!("libusb bulk status {status}, transferred {transferred}"),
        ));
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
            if self.name_fragment.len() + transfer.len() > NAME_MAX {
                self.name_fragment.clear();
                return Err(invalid("oversized KDUSB NAME reply"));
            }
            self.name_fragment.extend_from_slice(transfer);
            let bytes = &self.name_fragment;
            if !(bytes.starts_with(NAME_PREFIX) || NAME_PREFIX.starts_with(bytes)) {
                self.name_fragment.clear();
                return Err(invalid("invalid split KDUSB NAME prefix"));
            }
            if bytes.ends_with(&[0, 0]) {
                let result = parse_name(bytes).map(<[u8]>::to_vec);
                self.name_fragment.clear();
                let name = result?;
                // Bound unattended discovery traffic.
                if self.names.len() == 16 {
                    return Err(invalid("too many unconsumed KDUSB NAME replies"));
                }
                self.names.push_back(name);
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

    /// Send NAME? and wait for the matching target identity without discarding
    /// KD completions that arrive before the NAME reply.
    pub(crate) fn probe_name(&mut self, expected: &[u8]) -> io::Result<()> {
        if expected.is_empty()
            || expected.len() > TARGET_NAME_MAX
            || !expected.is_ascii()
            || expected.contains(&0)
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "KDUSB target name must be 1..=24 non-NUL ASCII bytes",
            ));
        }

        let written = self
            .io
            .write_bulk(self.endpoints.output, NAME_PROBE, self.timeout)
            .map_err(|err| {
                io::Error::new(
                    err.kind(),
                    format!(
                        "KDUSB NAME? bulk OUT endpoint {:#04x} failed: {err}",
                        self.endpoints.output
                    ),
                )
            })?;
        if written != NAME_PROBE.len() {
            return Err(io::Error::new(
                io::ErrorKind::WriteZero,
                format!(
                    "short KDUSB NAME? probe: wrote {written} of {} bytes",
                    NAME_PROBE.len()
                ),
            ));
        }

        let start = Instant::now();
        loop {
            {
                let mut receive = self
                    .receive
                    .lock()
                    .map_err(|_| io::Error::other("receive lock poisoned"))?;
                if let Some(name) = receive.names.pop_front() {
                    if name == expected {
                        return Ok(());
                    }
                    return Err(io::Error::new(
                        io::ErrorKind::NotFound,
                        format!(
                            "KDUSB NAME mismatch: expected {:?}, got {:?}",
                            String::from_utf8_lossy(expected),
                            String::from_utf8_lossy(&name)
                        ),
                    ));
                }
            }

            let remaining = self
                .timeout
                .checked_sub(start.elapsed())
                .filter(|t| !t.is_zero())
                .ok_or_else(|| {
                    io::Error::new(io::ErrorKind::TimedOut, "KDUSB NAME discovery deadline")
                })?;
            let mut transfer = [0u8; RECEIVE_CAPACITY];
            let len = self
                .io
                .read_bulk(self.endpoints.input, &mut transfer, remaining)
                .map_err(|err| {
                    io::Error::new(
                        err.kind(),
                        format!(
                            "KDUSB NAME reply bulk IN endpoint {:#04x} failed: {err}",
                            self.endpoints.input
                        ),
                    )
                })?;
            let bytes = transfer
                .get(..len)
                .ok_or_else(|| invalid("bulk read overflow"))?;
            self.receive
                .lock()
                .map_err(|_| io::Error::other("receive lock poisoned"))?
                .ingest(bytes)?;
        }
    }
}

impl<I: BulkIo> Read for KdUsbStream<I> {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        if output.is_empty() {
            return Ok(0);
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
                .ok_or_else(|| io::Error::new(io::ErrorKind::TimedOut, "KDUSB receive deadline"))?;
            let mut transfer = [0u8; RECEIVE_CAPACITY];
            let len = self
                .io
                .read_bulk(self.endpoints.input, &mut transfer, remaining)?;
            let bytes = transfer
                .get(..len)
                .ok_or_else(|| invalid("bulk read overflow"))?;
            receive.ingest(bytes)?;
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
        if self.transmit.is_empty() {
            return Ok(());
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
                    return Err(match result {
                        Err(error) => error,
                        _ => io::Error::new(
                            io::ErrorKind::WriteZero,
                            "short KDUSB write; no automatic retry",
                        ),
                    });
                }
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests;
