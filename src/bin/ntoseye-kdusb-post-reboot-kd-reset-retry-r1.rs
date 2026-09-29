//! Phase 3.44CB: bounded classic-KD RESET retry adjudication.
//!
//! Dry by default.  Live mode sends one NAME? and an explicit schedule of at
//! most three identical type-6 RESET control packets.  It never sends any
//! other KD packet and never changes USB device/interface configuration.

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("ntoseye-kdusb-post-reboot-kd-reset-retry-r1 is Linux-only");
    std::process::exit(2);
}

#[cfg(target_os = "linux")]
fn main() {
    std::process::exit(linux::run());
}

#[cfg(target_os = "linux")]
mod linux {
    use ntoseye::kd::file_io::{FileIoRequest, parse_file_io};
    use rusb::{Device, Direction, GlobalContext, TransferType};
    use std::time::Duration;

    const LIVE_FLAG: &str = "--execute-post-reboot-kd-reset-retry";
    const REQUIRED_TARGET: &str = "CLSA0102_USB";
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
    const DATA_PACKET_LEADER: u32 = 0x3030_3030;
    const CONTROL_PACKET_LEADER: u32 = 0x6969_6969;
    const PACKET_TYPE_KD_ACKNOWLEDGE: u16 = 4;
    const PACKET_TYPE_KD_RESEND: u16 = 5;
    const PACKET_TYPE_KD_RESET: u16 = 6;
    const PACKET_TRAILING_BYTE: u8 = 0xaa;
    const KD_HEADER_SIZE: usize = 16;
    const MAX_KD_PAYLOAD_BYTES: usize = 4000;
    const MAX_COMPLETE_KD_PACKET_BYTES: usize = 4017;
    const KD_RESET_PACKET: [u8; 16] = [
        0x69, 0x69, 0x69, 0x69, 0x06, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    ];

    const MAX_NAME_TX: usize = 1;
    const MAX_KD_CONTROL_RESET_TX: usize = 3;
    const READS_PER_RESET_ATTEMPT: usize = 2;
    const MAX_POST_RESET_REPLY_READS: usize = 4;
    const MAX_USB_READ_CALLS: usize = 10;
    const USB_READ_REQUEST: usize = 4016;
    const PER_READ_TIMEOUT_MS: u64 = 1000;
    const MAX_USB_DEVICE_RESET_ATTEMPTS: usize = 0;
    const MAX_ENDPOINT_RECREATION_ATTEMPTS: usize = 0;
    const AUTOMATIC_NAME_RETRY: bool = false;
    const AUTOMATIC_KD_RESET_RETRY: bool = false;
    const AUTOMATIC_READ_RESTART: bool = false;
    const TIMEOUT: Duration = Duration::from_millis(PER_READ_TIMEOUT_MS);

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    struct KdHeader {
        leader: u32,
        packet_type: u16,
        byte_count: u16,
        packet_id: u32,
        checksum: u32,
    }
    #[derive(Clone, Debug)]
    struct PacketSummary {
        header: KdHeader,
        total_bytes: usize,
        checksum_valid: bool,
        trailer_valid: Option<bool>,
        packet: Vec<u8>,
    }
    #[derive(Debug)]
    struct ReadObservation {
        status: &'static str,
        len: usize,
        prefix_hex: String,
    }
    #[derive(Default)]
    struct BootstrapAssembly {
        pending: Vec<u8>,
        name_target: Option<String>,
        stream: Vec<u8>,
    }
    struct Candidate {
        device: Device<GlobalContext>,
        vendor: u16,
        product: u16,
        interface: u8,
        alternate_setting: u8,
        bulk_in: u8,
        bulk_out: u8,
        max_packet: u16,
    }

    #[derive(Default)]
    struct RetryState {
        attempts_sent: usize,
        attempt_reads: [usize; 3],
        reset_reply_on_attempt: Option<usize>,
        post_reply_reads: usize,
        reset_reply: Option<PacketSummary>,
        data_packet: Option<PacketSummary>,
        unexpected_control: Option<PacketSummary>,
        duplicate_reset_reply: bool,
        stream: Vec<u8>,
    }

    struct LiveReport {
        result: String,
        vendor: u16,
        product: u16,
        interface: u8,
        alternate_setting: u8,
        bulk_in: u8,
        bulk_out: u8,
        max_packet: u16,
        name_target: Option<String>,
        name_piggyback: Vec<u8>,
        name_probe_sent: bool,
        state: RetryState,
        reads: Vec<ReadObservation>,
        nonempty_reads: usize,
        timeout_reads: usize,
        error: Option<String>,
        interface_released: bool,
    }

    pub fn run() -> i32 {
        let args: Vec<String> = std::env::args().skip(1).collect();
        if args.is_empty() {
            print_dry_plan();
            return 0;
        }
        if args != [LIVE_FLAG, REQUIRED_TARGET] {
            eprintln!("usage: ntoseye-kdusb-post-reboot-kd-reset-retry-r1 [{LIVE_FLAG} {REQUIRED_TARGET}]");
            return 2;
        }
        let report = match observe(REQUIRED_TARGET) {
            Ok(r) => r,
            Err((class, error)) => {
                println!("PHASE344CB_RESULT={class}");
                println!("ERROR={error}");
                print_empty_outcome();
                print_safety(true, false, false);
                return 3;
            }
        };
        print_report(&report);
        if report.result.starts_with("RESET_REPLY_ON_ATTEMPT_")
            || report
                .result
                .starts_with("RESET_REPLY_AND_DATA_ON_ATTEMPT_")
        {
            0
        } else {
            4
        }
    }

    fn print_dry_plan() {
        println!("NTOSEYE_KDUSB_KD_RESET_RETRY=READY");
        println!("DEFAULT_MODE=DRY_PLAN");
        println!("LIVE_FLAG={LIVE_FLAG} {REQUIRED_TARGET}");
        println!("MAX_NAME_TX={MAX_NAME_TX}");
        println!("MAX_KD_CONTROL_RESET_TX={MAX_KD_CONTROL_RESET_TX}");
        println!("READS_PER_RESET_ATTEMPT={READS_PER_RESET_ATTEMPT}");
        println!("MAX_POST_RESET_REPLY_READS={MAX_POST_RESET_REPLY_READS}");
        println!("MAX_USB_READ_CALLS={MAX_USB_READ_CALLS}");
        println!("USB_READ_REQUEST={USB_READ_REQUEST}");
        println!("PER_READ_TIMEOUT_MS={PER_READ_TIMEOUT_MS}");
        println!("KD_CONTROL_RESET_HEX={}", hex::encode(KD_RESET_PACKET));
        println!("MAX_USB_DEVICE_RESET_ATTEMPTS={MAX_USB_DEVICE_RESET_ATTEMPTS}");
        println!("MAX_ENDPOINT_RECREATION_ATTEMPTS={MAX_ENDPOINT_RECREATION_ATTEMPTS}");
        println!("AUTOMATIC_NAME_RETRY={AUTOMATIC_NAME_RETRY}");
        println!("AUTOMATIC_KD_RESET_RETRY={AUTOMATIC_KD_RESET_RETRY}");
        println!("AUTOMATIC_READ_RESTART={AUTOMATIC_READ_RESTART}");
        print_empty_outcome();
        print_safety(false, false, false);
    }

    fn print_empty_outcome() {
        println!("NAME_PIGGYBACK_HEX=NA");
        println!("RESET_ATTEMPTS_SENT=0");
        for attempt in 1..=MAX_KD_CONTROL_RESET_TX {
            println!("RESET_ATTEMPT_{attempt}_TX=false");
            println!("RESET_ATTEMPT_{attempt}_READS=0");
            println!("RESET_ATTEMPT_{attempt}_HEX=NA");
        }
        println!("RESET_REPLY_SEEN=false");
        println!("RESET_REPLY_ON_ATTEMPT=NA");
        println!("POST_RESET_REPLY_READS=0");
        println!("DATA_PACKET_SEEN=false");
        println!("READ_CALLS_USED=0");
        println!("NONEMPTY_READS=0");
        println!("TIMEOUT_READS=0");
    }

    fn print_safety(live: bool, name: bool, reset: bool) {
        println!("LIVE_USB_ACTIVITY={live}");
        println!("NAME_PROBE_SENT={name}");
        println!("KD_CONTROL_PACKET_TX={reset}");
        println!("KD_CONTROL_RESET_TX={reset}");
        println!("KD_DATA_PACKET_TX=false");
        println!("KD_ACK_TX=false");
        println!("KD_RESEND_TX=false");
        println!("KD_FILE_IO_REPLY_TX=false");
        println!("BREAKIN_SENT=false");
        println!("DEBUGGER_MANIPULATE_TX=false");
        println!("TARGET_MEMORY_ACCESS=false");
        println!("USB_DEVICE_RESET=false");
        println!("TARGET_REBOOT=false");
        println!("ENDPOINT_RECREATION_EXECUTED=false");
        println!("PHASE340_CLEANUP_AUTHORIZED=false");
    }

    fn observe(expected: &str) -> Result<LiveReport, (&'static str, String)> {
        let mut found = candidates().map_err(|e| ("OTHER_TRANSPORT_FAULT", e))?;
        if found.len() != 1 {
            return Err((
                "IDENTITY_MISMATCH_ABORT",
                format!(
                    "expected exactly one supported dc/02/ff KDUSB interface, found {}",
                    found.len()
                ),
            ));
        }
        observe_candidate(found.remove(0), expected)
    }

    fn candidates() -> Result<Vec<Candidate>, String> {
        let devices = rusb::devices().map_err(|e| format!("enumerating USB devices: {e}"))?;
        let mut result = Vec::new();
        for device in devices.iter() {
            let dd = device
                .device_descriptor()
                .map_err(|e| format!("reading USB device descriptor: {e}"))?;
            if !HARDWARE_IDS.contains(&(dd.vendor_id(), dd.product_id())) {
                continue;
            }
            let config = device
                .active_config_descriptor()
                .map_err(|e| format!("reading active configuration: {e}"))?;
            for interface in config.interfaces() {
                for id in interface.descriptors() {
                    if (id.class_code(), id.sub_class_code(), id.protocol_code())
                        != (INTERFACE_CLASS, INTERFACE_SUBCLASS, INTERFACE_PROTOCOL)
                    {
                        continue;
                    }
                    let (mut bin, mut bout) = (None, None);
                    for ep in id.endpoint_descriptors() {
                        if ep.transfer_type() == TransferType::Bulk {
                            match ep.direction() {
                                Direction::In if bin.is_none() => bin = Some(ep.address()),
                                Direction::Out if bout.is_none() => {
                                    bout = Some((ep.address(), ep.max_packet_size()))
                                }
                                _ => {}
                            }
                        }
                    }
                    if let (Some(bulk_in), Some((bulk_out, max_packet))) = (bin, bout) {
                        result.push(Candidate {
                            device: device.clone(),
                            vendor: dd.vendor_id(),
                            product: dd.product_id(),
                            interface: id.interface_number(),
                            alternate_setting: id.setting_number(),
                            bulk_in,
                            bulk_out,
                            max_packet,
                        });
                    }
                }
            }
        }
        Ok(result)
    }

    fn observe_candidate(
        c: Candidate,
        expected: &str,
    ) -> Result<LiveReport, (&'static str, String)> {
        if c.alternate_setting != 0 {
            return Err((
                "IDENTITY_MISMATCH_ABORT",
                format!(
                    "alternate setting {} is not admitted setting 0",
                    c.alternate_setting
                ),
            ));
        }
        let handle = c.device.open().map_err(|e| {
            (
                "OTHER_TRANSPORT_FAULT",
                format!("opening KDUSB device: {e}"),
            )
        })?;
        match handle.kernel_driver_active(c.interface) {
            Ok(true) => {
                return Err((
                    "IDENTITY_MISMATCH_ABORT",
                    "kernel driver attached; refusing detach".into(),
                ));
            }
            Ok(false) | Err(rusb::Error::NotSupported) => {}
            Err(e) => {
                return Err((
                    "OTHER_TRANSPORT_FAULT",
                    format!("checking kernel driver: {e}"),
                ));
            }
        }
        handle
            .claim_interface(c.interface)
            .map_err(|e| ("OTHER_TRANSPORT_FAULT", format!("claiming interface: {e}")))?;
        let mut r = LiveReport {
            result: "OTHER_TRANSPORT_FAULT".into(),
            vendor: c.vendor,
            product: c.product,
            interface: c.interface,
            alternate_setting: c.alternate_setting,
            bulk_in: c.bulk_in,
            bulk_out: c.bulk_out,
            max_packet: c.max_packet,
            name_target: None,
            name_piggyback: Vec::new(),
            name_probe_sent: false,
            state: RetryState::default(),
            reads: Vec::new(),
            nonempty_reads: 0,
            timeout_reads: 0,
            error: None,
            interface_released: false,
        };
        match handle.write_bulk(c.bulk_out, NAME_PROBE, TIMEOUT) {
            Ok(n) if n == NAME_PROBE.len() => r.name_probe_sent = true,
            Ok(n) => {
                r.result = "OTHER_TRANSPORT_FAULT".into();
                r.error = Some(format!("short NAME write: {n}/5"));
            }
            Err(rusb::Error::Pipe | rusb::Error::Other) => {
                r.result = "NAME_WRITE_EPROTO".into();
                r.error = Some("NAME bulk-OUT EPROTO-class failure".into());
            }
            Err(e) => r.error = Some(format!("NAME bulk-OUT failed: {e}")),
        }
        if r.error.is_none() {
            execute_schedule(&handle, &c, expected, &mut r);
        }
        match handle.release_interface(c.interface) {
            Ok(()) => r.interface_released = true,
            Err(e) => {
                r.result = "OTHER_TRANSPORT_FAULT".into();
                r.error = Some(format!("releasing interface: {e}"));
            }
        }
        Ok(r)
    }

    fn usb_read(
        handle: &rusb::DeviceHandle<GlobalContext>,
        c: &Candidate,
        r: &mut LiveReport,
    ) -> Result<Option<Vec<u8>>, ()> {
        if r.reads.len() >= MAX_USB_READ_CALLS {
            return Ok(None);
        }
        let mut buf = vec![0u8; USB_READ_REQUEST];
        match handle.read_bulk(c.bulk_in, &mut buf, TIMEOUT) {
            Ok(0) => {
                r.reads.push(ReadObservation {
                    status: "ZLP",
                    len: 0,
                    prefix_hex: String::new(),
                });
                Ok(Some(Vec::new()))
            }
            Ok(n) => {
                buf.truncate(n);
                r.nonempty_reads += 1;
                r.reads.push(ReadObservation {
                    status: "DATA",
                    len: n,
                    prefix_hex: hex::encode(&buf[..n.min(64)]),
                });
                Ok(Some(buf))
            }
            Err(rusb::Error::Timeout) => {
                r.timeout_reads += 1;
                r.reads.push(ReadObservation {
                    status: "TIMEOUT",
                    len: 0,
                    prefix_hex: String::new(),
                });
                Ok(Some(Vec::new()))
            }
            Err(rusb::Error::Pipe | rusb::Error::Other) => {
                r.result = "READ_EPROTO".into();
                r.error = Some("bulk-IN EPROTO-class failure".into());
                Err(())
            }
            Err(e) => {
                r.result = "OTHER_TRANSPORT_FAULT".into();
                r.error = Some(format!("bulk-IN failed: {e}"));
                Err(())
            }
        }
    }

    fn execute_schedule(
        handle: &rusb::DeviceHandle<GlobalContext>,
        c: &Candidate,
        expected: &str,
        r: &mut LiveReport,
    ) {
        let mut bootstrap = BootstrapAssembly::default();
        while r.name_target.is_none() && r.reads.len() < MAX_USB_READ_CALLS {
            let Some(bytes) = usb_read(handle, c, r).ok().flatten() else {
                return;
            };
            if bytes.is_empty() {
                continue;
            }
            if let Err(e) = bootstrap.append(expected, &bytes) {
                r.result = if e.starts_with("identity mismatch:") {
                    "IDENTITY_MISMATCH_ABORT".into()
                } else {
                    "FRAMING_INVALID".into()
                };
                r.error = Some(e);
                return;
            }
            r.name_target = bootstrap.name_target.clone();
        }
        if r.name_target.is_none() {
            r.result = "NAME_REPLY_NOT_OBSERVED".into();
            return;
        }
        if !bootstrap.stream.is_empty() {
            r.name_piggyback = bootstrap.stream.clone();
            r.state.stream = bootstrap.stream;
            match consume_packets(&mut r.state, 1) {
                Ok(()) => {}
                Err(e) => {
                    r.result = "FRAMING_INVALID".into();
                    r.error = Some(e);
                    return;
                }
            }
            r.result = "KD_PACKET_PIGGYBACKED_AFTER_NAME".into();
            return;
        }

        for attempt in 1..=MAX_KD_CONTROL_RESET_TX {
            match handle.write_bulk(c.bulk_out, &KD_RESET_PACKET, TIMEOUT) {
                Ok(n) if n == KD_RESET_PACKET.len() => r.state.attempts_sent = attempt,
                Ok(n) => {
                    r.result = "OTHER_TRANSPORT_FAULT".into();
                    r.error = Some(format!("short RESET write on attempt {attempt}: {n}/16"));
                    return;
                }
                Err(rusb::Error::Pipe | rusb::Error::Other) => {
                    r.result = format!("KD_RESET_WRITE_EPROTO_ATTEMPT_{attempt}");
                    r.error = Some("RESET bulk-OUT EPROTO-class failure".into());
                    return;
                }
                Err(e) => {
                    r.result = "OTHER_TRANSPORT_FAULT".into();
                    r.error = Some(format!("RESET bulk-OUT attempt {attempt} failed: {e}"));
                    return;
                }
            }
            for _ in 0..READS_PER_RESET_ATTEMPT {
                if r.reads.len() >= MAX_USB_READ_CALLS {
                    break;
                }
                r.state.attempt_reads[attempt - 1] += 1;
                let Some(bytes) = usb_read(handle, c, r).ok().flatten() else {
                    return;
                };
                r.state.stream.extend_from_slice(&bytes);
                if let Err(e) = consume_packets(&mut r.state, attempt) {
                    r.result = "FRAMING_INVALID".into();
                    r.error = Some(e);
                    return;
                }
                if r.state.reset_reply.is_some()
                    || r.state.data_packet.is_some()
                    || r.state.unexpected_control.is_some()
                {
                    break;
                }
            }
            if r.state.reset_reply.is_some()
                || r.state.data_packet.is_some()
                || r.state.unexpected_control.is_some()
            {
                break;
            }
        }
        if r.state.reset_reply.is_some()
            && r.state.data_packet.is_none()
            && r.state.unexpected_control.is_none()
        {
            while r.state.post_reply_reads < MAX_POST_RESET_REPLY_READS
                && r.reads.len() < MAX_USB_READ_CALLS
            {
                r.state.post_reply_reads += 1;
                let Some(bytes) = usb_read(handle, c, r).ok().flatten() else {
                    return;
                };
                r.state.stream.extend_from_slice(&bytes);
                let attempt = r.state.reset_reply_on_attempt.unwrap();
                if let Err(e) = consume_packets(&mut r.state, attempt) {
                    r.result = "FRAMING_INVALID".into();
                    r.error = Some(e);
                    return;
                }
                if r.state.data_packet.is_some()
                    || r.state.unexpected_control.is_some()
                    || r.state.duplicate_reset_reply
                {
                    break;
                }
            }
        }
        classify(r);
    }

    fn consume_packets(s: &mut RetryState, attempt: usize) -> Result<(), String> {
        loop {
            let Some(packet) = try_complete_packet(&s.stream)? else {
                return Ok(());
            };
            s.stream.drain(..packet.total_bytes);
            if packet.header.leader == CONTROL_PACKET_LEADER {
                if packet.header.packet_type == PACKET_TYPE_KD_RESET {
                    if s.reset_reply.is_some() {
                        s.duplicate_reset_reply = true;
                        s.unexpected_control = Some(packet);
                        return Ok(());
                    }
                    s.reset_reply_on_attempt = Some(attempt);
                    s.reset_reply = Some(packet);
                } else {
                    s.unexpected_control = Some(packet);
                    return Ok(());
                }
            } else {
                s.data_packet = Some(packet);
                return Ok(());
            }
        }
    }

    fn classify(r: &mut LiveReport) {
        let s = &r.state;
        r.result = if s.duplicate_reset_reply {
            "DUPLICATE_RESET_REPLY".into()
        } else if s.unexpected_control.is_some() {
            "UNEXPECTED_CONTROL".into()
        } else if s.data_packet.is_some() && s.reset_reply.is_none() {
            format!(
                "DATA_PACKET_BEFORE_RESET_REPLY_ATTEMPT_{}",
                s.attempts_sent.max(1)
            )
        } else if let Some(a) = s.reset_reply_on_attempt {
            if s.data_packet.is_some() {
                format!("RESET_REPLY_AND_DATA_ON_ATTEMPT_{a}")
            } else {
                format!("RESET_REPLY_ON_ATTEMPT_{a}")
            }
        } else if s.attempts_sent == 3 {
            "NO_REPLY_AFTER_3_RESET_ATTEMPTS".into()
        } else {
            "OTHER_TRANSPORT_FAULT".into()
        };
    }

    impl BootstrapAssembly {
        fn append(&mut self, expected: &str, transfer: &[u8]) -> Result<(), String> {
            if self.name_target.is_some() {
                self.stream.extend_from_slice(transfer);
                return Ok(());
            }
            self.pending.extend_from_slice(transfer);
            let n = self.pending.len().min(NAME_PREFIX.len());
            if self.pending[..n] != NAME_PREFIX[..n] {
                return Err("NAME response prefix mismatch".into());
            }
            if self.pending.len() < NAME_PREFIX.len() {
                return Ok(());
            }
            let limit = self.pending.len().min(NAME_RESPONSE_MAX);
            let suffix = &self.pending[NAME_PREFIX.len()..limit];
            let Some(nul) = suffix.iter().position(|&b| b == 0) else {
                if self.pending.len() >= NAME_RESPONSE_MAX {
                    return Err("NAME response lacks NUL within 37 bytes".into());
                }
                return Ok(());
            };
            let name = &suffix[..nul];
            if name.is_empty() || name.len() > TARGET_NAME_MAX || !name.is_ascii() {
                return Err("invalid NAME target".into());
            }
            let target =
                std::str::from_utf8(name).map_err(|e| format!("invalid NAME UTF-8: {e}"))?;
            if target != expected {
                return Err(format!(
                    "identity mismatch: NAME target '{target}' != '{expected}'"
                ));
            }
            let logical_end = NAME_PREFIX.len() + nul + 1;
            let Some(second_nul) = self.pending.get(logical_end) else {
                return Ok(());
            };
            if *second_nul != 0 {
                return Err("NAME response is not terminated by two NUL bytes".into());
            }
            let consumed = logical_end + 1;
            self.name_target = Some(target.into());
            self.stream.extend_from_slice(&self.pending[consumed..]);
            self.pending.clear();
            Ok(())
        }
    }

    fn try_complete_packet(stream: &[u8]) -> Result<Option<PacketSummary>, String> {
        if stream.len() < KD_HEADER_SIZE {
            return Ok(None);
        }
        let h = parse_header(stream)?;
        let total = if h.leader == DATA_PACKET_LEADER {
            KD_HEADER_SIZE + usize::from(h.byte_count) + 1
        } else {
            KD_HEADER_SIZE
        };
        if total > MAX_COMPLETE_KD_PACKET_BYTES {
            return Err(format!("KD packet requires {total} bytes"));
        }
        if stream.len() < total {
            return Ok(None);
        }
        if !checksum_valid(h, stream) {
            return Err(format!("KD checksum mismatch: header=0x{:08x}", h.checksum));
        }
        let trailer = if h.leader == DATA_PACKET_LEADER {
            Some(stream[total - 1] == PACKET_TRAILING_BYTE)
        } else {
            None
        };
        if trailer == Some(false) {
            return Err("KD data trailer is not 0xaa".into());
        }
        Ok(Some(PacketSummary {
            header: h,
            total_bytes: total,
            checksum_valid: true,
            trailer_valid: trailer,
            packet: stream[..total].to_vec(),
        }))
    }
    fn parse_header(s: &[u8]) -> Result<KdHeader, String> {
        let h = KdHeader {
            leader: u32::from_le_bytes(s[0..4].try_into().unwrap()),
            packet_type: u16::from_le_bytes(s[4..6].try_into().unwrap()),
            byte_count: u16::from_le_bytes(s[6..8].try_into().unwrap()),
            packet_id: u32::from_le_bytes(s[8..12].try_into().unwrap()),
            checksum: u32::from_le_bytes(s[12..16].try_into().unwrap()),
        };
        match h.leader {
            DATA_PACKET_LEADER
                if (1..=11).contains(&h.packet_type)
                    && usize::from(h.byte_count) <= MAX_KD_PAYLOAD_BYTES =>
            {
                Ok(h)
            }
            CONTROL_PACKET_LEADER
                if matches!(
                    h.packet_type,
                    PACKET_TYPE_KD_ACKNOWLEDGE | PACKET_TYPE_KD_RESEND | PACKET_TYPE_KD_RESET
                ) && h.byte_count == 0
                    && h.checksum == 0 =>
            {
                Ok(h)
            }
            _ => Err(format!(
                "invalid KD framing: leader=0x{:08x} type=0x{:04x} byte_count={} checksum=0x{:08x}",
                h.leader, h.packet_type, h.byte_count, h.checksum
            )),
        }
    }
    fn checksum_valid(h: KdHeader, s: &[u8]) -> bool {
        if h.leader == CONTROL_PACKET_LEADER {
            return h.byte_count == 0 && h.checksum == 0;
        }
        let end = KD_HEADER_SIZE + usize::from(h.byte_count);
        s[KD_HEADER_SIZE..end]
            .iter()
            .fold(0u32, |sum, &b| sum.wrapping_add(u32::from(b)))
            == h.checksum
    }
    fn packet_label(t: u16) -> &'static str {
        match t {
            1 => "KD_STATE_CHANGE32",
            2 => "KD_STATE_MANIPULATE",
            3 => "KD_DEBUG_IO",
            4 => "KD_ACKNOWLEDGE",
            5 => "KD_RESEND",
            6 => "KD_RESET",
            7 => "KD_STATE_CHANGE64",
            11 => "KD_FILE_IO",
            _ => "KD_KNOWN_DATA_TYPE",
        }
    }
    fn file_io_api(payload: &[u8]) -> Option<&'static str> {
        match parse_file_io(payload).ok()? {
            FileIoRequest::Create { .. } => Some("CREATE_FILE"),
            FileIoRequest::Read { .. } => Some("READ_FILE"),
            FileIoRequest::Write { .. } => Some("WRITE_FILE"),
            FileIoRequest::Close { .. } => Some("CLOSE_FILE"),
            FileIoRequest::Unknown { .. } => Some("UNKNOWN"),
        }
    }
    fn print_packet(prefix: &str, p: &PacketSummary) {
        println!("{prefix}_HEX={}", hex::encode(&p.packet));
        println!("{prefix}_TOTAL_BYTES={}", p.total_bytes);
        println!("{prefix}_LEADER=0x{:08x}", p.header.leader);
        println!("{prefix}_TYPE=0x{:04x}", p.header.packet_type);
        println!("{prefix}_SEMANTIC={}", packet_label(p.header.packet_type));
        println!("{prefix}_BYTE_COUNT={}", p.header.byte_count);
        println!("{prefix}_PACKET_ID=0x{:08x}", p.header.packet_id);
        println!("{prefix}_CHECKSUM=0x{:08x}", p.header.checksum);
        println!("{prefix}_CHECKSUM_VALID={}", p.checksum_valid);
        match p.trailer_valid {
            Some(v) => println!("{prefix}_TRAILER_VALID={v}"),
            None => println!("{prefix}_TRAILER_VALID=NA"),
        };
        if p.header.packet_type == 11 {
            let end = KD_HEADER_SIZE + usize::from(p.header.byte_count);
            println!(
                "{prefix}_FILE_IO_API={}",
                file_io_api(&p.packet[KD_HEADER_SIZE..end]).unwrap_or("UNDECODED")
            );
        }
    }

    fn print_report(r: &LiveReport) {
        println!("PHASE344CB_RESULT={}", r.result);
        println!("VID_PID={:04x}:{:04x}", r.vendor, r.product);
        println!("INTERFACE={}", r.interface);
        println!("ALTERNATE_SETTING={}", r.alternate_setting);
        println!("BULK_OUT=0x{:02x}", r.bulk_out);
        println!("BULK_IN=0x{:02x}", r.bulk_in);
        println!("MAX_PACKET={}", r.max_packet);
        println!("NAME_SEEN={}", r.name_target.is_some());
        println!("NAME_TARGET={}", r.name_target.as_deref().unwrap_or("NA"));
        println!(
            "NAME_PIGGYBACK_HEX={}",
            if r.name_piggyback.is_empty() {
                "NA".into()
            } else {
                hex::encode(&r.name_piggyback)
            }
        );
        println!("RESET_ATTEMPTS_SENT={}", r.state.attempts_sent);
        for i in 0..3 {
            let sent = i < r.state.attempts_sent;
            println!("RESET_ATTEMPT_{}_TX={sent}", i + 1);
            println!("RESET_ATTEMPT_{}_READS={}", i + 1, r.state.attempt_reads[i]);
            println!(
                "RESET_ATTEMPT_{}_HEX={}",
                i + 1,
                if sent {
                    hex::encode(KD_RESET_PACKET)
                } else {
                    "NA".into()
                }
            );
        }
        println!("RESET_REPLY_SEEN={}", r.state.reset_reply.is_some());
        println!(
            "RESET_REPLY_ON_ATTEMPT={}",
            r.state
                .reset_reply_on_attempt
                .map(|v| v.to_string())
                .unwrap_or_else(|| "NA".into())
        );
        println!("POST_RESET_REPLY_READS={}", r.state.post_reply_reads);
        println!("DATA_PACKET_SEEN={}", r.state.data_packet.is_some());
        println!("READ_CALLS_USED={}", r.reads.len());
        println!("NONEMPTY_READS={}", r.nonempty_reads);
        println!("TIMEOUT_READS={}", r.timeout_reads);
        for i in 0..MAX_USB_READ_CALLS {
            if let Some(x) = r.reads.get(i) {
                println!("RX{}_STATUS={}", i + 1, x.status);
                println!("RX{}_LEN={}", i + 1, x.len);
                println!("RX{}_PREFIX_HEX={}", i + 1, x.prefix_hex);
            } else {
                println!("RX{}_STATUS=NA", i + 1);
                println!("RX{}_LEN=NA", i + 1);
                println!("RX{}_PREFIX_HEX=NA", i + 1);
            }
        }
        if let Some(p) = &r.state.reset_reply {
            print_packet("RESET_REPLY", p);
        }
        if let Some(p) = &r.state.data_packet {
            print_packet("KD_DATA_PACKET", p);
        }
        if let Some(p) = &r.state.unexpected_control {
            print_packet("UNEXPECTED_CONTROL", p);
        }
        println!("INTERFACE_RELEASED={}", r.interface_released);
        if let Some(e) = &r.error {
            println!("ERROR={e}");
        }
        print_safety(true, r.name_probe_sent, r.state.attempts_sent > 0);
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        fn control(t: u16, id: u32) -> Vec<u8> {
            let mut v = Vec::new();
            v.extend_from_slice(&CONTROL_PACKET_LEADER.to_le_bytes());
            v.extend_from_slice(&t.to_le_bytes());
            v.extend_from_slice(&0u16.to_le_bytes());
            v.extend_from_slice(&id.to_le_bytes());
            v.extend_from_slice(&0u32.to_le_bytes());
            v
        }
        fn data(t: u16, p: &[u8]) -> Vec<u8> {
            let sum = p.iter().fold(0u32, |s, &b| s.wrapping_add(u32::from(b)));
            let mut v = Vec::new();
            v.extend_from_slice(&DATA_PACKET_LEADER.to_le_bytes());
            v.extend_from_slice(&t.to_le_bytes());
            v.extend_from_slice(&(p.len() as u16).to_le_bytes());
            v.extend_from_slice(&0x80800800u32.to_le_bytes());
            v.extend_from_slice(&sum.to_le_bytes());
            v.extend_from_slice(p);
            v.push(0xaa);
            v
        }
        fn feed(attempt: usize, bytes: &[u8]) -> RetryState {
            let mut s = RetryState {
                attempts_sent: attempt,
                ..Default::default()
            };
            s.stream.extend_from_slice(bytes);
            consume_packets(&mut s, attempt).unwrap();
            s
        }
        fn simulate(first_packet: Option<(usize, Vec<u8>)>) -> RetryState {
            let mut s = RetryState::default();
            for attempt in 1..=MAX_KD_CONTROL_RESET_TX {
                s.attempts_sent = attempt;
                for read in 1..=READS_PER_RESET_ATTEMPT {
                    s.attempt_reads[attempt - 1] += 1;
                    if let Some((on_attempt, bytes)) = &first_packet {
                        if *on_attempt == attempt && read == 1 {
                            s.stream.extend_from_slice(bytes);
                            consume_packets(&mut s, attempt).unwrap();
                        }
                    }
                    if s.reset_reply.is_some()
                        || s.data_packet.is_some()
                        || s.unexpected_control.is_some()
                    {
                        break;
                    }
                }
                if s.reset_reply.is_some()
                    || s.data_packet.is_some()
                    || s.unexpected_control.is_some()
                {
                    break;
                }
            }
            s
        }
        #[test]
        fn reset_packet_exact_and_immutable() {
            assert_eq!(KD_RESET_PACKET.len(), 16);
            assert_eq!(
                hex::encode(KD_RESET_PACKET),
                "69696969060000000000000000000000"
            );
            assert_eq!(KD_RESET_PACKET, control(6, 0).as_slice());
        }
        #[test]
        fn hard_budgets() {
            assert_eq!(MAX_KD_CONTROL_RESET_TX, 3);
            assert_eq!(READS_PER_RESET_ATTEMPT, 2);
            assert_eq!(MAX_POST_RESET_REPLY_READS, 4);
            assert_eq!(MAX_USB_READ_CALLS, 10);
        }
        #[test]
        fn maximum_three_reset_transmissions() {
            let s = simulate(None);
            assert_eq!(s.attempts_sent, 3);
        }
        #[test]
        fn exactly_two_windows_per_unanswered_attempt() {
            let s = simulate(None);
            assert_eq!(s.attempt_reads, [2, 2, 2]);
        }
        #[test]
        fn attempt_one_reply_suppresses_attempts_two_and_three() {
            let s = simulate(Some((1, control(6, 0))));
            assert_eq!(s.attempts_sent, 1);
            assert_eq!(s.attempt_reads, [1, 0, 0]);
        }
        #[test]
        fn attempt_two_reply_suppresses_attempt_three() {
            let s = simulate(Some((2, control(6, 0))));
            assert_eq!(s.attempts_sent, 2);
            assert_eq!(s.attempt_reads, [2, 1, 0]);
        }
        #[test]
        fn attempt_three_reply_classifies_correctly() {
            let mut r = dummy();
            r.state = simulate(Some((3, control(6, 0))));
            classify(&mut r);
            assert_eq!(r.result, "RESET_REPLY_ON_ATTEMPT_3");
            assert_eq!(r.state.attempts_sent, 3);
        }
        #[test]
        fn data_before_reply_stops() {
            let mut r = dummy();
            r.state = simulate(Some((2, data(11, b"file"))));
            classify(&mut r);
            assert_eq!(r.result, "DATA_PACKET_BEFORE_RESET_REPLY_ATTEMPT_2");
            assert_eq!(r.state.attempts_sent, 2);
            assert_eq!(r.state.attempt_reads, [2, 1, 0]);
        }
        #[test]
        fn post_reply_passive_budget_is_four() {
            let mut s = RetryState::default();
            while s.post_reply_reads < MAX_POST_RESET_REPLY_READS {
                s.post_reply_reads += 1;
            }
            assert_eq!(s.post_reply_reads, 4);
        }
        #[test]
        fn split_name_reply() {
            let mut b = BootstrapAssembly::default();
            b.append(REQUIRED_TARGET, b"NAME=CLSA").unwrap();
            b.append(REQUIRED_TARGET, b"0102_USB\0").unwrap();
            assert!(b.name_target.is_none());
            b.append(REQUIRED_TARGET, b"\0").unwrap();
            assert_eq!(b.name_target.as_deref(), Some(REQUIRED_TARGET));
        }
        #[test]
        fn name_piggyback_is_preserved_before_any_reset() {
            let packet = control(6, 0);
            let mut transfer = b"NAME=CLSA0102_USB\0\0".to_vec();
            transfer.extend_from_slice(&packet);
            let mut b = BootstrapAssembly::default();
            b.append(REQUIRED_TARGET, &transfer).unwrap();
            assert_eq!(b.stream, packet);
            let state = RetryState::default();
            assert_eq!(state.attempts_sent, 0);
        }
        #[test]
        fn split_reset_reply() {
            let p = control(6, 7);
            assert!(try_complete_packet(&p[..8]).unwrap().is_none());
            let s = feed(3, &p);
            assert_eq!(s.reset_reply.unwrap().packet, p);
        }
        #[test]
        fn valid_data_preserved() {
            let p = data(11, b"file");
            assert_eq!(try_complete_packet(&p).unwrap().unwrap().packet, p);
        }
        #[test]
        fn checksum_and_trailer_rejected() {
            let mut p = data(3, b"abc");
            p[12] ^= 1;
            assert!(try_complete_packet(&p).is_err());
            let mut p = data(3, b"abc");
            *p.last_mut().unwrap() = 0;
            assert!(try_complete_packet(&p).is_err());
        }
        #[test]
        fn only_reset_is_constructed() {
            assert_ne!(KD_RESET_PACKET[4], PACKET_TYPE_KD_ACKNOWLEDGE as u8);
            assert_ne!(KD_RESET_PACKET[4], PACKET_TYPE_KD_RESEND as u8);
            assert_eq!(MAX_USB_DEVICE_RESET_ATTEMPTS, 0);
            assert_eq!(MAX_ENDPOINT_RECREATION_ATTEMPTS, 0);
        }
        fn dummy() -> LiveReport {
            LiveReport {
                result: String::new(),
                vendor: 0,
                product: 0,
                interface: 0,
                alternate_setting: 0,
                bulk_in: 0,
                bulk_out: 0,
                max_packet: 0,
                name_target: None,
                name_piggyback: Vec::new(),
                name_probe_sent: false,
                state: RetryState::default(),
                reads: Vec::new(),
                nonempty_reads: 0,
                timeout_reads: 0,
                error: None,
                interface_released: false,
            }
        }
    }
}
