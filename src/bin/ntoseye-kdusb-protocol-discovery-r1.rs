//! One-shot, bounded classic-KDUSB protocol discovery campaign.

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("ntoseye-kdusb-protocol-discovery-r1 is Linux-only");
    std::process::exit(2);
}

#[cfg(target_os = "linux")]
fn main() {
    std::process::exit(linux::run());
}

#[cfg(target_os = "linux")]
mod linux {
    use ntoseye::kdusb_discovery::{
        Classification, DATA_LEADER, INITIAL_PACKET_ID, KD_ACKNOWLEDGE, KD_CONTROL_REQUEST,
        KD_DEBUG_IO, KD_FILE_IO, KD_RESET, KD_STATE_MANIPULATE, PacketIdDisposition,
        PacketIdTracker, acknowledge, classify_usb_transfer, get_version_query,
    };
    use rusb::{Device, Direction, GlobalContext, TransferType};
    use serde_json::{Value, json};
    use std::collections::BTreeSet;
    use std::fs::{self, File, OpenOptions};
    use std::io::{BufRead, BufReader, Write};
    use std::path::{Path, PathBuf};
    use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

    const LIVE_FLAG: &str = "--execute-campaign";
    const REPLAY_FLAG: &str = "--replay";
    const REQUIRED_TARGET: &str = "CLSA0102_USB";
    const HARDWARE_IDS: &[(u16, u16)] = &[
        (0x3495, 0x00e0),
        (0x0525, 0x127a),
        (0x046b, 0x0980),
        (0x045e, 0x062d),
    ];
    const MAX_READS: usize = 64;
    const MAX_ACKED_DATA: usize = 16;
    const MAX_CONTROL_TX: usize = 16;
    const MAX_QUERY_TX: usize = 1;
    const ACTIVE_SECONDS: u64 = 60;
    const READ_SIZE: usize = 4016;
    const IO_TIMEOUT: Duration = Duration::from_millis(1000);
    const FIRST_ACK: [u8; 16] = [
        0x69, 0x69, 0x69, 0x69, 0x04, 0x00, 0x00, 0x00, 0x00, 0x08, 0x80, 0x80, 0x00, 0x00, 0x00,
        0x00,
    ];

    #[derive(Clone)]
    struct Candidate {
        device: Device<GlobalContext>,
        vendor: u16,
        product: u16,
        interface: u8,
        alternate: u8,
        bulk_in: u8,
        bulk_out: u8,
        max_packet: u16,
    }

    struct Recorder {
        start: Instant,
        transcript: File,
        ledger: File,
        out: PathBuf,
        event: usize,
        step: usize,
        rx_file: usize,
        tx_file: usize,
    }

    impl Recorder {
        fn new(out: &Path) -> Result<Self, String> {
            fs::create_dir_all(out).map_err(|e| format!("create output directory: {e}"))?;
            let append = |name: &str| {
                OpenOptions::new()
                    .create(true)
                    .append(true)
                    .open(out.join(name))
            };
            Ok(Self {
                start: Instant::now(),
                transcript: append("conversation.jsonl").map_err(|e| e.to_string())?,
                ledger: append("experiment-ledger.jsonl").map_err(|e| e.to_string())?,
                out: out.to_owned(),
                event: 0,
                step: 0,
                rx_file: 0,
                tx_file: 0,
            })
        }

        fn ledger(&mut self, action: &str, decision: &str, reason: &str) -> Result<(), String> {
            self.step += 1;
            writeln!(
                self.ledger,
                "{}",
                json!({"step":self.step,"action":action,"decision":decision,"reason":reason})
            )
            .map_err(|e| e.to_string())?;
            self.ledger.sync_data().map_err(|e| e.to_string())
        }

        fn event(
            &mut self,
            direction: &str,
            endpoint: u8,
            bytes: &[u8],
            status: &str,
            decision: &str,
            reason: &str,
        ) -> Result<(), String> {
            self.event += 1;
            let decoded = classification_json(&classify_usb_transfer(bytes));
            let raw_file = if bytes.is_empty() {
                Value::Null
            } else {
                let (index, prefix) = if direction == "RX" {
                    self.rx_file += 1;
                    (self.rx_file, "rx")
                } else {
                    self.tx_file += 1;
                    (self.tx_file, "tx")
                };
                let name = format!("{prefix}-{index:03}.bin");
                fs::write(self.out.join(&name), bytes).map_err(|e| e.to_string())?;
                Value::String(name)
            };
            let record = json!({
                "event":self.event,
                "monotonic_ns":self.start.elapsed().as_nanos().to_string(),
                "wall_clock":wall_clock(),
                "direction":direction,
                "usb_endpoint":format!("0x{endpoint:02x}"),
                "byte_length":bytes.len(),
                "hex":hex::encode(bytes),
                "status":status,
                "classification":decoded,
                "decision":decision,
                "reason":reason,
                "raw_file":raw_file,
            });
            writeln!(self.transcript, "{record}").map_err(|e| e.to_string())?;
            self.transcript.sync_data().map_err(|e| e.to_string())
        }
    }

    pub fn run() -> i32 {
        let args: Vec<String> = std::env::args().skip(1).collect();
        if args.is_empty() {
            dry_plan();
            return 0;
        }
        if args.first().map(String::as_str) == Some(REPLAY_FLAG) && args.len() == 3 {
            return match replay(Path::new(&args[1]), Path::new(&args[2])) {
                Ok(count) => {
                    println!("REPLAY_EVENTS={count}");
                    println!("LIVE_USB_ACTIVITY=false");
                    0
                }
                Err(e) => {
                    eprintln!("replay failed: {e}");
                    2
                }
            };
        }
        if args.len() != 4
            || args[0] != LIVE_FLAG
            || args[1] != REQUIRED_TARGET
            || args[2] != "--output-dir"
        {
            eprintln!(
                "usage: ntoseye-kdusb-protocol-discovery-r1 [{LIVE_FLAG} {REQUIRED_TARGET} --output-dir DIR | {REPLAY_FLAG} INPUT OUTPUT]"
            );
            return 2;
        }
        match campaign(Path::new(&args[3])) {
            Ok(result) => {
                println!("PHASE345_RESULT={result}");
                println!("LIVE_USB_ACTIVITY=true");
                println!("PHASE340_CLEANUP_AUTHORIZED=false");
                0
            }
            Err((class, error)) => {
                println!("PHASE345_RESULT={class}");
                println!("ERROR={error}");
                println!("LIVE_USB_ACTIVITY=true");
                println!("PHASE340_CLEANUP_AUTHORIZED=false");
                5
            }
        }
    }

    fn dry_plan() {
        println!("NTOSEYE_KDUSB_PROTOCOL_DISCOVERY_R1=READY");
        println!("DEFAULT_MODE=DRY_PLAN");
        println!("FIRST_TX_HEX={}", hex::encode(FIRST_ACK));
        println!("MAX_ACKNOWLEDGED_KD_DATA={MAX_ACKED_DATA}");
        println!("MAX_BULK_IN_CALLS={MAX_READS}");
        println!("MAX_KD_CONTROL_TX={MAX_CONTROL_TX}");
        println!("MAX_QUERY_TX={MAX_QUERY_TX}");
        println!("ACTIVE_PROTOCOL_SECONDS={ACTIVE_SECONDS}");
        println!("QUERY_WHITELIST=DbgKdGetVersionApi");
        println!("NAME_PROBE_MAX_TX=1");
        println!("PLANNED_NAME_TX=0");
        println!("KD_RESEND_PLANNED=false");
        println!("KD_RESET_PLANNED=false");
        println!("BREAKIN_SENT=false");
        println!("TARGET_MEMORY_ACCESS=false");
        println!("USB_DEVICE_RESET=false");
        println!("SET_CONFIGURATION_TX=false");
        println!("CLEAR_HALT_TX=false");
        println!("PHASE340_CLEANUP_AUTHORIZED=false");
    }

    fn campaign(out: &Path) -> Result<String, (&'static str, String)> {
        let mut found = candidates().map_err(|e| ("IDENTITY_MISMATCH_ABORT", e))?;
        if found.len() != 1 {
            return Err((
                "IDENTITY_MISMATCH_ABORT",
                format!(
                    "expected one supported dc/02/ff interface, found {}",
                    found.len()
                ),
            ));
        }
        let c = found.remove(0);
        if c.alternate != 0 {
            return Err((
                "IDENTITY_MISMATCH_ABORT",
                "alternate setting is not zero".into(),
            ));
        }
        let handle = c
            .device
            .open()
            .map_err(|e| ("OTHER_TRANSPORT_FAULT", format!("open: {e}")))?;
        match handle.kernel_driver_active(c.interface) {
            Ok(false) | Err(rusb::Error::NotSupported) => {}
            Ok(true) => {
                return Err((
                    "IDENTITY_MISMATCH_ABORT",
                    "kernel driver is attached; refusing detach".into(),
                ));
            }
            Err(e) => return Err(("OTHER_TRANSPORT_FAULT", e.to_string())),
        }
        handle
            .claim_interface(c.interface)
            .map_err(|e| ("OTHER_TRANSPORT_FAULT", format!("claim: {e}")))?;
        let result = walk(&handle, &c, out);
        let release = handle.release_interface(c.interface);
        if let Err(e) = release {
            return Err(("OTHER_TRANSPORT_FAULT", format!("release: {e}")));
        }
        result
    }

    fn walk(
        handle: &rusb::DeviceHandle<GlobalContext>,
        c: &Candidate,
        out: &Path,
    ) -> Result<String, (&'static str, String)> {
        let mut rec = Recorder::new(out).map_err(|e| ("EVIDENCE_IO_FAULT", e))?;
        rec.ledger(
            "send_initial_ack",
            "execute_once",
            "authoritative predecessor requires exact ACK of 0x80800800",
        )
        .map_err(|e| ("EVIDENCE_IO_FAULT", e))?;
        write_exact(handle, c.bulk_out, &FIRST_ACK)
            .map_err(|e| transport_error("initial ACK", e))?;
        rec.event(
            "TX",
            c.bulk_out,
            &FIRST_ACK,
            "DATA",
            "sent",
            "first campaign action; exact predecessor ACK",
        )
        .map_err(|e| ("EVIDENCE_IO_FAULT", e))?;

        let started = Instant::now();
        let mut reads = 0usize;
        let mut control_tx = 1usize;
        // The authoritative first action successfully acknowledges the
        // retained CB data packet, so it consumes one data-ACK budget slot.
        let mut acked_data = 1usize;
        let mut timeouts = 0usize;
        let mut ids = PacketIdTracker::default();
        let mut acked_ids = BTreeSet::new();
        acked_ids.insert(0x8080_0800u32);
        let mut query_sent = false;
        let mut query_ack = false;
        let mut useful_packets = 0usize;
        let mut stop_reason = "READ_BUDGET_REACHED";

        while reads < MAX_READS
            && acked_data < MAX_ACKED_DATA
            && control_tx <= MAX_CONTROL_TX
            && started.elapsed() < Duration::from_secs(ACTIVE_SECONDS)
        {
            reads += 1;
            rec.ledger(
                "bulk_in",
                "execute_once",
                &format!("bounded receive call {reads}/{MAX_READS}"),
            )
            .map_err(|e| ("EVIDENCE_IO_FAULT", e))?;
            let mut buf = vec![0u8; READ_SIZE];
            match handle.read_bulk(c.bulk_in, &mut buf, IO_TIMEOUT) {
                Ok(n) => {
                    buf.truncate(n);
                    timeouts = 0;
                    let class = classify_usb_transfer(&buf);
                    let (decision, reason) = decide(&class);
                    rec.event(
                        "RX",
                        c.bulk_in,
                        &buf,
                        if n == 0 { "ZLP" } else { "DATA" },
                        decision,
                        reason,
                    )
                    .map_err(|e| ("EVIDENCE_IO_FAULT", e))?;
                    match class {
                        Classification::Kd(packet) if packet.header.leader == DATA_LEADER => {
                            useful_packets += 1;
                            if packet.payload_complete && packet.checksum_valid == Some(false) {
                                stop_reason = "INVALID_CHECKSUM_RESEND_NOT_PROVEN_SAFE";
                                break;
                            }
                            if !packet.payload_complete {
                                stop_reason = "INCOMPLETE_USB_TRANSPORT_PACKET";
                                break;
                            }
                            if packet.checksum_valid == Some(true) {
                                let disposition = ids.observe(packet.header.packet_id);
                                let duplicate = disposition == PacketIdDisposition::Duplicate;
                                if !duplicate && !acked_ids.contains(&packet.header.packet_id) {
                                    if control_tx >= MAX_CONTROL_TX {
                                        stop_reason = "CONTROL_TX_BUDGET_REACHED";
                                        break;
                                    }
                                    let ack = acknowledge(packet.header.packet_id);
                                    rec.ledger(
                                        "ack_valid_kd_data",
                                        "execute_once",
                                        &format!(
                                            "valid checksum; exact packet id 0x{:08x}",
                                            packet.header.packet_id
                                        ),
                                    )
                                    .map_err(|e| ("EVIDENCE_IO_FAULT", e))?;
                                    write_exact(handle, c.bulk_out, &ack)
                                        .map_err(|e| transport_error("data ACK", e))?;
                                    control_tx += 1;
                                    acked_data += 1;
                                    acked_ids.insert(packet.header.packet_id);
                                    rec.event(
                                        "TX",
                                        c.bulk_out,
                                        &ack,
                                        "DATA",
                                        "sent",
                                        "valid new KD data packet acknowledged exactly once",
                                    )
                                    .map_err(|e| ("EVIDENCE_IO_FAULT", e))?;
                                }
                            }
                            if matches!(
                                packet.header.packet_type,
                                KD_FILE_IO | KD_DEBUG_IO | KD_CONTROL_REQUEST
                            ) {
                                stop_reason = "UNEXPECTED_SEMANTIC_CLASS_PASSIVE_STOP";
                                break;
                            }
                            if packet.class == "KD_UNKNOWN_TYPE"
                                || packet
                                    .manipulate
                                    .as_ref()
                                    .is_some_and(|m| m.semantic == "unknown-manipulate-api")
                            {
                                stop_reason = "UNKNOWN_KD_SEMANTIC_PASSIVE_STOP";
                                break;
                            }
                            if packet.header.packet_type == KD_STATE_MANIPULATE
                                && packet
                                    .manipulate
                                    .as_ref()
                                    .is_some_and(|m| m.api_number == 0x3146)
                            {
                                stop_reason = "GET_VERSION_REPLY_CAPTURED";
                                break;
                            }
                        }
                        Classification::Kd(packet)
                            if packet.header.packet_type == KD_ACKNOWLEDGE =>
                        {
                            if packet.header.packet_id == INITIAL_PACKET_ID {
                                query_ack = true;
                            }
                        }
                        Classification::Kd(packet) if packet.header.packet_type == KD_RESET => {
                            stop_reason = "TARGET_RESET_OBSERVED_NO_AUTOMATIC_RESPONSE";
                            break;
                        }
                        Classification::Unknown => {
                            stop_reason = "UNKNOWN_TRANSPORT_PACKET";
                            break;
                        }
                        _ => {}
                    }
                }
                Err(rusb::Error::Timeout) => {
                    timeouts += 1;
                    rec.event(
                        "RX",
                        c.bulk_in,
                        &[],
                        "TIMEOUT",
                        "continue_or_query",
                        "bounded timeout is not a transport fault",
                    )
                    .map_err(|e| ("EVIDENCE_IO_FAULT", e))?;
                    if !query_sent {
                        let query = get_version_query(INITIAL_PACKET_ID, 13);
                        rec.ledger(
                            "send_get_version",
                            "execute_once",
                            "initial LoadSymbols packet was ACKed and passive receive made no progress; sole whitelisted query",
                        )
                        .map_err(|e| ("EVIDENCE_IO_FAULT", e))?;
                        write_exact(handle, c.bulk_out, &query)
                            .map_err(|e| transport_error("GetVersion", e))?;
                        query_sent = true;
                        rec.event(
                            "TX",
                            c.bulk_out,
                            &query,
                            "DATA",
                            "sent",
                            "DbgKdGetVersionApi query-only handshake request",
                        )
                        .map_err(|e| ("EVIDENCE_IO_FAULT", e))?;
                        continue;
                    }
                    if timeouts >= 4 {
                        stop_reason = if query_ack {
                            "SILENCE_AFTER_GET_VERSION_ACK"
                        } else {
                            "SILENCE_AFTER_GET_VERSION"
                        };
                        break;
                    }
                }
                Err(e @ (rusb::Error::Pipe | rusb::Error::Other | rusb::Error::Io)) => {
                    rec.event(
                        "RX",
                        c.bulk_in,
                        &[],
                        "EPROTO_CLASS",
                        "stop",
                        "hard safety boundary forbids recovery",
                    )
                    .map_err(|x| ("EVIDENCE_IO_FAULT", x))?;
                    return Err(("EPROTO_CLASS_TRANSPORT_FAULT", e.to_string()));
                }
                Err(e) => return Err(("OTHER_TRANSPORT_FAULT", e.to_string())),
            }
        }

        rec.ledger("campaign_stop", "stop", stop_reason)
            .map_err(|e| ("EVIDENCE_IO_FAULT", e))?;
        fs::write(
            out.join("engine-summary.json"),
            serde_json::to_vec_pretty(&json!({
                "result":stop_reason,
                "reads":reads,
                "control_tx":control_tx,
                "query_tx":usize::from(query_sent),
                "acknowledged_data_total":acked_data,
                "acked_new_data":acked_data.saturating_sub(1),
                "useful_packets":useful_packets,
                "query_ack":query_ack,
                "vendor":format!("0x{:04x}", c.vendor),
                "product":format!("0x{:04x}", c.product),
                "interface":c.interface,
                "alternate_setting":c.alternate,
                "bulk_in":format!("0x{:02x}", c.bulk_in),
                "bulk_out":format!("0x{:02x}", c.bulk_out),
                "max_packet":c.max_packet,
                "keep_for_further_analysis":true,
                "phase340_cleanup_authorized":false
            }))
            .map_err(|e| ("EVIDENCE_IO_FAULT", e.to_string()))?,
        )
        .map_err(|e| ("EVIDENCE_IO_FAULT", e.to_string()))?;
        Ok(stop_reason.into())
    }

    fn decide(class: &Classification) -> (&'static str, &'static str) {
        match class {
            Classification::Kd(packet) if packet.header.leader == DATA_LEADER => (
                "validate_then_ack_once",
                "KD data is independently checksum-checked",
            ),
            Classification::Name { .. } => {
                ("retain_and_continue", "NAME may interleave with KD traffic")
            }
            Classification::Kd(_) => (
                "classify_control",
                "control packet changes conversation state",
            ),
            Classification::Empty => ("continue", "USB ZLP is not stream EOF"),
            Classification::Unknown => ("stop", "wire structure is not verified"),
        }
    }

    fn write_exact(
        handle: &rusb::DeviceHandle<GlobalContext>,
        endpoint: u8,
        bytes: &[u8],
    ) -> Result<(), rusb::Error> {
        let n = handle.write_bulk(endpoint, bytes, IO_TIMEOUT)?;
        if n != bytes.len() {
            return Err(rusb::Error::Other);
        }
        Ok(())
    }

    fn transport_error(context: &str, error: rusb::Error) -> (&'static str, String) {
        let class = match error {
            rusb::Error::Pipe | rusb::Error::Other | rusb::Error::Io => {
                "EPROTO_CLASS_TRANSPORT_FAULT"
            }
            _ => "OTHER_TRANSPORT_FAULT",
        };
        (class, format!("{context}: {error}"))
    }

    fn candidates() -> Result<Vec<Candidate>, String> {
        let devices = rusb::devices().map_err(|e| e.to_string())?;
        let mut found = Vec::new();
        for device in devices.iter() {
            let dd = device.device_descriptor().map_err(|e| e.to_string())?;
            if !HARDWARE_IDS.contains(&(dd.vendor_id(), dd.product_id())) {
                continue;
            }
            let config = device
                .active_config_descriptor()
                .map_err(|e| e.to_string())?;
            for interface in config.interfaces() {
                for id in interface.descriptors() {
                    if (id.class_code(), id.sub_class_code(), id.protocol_code()) != (0xdc, 2, 0xff)
                    {
                        continue;
                    }
                    let mut input = None;
                    let mut output = None;
                    for ep in id.endpoint_descriptors() {
                        if ep.transfer_type() != TransferType::Bulk {
                            continue;
                        }
                        match ep.direction() {
                            Direction::In if input.is_none() => input = Some(ep.address()),
                            Direction::Out if output.is_none() => {
                                output = Some((ep.address(), ep.max_packet_size()))
                            }
                            _ => {}
                        }
                    }
                    if let (Some(bulk_in), Some((bulk_out, max_packet))) = (input, output) {
                        found.push(Candidate {
                            device: device.clone(),
                            vendor: dd.vendor_id(),
                            product: dd.product_id(),
                            interface: id.interface_number(),
                            alternate: id.setting_number(),
                            bulk_in,
                            bulk_out,
                            max_packet,
                        });
                    }
                }
            }
        }
        Ok(found)
    }

    fn classification_json(class: &Classification) -> Value {
        match class {
            Classification::Empty => json!({"class":"EMPTY"}),
            Classification::Name { name } => json!({"class":"NAME","name":name}),
            Classification::Unknown => json!({"class":"UNKNOWN"}),
            Classification::Kd(packet) => json!({
                "class":packet.class,
                "leader":format!("0x{:08x}",packet.header.leader),
                "packet_type":packet.header.packet_type,
                "payload_length_declared":packet.header.byte_count,
                "packet_id":format!("0x{:08x}",packet.header.packet_id),
                "sync_bit":packet.header.packet_id & 0x800 != 0,
                "checksum":format!("0x{:08x}",packet.header.checksum),
                "checksum_valid":packet.checksum_valid,
                "payload_complete":packet.payload_complete,
                "trailer_present":packet.trailer_present,
                "trailer_value":packet.trailer_value.map(|v|format!("0x{v:02x}")),
                "extra_bytes_hex":hex::encode(&packet.extra_bytes),
                "state_change":packet.state_change.as_ref().map(|s|json!({"new_state":format!("0x{:08x}",s.new_state),"semantic":s.semantic,"processor_level":s.processor_level,"processor":s.processor,"number_processors":s.number_processors})),
                "manipulate":packet.manipulate.as_ref().map(|m|json!({"api_number":format!("0x{:08x}",m.api_number),"semantic":m.semantic,"processor_level":m.processor_level,"processor":m.processor,"return_status":format!("0x{:08x}",m.return_status)}))
            }),
        }
    }

    fn replay(input: &Path, output: &Path) -> Result<usize, String> {
        let reader = BufReader::new(File::open(input).map_err(|e| e.to_string())?);
        let mut out = File::create(output).map_err(|e| e.to_string())?;
        let mut count = 0usize;
        for line in reader.lines() {
            let line = line.map_err(|e| e.to_string())?;
            if line.trim().is_empty() {
                continue;
            }
            let value: Value = serde_json::from_str(&line).map_err(|e| e.to_string())?;
            let Some(encoded) = value.get("hex").and_then(Value::as_str) else {
                continue;
            };
            let bytes = hex::decode(encoded).map_err(|e| e.to_string())?;
            count += 1;
            writeln!(out, "{}", json!({"event":count,"byte_length":bytes.len(),"hex":encoded,"classification":classification_json(&classify_usb_transfer(&bytes))})).map_err(|e| e.to_string())?;
        }
        Ok(count)
    }

    fn wall_clock() -> String {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default();
        let seconds = now.as_secs() as libc::time_t;
        let mut tm = unsafe { std::mem::zeroed::<libc::tm>() };
        unsafe { libc::gmtime_r(&seconds, &mut tm) };
        format!(
            "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}.{:09}Z",
            tm.tm_year + 1900,
            tm.tm_mon + 1,
            tm.tm_mday,
            tm.tm_hour,
            tm.tm_min,
            tm.tm_sec,
            now.subsec_nanos()
        )
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn hard_budgets_and_first_action_are_fixed() {
            assert_eq!(MAX_READS, 64);
            assert_eq!(MAX_ACKED_DATA, 16);
            assert_eq!(MAX_CONTROL_TX, 16);
            assert_eq!(MAX_QUERY_TX, 1);
            assert_eq!(hex::encode(FIRST_ACK), "69696969040000000008808000000000");
        }

        #[test]
        fn replay_is_deterministic_and_interleaving_safe() {
            let base =
                std::env::temp_dir().join(format!("ntoseye-kdusb-replay-{}", std::process::id()));
            let input = base.with_extension("jsonl");
            let a = base.with_extension("a.jsonl");
            let b = base.with_extension("b.jsonl");
            let cb = "3030303007004a0100088080524400003130000019000d00100000000000000040f050980ea7ffff05e02f9b07f8ffff5a0000000000000000000b2a07f8ffff";
            fs::write(
                &input,
                format!(
                    "{{\"hex\":\"{cb}\"}}\n{{\"hex\":\"{}\"}}\n",
                    hex::encode(b"NAME=CLSA0102_USB\0\0")
                ),
            )
            .unwrap();
            assert_eq!(replay(&input, &a).unwrap(), 2);
            assert_eq!(replay(&input, &b).unwrap(), 2);
            assert_eq!(fs::read(&a).unwrap(), fs::read(&b).unwrap());
            let text = fs::read_to_string(&a).unwrap();
            assert!(text.contains("KD_STATE_CHANGE64"));
            assert!(text.contains("NAME"));
            let _ = fs::remove_file(input);
            let _ = fs::remove_file(a);
            let _ = fs::remove_file(b);
        }
    }
}
