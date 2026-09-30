//! One-shot, bounded classic-KDUSB protocol discovery campaign.

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("ntoseye-kdusb-protocol-discovery-r3 is Linux-only");
    std::process::exit(2);
}

#[cfg(target_os = "linux")]
fn main() {
    std::process::exit(linux::run());
}

#[cfg(target_os = "linux")]
mod linux {
    use ntoseye::kdusb_discovery_r2::{
        Budgets, Classification, Conversation, Decision, PacketIdDisposition, acknowledge,
        classify_usb_transfer,
    };
    use rusb::{Device, GlobalContext};
    use serde_json::{Value, json};
    use std::collections::BTreeMap;
    use std::fs::{self, File, OpenOptions};
    use std::io::{BufRead, BufReader, Write};
    use std::os::unix::fs::MetadataExt;
    use std::path::{Path, PathBuf};
    use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

    const LIVE_FLAG: &str = "--execute-campaign";
    const REPLAY_FLAG: &str = "--replay";
    const REQUIRED_TARGET: &str = "CLSA0102_USB";
    const MAX_READS: usize = 64;
    const MAX_ACKED_DATA: usize = 16;
    const MAX_CONTROL_TX: usize = 20;
    const MAX_QUERY_TX: usize = 1;
    const ACTIVE_SECONDS: u64 = 60;
    const READ_SIZE: usize = 4016;
    const IO_TIMEOUT: Duration = Duration::from_millis(1000);
    const FIRST_ACK: [u8; 16] = [
        0x69, 0x69, 0x69, 0x69, 0x04, 0x00, 0x00, 0x00, 0x00, 0x08, 0x80, 0x80, 0x00, 0x00, 0x00,
        0x00,
    ];
    const PROJECT: &str = "/home/kodi/engineering/CLSA0102-Reverse-Engineering-Project";
    // r3 is a separately authorized revision. Its exclusive sentinel is created
    // only inside the admitted binary immediately before the first protocol TX.
    const LIVE_SESSION_CLOSED: bool = false;
    const CAMPAIGN_CONSUMED_AT_UTC: &str = "";

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
                    .create_new(true)
                    .write(true)
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
                json!({"step":self.step,"monotonic_ns":self.start.elapsed().as_nanos().to_string(),"wall_clock":wall_clock(),"action":action,"decision":decision,"reason":reason})
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
                "step":self.step,
                "monotonic_ns":self.start.elapsed().as_nanos().to_string(),
                "wall_clock":wall_clock(),
                "direction":direction,
                "usb_endpoint":format!("0x{endpoint:02x}"),
                "byte_length":bytes.len(),
                "requested_length":if direction == "TX" { Some(bytes.len()) } else if direction == "RX" { Some(READ_SIZE) } else { None },
                "actual_length":if direction == "TX" { None } else if direction == "TX_STATUS" { reason.strip_prefix("actual=").and_then(|x|x.split(';').next()).and_then(|x|x.parse::<usize>().ok()) } else { Some(bytes.len()) },
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
            || !matches!(args[0].as_str(), LIVE_FLAG | "--claim-lifecycle")
            || args[1] != REQUIRED_TARGET
            || args[2] != "--output-dir"
        {
            eprintln!(
                "usage: ntoseye-kdusb-protocol-discovery-r3 [{LIVE_FLAG} {REQUIRED_TARGET} --output-dir DIR | {REPLAY_FLAG} INPUT OUTPUT]"
            );
            return 2;
        }
        if !live_campaign_enabled() {
            println!("PHASE345R3_RESULT=CAMPAIGN_SESSION_CLOSED");
            println!("CONSUMED_AT_UTC={CAMPAIGN_CONSUMED_AT_UTC}");
            println!("LIVE_USB_ACTIVITY=false");
            println!("PHASE340_CLEANUP_AUTHORIZED=false");
            return 5;
        }
        match campaign(Path::new(&args[3]), args[0] == "--claim-lifecycle") {
            Ok(result) => {
                println!("PHASE345R3_RESULT={result}");
                println!("HOST_INTERFACE_ACTIVITY=true");
                println!("PHASE340_CLEANUP_AUTHORIZED=false");
                0
            }
            Err((class, error)) => {
                println!("PHASE345R3_RESULT={class}");
                println!("ERROR={error}");
                println!("HOST_INTERFACE_ACTIVITY=true");
                println!("PHASE340_CLEANUP_AUTHORIZED=false");
                5
            }
        }
    }

    fn dry_plan() {
        println!("NTOSEYE_KDUSB_PROTOCOL_DISCOVERY_R2=READY");
        println!("DEFAULT_MODE=DRY_PLAN");
        println!("CAMPAIGN_LIVE_ENABLED={}", live_campaign_enabled());
        println!("FIRST_TX_HEX={}", hex::encode(FIRST_ACK));
        println!("MAX_ACKNOWLEDGED_KD_DATA={MAX_ACKED_DATA}");
        println!("MAX_BULK_IN_CALLS={MAX_READS}");
        println!("MAX_KD_CONTROL_TX={MAX_CONTROL_TX}");
        println!("MAX_QUERY_TX={MAX_QUERY_TX}");
        println!("ACTIVE_PROTOCOL_SECONDS={ACTIVE_SECONDS}");
        println!("QUERY_WHITELIST=DbgKdGetVersionApi");
        println!("LIVE_QUERY_FRAMING_VERIFIED=false");
        println!("PLANNED_QUERY_TX=0");
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

    fn live_campaign_enabled() -> bool {
        !LIVE_SESSION_CLOSED
    }

    fn campaign(out: &Path, preflight: bool) -> Result<String, (&'static str, String)> {
        let mut guard =
            Guard::load(out, preflight).map_err(|e| ("PRELIVE_ADMISSION_INVALID", e))?;
        guard.check().map_err(|e| ("IDENTITY_MISMATCH_ABORT", e))?;
        let device = rusb::devices()
            .map_err(|e| transport_error("enumerate", e))?
            .iter()
            .find(|d| d.bus_number() == 6 && d.address() == 8)
            .ok_or((
                "IDENTITY_MISMATCH_ABORT",
                "admitted bus/address absent".into(),
            ))?;
        let c = Candidate {
            device,
            vendor: 0x3495,
            product: 0x00e0,
            interface: 0,
            alternate: 0,
            bulk_in: 0x81,
            bulk_out: 1,
            max_packet: 1024,
        };
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
        // Linux binds the claimed interface to usbfs. This is ownership by
        // this successful claim, not an independently attached kernel driver.
        guard.claim_owned = true;
        let result = if preflight {
            guard
                .check()
                .map_err(|e| ("LIFECYCLE_POST_CLAIM_FAILED", e))
                .and_then(|_| {
                    fs::write(
                        out.join("claim-owned.json"),
                        serde_json::to_vec_pretty(&json!({
                            "driver":"/sys/bus/usb/drivers/usbfs", "wall_clock":wall_clock(),
                            "protocol_io":false, "bulk_out":0, "bulk_in":0, "control":0
                        }))
                        .unwrap(),
                    )
                    .map_err(|e| ("EVIDENCE_IO_FAULT", e.to_string()))?;
                    Ok("LIFECYCLE_CLAIM_PROVEN".into())
                })
        } else {
            walk(&handle, &c, out, &guard)
        };
        let release = handle.release_interface(c.interface);
        if let Err(e) = release {
            return Err(("OTHER_TRANSPORT_FAULT", format!("release: {e}")));
        }
        guard.claim_owned = false;
        guard
            .check()
            .map_err(|e| ("LIFECYCLE_POST_RELEASE_FAILED", e))?;
        fs::write(
            out.join("release-ownership.json"),
            serde_json::to_vec_pretty(&json!({
                "driver":null, "wall_clock":wall_clock(), "continuity_unchanged":true
            }))
            .unwrap(),
        )
        .map_err(|e| ("EVIDENCE_IO_FAULT", e.to_string()))?;
        result
    }

    fn walk(
        handle: &rusb::DeviceHandle<GlobalContext>,
        c: &Candidate,
        out: &Path,
        guard: &Guard,
    ) -> Result<String, (&'static str, String)> {
        let mut rec = Recorder::new(out).map_err(|e| ("EVIDENCE_IO_FAULT", e))?;
        guard.check_recorded(&mut rec)?;
        // Binary-level global protection also prevents a direct second launch
        // with a different output directory after the shell was consumed.
        OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(Path::new(PROJECT).join("tmp/phase345r3-engine-started.txt"))
            .and_then(|mut file| {
                writeln!(file, "{}", out.display())?;
                file.sync_all()
            })
            .map_err(|e| ("ENGINE_ALREADY_STARTED_OR_LOCK_FAILURE", e.to_string()))?;
        let started = Instant::now();
        let admission = fs::read(out.join("admission.json"))
            .map_err(|e| ("EVIDENCE_IO_FAULT", e.to_string()))?;
        consume_marker(&Path::new(PROJECT).join("tmp/phase345r3-live-consumed.txt"),
            &format!("PHASE=3.45r3\nCONSUMED_AT_UTC={}\nEVIDENCE_DIRECTORY={}\nADMISSION_JSON={}\nKEEP_FOR_FURTHER_ANALYSIS=true\nPHASE340_CLEANUP_AUTHORIZED=false\n",
                wall_clock(), out.display(), String::from_utf8_lossy(&admission).replace('\n', " ")))
            .map_err(|e| ("CAMPAIGN_ALREADY_CONSUMED_OR_LOCK_FAILURE", e.to_string()))?;
        File::open(Path::new(PROJECT).join("tmp"))
            .and_then(|f| f.sync_all())
            .map_err(|e| ("EVIDENCE_IO_FAULT", e.to_string()))?;
        let mut budgets = Budgets::default();
        let mut conv = Conversation::default();
        budgets
            .reserve_control(0, false)
            .map_err(|e| ("BUDGET_EXHAUSTED", e.into()))?;
        rec.ledger(
            "send_initial_ack",
            "execute_once",
            "authoritative predecessor requires exact ACK of 0x80800800",
        )
        .map_err(|e| ("EVIDENCE_IO_FAULT", e))?;
        write_recorded(
            handle,
            c.bulk_out,
            &FIRST_ACK,
            &mut rec,
            guard,
            "exact predecessor ACK; checksum of original CB payload remains unavailable",
            started,
        )?;
        let mut useful_packets = 0usize;
        let stop_reason;

        loop {
            if let Err(reason) = budgets.reserve_read(started.elapsed().as_millis() as u64) {
                stop_reason = reason;
                break;
            }
            guard.check_recorded(&mut rec)?;
            rec.ledger(
                "bulk_in",
                "execute_once",
                &format!("bounded receive call {}/{MAX_READS}", budgets.reads),
            )
            .map_err(|e| ("EVIDENCE_IO_FAULT", e))?;
            let mut buf = vec![0u8; READ_SIZE];
            let remaining = Duration::from_secs(ACTIVE_SECONDS).saturating_sub(started.elapsed());
            if remaining.is_zero() {
                stop_reason = "ACTIVE_TIME_BUDGET_REACHED";
                break;
            }
            match handle.read_bulk(c.bulk_in, &mut buf, IO_TIMEOUT.min(remaining)) {
                Ok(n) => {
                    buf.truncate(n);
                    let class = classify_usb_transfer(&buf);
                    let action = conv.receive(&class, &buf);
                    let decision = format!("{action:?}");
                    rec.event(
                        "RX",
                        c.bulk_in,
                        &buf,
                        if n == 0 { "ZLP" } else { "DATA" },
                        &decision,
                        "transport packet retained before protocol decision",
                    )
                    .map_err(|e| ("EVIDENCE_IO_FAULT", e))?;
                    guard.check_recorded(&mut rec)?;
                    match action {
                        Decision::Acknowledge {
                            packet_id,
                            disposition,
                        } => {
                            if let Err(reason) = budgets.reserve_control(
                                started.elapsed().as_millis() as u64,
                                disposition != PacketIdDisposition::Duplicate,
                            ) {
                                stop_reason = reason;
                                break;
                            }
                            rec.ledger(
                                "ack_valid_kd_data",
                                "execute_once",
                                &format!(
                                    "valid checksum; PacketId 0x{packet_id:08x}; {disposition:?}"
                                ),
                            )
                            .map_err(|e| ("EVIDENCE_IO_FAULT", e))?;
                            write_recorded(
                                handle,
                                c.bulk_out,
                                &acknowledge(packet_id),
                                &mut rec,
                                guard,
                                "checksum-valid packet; new ACK or bounded duplicate ACK",
                                started,
                            )?;
                            useful_packets +=
                                usize::from(disposition != PacketIdDisposition::Duplicate);
                            if let Some(reason) = conv.after_ack(&class) {
                                stop_reason = reason;
                                break;
                            }
                        }
                        Decision::Retransmit(_) => {
                            stop_reason = "INTERNAL_UNADMITTED_HOST_DATA_RETRANSMISSION";
                            break;
                        }
                        Decision::Stop(reason) => {
                            stop_reason = reason;
                            break;
                        }
                        Decision::Receive(reason) => {
                            rec.ledger("receive_decision", "passive", reason)
                                .map_err(|e| ("EVIDENCE_IO_FAULT", e))?;
                        }
                    }
                }
                Err(rusb::Error::Timeout) => {
                    let action = conv.timeout();
                    rec.event(
                        "RX",
                        c.bulk_in,
                        &[],
                        "TIMEOUT",
                        &format!("{action:?}"),
                        "bounded timeout is not a transport fault",
                    )
                    .map_err(|e| ("EVIDENCE_IO_FAULT", e))?;
                    guard.check_recorded(&mut rec)?;
                    if let Decision::Stop(reason) = action {
                        stop_reason = reason;
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
                Err(e) => {
                    rec.event(
                        "RX",
                        c.bulk_in,
                        &[],
                        &format!("{e:?}"),
                        "stop",
                        "transport failure; no recovery",
                    )
                    .map_err(|x| ("EVIDENCE_IO_FAULT", x))?;
                    return Err(("OTHER_TRANSPORT_FAULT", e.to_string()));
                }
            }
        }

        rec.ledger("campaign_stop", "stop", stop_reason)
            .map_err(|e| ("EVIDENCE_IO_FAULT", e))?;
        fs::write(
            out.join("engine-summary.json"),
            serde_json::to_vec_pretty(&json!({
                "result":stop_reason,
                "reads":budgets.reads,
                "control_tx":budgets.control_tx,
                "query_tx":budgets.query_tx,
                "new_data_ack_reservations":budgets.data_acks,
                "successful_new_data_acks":useful_packets,
                "useful_packets":useful_packets,
                "live_query_framing_verified":false,
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

    fn consume_marker(path: &Path, contents: &str) -> std::io::Result<()> {
        let mut file = OpenOptions::new().write(true).create_new(true).open(path)?;
        file.write_all(contents.as_bytes())?;
        file.sync_all()
    }

    fn write_recorded(
        handle: &rusb::DeviceHandle<GlobalContext>,
        endpoint: u8,
        bytes: &[u8],
        rec: &mut Recorder,
        guard: &Guard,
        reason: &str,
        started: Instant,
    ) -> Result<(), (&'static str, String)> {
        guard.check_recorded(rec)?;
        // Preserve intended bytes and the action BEFORE calling libusb, even
        // when the actual transfer faults or completes only partially.
        rec.event("TX", endpoint, bytes, "ATTEMPT", "execute_once", reason)
            .map_err(|e| ("EVIDENCE_IO_FAULT", e))?;
        let remaining = Duration::from_secs(ACTIVE_SECONDS).saturating_sub(started.elapsed());
        if remaining.is_zero() {
            return Err(("ACTIVE_TIME_BUDGET_REACHED", "before TX submission".into()));
        }
        match handle.write_bulk(endpoint, bytes, IO_TIMEOUT.min(remaining)) {
            Ok(n) => {
                let status = if n == bytes.len() {
                    "SUCCESS"
                } else {
                    "SHORT_WRITE"
                };
                rec.event(
                    "TX_STATUS",
                    endpoint,
                    &[],
                    status,
                    "completion",
                    &format!("actual={n}; requested={}", bytes.len()),
                )
                .map_err(|e| ("EVIDENCE_IO_FAULT", e))?;
                if n != bytes.len() {
                    return Err(("SHORT_WRITE", format!("{n}/{}", bytes.len())));
                }
            }
            Err(error) => {
                rec.event(
                    "TX_STATUS",
                    endpoint,
                    &[],
                    &format!("{error:?}"),
                    "stop",
                    "transmission failed; do not retry",
                )
                .map_err(|e| ("EVIDENCE_IO_FAULT", e))?;
                return Err(transport_error("bulk-OUT", error));
            }
        }
        guard.check_recorded(rec)?;
        Ok(())
    }

    struct Guard {
        values: BTreeMap<String, String>,
        links: BTreeMap<String, String>,
        inode: u64,
        trace_instance: PathBuf,
        usbmon_pid: i32,
        claim_owned: bool,
    }

    impl Guard {
        fn check_recorded(&self, rec: &mut Recorder) -> Result<(), (&'static str, String)> {
            if let Err(error) = self.check() {
                rec.event("GUARD", 0, &[], "CONTINUITY_LOST", "stop", &error)
                    .map_err(|e| ("EVIDENCE_IO_FAULT", e))?;
                return Err(("IDENTITY_OR_CAPTURE_CONTINUITY_LOST", error));
            }
            rec.event(
                "GUARD",
                0,
                &[],
                "CONTINUITY_OK",
                "continue",
                "identity, owned usbfs claim and capture checked",
            )
            .map_err(|e| ("EVIDENCE_IO_FAULT", e))?;
            Ok(())
        }

        fn load(out: &Path, preflight: bool) -> Result<Self, String> {
            let out = out.canonicalize().map_err(|e| e.to_string())?;
            if out.parent() != Some(&Path::new(PROJECT).join("tmp"))
                || !out.file_name().is_some_and(|s| {
                    s.to_string_lossy().starts_with(if preflight {
                        "phase345r3-claim-lifecycle-"
                    } else {
                        "phase345r3-kdusb-protocol-discovery-"
                    })
                })
            {
                return Err("output is not the admitted project evidence directory".into());
            }
            if Path::new(PROJECT)
                .join("tmp/phase345r3-live-consumed.txt")
                .exists()
            {
                return Err("r2 already consumed; direct invocation forbidden".into());
            }
            if !preflight && !out.join("lifecycle-admission.json").exists() {
                return Err("sealed lifecycle proof missing".into());
            }
            let value: Value = serde_json::from_slice(
                &fs::read(out.join("admission.json")).map_err(|e| e.to_string())?,
            )
            .map_err(|e| e.to_string())?;
            for (repo, key) in [
                (PROJECT, "project_head"),
                ("/home/kodi/engineering/ntoseye-kdusb", "ntoseye_head"),
            ] {
                let current = std::process::Command::new("git")
                    .args(["-C", repo, "rev-parse", "HEAD"])
                    .output()
                    .map_err(|e| e.to_string())?;
                if !current.status.success()
                    || Some(String::from_utf8_lossy(&current.stdout).trim()) != value[key].as_str()
                {
                    return Err(format!("source pin mismatch: {key}"));
                }
                let status = std::process::Command::new("git")
                    .args(["-C", repo, "status", "--porcelain", "--untracked-files=no"])
                    .output()
                    .map_err(|e| e.to_string())?;
                if !status.status.success() || !status.stdout.is_empty() {
                    return Err("tracked tree dirty".into());
                }
            }
            if !preflight {
                let proof: Value = serde_json::from_slice(
                    &fs::read(out.join("lifecycle-admission.json")).map_err(|e| e.to_string())?,
                )
                .map_err(|e| e.to_string())?;
                if proof["result"] != "LIFECYCLE_PREFLIGHT_PASS" {
                    return Err("lifecycle proof did not pass".into());
                }
                for key in ["values", "links", "device_inode"] {
                    if proof["fingerprint"][key] != value[key] {
                        return Err(format!("lifecycle identity changed: {key}"));
                    }
                }
                for key in ["project_head", "ntoseye_head"] {
                    if proof[key] != value[key] {
                        return Err(format!("lifecycle source changed: {key}"));
                    }
                }
            }
            let map = |key: &str| -> Result<BTreeMap<String, String>, String> {
                value[key]
                    .as_object()
                    .ok_or_else(|| format!("missing {key}"))?
                    .iter()
                    .map(|(k, v)| {
                        Ok((
                            k.clone(),
                            v.as_str()
                                .ok_or_else(|| format!("{key} is not a string"))?
                                .to_owned(),
                        ))
                    })
                    .collect()
            };
            let guard = Self {
                values: map("values")?,
                links: map("links")?,
                inode: value["device_inode"]
                    .as_u64()
                    .ok_or("missing device_inode")?,
                trace_instance: PathBuf::from(
                    value["trace_instance"]
                        .as_str()
                        .ok_or("missing trace_instance")?,
                ),
                usbmon_pid: value["usbmon_pid"].as_i64().ok_or("missing usbmon_pid")? as i32,
                claim_owned: false,
            };
            if guard.usbmon_pid <= 1
                || !guard
                    .trace_instance
                    .starts_with("/sys/kernel/tracing/instances")
            {
                return Err("invalid capture admission".into());
            }
            for required in [
                "/proc/sys/kernel/random/boot_id",
                "/sys/bus/usb/devices/6-1/devnum",
                "/sys/bus/usb/devices/6-1:1.0/ep_81/bEndpointAddress",
                "/sys/bus/usb/devices/6-1:1.0/ep_01/bEndpointAddress",
            ] {
                if !guard.values.contains_key(required) {
                    return Err(format!("missing required guard: {required}"));
                }
            }
            Ok(guard)
        }

        fn check(&self) -> Result<(), String> {
            for (path, expected) in &self.values {
                let value =
                    fs::read_to_string(path).map_err(|e| format!("identity file {path}: {e}"))?;
                if value.trim() != expected {
                    return Err(format!("identity changed: {path}"));
                }
            }
            for (path, expected) in &self.links {
                let actual =
                    fs::canonicalize(path).map_err(|e| format!("identity link {path}: {e}"))?;
                if actual.to_string_lossy() != expected.as_str() {
                    return Err(format!("ownership/path changed: {path}"));
                }
            }
            if fs::metadata("/sys/bus/usb/devices/6-1")
                .map_err(|e| e.to_string())?
                .ino()
                != self.inode
            {
                return Err("USB device sysfs object replaced".into());
            }
            let driver = match fs::canonicalize("/sys/bus/usb/devices/6-1:1.0/driver") {
                Ok(path) => Some(path),
                Err(error)
                    if error.kind() == std::io::ErrorKind::NotFound
                        && fs::symlink_metadata("/sys/bus/usb/devices/6-1:1.0/driver").is_err() =>
                {
                    None
                }
                Err(error) => return Err(format!("interface driver: {error}")),
            };
            validate_interface_driver(driver.as_deref(), self.claim_owned)?;
            let state = fs::read_to_string(self.trace_instance.join("tracing_on"))
                .map_err(|e| e.to_string())?;
            if state.trim() != "1" {
                return Err("trace capture stopped".into());
            }
            for event in [
                "xhci_urb_enqueue",
                "xhci_handle_event",
                "xhci_handle_transfer",
            ] {
                let enabled = fs::read_to_string(
                    self.trace_instance
                        .join(format!("events/xhci-hcd/{event}/enable")),
                )
                .map_err(|e| e.to_string())?;
                if enabled.trim() != "1" {
                    return Err(format!("tracepoint disabled: {event}"));
                }
            }
            if unsafe { libc::kill(self.usbmon_pid, 0) } != 0 {
                return Err("usbmon capture process disappeared".into());
            }
            Ok(())
        }
    }

    fn validate_interface_driver(driver: Option<&Path>, claim_owned: bool) -> Result<(), String> {
        match (claim_owned, driver) {
            (false, None) => Ok(()),
            (true, Some(path)) if path == Path::new("/sys/bus/usb/drivers/usbfs") => Ok(()),
            (false, Some(_)) => Err("interface driver attached before our claim".into()),
            (true, None) => Err("our usbfs interface claim disappeared".into()),
            (true, Some(_)) => Err("interface ownership changed away from our usbfs claim".into()),
        }
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
                "checksum_computed":packet.payload_complete.then(||format!("0x{:08x}", ntoseye::kdusb_discovery_r2::checksum(&packet.payload))),
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
        let mut conv = Conversation::default();
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
            let class = classify_usb_transfer(&bytes);
            let direction = value
                .get("direction")
                .and_then(Value::as_str)
                .unwrap_or("RX");
            let action = if direction == "RX" {
                if value.get("status").and_then(Value::as_str) == Some("TIMEOUT") {
                    Some(conv.timeout())
                } else if value
                    .get("status")
                    .and_then(Value::as_str)
                    .is_none_or(|s| matches!(s, "DATA" | "ZLP"))
                {
                    Some(conv.receive(&class, &bytes))
                } else {
                    None
                }
            } else {
                None
            };
            writeln!(out, "{}", json!({"event":count,"direction":direction,"reported_usb_length":value.get("reported_usb_length").or_else(||value.get("byte_length")),"prefix_only":value.get("prefix_only"),"byte_length":bytes.len(),"hex":encoded,"classification":classification_json(&class),"decision":action.map(|d|format!("{d:?}")).or_else(|| if direction == "RX" {value.get("decision").and_then(Value::as_str).map(ToOwned::to_owned)} else {None})})).map_err(|e| e.to_string())?;
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
        fn binary_consumption_is_exclusive_and_preserves_first_attempt() {
            let path =
                std::env::temp_dir().join(format!("kdusb-r2-consume-test-{}", std::process::id()));
            consume_marker(&path, "first-intention").unwrap();
            assert!(consume_marker(&path, "second-intention").is_err());
            assert_eq!(fs::read_to_string(&path).unwrap(), "first-intention");
            fs::remove_file(path).unwrap();
        }

        #[test]
        fn lifecycle_pre_claim_own_claim_release_and_ownership_faults() {
            let usbfs = Some(Path::new("/sys/bus/usb/drivers/usbfs"));
            assert!(validate_interface_driver(None, false).is_ok());
            assert!(validate_interface_driver(usbfs, true).is_ok());
            assert!(validate_interface_driver(None, false).is_ok());
            assert!(validate_interface_driver(None, true).is_err());
            assert!(validate_interface_driver(usbfs, false).is_err());
        }

        #[test]
        fn r3_live_revision_is_open_before_exclusive_consumption() {
            assert!(live_campaign_enabled());
            assert_eq!(CAMPAIGN_CONSUMED_AT_UTC, "");
            assert_eq!(
                hex::encode(FIRST_ACK),
                "69696969040000000008808000000000"
            );
        }

        #[test]
        fn interface_guard_distinguishes_our_claim_from_external_drivers() {
            let usbfs = Some(Path::new("/sys/bus/usb/drivers/usbfs"));
            let other = Some(Path::new("/sys/bus/usb/drivers/usb-storage"));
            assert!(validate_interface_driver(None, false).is_ok());
            assert!(validate_interface_driver(usbfs, false).is_err());
            assert!(validate_interface_driver(other, false).is_err());
            assert!(validate_interface_driver(usbfs, true).is_ok());
            assert!(validate_interface_driver(None, true).is_err());
            assert!(validate_interface_driver(other, true).is_err());
        }

        #[test]
        fn hard_budgets_and_first_action_are_fixed() {
            assert_eq!(MAX_READS, 64);
            assert_eq!(MAX_ACKED_DATA, 16);
            assert_eq!(MAX_CONTROL_TX, 20);
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
