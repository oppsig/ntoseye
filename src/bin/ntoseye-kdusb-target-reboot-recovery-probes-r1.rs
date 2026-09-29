//! Phase 3.44CA: one-shot, read-mostly KDUSB transport characterization.
//!
//! Dry by default. Live mode claims the existing interface and executes the
//! fixed P01..P19 schedule. It never changes USB configuration or recovery
//! state and transmits only the five-byte `NAME?` probe.

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("ntoseye-kdusb-target-reboot-recovery-probes-r1 is Linux-only");
    std::process::exit(2);
}

#[cfg(target_os = "linux")]
fn main() {
    std::process::exit(linux::run());
}

#[cfg(target_os = "linux")]
mod linux {
    use rusb::{Direction, GlobalContext, TransferType};
    use std::fs::{File, OpenOptions};
    use std::io::Write;
    use std::time::Duration;

    const LIVE_FLAG: &str = "--execute-target-reboot-recovery-probes";
    const TARGET: &str = "CLSA0102_USB";
    const VID: u16 = 0x3495;
    const PID: u16 = 0x00e0;
    const INTERFACE: u8 = 0;
    const BULK_OUT: u8 = 0x01;
    const BULK_IN: u8 = 0x81;
    const NAME: &[u8; 5] = b"NAME?";
    const NAME_REPLY: &[u8] = b"NAME=CLSA0102_USB";
    const CONTROL_TIMEOUT: Duration = Duration::from_millis(500);
    const BULK_TIMEOUT: Duration = Duration::from_millis(1000);
    const BULK_READ_LEN: usize = 4016;

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum Kind {
        Control,
        BulkOut,
        BulkIn,
    }

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    struct Spec {
        id: u8,
        name: &'static str,
        kind: Kind,
        request_type: u8,
        request: u8,
        value: u16,
        index: u16,
        length: usize,
    }

    const fn control(
        id: u8,
        name: &'static str,
        request_type: u8,
        request: u8,
        value: u16,
        index: u16,
        length: usize,
    ) -> Spec {
        Spec {
            id,
            name,
            kind: Kind::Control,
            request_type,
            request,
            value,
            index,
            length,
        }
    }

    const PROBES: [Spec; 19] = [
        control(1, "GET_STATUS_DEVICE_PRE", 0x80, 0x00, 0, 0, 2),
        control(2, "GET_CONFIGURATION_PRE", 0x80, 0x08, 0, 0, 1),
        control(3, "GET_DESCRIPTOR_DEVICE_PRE", 0x80, 0x06, 0x0100, 0, 18),
        control(
            4,
            "GET_DESCRIPTOR_CONFIG_HEADER_PRE",
            0x80,
            0x06,
            0x0200,
            0,
            9,
        ),
        control(5, "GET_INTERFACE_PRE", 0x81, 0x0a, 0, 0, 1),
        control(6, "GET_STATUS_EP_OUT_PRE", 0x82, 0x00, 0, 0x01, 2),
        control(7, "GET_STATUS_EP_IN_PRE", 0x82, 0x00, 0, 0x81, 2),
        Spec {
            id: 8,
            name: "NAME_OUT",
            kind: Kind::BulkOut,
            request_type: 0,
            request: 0,
            value: 0,
            index: 0,
            length: 5,
        },
        Spec {
            id: 9,
            name: "BULK_IN_1",
            kind: Kind::BulkIn,
            request_type: 0,
            request: 0,
            value: 0,
            index: 0,
            length: BULK_READ_LEN,
        },
        Spec {
            id: 10,
            name: "BULK_IN_2",
            kind: Kind::BulkIn,
            request_type: 0,
            request: 0,
            value: 0,
            index: 0,
            length: BULK_READ_LEN,
        },
        Spec {
            id: 11,
            name: "BULK_IN_3",
            kind: Kind::BulkIn,
            request_type: 0,
            request: 0,
            value: 0,
            index: 0,
            length: BULK_READ_LEN,
        },
        Spec {
            id: 12,
            name: "BULK_IN_4",
            kind: Kind::BulkIn,
            request_type: 0,
            request: 0,
            value: 0,
            index: 0,
            length: BULK_READ_LEN,
        },
        control(13, "GET_STATUS_DEVICE_POST", 0x80, 0x00, 0, 0, 2),
        control(14, "GET_CONFIGURATION_POST", 0x80, 0x08, 0, 0, 1),
        control(15, "GET_INTERFACE_POST", 0x81, 0x0a, 0, 0, 1),
        control(16, "GET_STATUS_EP_OUT_POST", 0x82, 0x00, 0, 0x01, 2),
        control(17, "GET_STATUS_EP_IN_POST", 0x82, 0x00, 0, 0x81, 2),
        control(18, "GET_DESCRIPTOR_DEVICE_POST", 0x80, 0x06, 0x0100, 0, 18),
        control(
            19,
            "GET_DESCRIPTOR_CONFIG_HEADER_POST",
            0x80,
            0x06,
            0x0200,
            0,
            9,
        ),
    ];

    #[derive(Clone, Debug, PartialEq, Eq)]
    enum UsbError {
        Timeout,
        Pipe,
        Io,
        NoDevice,
        Other(String),
    }

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum Status {
        Ok,
        Timeout,
        Pipe,
        Io,
        NoDevice,
        Short,
        Other,
        NotAttempted,
    }

    impl Status {
        fn text(self) -> &'static str {
            match self {
                Self::Ok => "OK",
                Self::Timeout => "TIMEOUT",
                Self::Pipe => "PIPE",
                Self::Io => "IO",
                Self::NoDevice => "NO_DEVICE",
                Self::Short => "SHORT",
                Self::Other => "OTHER_ERROR",
                Self::NotAttempted => "NOT_ATTEMPTED",
            }
        }
    }

    #[derive(Clone, Debug)]
    struct Observation {
        status: Status,
        data: Vec<u8>,
        error: Option<String>,
    }

    impl Default for Observation {
        fn default() -> Self {
            Self {
                status: Status::NotAttempted,
                data: Vec::new(),
                error: None,
            }
        }
    }

    trait Backend {
        fn control(&mut self, spec: Spec, buffer: &mut [u8]) -> Result<usize, UsbError>;
        fn name_out(&mut self, payload: &[u8]) -> Result<usize, UsbError>;
        fn bulk_in(&mut self, buffer: &mut [u8]) -> Result<usize, UsbError>;
        fn marker(&mut self, marker: &str) -> Result<(), String>;
        fn release(&mut self) -> Result<(), String>;
    }

    struct Report {
        observations: Vec<Observation>,
        result: &'static str,
        name_probe_sent: bool,
        name_seen: bool,
        name_on: Option<usize>,
        surplus: Vec<u8>,
        disappeared: bool,
        identity_mismatch: bool,
        interface_released: bool,
        fatal_error: Option<String>,
    }

    pub fn run() -> i32 {
        let args: Vec<String> = std::env::args().skip(1).collect();
        if args.is_empty() {
            print_dry();
            return 0;
        }
        if args != [LIVE_FLAG, TARGET] {
            eprintln!(
                "usage: ntoseye-kdusb-target-reboot-recovery-probes-r1 [{LIVE_FLAG} {TARGET}]"
            );
            return 2;
        }
        let mut backend = match RusbBackend::open() {
            Ok(value) => value,
            Err((class, detail)) => {
                print_unavailable(class, &detail);
                return 3;
            }
        };
        println!("USB_BUS={}", backend.bus);
        println!("USB_ADDRESS={}", backend.address);
        println!("USB_PORT_PATH=1");
        let report = execute(&mut backend);
        print_report(&report, true);
        if report.name_seen && !report.disappeared && !report.identity_mismatch {
            0
        } else {
            4
        }
    }

    fn execute<B: Backend>(backend: &mut B) -> Report {
        let mut observations = vec![Observation::default(); PROBES.len()];
        let mut stop = false;
        let mut disappeared = false;
        let mut identity_mismatch = false;
        let mut fatal_error = None;
        let mut name_probe_sent = false;
        let mut bulk_stream = Vec::new();
        let mut bulk_ends = Vec::new();

        for (slot, spec) in PROBES.iter().copied().enumerate() {
            if stop {
                continue;
            }
            let begin = format!("CA_P{:02}_{}_BEGIN", spec.id, spec.name);
            let end = format!("CA_P{:02}_{}_END", spec.id, spec.name);
            if let Err(error) = backend.marker(&begin) {
                observations[slot].error = Some(format!("trace marker BEGIN failed: {error}"));
                fatal_error = Some(format!("{begin}: {error}"));
                break;
            }
            let observation = match spec.kind {
                Kind::Control => {
                    let mut buffer = vec![0; spec.length];
                    observe_transfer(backend.control(spec, &mut buffer), buffer, spec.length)
                }
                Kind::BulkOut => {
                    name_probe_sent = true;
                    let result = backend.name_out(NAME);
                    observe_transfer(result, NAME.to_vec(), NAME.len())
                }
                Kind::BulkIn => {
                    let mut buffer = vec![0; spec.length];
                    let obs = observe_transfer(backend.bulk_in(&mut buffer), buffer, usize::MAX);
                    if !obs.data.is_empty() {
                        bulk_stream.extend_from_slice(&obs.data);
                    }
                    bulk_ends.push(bulk_stream.len());
                    obs
                }
            };
            if let Err(error) = backend.marker(&end) {
                observations[slot] = observation;
                observations[slot].error = Some(format!("trace marker END failed: {error}"));
                fatal_error = Some(format!("{end}: {error}"));
                break;
            }
            disappeared = observation.status == Status::NoDevice;
            if spec.kind == Kind::Control && observation.status == Status::Ok {
                if let Err(error) = validate_control(spec, &observation.data) {
                    identity_mismatch = true;
                    fatal_error = Some(error);
                }
            }
            observations[slot] = observation;
            stop = disappeared || identity_mismatch;
        }

        let (name_seen, name_on, surplus) = parse_name(&bulk_stream, &bulk_ends);
        let interface_released = match backend.release() {
            Ok(()) => true,
            Err(error) => {
                if fatal_error.is_none() {
                    fatal_error = Some(format!("interface release failed: {error}"));
                }
                false
            }
        };
        let result = classify(
            &observations,
            name_seen,
            name_on,
            disappeared,
            identity_mismatch,
            fatal_error.is_some(),
        );
        Report {
            observations,
            result,
            name_probe_sent,
            name_seen,
            name_on,
            surplus,
            disappeared,
            identity_mismatch,
            interface_released,
            fatal_error,
        }
    }

    fn observe_transfer(
        result: Result<usize, UsbError>,
        mut buffer: Vec<u8>,
        expected: usize,
    ) -> Observation {
        match result {
            Ok(length) => {
                buffer.truncate(length);
                Observation {
                    status: if expected != usize::MAX && length != expected {
                        Status::Short
                    } else {
                        Status::Ok
                    },
                    data: buffer,
                    error: None,
                }
            }
            Err(UsbError::Timeout) => Observation {
                status: Status::Timeout,
                data: Vec::new(),
                error: Some("timeout".into()),
            },
            Err(UsbError::Pipe) => Observation {
                status: Status::Pipe,
                data: Vec::new(),
                error: Some("rusb::Error::Pipe".into()),
            },
            Err(UsbError::Io) => Observation {
                status: Status::Io,
                data: Vec::new(),
                error: Some("rusb::Error::Io".into()),
            },
            Err(UsbError::NoDevice) => Observation {
                status: Status::NoDevice,
                data: Vec::new(),
                error: Some("device disappeared".into()),
            },
            Err(UsbError::Other(error)) => other(error),
        }
    }

    fn other(error: String) -> Observation {
        Observation {
            status: Status::Other,
            data: Vec::new(),
            error: Some(error),
        }
    }

    fn validate_control(spec: Spec, data: &[u8]) -> Result<(), String> {
        match spec.id {
            2 | 14 if data[0] != 1 => {
                Err(format!("P{:02} configuration {} != 1", spec.id, data[0]))
            }
            3 | 18 if data[0] != 18 || data[1] != 1 => {
                Err(format!("P{:02} invalid device descriptor header", spec.id))
            }
            3 | 18
                if u16::from_le_bytes([data[8], data[9]]) != VID
                    || u16::from_le_bytes([data[10], data[11]]) != PID =>
            {
                Err(format!("P{:02} device VID/PID mismatch", spec.id))
            }
            4 | 19 if data[0] != 9 || data[1] != 2 => Err(format!(
                "P{:02} invalid configuration descriptor header",
                spec.id
            )),
            4 | 19 if data[5] != 1 => Err(format!(
                "P{:02} descriptor configuration {} != 1",
                spec.id, data[5]
            )),
            5 | 15 if data[0] != 0 => Err(format!(
                "P{:02} alternate setting {} != 0",
                spec.id, data[0]
            )),
            _ => Ok(()),
        }
    }

    fn parse_name(stream: &[u8], ends: &[usize]) -> (bool, Option<usize>, Vec<u8>) {
        if !stream.starts_with(NAME_REPLY)
            || stream.len() <= NAME_REPLY.len()
            || stream[NAME_REPLY.len()] != 0
        {
            return (false, None, Vec::new());
        }
        let mut consumed = NAME_REPLY.len() + 1;
        if stream.get(consumed) == Some(&0) {
            consumed += 1;
        }
        let on = ends
            .iter()
            .position(|end| *end >= consumed)
            .map(|index| index + 1);
        (true, on, stream[consumed..].to_vec())
    }

    fn is_fault(status: Status) -> bool {
        matches!(
            status,
            Status::Timeout
                | Status::Pipe
                | Status::Io
                | Status::Other
                | Status::Short
                | Status::NoDevice
        )
    }

    fn classify(
        obs: &[Observation],
        name: bool,
        name_on: Option<usize>,
        disappeared: bool,
        mismatch: bool,
        fatal: bool,
    ) -> &'static str {
        if mismatch {
            return "IDENTITY_MISMATCH_ABORT";
        }
        if disappeared {
            return "DEVICE_DISAPPEARED";
        }
        if fatal {
            return "OTHER_TRANSPORT_FAULT";
        }
        if is_fault(obs[7].status) {
            return "NAME_WRITE_FAULT";
        }
        let control_fault = PROBES
            .iter()
            .enumerate()
            .any(|(i, p)| p.kind == Kind::Control && is_fault(obs[i].status));
        let bulk_fault = (8..12).any(|i| is_fault(obs[i].status));
        if name {
            if name_on.unwrap_or(1) > 1
                && (8..8 + name_on.unwrap()).any(|i| is_fault(obs[i].status))
            {
                return "NAME_RECOVERED_AFTER_INITIAL_BULK_IN_FAULT";
            }
            if control_fault {
                return "NAME_SUCCESS_WITH_CONTROL_PROBE_FAULTS";
            }
            return "NAME_SUCCESS_ALL_CONTROL_PROBES_OK";
        }
        if bulk_fault && !control_fault {
            return "BULK_IN_FAULT_CONTROL_PLANE_STILL_HEALTHY";
        }
        if bulk_fault && control_fault {
            return "CONTROL_AND_BULK_FAULTS";
        }
        if !control_fault {
            return "NO_NAME_ALL_CONTROL_PROBES_OK";
        }
        "OTHER_TRANSPORT_FAULT"
    }

    fn print_report(report: &Report, live: bool) {
        println!("PHASE344CA_RESULT={}", report.result);
        for (spec, obs) in PROBES.iter().zip(&report.observations) {
            println!("PROBE_P{:02}_NAME={}", spec.id, spec.name);
            println!(
                "PROBE_P{:02}_ATTEMPTED={}",
                spec.id,
                obs.status != Status::NotAttempted
            );
            println!("PROBE_P{:02}_STATUS={}", spec.id, obs.status.text());
            println!(
                "PROBE_P{:02}_BYTES={}",
                spec.id,
                if obs.status == Status::NotAttempted {
                    "NA".into()
                } else {
                    obs.data.len().to_string()
                }
            );
            println!(
                "PROBE_P{:02}_DATA_HEX={}",
                spec.id,
                if obs.data.is_empty() {
                    "NA".into()
                } else {
                    hex::encode(&obs.data)
                }
            );
            println!(
                "PROBE_P{:02}_ERROR={}",
                spec.id,
                obs.error.as_deref().unwrap_or("NA")
            );
            println!(
                "PROBE_P{:02}_VALIDATION={}",
                spec.id,
                validation_text(*spec, obs)
            );
        }
        let attempted = report
            .observations
            .iter()
            .filter(|o| o.status != Status::NotAttempted)
            .count();
        fn count(observations: &[Observation], kind: Kind, status: fn(Status) -> bool) -> usize {
            PROBES
                .iter()
                .zip(observations)
                .filter(|(p, o)| p.kind == kind && status(o.status))
                .count()
        }
        println!("PROBES_ATTEMPTED={attempted}");
        println!(
            "CONTROL_PROBES_ATTEMPTED={}",
            count(&report.observations, Kind::Control, |s| s
                != Status::NotAttempted)
        );
        println!(
            "CONTROL_PROBES_OK={}",
            count(&report.observations, Kind::Control, |s| s == Status::Ok)
        );
        println!(
            "CONTROL_PROBES_TIMEOUT={}",
            count(&report.observations, Kind::Control, |s| s
                == Status::Timeout)
        );
        println!(
            "CONTROL_PROBES_PIPE={}",
            count(&report.observations, Kind::Control, |s| s == Status::Pipe)
        );
        println!(
            "CONTROL_PROBES_IO={}",
            count(&report.observations, Kind::Control, |s| s == Status::Io)
        );
        println!(
            "BULK_OUT_PROBES_ATTEMPTED={}",
            count(&report.observations, Kind::BulkOut, |s| s
                != Status::NotAttempted)
        );
        println!(
            "BULK_IN_PROBES_ATTEMPTED={}",
            count(&report.observations, Kind::BulkIn, |s| s
                != Status::NotAttempted)
        );
        println!(
            "BULK_IN_PROBES_OK={}",
            count(&report.observations, Kind::BulkIn, |s| s == Status::Ok)
        );
        println!(
            "BULK_IN_PROBES_TIMEOUT={}",
            count(&report.observations, Kind::BulkIn, |s| s == Status::Timeout)
        );
        println!(
            "BULK_IN_PROBES_PIPE={}",
            count(&report.observations, Kind::BulkIn, |s| s == Status::Pipe)
        );
        println!(
            "BULK_IN_PROBES_IO={}",
            count(&report.observations, Kind::BulkIn, |s| s == Status::Io)
        );
        println!("NAME_PROBE_SENT={}", report.name_probe_sent);
        println!("NAME_SEEN={}", report.name_seen);
        println!(
            "NAME_TARGET={}",
            if report.name_seen { TARGET } else { "NA" }
        );
        println!(
            "NAME_REPLY_ON_BULK_IN={}",
            report
                .name_on
                .map(|n| n.to_string())
                .unwrap_or_else(|| "NA".into())
        );
        println!("SURPLUS_AFTER_NAME_BYTES={}", report.surplus.len());
        println!(
            "SURPLUS_AFTER_NAME_HEX={}",
            if report.surplus.is_empty() {
                "NA".into()
            } else {
                hex::encode(&report.surplus)
            }
        );
        println!("DEVICE_DISAPPEARED={}", report.disappeared);
        println!("IDENTITY_MISMATCH_ABORT={}", report.identity_mismatch);
        println!("INTERFACE_RELEASED={}", report.interface_released);
        println!("ERROR={}", report.fatal_error.as_deref().unwrap_or("NA"));
        print_safety(live, report.name_probe_sent);
    }

    fn validation_text(spec: Spec, obs: &Observation) -> String {
        if obs.status != Status::Ok {
            return "NA".into();
        }
        match spec.id {
            2 | 14 => format!(
                "CONFIGURATION_VALUE={};IS_1={}",
                obs.data[0],
                obs.data[0] == 1
            ),
            3 | 18 => format!(
                "DESCRIPTOR_TYPE_LENGTH_VALID={};VID_PID={:04x}:{:04x};IDENTITY_MATCH={}",
                obs.data[0] == 18 && obs.data[1] == 1,
                u16::from_le_bytes([obs.data[8], obs.data[9]]),
                u16::from_le_bytes([obs.data[10], obs.data[11]]),
                u16::from_le_bytes([obs.data[8], obs.data[9]]) == VID
                    && u16::from_le_bytes([obs.data[10], obs.data[11]]) == PID
            ),
            4 | 19 => format!(
                "DESCRIPTOR_TYPE_LENGTH_VALID={};CONFIGURATION_VALUE={};IS_1={}",
                obs.data[0] == 9 && obs.data[1] == 2,
                obs.data[5],
                obs.data[5] == 1
            ),
            5 | 15 => format!(
                "ALTERNATE_SETTING={};IS_0={}",
                obs.data[0],
                obs.data[0] == 0
            ),
            6 | 7 | 16 | 17 => format!("ENDPOINT_HALTED={}", obs.data[0] & 1 == 1),
            _ => "NA".into(),
        }
    }

    fn print_dry() {
        println!("NTOSEYE_KDUSB_TARGET_REBOOT_RECOVERY_PROBES=READY");
        println!("DEFAULT_MODE=DRY_PLAN");
        println!("LIVE_FLAG={LIVE_FLAG} {TARGET}");
        println!("POST_REBOOT_ADDRESS_DYNAMIC=true");
        for spec in PROBES {
            println!("PROBE_P{:02}_NAME={}", spec.id, spec.name);
            println!("PROBE_P{:02}_ATTEMPTED=false", spec.id);
            println!("PROBE_P{:02}_STATUS=NOT_ATTEMPTED", spec.id);
            println!("PROBE_P{:02}_BYTES=NA", spec.id);
            println!("PROBE_P{:02}_DATA_HEX=NA", spec.id);
            println!("PROBE_P{:02}_ERROR=NA", spec.id);
            println!("PROBE_P{:02}_VALIDATION=NA", spec.id);
        }
        println!("PROBES_ATTEMPTED=0");
        println!("CONTROL_PROBES_ATTEMPTED=0");
        println!("CONTROL_PROBES_OK=0");
        println!("CONTROL_PROBES_TIMEOUT=0");
        println!("CONTROL_PROBES_PIPE=0");
        println!("CONTROL_PROBES_IO=0");
        println!("BULK_OUT_PROBES_ATTEMPTED=0");
        println!("BULK_IN_PROBES_ATTEMPTED=0");
        println!("BULK_IN_PROBES_OK=0");
        println!("BULK_IN_PROBES_TIMEOUT=0");
        println!("BULK_IN_PROBES_PIPE=0");
        println!("BULK_IN_PROBES_IO=0");
        println!("NAME_SEEN=false");
        println!("NAME_TARGET=NA");
        println!("NAME_REPLY_ON_BULK_IN=NA");
        println!("SURPLUS_AFTER_NAME_BYTES=0");
        println!("SURPLUS_AFTER_NAME_HEX=NA");
        println!("DEVICE_DISAPPEARED=false");
        println!("INTERFACE_RELEASED=false");
        print_safety(false, false);
    }

    fn print_unavailable(class: &'static str, detail: &str) {
        println!("PHASE344CA_RESULT={class}");
        println!("ERROR={detail}");
        for spec in PROBES {
            println!("PROBE_P{:02}_NAME={}", spec.id, spec.name);
            println!("PROBE_P{:02}_ATTEMPTED=false", spec.id);
            println!("PROBE_P{:02}_STATUS=NOT_ATTEMPTED", spec.id);
            println!("PROBE_P{:02}_BYTES=NA", spec.id);
            println!("PROBE_P{:02}_DATA_HEX=NA", spec.id);
            println!("PROBE_P{:02}_ERROR=NA", spec.id);
            println!("PROBE_P{:02}_VALIDATION=NA", spec.id);
        }
        println!("PROBES_ATTEMPTED=0");
        println!("CONTROL_PROBES_ATTEMPTED=0");
        println!("CONTROL_PROBES_OK=0");
        println!("CONTROL_PROBES_TIMEOUT=0");
        println!("CONTROL_PROBES_PIPE=0");
        println!("BULK_OUT_PROBES_ATTEMPTED=0");
        println!("BULK_IN_PROBES_ATTEMPTED=0");
        println!("BULK_IN_PROBES_OK=0");
        println!("BULK_IN_PROBES_TIMEOUT=0");
        println!("BULK_IN_PROBES_PIPE=0");
        println!("NAME_SEEN=false");
        println!("NAME_TARGET=NA");
        println!("NAME_REPLY_ON_BULK_IN=NA");
        println!("SURPLUS_AFTER_NAME_BYTES=0");
        println!("SURPLUS_AFTER_NAME_HEX=NA");
        println!("DEVICE_DISAPPEARED={}", class == "DEVICE_DISAPPEARED");
        println!("INTERFACE_RELEASED=false");
        print_safety(false, false);
    }

    fn print_safety(live: bool, name: bool) {
        println!("LIVE_USB_ACTIVITY={live}");
        println!("MAX_USB_TRANSACTIONS=19");
        println!("MAX_CONTROL_READ_PROBES=14");
        println!("MAX_BULK_OUT_PROBES=1");
        println!("MAX_BULK_IN_PROBES=4");
        println!("MAX_NAME_TX=1");
        println!("AUTOMATIC_RETRY=false");
        println!("NAME_PROBE_SENT={name}");
        println!("USB_DEVICE_RESET=false");
        println!("SET_CONFIGURATION_TX=false");
        println!("CLEAR_HALT_TX=false");
        println!("ENDPOINT_RECREATION_EXECUTED=false");
        println!("KERNEL_DRIVER_DETACH=false");
        println!("ALTERNATE_SETTING_CHANGE=false");
        println!("KD_PACKET_TX=false");
        println!("KD_ACK_TX=false");
        println!("KD_RESEND_TX=false");
        println!("KD_RESET_TX=false");
        println!("KD_FILE_IO_REPLY_TX=false");
        println!("BREAKIN_SENT=false");
        println!("DEBUGGER_SESSION=false");
        println!("TARGET_MEMORY_ACCESS=false");
        println!("PCI_UNBIND_REBIND=false");
        println!("RUNTIME_PM_CHANGE=false");
        println!("HOST_REBOOT=false");
        println!("TARGET_REBOOT_INITIATED_BY_BINARY=false");
        println!("BCD_CHANGE=false");
        println!("PHASE340_CLEANUP_AUTHORIZED=false");
    }

    struct RusbBackend {
        handle: rusb::DeviceHandle<GlobalContext>,
        marker: File,
        claimed: bool,
        bus: u8,
        address: u8,
    }

    impl RusbBackend {
        fn open() -> Result<Self, (&'static str, String)> {
            let marker_path = std::env::var("NTOSEYE_TRACE_MARKER").map_err(|_| {
                (
                    "OTHER_TRANSPORT_FAULT",
                    "NTOSEYE_TRACE_MARKER is required".into(),
                )
            })?;
            let mut marker = OpenOptions::new()
                .write(true)
                .open(&marker_path)
                .map_err(|e| {
                    (
                        "OTHER_TRANSPORT_FAULT",
                        format!("trace marker is not writable: {e}"),
                    )
                })?;
            marker
                .write_all(b"CA_ADMISSION_MARKER\n")
                .and_then(|_| marker.flush())
                .map_err(|e| {
                    (
                        "OTHER_TRANSPORT_FAULT",
                        format!("trace marker write test failed: {e}"),
                    )
                })?;
            let devices = rusb::devices()
                .map_err(|e| ("OTHER_TRANSPORT_FAULT", format!("enumerating devices: {e}")))?;
            let mut candidates = Vec::new();
            for device in devices.iter() {
                let dd = match device.device_descriptor() {
                    Ok(v) => v,
                    Err(_) => continue,
                };
                if (dd.vendor_id(), dd.product_id()) != (VID, PID) {
                    continue;
                }
                if device.bus_number() != 6
                    || device.port_numbers().ok().as_deref() != Some(&[1])
                {
                    continue;
                }
                let config = device.active_config_descriptor().map_err(|e| {
                    (
                        "IDENTITY_MISMATCH_ABORT",
                        format!("active configuration: {e}"),
                    )
                })?;
                if config.number() != 1 {
                    continue;
                }
                for iface in config.interfaces() {
                    for desc in iface.descriptors() {
                        if desc.interface_number() != INTERFACE
                            || desc.setting_number() != 0
                            || (
                                desc.class_code(),
                                desc.sub_class_code(),
                                desc.protocol_code(),
                            ) != (0xdc, 0x02, 0xff)
                        {
                            continue;
                        }
                        let mut input = false;
                        let mut output = false;
                        for ep in desc.endpoint_descriptors() {
                            input |= ep.address() == BULK_IN
                                && ep.transfer_type() == TransferType::Bulk
                                && ep.direction() == Direction::In;
                            output |= ep.address() == BULK_OUT
                                && ep.transfer_type() == TransferType::Bulk
                                && ep.direction() == Direction::Out;
                        }
                        if input && output {
                            candidates.push(device.clone());
                        }
                    }
                }
            }
            if candidates.len() != 1 {
                return Err((
                    "IDENTITY_MISMATCH_ABORT",
                    format!(
                        "expected one exact 3495:00e0 at bus 6 port path 1, found {}",
                        candidates.len()
                    ),
                ));
            }
            let device = candidates.remove(0);
            let bus = device.bus_number();
            let address = device.address();
            let handle = device
                .open()
                .map_err(|e| map_open_error("open", e))?;
            match handle.kernel_driver_active(INTERFACE) {
                Ok(true) => {
                    return Err((
                        "IDENTITY_MISMATCH_ABORT",
                        "kernel driver attached; refusing detach".into(),
                    ));
                }
                Ok(false) | Err(rusb::Error::NotSupported) => {}
                Err(e) => return Err(map_open_error("kernel driver check", e)),
            }
            handle
                .claim_interface(INTERFACE)
                .map_err(|e| map_open_error("claim interface", e))?;
            Ok(Self {
                handle,
                marker,
                claimed: true,
                bus,
                address,
            })
        }
    }

    fn map_usb_error(error: rusb::Error) -> UsbError {
        match error {
            rusb::Error::Timeout => UsbError::Timeout,
            // Preserve libusb/rusb's exact public error enum. Linux usbfs
            // -EPROTO commonly appears as Error::Io; Error::Pipe remains
            // distinguishable and must not be collapsed into the same class.
            rusb::Error::Pipe => UsbError::Pipe,
            rusb::Error::Io => UsbError::Io,
            rusb::Error::NoDevice => UsbError::NoDevice,
            other => UsbError::Other(format!("{other}")),
        }
    }

    fn map_open_error(operation: &str, error: rusb::Error) -> (&'static str, String) {
        let class = if error == rusb::Error::NoDevice {
            "DEVICE_DISAPPEARED"
        } else {
            "OTHER_TRANSPORT_FAULT"
        };
        (class, format!("{operation}: {error}"))
    }

    impl Backend for RusbBackend {
        fn control(&mut self, spec: Spec, buffer: &mut [u8]) -> Result<usize, UsbError> {
            self.handle
                .read_control(
                    spec.request_type,
                    spec.request,
                    spec.value,
                    spec.index,
                    buffer,
                    CONTROL_TIMEOUT,
                )
                .map_err(map_usb_error)
        }
        fn name_out(&mut self, payload: &[u8]) -> Result<usize, UsbError> {
            self.handle
                .write_bulk(BULK_OUT, payload, BULK_TIMEOUT)
                .map_err(map_usb_error)
        }
        fn bulk_in(&mut self, buffer: &mut [u8]) -> Result<usize, UsbError> {
            self.handle
                .read_bulk(BULK_IN, buffer, BULK_TIMEOUT)
                .map_err(map_usb_error)
        }
        fn marker(&mut self, marker: &str) -> Result<(), String> {
            writeln!(self.marker, "{marker}")
                .and_then(|_| self.marker.flush())
                .map_err(|e| e.to_string())
        }
        fn release(&mut self) -> Result<(), String> {
            if self.claimed {
                self.handle
                    .release_interface(INTERFACE)
                    .map_err(|e| e.to_string())?;
                self.claimed = false;
            }
            Ok(())
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use std::collections::VecDeque;

        struct Fake {
            replies: VecDeque<Result<Vec<u8>, UsbError>>,
            markers: Vec<String>,
            calls: Vec<Kind>,
            released: bool,
        }
        impl Fake {
            fn successful() -> Self {
                let device = vec![
                    18, 1, 0, 0, 0, 0, 0, 0, 0x95, 0x34, 0xe0, 0x00, 0, 0, 0, 0, 0, 0,
                ];
                let config = vec![9, 2, 9, 0, 0, 1, 0, 0, 0];
                let mut data = vec![
                    vec![0, 0],
                    vec![1],
                    device.clone(),
                    config.clone(),
                    vec![0],
                    vec![0, 0],
                    vec![0, 0],
                    NAME.to_vec(),
                    [NAME_REPLY, &[0]].concat(),
                    vec![],
                    vec![],
                    vec![],
                    vec![0, 0],
                    vec![1],
                    vec![0],
                    vec![0, 0],
                    vec![0, 0],
                    device,
                    config,
                ];
                Self {
                    replies: data.drain(..).map(Ok).collect(),
                    markers: vec![],
                    calls: vec![],
                    released: false,
                }
            }
        }
        impl Backend for Fake {
            fn control(&mut self, _: Spec, b: &mut [u8]) -> Result<usize, UsbError> {
                self.calls.push(Kind::Control);
                copy(self.replies.pop_front().unwrap(), b)
            }
            fn name_out(&mut self, _: &[u8]) -> Result<usize, UsbError> {
                self.calls.push(Kind::BulkOut);
                self.replies.pop_front().unwrap().map(|v| v.len())
            }
            fn bulk_in(&mut self, b: &mut [u8]) -> Result<usize, UsbError> {
                self.calls.push(Kind::BulkIn);
                copy(self.replies.pop_front().unwrap(), b)
            }
            fn marker(&mut self, m: &str) -> Result<(), String> {
                self.markers.push(m.into());
                Ok(())
            }
            fn release(&mut self) -> Result<(), String> {
                self.released = true;
                Ok(())
            }
        }
        fn copy(r: Result<Vec<u8>, UsbError>, b: &mut [u8]) -> Result<usize, UsbError> {
            r.map(|v| {
                b[..v.len()].copy_from_slice(&v);
                v.len()
            })
        }

        #[test]
        fn exact_schedule_counts_and_markers() {
            let mut f = Fake::successful();
            let r = execute(&mut f);
            assert_eq!(f.calls, PROBES.iter().map(|p| p.kind).collect::<Vec<_>>());
            assert_eq!(f.calls.iter().filter(|k| **k == Kind::Control).count(), 14);
            assert_eq!(f.calls.iter().filter(|k| **k == Kind::BulkOut).count(), 1);
            assert_eq!(f.calls.iter().filter(|k| **k == Kind::BulkIn).count(), 4);
            assert_eq!(f.markers.len(), 38);
            assert_eq!(f.markers[0], "CA_P01_GET_STATUS_DEVICE_PRE_BEGIN");
            assert_eq!(
                f.markers[37],
                "CA_P19_GET_DESCRIPTOR_CONFIG_HEADER_POST_END"
            );
            assert!(r.name_seen && f.released);
        }
        fn name_case(read: usize, prefix: Result<Vec<u8>, UsbError>) -> Report {
            let mut f = Fake::successful();
            for i in 0..4 {
                f.replies[8 + i] = if i + 1 == read {
                    Ok([NAME_REPLY, &[0]].concat())
                } else if i == 0 {
                    prefix.clone()
                } else {
                    Ok(vec![])
                };
            }
            execute(&mut f)
        }
        #[test]
        fn name_on_reads_two_three_four() {
            for n in 2..=4 {
                let r = name_case(n, Ok(vec![]));
                assert_eq!(r.name_on, Some(n));
            }
        }
        #[test]
        fn split_name_and_surplus_preserved() {
            let mut f = Fake::successful();
            f.replies[8] = Ok(b"NAME=CLSA".to_vec());
            f.replies[9] = Ok(b"0102_USB\0\0xyz".to_vec());
            f.replies[10] = Ok(vec![1, 2]);
            let r = execute(&mut f);
            assert_eq!(r.name_on, Some(2));
            assert_eq!(r.surplus, b"xyz\x01\x02");
        }
        #[test]
        fn eproto_then_name_recovers() {
            let r = name_case(2, Err(UsbError::Io));
            assert_eq!(r.result, "NAME_RECOVERED_AFTER_INITIAL_BULK_IN_FAULT");
        }
        #[test]
        fn control_fault_does_not_stop() {
            let mut f = Fake::successful();
            f.replies[0] = Err(UsbError::Io);
            let r = execute(&mut f);
            assert_eq!(r.observations[18].status, Status::Ok);
            assert_eq!(r.result, "NAME_SUCCESS_WITH_CONTROL_PROBE_FAULTS");
        }
        #[test]
        fn no_device_stops_remaining() {
            let mut f = Fake::successful();
            f.replies[3] = Err(UsbError::NoDevice);
            let r = execute(&mut f);
            assert_eq!(r.observations[4].status, Status::NotAttempted);
            assert_eq!(r.result, "DEVICE_DISAPPEARED");
        }
        #[test]
        fn descriptor_config_alt_validation() {
            let mut f = Fake::successful();
            f.replies[1] = Ok(vec![2]);
            let r = execute(&mut f);
            assert!(r.identity_mismatch);
            assert_eq!(r.result, "IDENTITY_MISMATCH_ABORT");

            let mut f = Fake::successful();
            f.replies[2] = Ok(vec![18, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
            assert!(execute(&mut f).identity_mismatch);

            let mut f = Fake::successful();
            f.replies[4] = Ok(vec![1]);
            assert!(execute(&mut f).identity_mismatch);
        }
        #[test]
        fn endpoint_halt_decode_bytes_preserved() {
            let mut f = Fake::successful();
            f.replies[5] = Ok(vec![1, 0]);
            let r = execute(&mut f);
            assert_eq!(r.observations[5].data[0] & 1, 1);
        }
        #[test]
        fn deterministic_classes() {
            let r = name_case(1, Ok([NAME_REPLY, &[0]].concat()));
            assert_eq!(r.result, "NAME_SUCCESS_ALL_CONTROL_PROBES_OK");
            assert_eq!(
                classify(&r.observations, false, None, false, false, false),
                "NO_NAME_ALL_CONTROL_PROBES_OK"
            );
            let mut obs = r.observations.clone();
            obs[0].status = Status::Io;
            assert_eq!(
                classify(&obs, true, Some(1), false, false, false),
                "NAME_SUCCESS_WITH_CONTROL_PROBE_FAULTS"
            );
            obs[8].status = Status::Timeout;
            assert_eq!(
                classify(&obs, true, Some(2), false, false, false),
                "NAME_RECOVERED_AFTER_INITIAL_BULK_IN_FAULT"
            );
            assert_eq!(
                classify(&obs, false, None, false, false, false),
                "CONTROL_AND_BULK_FAULTS"
            );
            obs[0].status = Status::Ok;
            assert_eq!(
                classify(&obs, false, None, false, false, false),
                "BULK_IN_FAULT_CONTROL_PLANE_STILL_HEALTHY"
            );
            obs[8].status = Status::Ok;
            obs[7].status = Status::Io;
            assert_eq!(
                classify(&obs, false, None, false, false, false),
                "NAME_WRITE_FAULT"
            );
            assert_eq!(
                classify(&obs, false, None, true, false, false),
                "DEVICE_DISAPPEARED"
            );
            assert_eq!(
                classify(&obs, false, None, false, true, false),
                "IDENTITY_MISMATCH_ABORT"
            );
            obs[7].status = Status::Ok;
            obs[0].status = Status::Io;
            assert_eq!(
                classify(&obs, false, None, false, false, false),
                "OTHER_TRANSPORT_FAULT"
            );
            assert_eq!(
                classify(&obs, false, None, false, false, true),
                "OTHER_TRANSPORT_FAULT"
            );
        }
        #[test]
        fn io_and_pipe_are_preserved_as_distinct_statuses() {
            let io = observe_transfer(Err(UsbError::Io), vec![0; 2], 2);
            let pipe = observe_transfer(Err(UsbError::Pipe), vec![0; 2], 2);
            assert_eq!(io.status, Status::Io);
            assert_eq!(pipe.status, Status::Pipe);
            assert_eq!(io.error.as_deref(), Some("rusb::Error::Io"));
            assert_eq!(pipe.error.as_deref(), Some("rusb::Error::Pipe"));
        }

        #[test]
        fn constants_are_exact() {
            assert_eq!(NAME, b"NAME?");
            assert_eq!(PROBES.len(), 19);
            assert_eq!(
                PROBES.iter().filter(|p| p.kind == Kind::Control).count(),
                14
            );
        }
    }
}
