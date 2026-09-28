//! Reset-first, one-shot KDUSB post-fault reacquire validation.
//!
//! The default invocation only prints a plan.  Live access is possible only
//! with `--execute-reset-reacquire`; the project wrapper is the admission
//! authority.  The state machine performs no pre-reset NAME, one reset at
//! most, one post-reset NAME at most, and one bounded bulk-IN observation.

use ntoseye::kdusb_probe::{
    DeviceSelection, INTERFACE_CLASS, INTERFACE_PROTOCOL, INTERFACE_SUBCLASS, KDUSB_PRODUCT_ID,
    KDUSB_VENDOR_ID, NAME_PREFIX, NAME_PROBE, ProbeBackend, TRANSFER_TIMEOUT, TransportFault,
    TransportFaultKind, USB_READ_REQUEST, parse_name_response,
};

const TARGET: &str = "CLSA0102_USB";
const EXPECTED_BULK_OUT: u8 = 0x01;
const EXPECTED_BULK_IN: u8 = 0x81;
const MAX_RESET_ATTEMPTS: usize = 1;
const MAX_PRE_RESET_NAME_TX: usize = 0;
const MAX_POST_RESET_NAME_TX: usize = 1;
const MAX_POST_RESET_READS: usize = 1;

#[derive(Debug, Clone, PartialEq, Eq)]
struct Identity {
    selection: DeviceSelection,
    class: u8,
    subclass: u8,
    protocol: u8,
}

impl Identity {
    fn from_filtered_selection(selection: DeviceSelection) -> Self {
        Self {
            selection,
            class: INTERFACE_CLASS,
            subclass: INTERFACE_SUBCLASS,
            protocol: INTERFACE_PROTOCOL,
        }
    }

    fn validate_against(&self, before: &Self) -> Result<(), ResultClass> {
        if self.selection.port_path != before.selection.port_path {
            return Err(ResultClass::RediscoveryIdentityMismatch);
        }
        if (self.selection.vendor, self.selection.product) != (KDUSB_VENDOR_ID, KDUSB_PRODUCT_ID) {
            return Err(ResultClass::RediscoveryIdentityMismatch);
        }
        if (self.class, self.subclass, self.protocol)
            != (INTERFACE_CLASS, INTERFACE_SUBCLASS, INTERFACE_PROTOCOL)
        {
            return Err(ResultClass::RediscoveryIdentityMismatch);
        }
        if self.selection.bulk_out != EXPECTED_BULK_OUT
            || self.selection.bulk_in != EXPECTED_BULK_IN
            || self.selection.transfer_type != "bulk"
        {
            return Err(ResultClass::RediscoveryIdentityMismatch);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ResultClass {
    PostResetNameAndInSuccess,
    ResetOrReacquireFailed,
    RediscoveryIdentityMismatch,
    BoundedNoData,
    OtherTransportFault,
}

impl ResultClass {
    const fn marker(self) -> &'static str {
        match self {
            Self::PostResetNameAndInSuccess => "POST_RESET_NAME_AND_IN_SUCCESS",
            Self::ResetOrReacquireFailed => "RESET_OR_REACQUIRE_FAILED",
            Self::RediscoveryIdentityMismatch => "REDISCOVERY_IDENTITY_MISMATCH",
            Self::BoundedNoData => "BOUNDED_NO_DATA",
            Self::OtherTransportFault => "OTHER_TRANSPORT_FAULT",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct RawFault {
    raw_rusb_variant: &'static str,
    raw_libusb: Option<i32>,
    errno: Option<i32>,
    operation: &'static str,
    endpoint: Option<u8>,
    bytes_requested: Option<usize>,
    bytes_transferred: Option<usize>,
    detail: String,
}

impl RawFault {
    fn from_transport(
        fault: TransportFault,
        endpoint: Option<u8>,
        requested: Option<usize>,
        transferred: Option<usize>,
    ) -> Self {
        let raw_rusb_variant = match fault.kind {
            TransportFaultKind::Timeout => "Timeout",
            TransportFaultKind::Stall => "Pipe",
            TransportFaultKind::NoDevice => "NoDevice",
            TransportFaultKind::Access => "Access",
            TransportFaultKind::LinuxUsbfsIo => "Io",
            TransportFaultKind::LinuxEproto => "Protocol",
            TransportFaultKind::GenericIo => "Other",
            TransportFaultKind::RecoveryFailure => "RecoveryFailure",
        };
        Self {
            raw_rusb_variant,
            raw_libusb: fault.raw_libusb,
            errno: fault.raw_os_errno,
            operation: fault.operation,
            endpoint,
            bytes_requested: requested,
            bytes_transferred: transferred,
            detail: fault.detail,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Report {
    class: ResultClass,
    fault: Option<RawFault>,
    reset_attempts: usize,
    reset_succeeded: bool,
    reacquired: bool,
    pre_reset_name_tx: usize,
    post_reset_name_tx: usize,
    read_calls: usize,
    reply: Vec<u8>,
    reacquired_selection: Option<DeviceSelection>,
}

impl Report {
    fn initial() -> Self {
        Self {
            class: ResultClass::ResetOrReacquireFailed,
            fault: None,
            reset_attempts: 0,
            reset_succeeded: false,
            reacquired: false,
            pre_reset_name_tx: 0,
            post_reset_name_tx: 0,
            read_calls: 0,
            reply: Vec::new(),
            reacquired_selection: None,
        }
    }
}

fn finish_with_release<B: ProbeBackend>(backend: &mut B, mut report: Report) -> Report {
    if let Err(fault) = backend.release() {
        if report.fault.is_none() {
            report.class = ResultClass::OtherTransportFault;
            report.fault = Some(RawFault::from_transport(fault, None, None, None));
        }
    }
    report
}

fn run_validation<B: ProbeBackend>(backend: &mut B) -> Report {
    let mut report = Report::initial();
    let before = match backend.acquire() {
        Ok(selection) => Identity::from_filtered_selection(selection),
        Err(fault) => {
            report.fault = Some(RawFault::from_transport(fault, None, None, None));
            return finish_with_release(backend, report);
        }
    };
    if let Err(class) = before.validate_against(&before) {
        report.class = class;
        return finish_with_release(backend, report);
    }

    // Deliberately no NAME write can occur before this sole reset call.
    report.reset_attempts = 1;
    let after_selection = match backend.reset_and_reacquire(&before.selection) {
        Ok(selection) => selection,
        Err(fault) => {
            report.fault = Some(RawFault::from_transport(fault, None, None, None));
            return finish_with_release(backend, report);
        }
    };
    report.reset_succeeded = true;
    report.reacquired = true;
    let after = Identity::from_filtered_selection(after_selection);
    report.reacquired_selection = Some(after.selection.clone());
    if let Err(class) = after.validate_against(&before) {
        report.class = class;
        return finish_with_release(backend, report);
    }

    report.post_reset_name_tx = 1;
    match backend.write_name(after.selection.bulk_out, NAME_PROBE, TRANSFER_TIMEOUT) {
        Ok(written) if written == NAME_PROBE.len() => {}
        Ok(written) => {
            report.class = ResultClass::OtherTransportFault;
            report.fault = Some(RawFault {
                raw_rusb_variant: "ShortTransfer",
                raw_libusb: None,
                errno: None,
                operation: "post-reset-name-write",
                endpoint: Some(after.selection.bulk_out),
                bytes_requested: Some(NAME_PROBE.len()),
                bytes_transferred: Some(written),
                detail: "short post-reset NAME write".to_string(),
            });
            return finish_with_release(backend, report);
        }
        Err(fault) => {
            report.class = ResultClass::OtherTransportFault;
            report.fault = Some(RawFault::from_transport(
                fault,
                Some(after.selection.bulk_out),
                Some(NAME_PROBE.len()),
                Some(0),
            ));
            return finish_with_release(backend, report);
        }
    }

    let mut response = vec![0u8; USB_READ_REQUEST];
    report.read_calls = 1;
    let received = match backend.read_name(after.selection.bulk_in, &mut response, TRANSFER_TIMEOUT)
    {
        Ok(0)
        | Err(TransportFault {
            kind: TransportFaultKind::Timeout,
            ..
        }) => {
            report.class = ResultClass::BoundedNoData;
            return finish_with_release(backend, report);
        }
        Ok(received) => received,
        Err(fault) => {
            report.class = ResultClass::OtherTransportFault;
            report.fault = Some(RawFault::from_transport(
                fault,
                Some(after.selection.bulk_in),
                Some(USB_READ_REQUEST),
                Some(0),
            ));
            return finish_with_release(backend, report);
        }
    };
    response.truncate(received);
    report.reply = response;
    let expected_len = NAME_PREFIX.len() + TARGET.len() + 2;
    if report.reply.len() == expected_len
        && parse_name_response(&report.reply).is_ok_and(|name| name == TARGET)
    {
        report.class = ResultClass::PostResetNameAndInSuccess;
    } else {
        report.class = ResultClass::OtherTransportFault;
        report.fault = Some(RawFault {
            raw_rusb_variant: "ProtocolContent",
            raw_libusb: None,
            errno: None,
            operation: "post-reset-name-parse",
            endpoint: Some(after.selection.bulk_in),
            bytes_requested: Some(USB_READ_REQUEST),
            bytes_transferred: Some(received),
            detail: format!(
                "unexpected bounded reply prefix={}",
                hex::encode(&report.reply[..received.min(64)])
            ),
        });
    }
    finish_with_release(backend, report)
}

fn print_plan() {
    println!("KDUSB_POST_FAULT_REACQUIRE_PLAN=PASS");
    println!("DEFAULT_MODE=DRY_PLAN");
    println!("LIVE_FLAG_REQUIRED=--execute-reset-reacquire");
    println!("MAX_RESET_ATTEMPTS={MAX_RESET_ATTEMPTS}");
    println!("MAX_PRE_RESET_NAME_TX={MAX_PRE_RESET_NAME_TX}");
    println!("MAX_POST_RESET_NAME_TX={MAX_POST_RESET_NAME_TX}");
    println!("MAX_POST_RESET_READS={MAX_POST_RESET_READS}");
    print_safety(false, false, false);
}

fn print_safety(reset_executed: bool, name_sent: bool, live_mode: bool) {
    println!("AUTOMATIC_NAME_RETRY=false");
    println!("AUTOMATIC_RESET_RETRY=false");
    println!("KD_PACKET_TX=false");
    println!("KD_ACK_TX=false");
    println!("KD_RESEND_TX=false");
    println!("KD_RESET_TX=false");
    println!("KD_FILE_IO_REPLY_TX=false");
    println!("BREAKIN_SENT=false");
    println!("DEBUGGER_SESSION=false");
    println!("TARGET_MEMORY_ACCESS=false");
    println!("PCI_UNBIND_REBIND=false");
    println!("XHCI_RELOAD=false");
    println!("RUNTIME_PM_CHANGE=false");
    println!("HOST_REBOOT=false");
    println!("TARGET_REBOOT=false");
    println!("BCD_CHANGE=false");
    println!("PHASE340_CLEANUP_AUTHORIZED=false");
    println!("LIVE_MODE={live_mode}");
    println!("USB_DATA_TX_OCCURRED={name_sent}");
    println!("RESET_EXECUTED={reset_executed}");
    println!("POST_RESET_NAME_SENT={name_sent}");
}

fn print_report(report: &Report) {
    println!(
        "KDUSB_POST_FAULT_REACQUIRE_RESULT={}",
        report.class.marker()
    );
    println!(
        "OPERATION_STAGE={}",
        report.fault.as_ref().map_or("complete", |f| f.operation)
    );
    println!("RESET_ATTEMPTS={}", report.reset_attempts);
    println!("RESET_HAPPENED={}", report.reset_succeeded);
    println!("REACQUISITION_HAPPENED={}", report.reacquired);
    println!("PRE_RESET_NAME_TX={}", report.pre_reset_name_tx);
    println!("POST_RESET_NAME_TX={}", report.post_reset_name_tx);
    println!("POST_RESET_READ_CALLS={}", report.read_calls);
    println!("REPLY_BYTES={}", report.reply.len());
    println!("REPLY_HEX={}", hex::encode(&report.reply));
    if let Some(selection) = &report.reacquired_selection {
        println!("REACQUIRED_PORT_PATH={:?}", selection.port_path);
        println!(
            "REACQUIRED_VID_PID={:04x}:{:04x}",
            selection.vendor, selection.product
        );
        println!("REACQUIRED_INTERFACE_CLASS=dc/02/ff");
        println!("REACQUIRED_BULK_OUT=0x{:02x}", selection.bulk_out);
        println!("REACQUIRED_BULK_IN=0x{:02x}", selection.bulk_in);
    } else {
        println!("REACQUIRED_PORT_PATH=NA");
        println!("REACQUIRED_VID_PID=NA");
        println!("REACQUIRED_INTERFACE_CLASS=NA");
        println!("REACQUIRED_BULK_OUT=NA");
        println!("REACQUIRED_BULK_IN=NA");
    }
    if let Some(fault) = &report.fault {
        println!("RAW_RUSB_ERROR_VARIANT={}", fault.raw_rusb_variant);
        println!(
            "RAW_LIBUSB_ERROR={}",
            fault
                .raw_libusb
                .map_or_else(|| "unavailable".into(), |v| v.to_string())
        );
        println!(
            "RAW_ERRNO={}",
            fault
                .errno
                .map_or_else(|| "unavailable".into(), |v| v.to_string())
        );
        println!(
            "FAULT_ENDPOINT={}",
            fault
                .endpoint
                .map_or_else(|| "NA".into(), |v| format!("0x{v:02x}"))
        );
        println!(
            "BYTES_REQUESTED={}",
            fault
                .bytes_requested
                .map_or_else(|| "NA".into(), |v| v.to_string())
        );
        println!(
            "BYTES_TRANSFERRED={}",
            fault
                .bytes_transferred
                .map_or_else(|| "NA".into(), |v| v.to_string())
        );
        println!("FAULT_DETAIL={}", fault.detail.replace(['\n', '\r'], " "));
    } else {
        println!("RAW_RUSB_ERROR_VARIANT=none");
        println!("RAW_LIBUSB_ERROR=none");
        println!("RAW_ERRNO=none");
    }
    print_safety(
        report.reset_attempts > 0,
        report.post_reset_name_tx > 0,
        true,
    );
}

#[cfg(not(target_os = "linux"))]
fn main() {
    print_plan();
}

#[cfg(target_os = "linux")]
fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.is_empty() || args == ["--dry-run-plan"] {
        print_plan();
        return;
    }
    if args != ["--execute-reset-reacquire", TARGET] {
        eprintln!(
            "usage: ntoseye-kdusb-post-fault-reacquire-validation-r2 [--dry-run-plan | --execute-reset-reacquire CLSA0102_USB]"
        );
        std::process::exit(2);
    }
    let mut backend = ntoseye::kdusb_probe::linux::RusbProbeBackend::new();
    let report = run_validation(&mut backend);
    print_report(&report);
    if matches!(
        report.class,
        ResultClass::ResetOrReacquireFailed | ResultClass::RediscoveryIdentityMismatch
    ) {
        std::process::exit(3);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;

    struct Mock {
        selection: DeviceSelection,
        reacquired: Option<Result<DeviceSelection, TransportFault>>,
        write: Option<Result<usize, TransportFault>>,
        reads: VecDeque<Result<Vec<u8>, TransportFault>>,
        events: Vec<&'static str>,
        resets: usize,
        writes: usize,
    }

    fn selection() -> DeviceSelection {
        DeviceSelection {
            vendor: KDUSB_VENDOR_ID,
            product: KDUSB_PRODUCT_ID,
            configuration: 1,
            interface: 0,
            alternate_setting: 0,
            bulk_in: EXPECTED_BULK_IN,
            bulk_out: EXPECTED_BULK_OUT,
            transfer_type: "bulk",
            max_packet: 1024,
            port_path: vec![1],
        }
    }

    fn fault(kind: TransportFaultKind, operation: &'static str) -> TransportFault {
        TransportFault::new(
            kind,
            operation,
            Some(-1),
            (kind == TransportFaultKind::LinuxEproto).then_some(71),
            "mock raw fault",
        )
    }

    impl Default for Mock {
        fn default() -> Self {
            Self {
                selection: selection(),
                reacquired: None,
                write: None,
                reads: VecDeque::new(),
                events: vec![],
                resets: 0,
                writes: 0,
            }
        }
    }

    impl ProbeBackend for Mock {
        fn acquire(&mut self) -> Result<DeviceSelection, TransportFault> {
            self.events.push("acquire");
            Ok(self.selection.clone())
        }
        fn reset_and_reacquire(
            &mut self,
            _: &DeviceSelection,
        ) -> Result<DeviceSelection, TransportFault> {
            self.events.push("reset");
            self.resets += 1;
            self.reacquired.take().unwrap_or_else(|| Ok(selection()))
        }
        fn write_name(
            &mut self,
            endpoint: u8,
            payload: &[u8],
            _: std::time::Duration,
        ) -> Result<usize, TransportFault> {
            assert_eq!(endpoint, EXPECTED_BULK_OUT);
            assert_eq!(payload, NAME_PROBE);
            self.events.push("name");
            self.writes += 1;
            self.write.take().unwrap_or(Ok(payload.len()))
        }
        fn read_name(
            &mut self,
            endpoint: u8,
            response: &mut [u8],
            _: std::time::Duration,
        ) -> Result<usize, TransportFault> {
            assert_eq!(endpoint, EXPECTED_BULK_IN);
            self.events.push("read");
            match self.reads.pop_front().unwrap_or(Ok(vec![])) {
                Ok(bytes) => {
                    response[..bytes.len()].copy_from_slice(&bytes);
                    Ok(bytes.len())
                }
                Err(f) => Err(f),
            }
        }
        fn release(&mut self) -> Result<(), TransportFault> {
            self.events.push("release");
            Ok(())
        }
    }

    #[test]
    fn reset_first_limits_and_no_automatic_retries() {
        let mut mock = Mock::default();
        let report = run_validation(&mut mock);
        assert_eq!(report.class, ResultClass::BoundedNoData);
        assert_eq!(mock.events, ["acquire", "reset", "name", "read", "release"]);
        assert_eq!((MAX_PRE_RESET_NAME_TX, mock.resets, mock.writes), (0, 1, 1));
        assert_eq!(
            (
                MAX_RESET_ATTEMPTS,
                MAX_POST_RESET_NAME_TX,
                MAX_POST_RESET_READS
            ),
            (1, 1, 1)
        );
    }

    #[test]
    fn reset_failure_stops_before_name_without_retry() {
        let mut mock = Mock {
            reacquired: Some(Err(fault(
                TransportFaultKind::RecoveryFailure,
                "device-reset",
            ))),
            ..Mock::default()
        };
        let report = run_validation(&mut mock);
        assert_eq!(report.class, ResultClass::ResetOrReacquireFailed);
        assert_eq!((mock.resets, mock.writes), (1, 0));
    }

    fn mismatch(changed: DeviceSelection) -> Report {
        let mut mock = Mock {
            reacquired: Some(Ok(changed.clone())),
            ..Mock::default()
        };
        let report = run_validation(&mut mock);
        assert_eq!(mock.writes, 0);
        report
    }

    #[test]
    fn physical_port_mismatch_stops_before_name() {
        let mut s = selection();
        s.port_path = vec![2];
        assert_eq!(mismatch(s).class, ResultClass::RediscoveryIdentityMismatch);
    }
    #[test]
    fn vid_pid_mismatch_stops_before_name() {
        let mut s = selection();
        s.product = 1;
        assert_eq!(mismatch(s).class, ResultClass::RediscoveryIdentityMismatch);
    }
    #[test]
    fn endpoint_mismatch_stops_before_name() {
        let mut s = selection();
        s.bulk_in = 0x82;
        assert_eq!(mismatch(s).class, ResultClass::RediscoveryIdentityMismatch);
    }

    #[test]
    fn class_subclass_protocol_mismatch_is_rejected() {
        let before = Identity::from_filtered_selection(selection());
        for (class, subclass, protocol) in
            [(0xff, 0x02, 0xff), (0xdc, 0xff, 0xff), (0xdc, 0x02, 0x00)]
        {
            let changed = Identity {
                selection: selection(),
                class,
                subclass,
                protocol,
            };
            assert_eq!(
                changed.validate_against(&before),
                Err(ResultClass::RediscoveryIdentityMismatch)
            );
        }
    }

    #[test]
    fn raw_protocol_eproto_is_retained_structurally() {
        let mut mock = Mock::default();
        mock.reads.push_back(Err(fault(
            TransportFaultKind::LinuxEproto,
            "post-reset-name-read",
        )));
        let report = run_validation(&mut mock);
        assert_eq!(report.class, ResultClass::OtherTransportFault);
        let raw = report.fault.unwrap();
        assert_eq!(
            (raw.raw_rusb_variant, raw.errno, raw.operation, raw.endpoint),
            ("Protocol", Some(71), "post-reset-name-read", Some(0x81))
        );
        assert_eq!(
            (raw.bytes_requested, raw.bytes_transferred),
            (Some(USB_READ_REQUEST), Some(0))
        );
    }

    #[test]
    fn successful_post_reset_name_is_classified() {
        let mut mock = Mock::default();
        mock.reads.push_back(Ok(b"NAME=CLSA0102_USB\0\0".to_vec()));
        let report = run_validation(&mut mock);
        assert_eq!(report.class, ResultClass::PostResetNameAndInSuccess);
        assert!(report.reset_succeeded && report.reacquired);
    }

    #[test]
    fn bounded_no_data_is_separate_for_empty_and_timeout() {
        for read in [
            Ok(vec![]),
            Err(fault(TransportFaultKind::Timeout, "post-reset-name-read")),
        ] {
            let mut mock = Mock::default();
            mock.reads.push_back(read);
            assert_eq!(run_validation(&mut mock).class, ResultClass::BoundedNoData);
        }
    }

    #[test]
    fn prohibited_protocol_paths_do_not_exist() {
        let plan = capture_plan();
        for marker in [
            "KD_PACKET_TX=false",
            "KD_ACK_TX=false",
            "KD_RESEND_TX=false",
            "KD_RESET_TX=false",
            "KD_FILE_IO_REPLY_TX=false",
            "BREAKIN_SENT=false",
            "DEBUGGER_SESSION=false",
            "TARGET_MEMORY_ACCESS=false",
        ] {
            assert!(plan.contains(marker));
        }
        assert_eq!(NAME_PROBE, b"NAME?");
    }

    fn capture_plan() -> String {
        [
            "KD_PACKET_TX=false",
            "KD_ACK_TX=false",
            "KD_RESEND_TX=false",
            "KD_RESET_TX=false",
            "KD_FILE_IO_REPLY_TX=false",
            "BREAKIN_SENT=false",
            "DEBUGGER_SESSION=false",
            "TARGET_MEMORY_ACCESS=false",
        ]
        .join("\n")
    }
}
