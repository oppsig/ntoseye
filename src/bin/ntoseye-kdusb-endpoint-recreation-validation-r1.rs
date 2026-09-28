//! Dry-first, one-shot KDUSB endpoint recreation by reapplying the already
//! active USB configuration. No USB device-reset API is used by this binary.

use ntoseye::kdusb_endpoint_recreation::EndpointRecreationBackend;
use ntoseye::kdusb_probe::{
    DeviceSelection, KDUSB_PRODUCT_ID, KDUSB_VENDOR_ID, NAME_PREFIX, NAME_PROBE, TRANSFER_TIMEOUT,
    TransportFault, TransportFaultKind, USB_READ_REQUEST, parse_name_response,
};

const TARGET: &str = "CLSA0102_USB";
const EXPECTED_BULK_OUT: u8 = 0x01;
const EXPECTED_BULK_IN: u8 = 0x81;
const MAX_ENDPOINT_RECREATION_ATTEMPTS: usize = 1;
const MAX_USB_DEVICE_RESET_ATTEMPTS: usize = 0;
const MAX_PRE_OPERATION_NAME_TX: usize = 0;
const MAX_POST_OPERATION_NAME_TX: usize = 1;
const MAX_POST_OPERATION_READS: usize = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ResultClass {
    PostOperationNameAndInSuccess,
    EndpointRecreationFailed,
    IdentityMismatch,
    BoundedNoData,
    OtherTransportFault,
}

impl ResultClass {
    const fn marker(self) -> &'static str {
        match self {
            Self::PostOperationNameAndInSuccess => "POST_OPERATION_NAME_AND_IN_SUCCESS",
            Self::EndpointRecreationFailed => "ENDPOINT_RECREATION_FAILED",
            Self::IdentityMismatch => "IDENTITY_MISMATCH",
            Self::BoundedNoData => "BOUNDED_NO_DATA",
            Self::OtherTransportFault => "OTHER_TRANSPORT_FAULT",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct RawFault {
    kind: TransportFaultKind,
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
        Self {
            kind: fault.kind,
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
    operation_attempts: usize,
    operation_succeeded: bool,
    identity_validated: bool,
    pre_operation_name_tx: usize,
    post_operation_name_tx: usize,
    read_calls: usize,
    reply: Vec<u8>,
}

impl Report {
    fn initial() -> Self {
        Self {
            class: ResultClass::EndpointRecreationFailed,
            fault: None,
            operation_attempts: 0,
            operation_succeeded: false,
            identity_validated: false,
            pre_operation_name_tx: 0,
            post_operation_name_tx: 0,
            read_calls: 0,
            reply: Vec::new(),
        }
    }
}

fn exact_identity(before: &DeviceSelection, after: &DeviceSelection) -> bool {
    before == after
        && after.vendor == KDUSB_VENDOR_ID
        && after.product == KDUSB_PRODUCT_ID
        && after.alternate_setting == 0
        && after.bulk_out == EXPECTED_BULK_OUT
        && after.bulk_in == EXPECTED_BULK_IN
        && after.transfer_type == "bulk"
}

fn finish<B: EndpointRecreationBackend>(backend: &mut B, mut report: Report) -> Report {
    if let Err(fault) = backend.release()
        && report.fault.is_none()
    {
        report.class = ResultClass::OtherTransportFault;
        report.fault = Some(RawFault::from_transport(fault, None, None, None));
    }
    report
}

fn run_validation<B: EndpointRecreationBackend>(backend: &mut B) -> Report {
    let mut report = Report::initial();
    let before = match backend.discover_unclaimed() {
        Ok(selection) if exact_identity(&selection, &selection) => selection,
        Ok(_) => {
            report.class = ResultClass::IdentityMismatch;
            return finish(backend, report);
        }
        Err(fault) => {
            report.fault = Some(RawFault::from_transport(fault, None, None, None));
            return finish(backend, report);
        }
    };

    // There is deliberately no claimed interface and no NAME before this one call.
    report.operation_attempts = 1;
    if let Err(fault) = backend.reapply_current_configuration(&before) {
        report.fault = Some(RawFault::from_transport(fault, None, None, None));
        return finish(backend, report);
    }
    report.operation_succeeded = true;

    let after = match backend.acquire_after_recreation(&before) {
        Ok(selection) => selection,
        Err(fault) => {
            report.fault = Some(RawFault::from_transport(fault, None, None, None));
            return finish(backend, report);
        }
    };
    if !exact_identity(&before, &after) {
        report.class = ResultClass::IdentityMismatch;
        return finish(backend, report);
    }
    report.identity_validated = true;

    report.post_operation_name_tx = 1;
    match backend.write_name(after.bulk_out, NAME_PROBE, TRANSFER_TIMEOUT) {
        Ok(written) if written == NAME_PROBE.len() => {}
        Ok(written) => {
            report.class = ResultClass::OtherTransportFault;
            report.fault = Some(RawFault {
                kind: TransportFaultKind::GenericIo,
                raw_libusb: None,
                errno: None,
                operation: "post-operation-name-write",
                endpoint: Some(after.bulk_out),
                bytes_requested: Some(NAME_PROBE.len()),
                bytes_transferred: Some(written),
                detail: "short post-operation NAME write".into(),
            });
            return finish(backend, report);
        }
        Err(fault) => {
            report.class = ResultClass::OtherTransportFault;
            report.fault = Some(RawFault::from_transport(
                fault,
                Some(after.bulk_out),
                Some(NAME_PROBE.len()),
                Some(0),
            ));
            return finish(backend, report);
        }
    }

    report.read_calls = 1;
    let mut response = vec![0u8; USB_READ_REQUEST];
    let received = match backend.read_name(after.bulk_in, &mut response, TRANSFER_TIMEOUT) {
        Ok(0)
        | Err(TransportFault {
            kind: TransportFaultKind::Timeout,
            ..
        }) => {
            report.class = ResultClass::BoundedNoData;
            return finish(backend, report);
        }
        Ok(received) if received <= response.len() => received,
        Ok(received) => {
            report.class = ResultClass::OtherTransportFault;
            report.fault = Some(RawFault {
                kind: TransportFaultKind::GenericIo,
                raw_libusb: None,
                errno: None,
                operation: "post-operation-name-read",
                endpoint: Some(after.bulk_in),
                bytes_requested: Some(USB_READ_REQUEST),
                bytes_transferred: Some(received),
                detail: "backend returned more bytes than requested".into(),
            });
            return finish(backend, report);
        }
        Err(fault) => {
            report.class = ResultClass::OtherTransportFault;
            report.fault = Some(RawFault::from_transport(
                fault,
                Some(after.bulk_in),
                Some(USB_READ_REQUEST),
                Some(0),
            ));
            return finish(backend, report);
        }
    };
    response.truncate(received);
    report.reply = response;
    let expected_len = NAME_PREFIX.len() + TARGET.len() + 2;
    if report.reply.len() == expected_len
        && parse_name_response(&report.reply).is_ok_and(|name| name == TARGET)
    {
        report.class = ResultClass::PostOperationNameAndInSuccess;
    } else {
        report.class = ResultClass::OtherTransportFault;
        report.fault = Some(RawFault {
            kind: TransportFaultKind::GenericIo,
            raw_libusb: None,
            errno: None,
            operation: "post-operation-name-parse",
            endpoint: Some(after.bulk_in),
            bytes_requested: Some(USB_READ_REQUEST),
            bytes_transferred: Some(received),
            detail: "unexpected bounded NAME reply".into(),
        });
    }
    finish(backend, report)
}

fn print_safety(live_mode: bool, operation_executed: bool, name_sent: bool) {
    println!("MAX_ENDPOINT_RECREATION_ATTEMPTS={MAX_ENDPOINT_RECREATION_ATTEMPTS}");
    println!("MAX_USB_DEVICE_RESET_ATTEMPTS={MAX_USB_DEVICE_RESET_ATTEMPTS}");
    println!("MAX_PRE_OPERATION_NAME_TX={MAX_PRE_OPERATION_NAME_TX}");
    println!("MAX_POST_OPERATION_NAME_TX={MAX_POST_OPERATION_NAME_TX}");
    println!("MAX_POST_OPERATION_READS={MAX_POST_OPERATION_READS}");
    println!("AUTOMATIC_OPERATION_RETRY=false");
    println!("AUTOMATIC_NAME_RETRY=false");
    println!("USB_DEVICE_RESET=false");
    println!("ADDRESS_DEVICE_REQUESTED_BY_TOOL=false");
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
    println!("ENDPOINT_RECREATION_EXECUTED={operation_executed}");
    println!("NAME_PROBE_SENT={name_sent}");
}

fn print_plan() {
    println!("KDUSB_ENDPOINT_RECREATION_PLAN=PASS");
    println!("DEFAULT_MODE=DRY_PLAN");
    println!("LIVE_FLAG_REQUIRED=--execute-same-configuration-reapply");
    println!("SELECTED_OPERATION=USBDEVFS_SETCONFIGURATION_CURRENT_VALUE");
    print_safety(false, false, false);
}

fn print_report(report: &Report) {
    println!("KDUSB_ENDPOINT_RECREATION_RESULT={}", report.class.marker());
    println!("ENDPOINT_RECREATION_ATTEMPTS={}", report.operation_attempts);
    println!(
        "ENDPOINT_RECREATION_SUCCEEDED={}",
        report.operation_succeeded
    );
    println!("IDENTITY_VALIDATED={}", report.identity_validated);
    println!("PRE_OPERATION_NAME_TX={}", report.pre_operation_name_tx);
    println!("POST_OPERATION_NAME_TX={}", report.post_operation_name_tx);
    println!("POST_OPERATION_READ_CALLS={}", report.read_calls);
    println!("REPLY_BYTES={}", report.reply.len());
    println!("REPLY_HEX={}", hex::encode(&report.reply));
    if let Some(fault) = &report.fault {
        println!("TRANSPORT_FAULT={}", fault.kind.marker());
        println!("OPERATION_STAGE={}", fault.operation);
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
        println!("BYTES_REQUESTED={:?}", fault.bytes_requested);
        println!("BYTES_TRANSFERRED={:?}", fault.bytes_transferred);
        println!("FAULT_DETAIL={}", fault.detail.replace(['\n', '\r'], " "));
    }
    print_safety(
        true,
        report.operation_attempts > 0,
        report.post_operation_name_tx > 0,
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
    if args != ["--execute-same-configuration-reapply", TARGET] {
        eprintln!(
            "usage: ntoseye-kdusb-endpoint-recreation-validation-r1 [--dry-run-plan | --execute-same-configuration-reapply CLSA0102_USB]"
        );
        std::process::exit(2);
    }
    let mut backend =
        ntoseye::kdusb_endpoint_recreation::linux::RusbEndpointRecreationBackend::new();
    let report = run_validation(&mut backend);
    print_report(&report);
    if matches!(
        report.class,
        ResultClass::EndpointRecreationFailed | ResultClass::IdentityMismatch
    ) {
        std::process::exit(3);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;

    struct Mock {
        before: DeviceSelection,
        after: Option<Result<DeviceSelection, TransportFault>>,
        operation: Option<Result<(), TransportFault>>,
        write: Option<Result<usize, TransportFault>>,
        reads: VecDeque<Result<Vec<u8>, TransportFault>>,
        events: Vec<&'static str>,
        operations: usize,
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
                before: selection(),
                after: None,
                operation: None,
                write: None,
                reads: VecDeque::new(),
                events: vec![],
                operations: 0,
                writes: 0,
            }
        }
    }

    impl EndpointRecreationBackend for Mock {
        fn discover_unclaimed(&mut self) -> Result<DeviceSelection, TransportFault> {
            self.events.push("discover-unclaimed");
            Ok(self.before.clone())
        }
        fn reapply_current_configuration(
            &mut self,
            _: &DeviceSelection,
        ) -> Result<(), TransportFault> {
            self.events.push("reapply-current-configuration");
            self.operations += 1;
            self.operation.take().unwrap_or(Ok(()))
        }
        fn acquire_after_recreation(
            &mut self,
            _: &DeviceSelection,
        ) -> Result<DeviceSelection, TransportFault> {
            self.events.push("acquire-after-recreation");
            self.after.take().unwrap_or_else(|| Ok(selection()))
        }
        fn write_name(
            &mut self,
            _: u8,
            _: &[u8],
            _: std::time::Duration,
        ) -> Result<usize, TransportFault> {
            self.events.push("name");
            self.writes += 1;
            self.write.take().unwrap_or(Ok(NAME_PROBE.len()))
        }
        fn read_name(
            &mut self,
            _: u8,
            response: &mut [u8],
            _: std::time::Duration,
        ) -> Result<usize, TransportFault> {
            self.events.push("read");
            match self.reads.pop_front().unwrap_or(Ok(vec![])) {
                Ok(bytes) => {
                    response[..bytes.len()].copy_from_slice(&bytes);
                    Ok(bytes.len())
                }
                Err(fault) => Err(fault),
            }
        }
        fn release(&mut self) -> Result<(), TransportFault> {
            self.events.push("release");
            Ok(())
        }
    }

    #[test]
    fn operation_is_once_before_one_name_and_one_read() {
        let mut mock = Mock::default();
        let report = run_validation(&mut mock);
        assert_eq!(report.class, ResultClass::BoundedNoData);
        assert_eq!(mock.operations, 1);
        assert_eq!(mock.writes, 1);
        assert_eq!(report.read_calls, 1);
        assert_eq!(report.pre_operation_name_tx, 0);
        assert_eq!(
            mock.events,
            [
                "discover-unclaimed",
                "reapply-current-configuration",
                "acquire-after-recreation",
                "name",
                "read",
                "release"
            ]
        );
    }

    #[test]
    fn operation_failure_stops_before_name_without_retry() {
        let mut mock = Mock {
            operation: Some(Err(fault(
                TransportFaultKind::GenericIo,
                "same-configuration-reapply",
            ))),
            ..Mock::default()
        };
        let report = run_validation(&mut mock);
        assert_eq!(report.class, ResultClass::EndpointRecreationFailed);
        assert_eq!((mock.operations, mock.writes, report.read_calls), (1, 0, 0));
    }

    #[test]
    fn identity_mismatch_stops_before_name() {
        let mut changed = selection();
        changed.bulk_in = 0x82;
        let mut mock = Mock {
            after: Some(Ok(changed)),
            ..Mock::default()
        };
        let report = run_validation(&mut mock);
        assert_eq!(report.class, ResultClass::IdentityMismatch);
        assert_eq!((mock.writes, report.read_calls), (0, 0));
    }

    #[test]
    fn raw_transport_fault_remains_structural() {
        let mut mock = Mock::default();
        mock.reads.push_back(Err(fault(
            TransportFaultKind::LinuxEproto,
            "post-operation-name-read",
        )));
        let report = run_validation(&mut mock);
        let raw = report.fault.expect("structured fault");
        assert_eq!(raw.kind, TransportFaultKind::LinuxEproto);
        assert_eq!(raw.errno, Some(71));
        assert_eq!(raw.endpoint, Some(EXPECTED_BULK_IN));
    }

    #[test]
    fn successful_bounded_name_is_classified() {
        let mut mock = Mock::default();
        mock.reads.push_back(Ok(b"NAME=CLSA0102_USB\0\0".to_vec()));
        assert_eq!(
            run_validation(&mut mock).class,
            ResultClass::PostOperationNameAndInSuccess
        );
    }

    #[test]
    fn dry_plan_has_zero_live_activity_and_all_hard_limits() {
        assert_eq!(MAX_ENDPOINT_RECREATION_ATTEMPTS, 1);
        assert_eq!(MAX_USB_DEVICE_RESET_ATTEMPTS, 0);
        assert_eq!(MAX_PRE_OPERATION_NAME_TX, 0);
        assert_eq!(MAX_POST_OPERATION_NAME_TX, 1);
        assert_eq!(MAX_POST_OPERATION_READS, 1);
        let source = include_str!("ntoseye-kdusb-endpoint-recreation-validation-r1.rs");
        let reset_call = [".", "reset", "("].concat();
        let legacy_reset = ["reset", "_and_", "reacquire"].concat();
        let libusb_reset = ["libusb", "_reset_", "device"].concat();
        assert!(!source.contains(&reset_call));
        assert!(!source.contains(&legacy_reset));
        assert!(!source.contains(&libusb_reset));
        let backend_source = include_str!("../kdusb_endpoint_recreation.rs");
        assert!(!backend_source.contains(&reset_call));
        assert!(!backend_source.contains(&libusb_reset));
        for marker in [
            "AUTOMATIC_OPERATION_RETRY=false",
            "AUTOMATIC_NAME_RETRY=false",
            "USB_DEVICE_RESET=false",
            "ADDRESS_DEVICE_REQUESTED_BY_TOOL=false",
            "KD_PACKET_TX=false",
            "KD_ACK_TX=false",
            "KD_RESEND_TX=false",
            "KD_RESET_TX=false",
            "KD_FILE_IO_REPLY_TX=false",
            "BREAKIN_SENT=false",
            "DEBUGGER_SESSION=false",
            "TARGET_MEMORY_ACCESS=false",
            "DEFAULT_MODE=DRY_PLAN",
        ] {
            assert!(source.contains(marker), "missing {marker}");
        }
    }
}
