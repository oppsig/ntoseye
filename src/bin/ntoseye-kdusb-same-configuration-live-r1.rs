//! Phase 3.44BR two-stage KDUSB same-configuration validation.
//! Default execution is a dry plan. Live USB is reachable only through either
//! of the two explicit, mutually exclusive stage flags.

use ntoseye::kdusb_probe::{
    DeviceSelection, KDUSB_PRODUCT_ID, KDUSB_VENDOR_ID, NAME_PROBE, TRANSFER_TIMEOUT,
    TransportFault, TransportFaultKind, USB_READ_REQUEST, parse_name_response,
};
use ntoseye::kdusb_same_configuration_live::{LiveIdentity, SameConfigurationLiveBackend};
use serde::{Deserialize, Serialize};
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

const TARGET: &str = "CLSA0102_USB";
const STATE_SCHEMA: &str = "ntoseye-kdusb-same-configuration-state-v1";
const BARRIER_SCHEMA: &str = "clsa0102-phase344br-barrier-v1";
const EXPECTED_PHYSICAL_PATH: &str = "6-1";
const EXPECTED_CONFIGURATION: u8 = 1;
const EXPECTED_INTERFACE: u8 = 0;
const EXPECTED_ALTSETTING: u8 = 0;
const EXPECTED_BULK_OUT: u8 = 0x01;
const EXPECTED_BULK_IN: u8 = 0x81;
const MAX_ENDPOINT_RECREATION_ATTEMPTS: usize = 1;
const MAX_USB_DEVICE_RESET_ATTEMPTS: usize = 0;
const MAX_PRE_OPERATION_NAME_TX: usize = 0;
const MAX_POST_OPERATION_NAME_TX: usize = 1;
const MAX_POST_OPERATION_READS: usize = 1;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct StoredIdentity {
    vendor: u16,
    product: u16,
    physical_path: String,
    bus: u8,
    address: u8,
    configuration: u8,
    interface: u8,
    alternate_setting: u8,
    bulk_out: u8,
    bulk_in: u8,
    transfer_type: String,
    max_packet: u16,
    port_path: Vec<u8>,
}

impl From<&LiveIdentity> for StoredIdentity {
    fn from(value: &LiveIdentity) -> Self {
        let selection = &value.selection;
        Self {
            vendor: selection.vendor,
            product: selection.product,
            physical_path: value.physical_path.clone(),
            bus: value.bus,
            address: value.address,
            configuration: selection.configuration,
            interface: selection.interface,
            alternate_setting: selection.alternate_setting,
            bulk_out: selection.bulk_out,
            bulk_in: selection.bulk_in,
            transfer_type: selection.transfer_type.into(),
            max_packet: selection.max_packet,
            port_path: selection.port_path.clone(),
        }
    }
}

impl StoredIdentity {
    fn live(&self) -> LiveIdentity {
        LiveIdentity {
            selection: DeviceSelection {
                vendor: self.vendor,
                product: self.product,
                configuration: self.configuration,
                interface: self.interface,
                alternate_setting: self.alternate_setting,
                bulk_in: self.bulk_in,
                bulk_out: self.bulk_out,
                transfer_type: "bulk",
                max_packet: self.max_packet,
                port_path: self.port_path.clone(),
            },
            bus: self.bus,
            address: self.address,
            physical_path: self.physical_path.clone(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct StageState {
    schema: String,
    target: String,
    stage1_complete: bool,
    endpoint_recreation_attempts: usize,
    before: StoredIdentity,
    after: StoredIdentity,
    barrier_authorized_name: bool,
    name_authorization_consumed: bool,
    phase340_cleanup_authorized: bool,
}

#[allow(non_snake_case)]
#[derive(Debug, Clone, Serialize, Deserialize)]
struct Barrier {
    schema: String,
    RESET_DEVICE_OBSERVED: bool,
    ADDRESS_DEVICE_OBSERVED: bool,
    SLOT_REENUMERATION_OBSERVED: bool,
    PHYSICAL_PATH_STABLE: bool,
    BUS_ADDRESS_STABLE: bool,
    DESCRIPTOR_IDENTITY_STABLE: bool,
    CONFIGURE_ENDPOINT_OBSERVED: bool,
    CONFIGURE_ENDPOINT_SUCCESS_OBSERVED: bool,
    BL_PATCH_SUCCESS_PATH_OBSERVED: bool,
    ERR_COUNT_DIRECTLY_OBSERVED: bool,
    ALLOW_STAGE2_NAME: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ResultClass {
    SameConfigNameAndInSuccess,
    SameConfigNameWriteEproto,
    SameConfigNameReadEprotoReducedOrOther,
    SameConfigBoundedNoData,
    SameConfigOperationFailed,
    IdentityMismatchAbort,
    OtherTransportFault,
}

impl ResultClass {
    const fn marker(self) -> &'static str {
        match self {
            Self::SameConfigNameAndInSuccess => "SAME_CONFIG_NAME_AND_IN_SUCCESS",
            Self::SameConfigNameWriteEproto => "SAME_CONFIG_NAME_WRITE_EPROTO",
            Self::SameConfigNameReadEprotoReducedOrOther => {
                "SAME_CONFIG_NAME_READ_EPROTO_REDUCED_OR_OTHER"
            }
            Self::SameConfigBoundedNoData => "SAME_CONFIG_BOUNDED_NO_DATA",
            Self::SameConfigOperationFailed => "SAME_CONFIG_OPERATION_FAILED",
            Self::IdentityMismatchAbort => "IDENTITY_MISMATCH_ABORT",
            Self::OtherTransportFault => "OTHER_TRANSPORT_FAULT",
        }
    }
}

fn exact_identity(identity: &LiveIdentity) -> bool {
    let s = &identity.selection;
    s.vendor == KDUSB_VENDOR_ID
        && s.product == KDUSB_PRODUCT_ID
        && identity.physical_path == EXPECTED_PHYSICAL_PATH
        && s.configuration == EXPECTED_CONFIGURATION
        && s.interface == EXPECTED_INTERFACE
        && s.alternate_setting == EXPECTED_ALTSETTING
        && s.bulk_out == EXPECTED_BULK_OUT
        && s.bulk_in == EXPECTED_BULK_IN
        && s.transfer_type == "bulk"
        && s.max_packet > 0
}

fn is_eproto(fault: &TransportFault) -> bool {
    matches!(
        fault.kind,
        TransportFaultKind::LinuxEproto | TransportFaultKind::LinuxUsbfsIo
    ) || fault.raw_os_errno == Some(71)
}

fn atomic_json<T: Serialize>(path: &Path, value: &T) -> Result<(), String> {
    let parent = path.parent().ok_or("state file needs a parent directory")?;
    fs::create_dir_all(parent).map_err(|error| error.to_string())?;
    let file_name = path
        .file_name()
        .ok_or("invalid state filename")?
        .to_string_lossy();
    let temporary = parent.join(format!(".{file_name}.tmp-{}", std::process::id()));
    let bytes = serde_json::to_vec_pretty(value).map_err(|error| error.to_string())?;
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&temporary)
        .map_err(|error| error.to_string())?;
    file.write_all(&bytes).map_err(|error| error.to_string())?;
    file.write_all(b"\n").map_err(|error| error.to_string())?;
    file.sync_all().map_err(|error| error.to_string())?;
    fs::rename(&temporary, path).map_err(|error| error.to_string())?;
    Ok(())
}

fn load_state(path: &Path) -> Result<StageState, String> {
    let state: StageState = serde_json::from_slice(&fs::read(path).map_err(|e| e.to_string())?)
        .map_err(|error| error.to_string())?;
    if state.schema != STATE_SCHEMA
        || state.target != TARGET
        || !state.stage1_complete
        || state.endpoint_recreation_attempts != 1
        || state.phase340_cleanup_authorized
    {
        return Err("state schema, target, stage, attempts, or cleanup policy mismatch".into());
    }
    Ok(state)
}

fn lock_path(state_path: &Path) -> PathBuf {
    PathBuf::from(format!("{}.consumption-lock", state_path.display()))
}

fn acquire_consumption_lock(state_path: &Path) -> Result<(), String> {
    OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(lock_path(state_path))
        .and_then(|mut file| file.write_all(b"NAME_AUTHORIZATION_CONSUMPTION_STARTED=true\n"))
        .map_err(|error| format!("NAME authorization already being/been consumed: {error}"))
}

fn authorize_from_barrier(state_path: &Path, barrier_path: &Path) -> Result<(), String> {
    let mut state = load_state(state_path)?;
    if state.barrier_authorized_name || state.name_authorization_consumed {
        return Err("state has already been authorized or consumed".into());
    }
    let barrier: Barrier =
        serde_json::from_slice(&fs::read(barrier_path).map_err(|error| error.to_string())?)
            .map_err(|error| error.to_string())?;
    let admitted = barrier.schema == BARRIER_SCHEMA
        && !barrier.RESET_DEVICE_OBSERVED
        && !barrier.ADDRESS_DEVICE_OBSERVED
        && !barrier.SLOT_REENUMERATION_OBSERVED
        && barrier.PHYSICAL_PATH_STABLE
        && barrier.BUS_ADDRESS_STABLE
        && barrier.DESCRIPTOR_IDENTITY_STABLE
        && barrier.CONFIGURE_ENDPOINT_OBSERVED
        && barrier.CONFIGURE_ENDPOINT_SUCCESS_OBSERVED
        && barrier.BL_PATCH_SUCCESS_PATH_OBSERVED
        && !barrier.ERR_COUNT_DIRECTLY_OBSERVED
        && barrier.ALLOW_STAGE2_NAME;
    if !admitted {
        return Err("barrier does not authorize Stage 2 NAME".into());
    }
    state.barrier_authorized_name = true;
    atomic_json(state_path, &state)
}

fn run_stage1<B: SameConfigurationLiveBackend>(
    backend: &mut B,
    state_path: &Path,
) -> Result<(), (ResultClass, String)> {
    let (before, after) = backend
        .reapply_only()
        .map_err(|fault| (ResultClass::SameConfigOperationFailed, fault.to_string()))?;
    if !exact_identity(&before) || before != after {
        return Err((
            ResultClass::IdentityMismatchAbort,
            "pre/post identity mismatch".into(),
        ));
    }
    let state = StageState {
        schema: STATE_SCHEMA.into(),
        target: TARGET.into(),
        stage1_complete: true,
        endpoint_recreation_attempts: 1,
        before: StoredIdentity::from(&before),
        after: StoredIdentity::from(&after),
        barrier_authorized_name: false,
        name_authorization_consumed: false,
        phase340_cleanup_authorized: false,
    };
    atomic_json(state_path, &state).map_err(|error| (ResultClass::OtherTransportFault, error))?;
    Ok(())
}

#[derive(Debug)]
struct Stage2Report {
    class: ResultClass,
    fault: Option<TransportFault>,
    name_tx: usize,
    reads: usize,
    reply: Vec<u8>,
}

fn run_stage2<B: SameConfigurationLiveBackend>(
    backend: &mut B,
    state_path: &Path,
) -> Result<Stage2Report, String> {
    let mut state = load_state(state_path)?;
    if !state.barrier_authorized_name || state.name_authorization_consumed {
        return Err("NAME is not authorized or authorization was consumed".into());
    }
    let expected = state.after.live();
    if !exact_identity(&expected) || state.before != state.after {
        return Err("stored identity mismatch".into());
    }
    let actual = backend
        .acquire_exact(&expected)
        .map_err(|fault| fault.to_string())?;
    if actual != expected {
        let _ = backend.release();
        return Ok(Stage2Report {
            class: ResultClass::IdentityMismatchAbort,
            fault: None,
            name_tx: 0,
            reads: 0,
            reply: vec![],
        });
    }

    // This retained create-new lock and atomic state replacement happen before
    // transmission. A crash after this point spends the sole authorization.
    acquire_consumption_lock(state_path)?;
    state.name_authorization_consumed = true;
    atomic_json(state_path, &state)?;

    let write = backend.write_name(EXPECTED_BULK_OUT, NAME_PROBE, TRANSFER_TIMEOUT);
    let mut report = match write {
        Ok(written) if written == NAME_PROBE.len() => Stage2Report {
            class: ResultClass::SameConfigBoundedNoData,
            fault: None,
            name_tx: 1,
            reads: 0,
            reply: vec![],
        },
        Ok(_) => Stage2Report {
            class: ResultClass::OtherTransportFault,
            fault: None,
            name_tx: 1,
            reads: 0,
            reply: vec![],
        },
        Err(fault) => Stage2Report {
            class: if is_eproto(&fault) {
                ResultClass::SameConfigNameWriteEproto
            } else {
                ResultClass::OtherTransportFault
            },
            fault: Some(fault),
            name_tx: 1,
            reads: 0,
            reply: vec![],
        },
    };
    if report.fault.is_none() && report.class == ResultClass::SameConfigBoundedNoData {
        report.reads = 1;
        let mut response = vec![0; USB_READ_REQUEST];
        match backend.read_name(EXPECTED_BULK_IN, &mut response, TRANSFER_TIMEOUT) {
            Ok(0) => {}
            Err(
                fault @ TransportFault {
                    kind: TransportFaultKind::Timeout,
                    ..
                },
            ) => report.fault = Some(fault),
            Ok(received) if received <= response.len() => {
                response.truncate(received);
                report.reply = response;
                report.class =
                    if parse_name_response(&report.reply).is_ok_and(|name| name == TARGET) {
                        ResultClass::SameConfigNameAndInSuccess
                    } else {
                        ResultClass::OtherTransportFault
                    };
            }
            Ok(_) => report.class = ResultClass::OtherTransportFault,
            Err(fault) => {
                report.class = if is_eproto(&fault) {
                    ResultClass::SameConfigNameReadEprotoReducedOrOther
                } else {
                    ResultClass::OtherTransportFault
                };
                report.fault = Some(fault);
            }
        }
    }
    if let Err(fault) = backend.release()
        && report.fault.is_none()
    {
        report.class = ResultClass::OtherTransportFault;
        report.fault = Some(fault);
    }
    Ok(report)
}

fn print_safety(live: bool, reapply: bool, name: bool) {
    println!("MAX_ENDPOINT_RECREATION_ATTEMPTS={MAX_ENDPOINT_RECREATION_ATTEMPTS}");
    println!("MAX_USB_DEVICE_RESET_ATTEMPTS={MAX_USB_DEVICE_RESET_ATTEMPTS}");
    println!("MAX_PRE_OPERATION_NAME_TX={MAX_PRE_OPERATION_NAME_TX}");
    println!("MAX_POST_OPERATION_NAME_TX={MAX_POST_OPERATION_NAME_TX}");
    println!("MAX_POST_OPERATION_READS={MAX_POST_OPERATION_READS}");
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
        "PCI_UNBIND_REBIND=false",
        "XHCI_RELOAD=false",
        "RUNTIME_PM_CHANGE=false",
        "HOST_REBOOT=false",
        "TARGET_REBOOT=false",
        "BCD_CHANGE=false",
        "PHASE340_CLEANUP_AUTHORIZED=false",
    ] {
        println!("{marker}");
    }
    println!("LIVE_MODE={live}");
    println!("ENDPOINT_RECREATION_EXECUTED={reapply}");
    println!("NAME_PROBE_SENT={name}");
}

fn print_plan() {
    println!("KDUSB_SAME_CONFIGURATION_LIVE_PLAN=PASS");
    println!("DEFAULT_MODE=DRY_PLAN");
    println!("TWO_STAGE_LIVE_BARRIER=true");
    println!("STAGE1_FLAG=--execute-reapply-only");
    println!("BARRIER_AUTHORIZATION_FLAG=--authorize-name-from-barrier");
    println!("STAGE2_FLAG=--execute-name-once-from-state");
    print_safety(false, false, false);
}

fn argument_path(args: &[String], name: &str) -> Result<PathBuf, String> {
    let index = args
        .iter()
        .position(|arg| arg == name)
        .ok_or_else(|| format!("missing {name}"))?;
    args.get(index + 1)
        .map(PathBuf::from)
        .ok_or_else(|| format!("missing value after {name}"))
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
    let state_path = match argument_path(&args, "--state-file") {
        Ok(path) => path,
        Err(error) => {
            eprintln!("{error}");
            std::process::exit(2);
        }
    };
    if args
        .first()
        .is_some_and(|value| value == "--authorize-name-from-barrier")
    {
        let barrier = argument_path(&args, "--barrier-file").unwrap_or_else(|error| {
            eprintln!("{error}");
            std::process::exit(2)
        });
        authorize_from_barrier(&state_path, &barrier).unwrap_or_else(|error| {
            eprintln!("BARRIER_AUTHORIZATION_ERROR={error}");
            std::process::exit(3)
        });
        println!("BARRIER_AUTHORIZATION=RECORDED");
        print_safety(false, false, false);
        return;
    }
    if args.get(1).is_none_or(|value| value != TARGET) {
        eprintln!("target must be {TARGET}");
        std::process::exit(2);
    }
    let mut backend =
        ntoseye::kdusb_same_configuration_live::linux::RusbSameConfigurationLiveBackend::new();
    match args.first().map(String::as_str) {
        Some("--execute-reapply-only") => match run_stage1(&mut backend, &state_path) {
            Ok(()) => {
                println!("KDUSB_STAGE1_RESULT=SUCCESS");
                print_safety(true, true, false);
            }
            Err((class, error)) => {
                println!("KDUSB_STAGE1_RESULT={}", class.marker());
                eprintln!("FAULT={error}");
                print_safety(true, true, false);
                std::process::exit(3);
            }
        },
        Some("--execute-name-once-from-state") => match run_stage2(&mut backend, &state_path) {
            Ok(report) => {
                println!("KDUSB_STAGE2_RESULT={}", report.class.marker());
                println!("POST_OPERATION_NAME_TX={}", report.name_tx);
                println!("POST_OPERATION_READ_CALLS={}", report.reads);
                println!("REPLY_BYTES={}", report.reply.len());
                println!("REPLY_HEX={}", hex::encode(&report.reply));
                if let Some(fault) = report.fault {
                    println!("{fault}");
                }
                print_safety(true, false, report.name_tx == 1);
            }
            Err(error) => {
                eprintln!("STAGE2_ADMISSION_ERROR={error}");
                print_safety(true, false, false);
                std::process::exit(3);
            }
        },
        _ => {
            eprintln!("invalid action");
            std::process::exit(2);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;

    struct Mock {
        identity: LiveIdentity,
        events: Vec<&'static str>,
        writes: usize,
        reads: usize,
        read_results: VecDeque<Result<Vec<u8>, TransportFault>>,
    }
    fn identity() -> LiveIdentity {
        LiveIdentity {
            selection: DeviceSelection {
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
            },
            bus: 6,
            address: 9,
            physical_path: "6-1".into(),
        }
    }
    impl Default for Mock {
        fn default() -> Self {
            Self {
                identity: identity(),
                events: vec![],
                writes: 0,
                reads: 0,
                read_results: VecDeque::new(),
            }
        }
    }
    impl SameConfigurationLiveBackend for Mock {
        fn reapply_only(&mut self) -> Result<(LiveIdentity, LiveIdentity), TransportFault> {
            self.events.push("reapply");
            Ok((self.identity.clone(), self.identity.clone()))
        }
        fn acquire_exact(&mut self, _: &LiveIdentity) -> Result<LiveIdentity, TransportFault> {
            self.events.push("claim");
            Ok(self.identity.clone())
        }
        fn write_name(
            &mut self,
            _: u8,
            payload: &[u8],
            _: std::time::Duration,
        ) -> Result<usize, TransportFault> {
            self.events.push("name");
            self.writes += 1;
            Ok(payload.len())
        }
        fn read_name(
            &mut self,
            _: u8,
            out: &mut [u8],
            _: std::time::Duration,
        ) -> Result<usize, TransportFault> {
            self.events.push("read");
            self.reads += 1;
            match self.read_results.pop_front().unwrap_or(Ok(vec![])) {
                Ok(bytes) => {
                    out[..bytes.len()].copy_from_slice(&bytes);
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
    fn paths(label: &str) -> (PathBuf, PathBuf) {
        let root = std::env::temp_dir().join(format!("ntoseye-br-{label}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&root).unwrap();
        (root.join("state.json"), root.join("barrier.json"))
    }
    fn barrier() -> Barrier {
        Barrier {
            schema: BARRIER_SCHEMA.into(),
            RESET_DEVICE_OBSERVED: false,
            ADDRESS_DEVICE_OBSERVED: false,
            SLOT_REENUMERATION_OBSERVED: false,
            PHYSICAL_PATH_STABLE: true,
            BUS_ADDRESS_STABLE: true,
            DESCRIPTOR_IDENTITY_STABLE: true,
            CONFIGURE_ENDPOINT_OBSERVED: true,
            CONFIGURE_ENDPOINT_SUCCESS_OBSERVED: true,
            BL_PATCH_SUCCESS_PATH_OBSERVED: true,
            ERR_COUNT_DIRECTLY_OBSERVED: false,
            ALLOW_STAGE2_NAME: true,
        }
    }

    #[test]
    fn stage1_stops_without_name_and_requires_barrier() {
        let (state, _) = paths("stage1");
        let mut mock = Mock::default();
        run_stage1(&mut mock, &state).unwrap();
        assert_eq!(mock.events, ["reapply"]);
        let saved = load_state(&state).unwrap();
        assert!(!saved.barrier_authorized_name);
        assert!(!saved.name_authorization_consumed);
    }
    #[test]
    fn barrier_then_stage2_consumes_before_exactly_one_name_and_read() {
        let (state, barrier_path) = paths("stage2");
        let mut first = Mock::default();
        run_stage1(&mut first, &state).unwrap();
        atomic_json(&barrier_path, &barrier()).unwrap();
        authorize_from_barrier(&state, &barrier_path).unwrap();
        let mut second = Mock::default();
        second
            .read_results
            .push_back(Ok(b"NAME=CLSA0102_USB\0\0".to_vec()));
        let report = run_stage2(&mut second, &state).unwrap();
        assert_eq!(report.class, ResultClass::SameConfigNameAndInSuccess);
        assert_eq!((second.writes, second.reads), (1, 1));
        assert!(load_state(&state).unwrap().name_authorization_consumed);
        assert!(run_stage2(&mut Mock::default(), &state).is_err());
    }
    #[test]
    fn rejecting_barrier_never_authorizes_name() {
        let (state, barrier_path) = paths("reject");
        run_stage1(&mut Mock::default(), &state).unwrap();
        let mut b = barrier();
        b.ADDRESS_DEVICE_OBSERVED = true;
        atomic_json(&barrier_path, &b).unwrap();
        assert!(authorize_from_barrier(&state, &barrier_path).is_err());
    }
    #[test]
    fn hard_limits_and_no_reset_api() {
        assert_eq!(
            (
                MAX_ENDPOINT_RECREATION_ATTEMPTS,
                MAX_USB_DEVICE_RESET_ATTEMPTS,
                MAX_PRE_OPERATION_NAME_TX,
                MAX_POST_OPERATION_NAME_TX,
                MAX_POST_OPERATION_READS
            ),
            (1, 0, 0, 1, 1)
        );
        let source = include_str!("ntoseye-kdusb-same-configuration-live-r1.rs");
        let reset_call = [".", "reset", "("].concat();
        let libusb_reset = ["libusb", "_reset_", "device"].concat();
        assert!(!source.contains(&reset_call));
        assert!(!source.contains(&libusb_reset));
    }
}
