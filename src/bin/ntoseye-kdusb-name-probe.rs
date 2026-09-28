//! One-shot classic KDUSB NAME identity probe and dry-run recovery planner.

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("ntoseye-kdusb-name-probe is supported only on Linux hosts");
    std::process::exit(2);
}

#[cfg(target_os = "linux")]
fn main() {
    if let Err(error) = linux::run() {
        eprintln!("KDUSB_NAME_PROBE=FAIL");
        eprintln!("{error}");
        std::process::exit(2);
    }
}

#[cfg(target_os = "linux")]
mod linux {
    use ntoseye::kdusb_probe::linux::RusbProbeBackend;
    use ntoseye::kdusb_probe::{
        MAX_DISCOVERY_READS, MAX_NAME_TX, MAX_RECOVERY_ATTEMPTS, NAME_PROBE, ProbeOutcome,
        RecoveryPolicy, USB_READ_REQUEST, recovery_plan, run_probe, validate_target_name,
    };

    struct Arguments {
        target: Option<String>,
        policy: RecoveryPolicy,
        dry_run_plan: bool,
        execute_state_changing_recovery: bool,
    }

    pub fn run() -> Result<(), String> {
        let arguments = parse_arguments()?;
        if arguments.dry_run_plan {
            for line in recovery_plan(arguments.policy) {
                println!("{line}");
            }
            println!("DRY_RUN_RECOVERY_PLAN=PASS");
            return Ok(());
        }

        let target = arguments.target.as_deref().ok_or_else(usage)?;
        validate_target_name(target)?;
        if arguments.policy == RecoveryPolicy::ResetAndReacquire
            && !arguments.execute_state_changing_recovery
        {
            return Err(
                "reset-and-reacquire requires --execute-state-changing-recovery; use --dry-run-recovery-plan first"
                    .to_string(),
            );
        }
        if arguments.policy != RecoveryPolicy::ResetAndReacquire
            && arguments.execute_state_changing_recovery
        {
            return Err(
                "--execute-state-changing-recovery is valid only with --recovery reset-and-reacquire"
                    .to_string(),
            );
        }

        let mut backend = RusbProbeBackend::new();
        match run_probe(&mut backend, target, arguments.policy).map_err(|err| err.to_string())? {
            ProbeOutcome::Success(report) => {
                println!("KDUSB_NAME_PROBE=PASS");
                println!(
                    "VID_PID={:04x}:{:04x}",
                    report.selection.vendor, report.selection.product
                );
                println!("CONFIGURATION={}", report.selection.configuration);
                println!("INTERFACE={}", report.selection.interface);
                println!("ALTERNATE_SETTING={}", report.selection.alternate_setting);
                println!("TRANSFER_TYPE={}", report.selection.transfer_type);
                println!("BULK_OUT=0x{:02x}", report.selection.bulk_out);
                println!("BULK_IN=0x{:02x}", report.selection.bulk_in);
                println!("MAX_PACKET={}", report.selection.max_packet);
                println!("PROBE_TX_LEN={}", NAME_PROBE.len());
                println!("PROBE_TX_HEX=4e414d453f");
                println!("USB_RX_REQUEST_LEN={USB_READ_REQUEST}");
                println!("USB_RX_TOTAL_LEN={}", report.usb_rx_len);
                println!("USB_RX_TRANSFER_COUNT={}", report.usb_rx_transfers);
                println!("USB_RX_READ_CALL_COUNT={}", report.usb_rx_read_calls);
                println!("REPLY_RX_LEN={}", report.reply.len());
                println!("REPLY_RX_HEX={}", hex::encode(&report.reply));
                println!("PRELUDE_RX_LEN={}", report.prelude.len());
                println!(
                    "PRELUDE_RX_PREFIX_HEX={}",
                    hex::encode(&report.prelude[..report.prelude.len().min(64)])
                );
                println!("POSTLUDE_RX_LEN={}", report.postlude.len());
                println!(
                    "POSTLUDE_RX_PREFIX_HEX={}",
                    hex::encode(&report.postlude[..report.postlude.len().min(64)])
                );
                println!("REPLY_TARGET={}", report.target_name);
                print_safety(arguments.policy);
            }
            ProbeOutcome::RecoveredAwaitingBootstrap {
                original_fault,
                selection,
                recovery_attempts,
            } => {
                println!("KDUSB_RECOVERY=PASS");
                println!("ORIGINAL_{original_fault}");
                println!("RECOVERY_ATTEMPTS={recovery_attempts}");
                println!(
                    "REACQUIRED_VID_PID={:04x}:{:04x}",
                    selection.vendor, selection.product
                );
                println!("POST_RECOVERY_NAME_TX=false");
                println!("LIVE_TRANSMISSION_ADMISSION_REQUIRED=true");
                print_safety(arguments.policy);
            }
        }
        Ok(())
    }

    fn print_safety(policy: RecoveryPolicy) {
        println!("RECOVERY_POLICY={}", policy.marker());
        println!("INTERFACE_RELEASED=true");
        println!("USB_CONTROL_TRANSFER=false");
        println!("KD_PACKET_TX=false");
        println!("KD_ACK_TX=false");
        println!("KD_RESEND_TX=false");
        println!("KD_RESET_TX=false");
        println!("MAX_NAME_PROBE_TX={MAX_NAME_TX}");
        println!("MAX_DISCOVERY_READ_CALLS={MAX_DISCOVERY_READS}");
        println!("MAX_RECOVERY_ATTEMPTS={MAX_RECOVERY_ATTEMPTS}");
        println!("SINGLE_CANDIDATE_REQUIRED=true");
        println!("AUTOMATIC_TIMEOUT_RETRY=false");
        println!("AUTOMATIC_NAME_RETRY=false");
        println!("PRELUDE_RX_INTERPRETED=false");
        println!("POSTLUDE_RX_INTERPRETED=false");
        println!("BREAKIN_SENT=false");
        println!("DEBUGGER_SESSION=false");
        println!("TARGET_MEMORY_ACCESS=false");
    }

    fn parse_arguments() -> Result<Arguments, String> {
        parse_from(std::env::args().skip(1))
    }

    fn parse_from(arguments: impl IntoIterator<Item = String>) -> Result<Arguments, String> {
        let mut arguments = arguments.into_iter();
        let mut target = None;
        let mut policy = RecoveryPolicy::None;
        let mut dry_run_plan = false;
        let mut execute_state_changing_recovery = false;
        while let Some(argument) = arguments.next() {
            match argument.as_str() {
                "--recovery" => {
                    let value = arguments
                        .next()
                        .ok_or_else(|| "--recovery requires a policy".to_string())?;
                    policy = RecoveryPolicy::parse(&value)?;
                }
                "--dry-run-recovery-plan" => dry_run_plan = true,
                "--execute-state-changing-recovery" => {
                    execute_state_changing_recovery = true;
                }
                value if value.starts_with('-') => {
                    return Err(format!("unknown option '{value}'\n{}", usage()));
                }
                value if target.is_none() => target = Some(value.to_string()),
                _ => return Err(usage()),
            }
        }
        if dry_run_plan && execute_state_changing_recovery {
            return Err("dry-run planning cannot execute recovery".to_string());
        }
        if dry_run_plan && policy == RecoveryPolicy::None {
            return Err("dry-run planning requires --recovery <policy>".to_string());
        }
        if !dry_run_plan && target.is_none() {
            return Err(usage());
        }
        Ok(Arguments {
            target,
            policy,
            dry_run_plan,
            execute_state_changing_recovery,
        })
    }

    fn usage() -> String {
        "usage: ntoseye-kdusb-name-probe [--recovery none|reopen-handle|reset-and-reacquire] [--dry-run-recovery-plan | --execute-state-changing-recovery] <TARGET_NAME>".to_string()
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn default_cli_stays_one_shot_and_no_recovery() {
            let parsed = parse_from(["CLSA0102_USB".to_string()]).unwrap();
            assert_eq!(parsed.policy, RecoveryPolicy::None);
            assert!(!parsed.dry_run_plan);
            assert!(!parsed.execute_state_changing_recovery);
            assert_eq!(MAX_NAME_TX, 1);
        }

        #[test]
        fn planner_does_not_require_a_target() {
            let parsed = parse_from([
                "--recovery".to_string(),
                "reset-and-reacquire".to_string(),
                "--dry-run-recovery-plan".to_string(),
            ])
            .unwrap();
            assert!(parsed.target.is_none());
            assert!(parsed.dry_run_plan);
            assert!(!parsed.execute_state_changing_recovery);
        }
    }
}
