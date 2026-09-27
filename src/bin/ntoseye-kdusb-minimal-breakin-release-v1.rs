//! Bounded classic-KDUSB break-in/release probe.
//!
//! This binary performs NAME discovery, sends exactly one break-in byte,
//! accepts/ACKs exactly one state-change, then sends one AMD64 ContinueApi2
//! through strict one-shot framing. It does not issue GetVersion, RESET,
//! RESEND repair, breakpoint cleanup, or memory requests.

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("KDUSB_MINIMAL_BREAKIN_RELEASE=FAIL");
    eprintln!("ERROR=classic KDUSB is supported only on Linux");
    std::process::exit(2);
}

#[cfg(target_os = "linux")]
fn main() {
    use std::time::Duration;

    let mut args = std::env::args();
    let program = args
        .next()
        .unwrap_or_else(|| "ntoseye-kdusb-minimal-breakin-release-v1".to_string());
    let Some(target) = args.next() else {
        eprintln!("usage: {program} <TARGET_NAME>");
        std::process::exit(2);
    };
    if args.next().is_some() {
        eprintln!("usage: {program} <TARGET_NAME>");
        std::process::exit(2);
    }

    println!("KDUSB_MINIMAL_BREAKIN_RELEASE=START");
    println!("TARGET_NAME={target}");
    println!("READ_TIMEOUT_MS=2000");
    println!("NAME_DISCOVERY=true");
    println!("BREAKIN_MAX=1");
    println!("STATE_CHANGE_MAX=1");
    println!("CONTINUE_MAX=1");
    println!("GET_VERSION_TX=false");
    println!("RESET_TX=false");
    println!("RESEND_REPAIR_TX=false");
    println!("MEMORY_ACCESS=false");
    println!("BREAKPOINT_CLEANUP=false");

    match ntoseye::kd::minimal_breakin_release_usb(&target, Duration::from_secs(2)) {
        Ok(report) => {
            println!("KDUSB_MINIMAL_BREAKIN_RELEASE=PASS");
            println!("BREAKIN_SENT={}", report.breakin_sent);
            println!("STATE_CHANGE_RECEIVED={}", report.state_change_received);
            println!("PROCESSOR={}", report.processor);
            println!("NUMBER_PROCESSORS={}", report.number_processors);
            println!("PROGRAM_COUNTER=0x{:016x}", report.program_counter);
            println!("DR7=0x{:016x}", report.dr7);
            println!(
                "DR7_FROM_CONTROL_REPORT={}",
                report.dr7_from_control_report
            );
            println!("CONTINUE_ACKED={}", report.continue_acked);
            println!("TARGET_MAY_BE_HALTED=false");
        }
        Err(err) => {
            eprintln!("KDUSB_MINIMAL_BREAKIN_RELEASE=FAIL");
            eprintln!("FAILURE_STAGE={}", err.stage);
            eprintln!("TARGET_MAY_BE_HALTED={}", err.target_may_be_halted);
            eprintln!("ERROR={}", err.message);
            std::process::exit(2);
        }
    }
}
