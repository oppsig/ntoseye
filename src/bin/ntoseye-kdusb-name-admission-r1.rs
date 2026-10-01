use std::process::ExitCode;
use std::time::Duration;

use ntoseye::kd::kdusb::connect_named;

const AUTH_FLAG: &str = "--authorize-live-usb-name-probe";
const TARGET_FLAG: &str = "--target";
const TIMEOUT_FLAG: &str = "--timeout-ms";
const ADMITTED_TARGET: &str = "CLSA0102_USB";
const DEFAULT_TIMEOUT_MS: u64 = 3000;

fn usage() -> &'static str {
    "usage: ntoseye-kdusb-name-admission-r1 --authorize-live-usb-name-probe --target CLSA0102_USB [--timeout-ms 3000]"
}

fn parse_args() -> Result<u64, String> {
    let mut args = std::env::args().skip(1);
    let mut authorized = false;
    let mut target = None;
    let mut timeout_ms = DEFAULT_TIMEOUT_MS;

    while let Some(arg) = args.next() {
        match arg.as_str() {
            AUTH_FLAG => authorized = true,
            TARGET_FLAG => {
                target = Some(
                    args.next()
                        .ok_or_else(|| format!("{TARGET_FLAG} requires a value"))?,
                );
            }
            TIMEOUT_FLAG => {
                let raw = args
                    .next()
                    .ok_or_else(|| format!("{TIMEOUT_FLAG} requires a value"))?;
                timeout_ms = raw
                    .parse::<u64>()
                    .map_err(|_| format!("invalid timeout: {raw:?}"))?;
                if !(250..=10_000).contains(&timeout_ms) {
                    return Err("timeout must be between 250 and 10000 ms".into());
                }
            }
            "-h" | "--help" => return Err(usage().into()),
            other => return Err(format!("unknown argument: {other}\n{}", usage())),
        }
    }

    if !authorized {
        return Err(format!(
            "live USB NAME probe is not authorized; pass {AUTH_FLAG} explicitly"
        ));
    }

    let target = target.ok_or_else(|| format!("{TARGET_FLAG} is required"))?;
    if target != ADMITTED_TARGET {
        return Err(format!(
            "target must be exact admitted name {ADMITTED_TARGET:?}, got {target:?}"
        ));
    }

    Ok(timeout_ms)
}

fn main() -> ExitCode {
    let timeout_ms = match parse_args() {
        Ok(value) => value,
        Err(error) => {
            eprintln!("FAIL_KDUSB_NAME_ADMISSION_ARGS={error}");
            return ExitCode::from(2);
        }
    };

    println!("PHASE349F_MODE=BOUNDED_LIVE_USB_NAME_ADMISSION");
    println!("TARGET_NAME={ADMITTED_TARGET}");
    println!("USB_EXPECTED_VID_PID=3495:00e0");
    println!("USB_EXPECTED_INTERFACE=dc/02/ff");
    println!("USB_EXPECTED_ALT_SETTING=0");
    println!("USB_EXPECTED_ENDPOINTS=81/01");
    println!("USB_EXPECTED_MAX_PACKET=1024");
    println!("BREAKIN=false");
    println!("GETVERSION=false");
    println!("BACKEND_ATTACH=false");
    println!("CONFIGURATION_CHANGE=false");
    println!("ALTERNATE_SETTING_CHANGE=false");
    println!("KERNEL_DRIVER_DETACH=false");
    println!("DEVICE_RESET=false");

    match connect_named(ADMITTED_TARGET, Duration::from_millis(timeout_ms)) {
        Ok(stream) => {
            drop(stream);
            println!("PASS_KDUSB_NAME_IDENTITY=CLSA0102_USB");
            println!("PASS_KDUSB_STREAM_DROPPED=true");
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("FAIL_KDUSB_NAME_ADMISSION={error}");
            ExitCode::from(1)
        }
    }
}
