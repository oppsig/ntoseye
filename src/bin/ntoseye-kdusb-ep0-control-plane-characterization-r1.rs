//! Bounded read-only EP0 observer. Cached admission; no libusb context initialized.
#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("Linux-only observer");
    std::process::exit(2);
}
#[cfg(target_os = "linux")]
fn main() {
    std::process::exit(linux::run());
}
#[cfg(target_os = "linux")]
mod linux {
    use std::fs::{self, File, OpenOptions};
    use std::io::{self, Write};
    use std::os::fd::AsRawFd;
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
    use std::path::Path;
    use std::time::{SystemTime, UNIX_EPOCH};

    const TIMEOUT_MS: u32 = 750;
    // Pinned devio.c check_ctrlrecip leaves ret=0 for standard device recipients.
    // See retained kernel-contract-blocker.json and matrix-resolution.json in project.
    // Interface/endpoint requests remain excluded: they can implicitly claim ownership.
    const DEVICE_RECIPIENT_NO_IMPLICIT_CLAIM_PROVEN: bool = true;
    const AUTH: &str = "--execute-ep0-control-plane-characterization";
    #[derive(Clone, Copy, Debug, PartialEq)]
    struct Probe {
        name: &'static str,
        setup: (u8, u8, u16, u16, u16),
    }
    const PROBES: [Probe; 6] = [
        Probe {
            name: "GET_CONFIGURATION_PRE",
            setup: (0x80, 8, 0, 0, 1),
        },
        Probe {
            name: "GET_STATUS_DEVICE_PRE",
            setup: (0x80, 0, 0, 0, 2),
        },
        Probe {
            name: "GET_DESCRIPTOR_DEVICE",
            setup: (0x80, 6, 0x0100, 0, 18),
        },
        Probe {
            name: "GET_DESCRIPTOR_CONFIGURATION_HEADER",
            setup: (0x80, 6, 0x0200, 0, 9),
        },
        Probe {
            name: "GET_STATUS_DEVICE_POST",
            setup: (0x80, 0, 0, 0, 2),
        },
        Probe {
            name: "GET_CONFIGURATION_POST",
            setup: (0x80, 8, 0, 0, 1),
        },
    ];
    fn matrix_admissible(probes: &[Probe]) -> bool {
        DEVICE_RECIPIENT_NO_IMPLICIT_CLAIM_PROVEN
            && TIMEOUT_MS == 750
            && probes.len() == 6
            && probes.iter().all(|p| p.setup.0 == 0x80 && p.setup.3 == 0)
            && probes.iter().map(|p| p.setup).eq([
                (0x80, 8, 0, 0, 1),
                (0x80, 0, 0, 0, 2),
                (0x80, 6, 0x0100, 0, 18),
                (0x80, 6, 0x0200, 0, 9),
                (0x80, 0, 0, 0, 2),
                (0x80, 8, 0, 0, 1),
            ])
    }
    // Linux usbdevice_fs.h: USBDEVFS_CONTROL = _IOWR('U', 0, struct usbdevfs_ctrltransfer).
    #[repr(C)]
    struct Control {
        request_type: u8,
        request: u8,
        value: u16,
        index: u16,
        length: u16,
        timeout: u32,
        data: *mut libc::c_void,
    }
    const CONTROL_IOCTL: libc::c_ulong = (3 << 30)
        | ((std::mem::size_of::<Control>() as libc::c_ulong) << 16)
        | (b'U' as libc::c_ulong) << 8;
    fn read_control(file: &File, p: Probe, data: &mut [u8]) -> io::Result<usize> {
        let (request_type, request, value, index, length) = p.setup;
        assert!(request_type == 0x80 && data.len() == usize::from(length));
        let mut control = Control {
            request_type,
            request,
            value,
            index,
            length,
            timeout: TIMEOUT_MS,
            data: data.as_mut_ptr().cast(),
        };
        // SAFETY: C layout, native fields, mutable buffer lives through the synchronous ioctl.
        // This sole USB ioctl requests a standard control-IN operation with bounded timeout.
        let rc = unsafe { libc::ioctl(file.as_raw_fd(), CONTROL_IOCTL, &mut control) };
        if rc < 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(rc as usize)
        }
    }
    #[derive(Clone, Debug)]
    struct Record {
        status: &'static str,
        data: Option<Vec<u8>>,
        error: String,
        errno: Option<i32>,
        rc: Option<i32>,
        valid: Option<bool>,
        begin: Option<u128>,
        end: Option<u128>,
    }
    impl Default for Record {
        fn default() -> Self {
            Self {
                status: "NOT_ATTEMPTED",
                data: None,
                error: "NA".into(),
                errno: None,
                rc: None,
                valid: None,
                begin: None,
                end: None,
            }
        }
    }
    fn expectation(n: usize, d: &[u8]) -> bool {
        match n {
            0 | 5 => d == [1],
            2 => {
                d.len() == 18
                    && d[0..2] == [18, 1]
                    && u16::from_le_bytes([d[8], d[9]]) == 0x3495
                    && u16::from_le_bytes([d[10], d[11]]) == 0x00e0
            }
            3 => {
                d.len() == 9
                    && d[0..2] == [9, 2]
                    && d[5] == 1
                    && u16::from_le_bytes([d[2], d[3]]) >= 9
            }
            _ => d.len() == 2,
        }
    }
    fn errno_class(e: i32) -> (rusb::Error, &'static str) {
        use rusb::Error as E;
        match e {
            libc::ETIMEDOUT => (E::Timeout, "TIMEOUT"),
            libc::EPIPE => (E::Pipe, "PIPE"),
            libc::EIO | libc::EPROTO | libc::EILSEQ => (E::Io, "IO"),
            libc::ENODEV | libc::ESHUTDOWN | libc::ENOENT => (E::NoDevice, "NO_DEVICE"),
            libc::EACCES | libc::EPERM => (E::Access, "ACCESS"),
            libc::EBUSY => (E::Busy, "BUSY"),
            libc::EINTR => (E::Interrupted, "INTERRUPTED"),
            libc::EOVERFLOW => (E::Overflow, "OVERFLOW"),
            _ => (E::Other, "OTHER_ERROR"),
        }
    }
    fn epoch() -> u128 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock before epoch")
            .as_micros()
    }
    fn execute<F, M>(mut call: F, mut mark: M) -> (Vec<Record>, bool)
    where
        F: FnMut(Probe, &mut [u8]) -> io::Result<usize>,
        M: FnMut(String) -> io::Result<()>,
    {
        let mut records = vec![Record::default(); PROBES.len()];
        let mut marker_fault = false;
        for (n, p) in PROBES.iter().enumerate() {
            let mut data = vec![0; usize::from(p.setup.4)];
            if mark(format!("I_P{:02}_{}_BEGIN", n + 1, p.name)).is_err() {
                marker_fault = true;
                break;
            }
            let begin = epoch();
            let result = call(*p, &mut data);
            let end = epoch();
            let end_ok = mark(format!("I_P{:02}_{}_END", n + 1, p.name)).is_ok();
            let r = &mut records[n];
            r.begin = Some(begin);
            r.end = Some(end);
            match result {
                Ok(size) if size <= data.len() => {
                    data.truncate(size);
                    r.rc = Some(size as i32);
                    r.status = if size == usize::from(p.setup.4) {
                        "OK"
                    } else {
                        "SHORT"
                    };
                    r.valid = Some(expectation(n, &data));
                    r.data = Some(data);
                }
                Ok(size) => {
                    r.status = "OVERFLOW";
                    r.rc = Some(size as i32);
                }
                Err(e) => {
                    let raw = e.raw_os_error().unwrap_or(0);
                    let (mapped, class) = errno_class(raw);
                    r.status = class;
                    r.errno = e.raw_os_error();
                    r.rc = Some(-1);
                    r.error = format!("{mapped:?}/{mapped} (errno mapping; direct usbfs: {e})");
                }
            }
            if !end_ok {
                marker_fault = true;
                break;
            }
            if r.status == "NO_DEVICE" {
                break;
            }
        }
        (records, marker_fault)
    }
    fn matched(r: &[Record], a: usize, b: usize) -> Option<bool> {
        if r[a].status == "OK" && r[b].status == "OK" {
            Some(r[a].data == r[b].data)
        } else {
            None
        }
    }
    fn classify(r: &[Record]) -> &'static str {
        if r.iter().any(|x| x.status == "NO_DEVICE") {
            return "DEVICE_DISAPPEARED";
        }
        if r.iter().all(|x| x.status == "OK") {
            return if r.iter().any(|x| x.valid == Some(false))
                || matched(r, 0, 5) != Some(true)
                || matched(r, 1, 4) != Some(true)
            {
                "EP0_DEVICE_RECIPIENT_ALL_OK_EXPECTATION_MISMATCH"
            } else {
                "EP0_DEVICE_RECIPIENT_ALL_OK"
            };
        }
        if r.iter().any(|x| x.status == "OK") {
            return "EP0_DEVICE_RECIPIENT_PARTIAL_FAULTS";
        }
        for (s, result) in [
            ("IO", "EP0_DEVICE_RECIPIENT_NONOPERATIONAL"),
            ("PIPE", "EP0_DEVICE_RECIPIENT_NONOPERATIONAL"),
            ("TIMEOUT", "EP0_DEVICE_RECIPIENT_NONOPERATIONAL"),
        ] {
            if r.iter().all(|x| x.status == s) {
                return result;
            }
        }
        if r.iter()
            .all(|x| matches!(x.status, "IO" | "PIPE" | "TIMEOUT" | "SHORT"))
        {
            "EP0_MIXED_ERROR_SIGNATURE"
        } else {
            "OTHER_TRANSPORT_FAULT"
        }
    }
    fn text(root: &Path, name: &str) -> io::Result<String> {
        Ok(fs::read_to_string(root.join(name))?.trim().to_lowercase())
    }
    fn require(ok: bool) -> io::Result<()> {
        if ok {
            Ok(())
        } else {
            Err(io::Error::other("cached identity mismatch"))
        }
    }
    fn cached_descriptors(d: &[u8]) -> io::Result<()> {
        require(d.len() >= 18 && expectation(2, &d[..18]))?;
        let mut offset = 18;
        let mut configurations = 0;
        let mut matched = false;
        while offset < d.len() {
            require(offset + 9 <= d.len() && d[offset] == 9 && d[offset + 1] == 2)?;
            let total = usize::from(u16::from_le_bytes([d[offset + 2], d[offset + 3]]));
            require(total >= 9 && offset + total <= d.len())?;
            if d[offset + 5] == 1 {
                configurations += 1;
                require(d[offset + 4] == 1)?;
                let mut i = offset + 9;
                let end = offset + total;
                let mut interfaces = 0;
                let mut endpoints = Vec::new();
                while i < end {
                    let len = usize::from(d[i]);
                    require(len >= 2 && i + len <= end)?;
                    match d[i + 1] {
                        4 => {
                            require(len == 9 && d[i + 2..i + 8] == [0, 0, 2, 0xdc, 2, 0xff])?;
                            interfaces += 1;
                        }
                        5 => {
                            require(len >= 7 && interfaces == 1 && d[i + 3] & 3 == 2)?;
                            endpoints.push((d[i + 2], u16::from_le_bytes([d[i + 4], d[i + 5]])));
                        }
                        _ => {}
                    }
                    i += len;
                }
                endpoints.sort();
                require(interfaces == 1 && endpoints == [(1, 1024), (129, 1024)])?;
                matched = true;
            }
            offset += total;
        }
        require(configurations == 1 && matched)
    }
    fn admission(root: &Path) -> io::Result<()> {
        let mut candidates = Vec::new();
        for e in fs::read_dir(root)? {
            let p = e?.path();
            if p.join("idVendor").is_file()
                && text(&p, "idVendor")? == "3495"
                && text(&p, "idProduct")? == "00e0"
            {
                candidates.push(p);
            }
        }
        require(candidates.len() == 1 && candidates[0].file_name().unwrap() == "6-1")?;
        let p = &candidates[0];
        for (key, value) in [
            ("busnum", "6"),
            ("devnum", "8"),
            ("bConfigurationValue", "1"),
        ] {
            require(text(p, key)? == value)?;
        }
        let interface = root.join("6-1:1.0");
        for (key, value) in [
            ("bInterfaceNumber", "00"),
            ("bAlternateSetting", "0"),
            ("bInterfaceClass", "dc"),
            ("bInterfaceSubClass", "02"),
            ("bInterfaceProtocol", "ff"),
        ] {
            require(text(&interface, key)? == value)?;
        }
        require(!interface.join("driver").exists())?;
        for (ep, address) in [("ep_01", "01"), ("ep_81", "81")] {
            let e = interface.join(ep);
            for (key, value) in [("bEndpointAddress", address), ("bmAttributes", "02")] {
                require(text(&e, key)? == value)?;
            }
            require(u16::from_str_radix(&text(&e, "wMaxPacketSize")?, 16).ok() == Some(1024))?;
        }
        cached_descriptors(&fs::read(p.join("descriptors"))?)
    }
    fn marker(path: Option<std::ffi::OsString>) -> io::Result<File> {
        let p = path.ok_or_else(|| io::Error::other("NTOSEYE_TRACE_MARKER is required"))?;
        OpenOptions::new().write(true).open(p)
    }
    fn mode(args: &[String]) -> Result<bool, &'static str> {
        if args.is_empty() {
            Ok(false)
        } else if args == [AUTH, "CLSA0102_USB"] {
            Ok(true)
        } else {
            Err("only live form: --execute-ep0-control-plane-characterization CLSA0102_USB")
        }
    }
    fn opt<T: std::fmt::Display>(x: Option<T>) -> String {
        x.map(|v| v.to_string()).unwrap_or_else(|| "NA".into())
    }
    fn report(r: &[Record], live: bool, opened: bool, result: &str) {
        println!("CONTROL_TRANSPORT_IMPLEMENTATION=USBFS_DIRECT\nPHASE349I_RESULT={result}");
        println!("LIVE_USB_ACTIVITY={live}\nUSB_DEVICE_OPEN={opened}");
        println!(
            "DEVICE_RECIPIENT_NO_IMPLICIT_CLAIM_PROVEN={DEVICE_RECIPIENT_NO_IMPLICIT_CLAIM_PROVEN}\nINTERFACE_RECIPIENT_PROBES=0\nENDPOINT_RECIPIENT_PROBES=0\nINTERFACE_RECIPIENT_HEALTH=not_measured\nENDPOINT_RECIPIENT_HEALTH=not_measured"
        );
        for key in [
            "INTERFACE_CLAIM",
            "KERNEL_DRIVER_DETACH",
            "SET_CONFIGURATION_TX",
            "SET_INTERFACE_TX",
            "CLEAR_HALT_TX",
            "USB_DEVICE_RESET",
            "CONTROL_OUT_TX",
            "BULK_OUT_TX",
            "BULK_IN_RX",
            "NAME_PROBE_TX",
            "KD_PACKET_TX",
            "BREAKIN_SENT",
            "GETVERSION_TX",
            "DEBUGGER_SESSION",
            "TARGET_MEMORY_ACCESS",
            "PCI_UNBIND_REBIND",
            "XHCI_RELOAD",
            "RUNTIME_PM_CHANGE",
            "HOST_REBOOT",
            "TARGET_REBOOT",
            "BCD_CHANGE",
            "AUTOMATIC_RETRY",
            "PHASE340_CLEANUP_AUTHORIZED",
        ] {
            println!("{key}=false");
        }
        println!(
            "MAX_USB_TRANSACTIONS=6\nMAX_CONTROL_IN_PROBES=6\nMAX_CONTROL_OUT_PROBES=0\nMAX_BULK_OUT_PROBES=0\nMAX_BULK_IN_PROBES=0\nMAX_NAME_TX=0\nMAX_KD_PACKET_TX=0\nPER_PROBE_TIMEOUT_MS={TIMEOUT_MS}"
        );
        for (n, (p, x)) in PROBES.iter().zip(r).enumerate() {
            let pre = format!("PROBE_P{:02}", n + 1);
            println!(
                "{pre}_NAME={}\n{pre}_ATTEMPTED={}\n{pre}_STATUS={}\n{pre}_BYTES={}\n{pre}_DATA_HEX={}\n{pre}_RUSB_ERROR={}\n{pre}_EXPECTATION_VALID={}\n{pre}_USBFS_IOCTL_RETURN={}\n{pre}_USBFS_RAW_OS_ERROR={}\n{pre}_BEGIN_EPOCH_US={}\n{pre}_END_EPOCH_US={}",
                p.name,
                x.begin.is_some(),
                x.status,
                opt(x.data.as_ref().map(Vec::len)),
                x.data
                    .as_ref()
                    .map(hex::encode)
                    .unwrap_or_else(|| "NA".into()),
                x.error,
                opt(x.valid),
                opt(x.rc),
                opt(x.errno),
                opt(x.begin),
                opt(x.end)
            );
        }
        println!(
            "PROBES_ATTEMPTED={}",
            r.iter().filter(|x| x.begin.is_some()).count()
        );
        for s in [
            "OK",
            "SHORT",
            "TIMEOUT",
            "PIPE",
            "IO",
            "NO_DEVICE",
            "OTHER_ERROR",
            "ACCESS",
            "BUSY",
            "INTERRUPTED",
            "OVERFLOW",
        ] {
            println!("PROBES_{s}={}", r.iter().filter(|x| x.status == s).count());
        }
        println!(
            "DEVICE_DISAPPEARED={}",
            r.iter().any(|x| x.status == "NO_DEVICE")
        );
        let device = r[2].data.as_ref().filter(|d| d.len() == 18);
        println!(
            "DEVICE_DESCRIPTOR_VID={}\nDEVICE_DESCRIPTOR_PID={}\nDEVICE_DESCRIPTOR_IDENTITY_VALID={}",
            device
                .map(|d| format!("0x{:04x}", u16::from_le_bytes([d[8], d[9]])))
                .unwrap_or_else(|| "NA".into()),
            device
                .map(|d| format!("0x{:04x}", u16::from_le_bytes([d[10], d[11]])))
                .unwrap_or_else(|| "NA".into()),
            opt(device.map(|d| expectation(2, d)))
        );
        println!(
            "CONFIG_DESCRIPTOR_VALUE={}",
            opt(r[3].data.as_ref().filter(|d| d.len() == 9).map(|d| d[5]))
        );
        println!(
            "PRE_POST_GET_CONFIGURATION_MATCH={}\nPRE_POST_GET_STATUS_DEVICE_MATCH={}",
            opt(matched(r, 0, 5)),
            opt(matched(r, 1, 4))
        );
    }
    pub fn run() -> i32 {
        let mut r = vec![Record::default(); PROBES.len()];
        let args: Vec<_> = std::env::args().skip(1).collect();
        let live = match mode(&args) {
            Ok(v) => v,
            Err(e) => {
                eprintln!("{e}");
                report(&r, false, false, "OTHER_TRANSPORT_FAULT");
                return 2;
            }
        };
        if !live {
            println!("DEFAULT_MODE=DRY_PLAN");
            report(&r, false, false, "DRY_PLAN");
            return 0;
        }
        if !matrix_admissible(&PROBES) {
            eprintln!("LIVE_BLOCKED: compiled matrix violates device-recipient no-claim invariant");
            report(&r, false, false, "OTHER_TRANSPORT_FAULT");
            return 3;
        }
        let mut trace = match marker(std::env::var_os("NTOSEYE_TRACE_MARKER")) {
            Ok(f) => f,
            Err(e) => {
                eprintln!("trace marker unavailable: {e}");
                report(&r, false, false, "OTHER_TRANSPORT_FAULT");
                return 2;
            }
        };
        let root = Path::new("/sys/bus/usb/devices");
        if let Err(e) = admission(root) {
            eprintln!("pre-open admission: {e}");
            report(&r, false, false, "IDENTITY_MISMATCH_ABORT");
            return 3;
        }
        let file = match OpenOptions::new()
            .read(true)
            .write(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open("/dev/bus/usb/006/008")
        {
            Ok(f) => f,
            Err(e) => {
                eprintln!("USB node open: {e}");
                report(&r, false, false, "OTHER_TRANSPORT_FAULT");
                return 3;
            }
        };
        // Recheck cached identity/driver after open; fstat binds the admitted node, no extra ioctl.
        let node_ok = file
            .metadata()
            .map(|m| {
                m.mode() & libc::S_IFMT == libc::S_IFCHR
                    && libc::major(m.rdev()) == 189
                    && libc::minor(m.rdev()) == 647
            })
            .unwrap_or(false);
        if !node_ok || admission(root).is_err() {
            report(&r, false, true, "IDENTITY_MISMATCH_ABORT");
            return 3;
        }
        let fault;
        (r, fault) = execute(|p, d| read_control(&file, p, d), |s| writeln!(trace, "{s}"));
        let result = if fault {
            "OTHER_TRANSPORT_FAULT"
        } else {
            classify(&r)
        };
        report(&r, r.iter().any(|x| x.begin.is_some()), true, result);
        if result == "EP0_DEVICE_RECIPIENT_ALL_OK" {
            0
        } else {
            5
        }
    }
    #[cfg(test)]
    mod tests {
        use super::*;
        #[test]
        fn exact_matrix() {
            assert_eq!(
                PROBES.map(|p| p.setup),
                [
                    (128, 8, 0, 0, 1),
                    (128, 0, 0, 0, 2),
                    (128, 6, 256, 0, 18),
                    (128, 6, 512, 0, 9),
                    (128, 0, 0, 0, 2),
                    (128, 8, 0, 0, 1)
                ]
            );
            assert_eq!(
                PROBES.map(|p| p.name),
                [
                    "GET_CONFIGURATION_PRE",
                    "GET_STATUS_DEVICE_PRE",
                    "GET_DESCRIPTOR_DEVICE",
                    "GET_DESCRIPTOR_CONFIGURATION_HEADER",
                    "GET_STATUS_DEVICE_POST",
                    "GET_CONFIGURATION_POST"
                ]
            );
            assert!(PROBES.iter().all(|p| p.setup.0 == 0x80));
            assert_eq!(PROBES.len(), 6);
        }
        #[test]
        fn independent_faults_and_no_retry() {
            for error in [libc::ETIMEDOUT, libc::EPIPE, libc::EIO, libc::EINTR] {
                let mut calls = 0;
                let mut marks = Vec::new();
                let (r, f) = execute(
                    |_, _| {
                        calls += 1;
                        Err(io::Error::from_raw_os_error(error))
                    },
                    |s| {
                        marks.push(s);
                        Ok(())
                    },
                );
                assert_eq!(calls, 6);
                assert!(!f);
                assert_eq!(marks.len(), 12);
                assert!(r.iter().all(|x| x.begin.is_some()));
                assert_eq!(marks[0], "I_P01_GET_CONFIGURATION_PRE_BEGIN");
                assert_eq!(marks[11], "I_P06_GET_CONFIGURATION_POST_END");
            }
        }
        #[test]
        fn disappearance_stops() {
            let mut calls = 0;
            let (r, _) = execute(
                |_, _| {
                    calls += 1;
                    Err(io::Error::from_raw_os_error(libc::ENODEV))
                },
                |_| Ok(()),
            );
            assert_eq!(calls, 1);
            assert!(r[1..].iter().all(|x| x.status == "NOT_ATTEMPTED"));
            assert_eq!(classify(&r), "DEVICE_DISAPPEARED");
        }
        #[test]
        fn marker_failure_stops_before_io() {
            let (r, f) = execute(|_, _| panic!("no I/O"), |_| Err(io::Error::other("marker")));
            assert!(f);
            assert!(r.iter().all(|x| x.begin.is_none()));
            assert!(marker(None).is_err());
            assert!(marker(Some("/nonexistent/phase349i/marker".into())).is_err());
        }
        #[test]
        fn descriptors_and_semantics() {
            let mut d = vec![0; 18];
            d[0] = 18;
            d[1] = 1;
            d[8..12].copy_from_slice(&[0x95, 0x34, 0xe0, 0]);
            assert!(expectation(2, &d));
            d[8] = 0;
            assert!(!expectation(2, &d));
            d[8] = 0x95;
            d[10] = 1;
            assert!(!expectation(2, &d));
            let mut c = [9, 2, 32, 0, 1, 1, 0, 0x80, 0];
            assert!(expectation(3, &c));
            c[5] = 2;
            assert!(!expectation(3, &c));
            assert!(expectation(4, &[0, 0]));
            assert!(expectation(5, &[1]));
            assert!(!expectation(5, &[0]));
        }
        #[test]
        fn consistency_and_classes() {
            let (mut r, _) = execute(
                |p, d| {
                    d.fill(0);
                    if p.setup.1 == 8 {
                        d[0] = 1;
                    }
                    Ok(d.len())
                },
                |_| Ok(()),
            );
            assert_eq!(matched(&r, 0, 5), Some(true));
            assert_eq!(matched(&r, 1, 4), Some(true));
            assert_eq!(
                classify(&r),
                "EP0_DEVICE_RECIPIENT_ALL_OK_EXPECTATION_MISMATCH"
            );
            r[5].data = Some(vec![2]);
            assert_eq!(matched(&r, 0, 5), Some(false));
            r[5].status = "SHORT";
            assert_eq!(matched(&r, 0, 5), None);
            assert_eq!(classify(&r), "EP0_DEVICE_RECIPIENT_PARTIAL_FAULTS");
            for (status, result) in [
                ("IO", "EP0_DEVICE_RECIPIENT_NONOPERATIONAL"),
                ("PIPE", "EP0_DEVICE_RECIPIENT_NONOPERATIONAL"),
                ("TIMEOUT", "EP0_DEVICE_RECIPIENT_NONOPERATIONAL"),
            ] {
                for x in &mut r {
                    x.status = status;
                }
                assert_eq!(classify(&r), result);
            }
            r[0].status = "PIPE";
            assert_eq!(classify(&r), "EP0_MIXED_ERROR_SIGNATURE");
            for x in &mut r {
                x.status = "OK";
                x.valid = Some(true);
            }
            r[5].data = r[0].data.clone();
            assert_eq!(classify(&r), "EP0_DEVICE_RECIPIENT_ALL_OK");
            r[4].data = Some(vec![1, 0]);
            assert_eq!(
                classify(&r),
                "EP0_DEVICE_RECIPIENT_ALL_OK_EXPECTATION_MISMATCH"
            );
        }
        #[test]
        fn dry_mode_zero_io_and_exact_authorization() {
            assert_eq!(mode(&[]), Ok(false));
            assert_eq!(mode(&[AUTH.into(), "CLSA0102_USB".into()]), Ok(true));
            assert!(mode(&[AUTH.into()]).is_err());
            assert!(mode(&[AUTH.into(), "OTHER".into()]).is_err());
        }
        #[test]
        fn cached_topology_and_writable_marker() {
            let mut d = vec![
                18, 1, 0, 3, 0, 0, 0, 9, 0x95, 0x34, 0xe0, 0, 0, 0, 0, 0, 0, 1,
            ];
            d.extend_from_slice(&[
                9, 2, 32, 0, 1, 1, 0, 0x80, 0, 9, 4, 0, 0, 2, 0xdc, 2, 0xff, 0, 7, 5, 1, 2, 0, 4,
                0, 7, 5, 0x81, 2, 0, 4, 0,
            ]);
            assert!(cached_descriptors(&d).is_ok());
            d[18 + 9 + 2] = 1;
            assert!(cached_descriptors(&d).is_err());
            assert!(cached_descriptors(&d[..20]).is_err());
            let path =
                std::env::temp_dir().join(format!("phase349i-marker-test-{}", std::process::id()));
            File::create(&path).unwrap();
            let mut file = marker(Some(path.clone().into_os_string())).unwrap();
            writeln!(file, "test marker").unwrap();
            assert_eq!(fs::read_to_string(&path).unwrap(), "test marker\n");
            fs::remove_file(&path).unwrap();
            assert!(marker(Some("/proc/version".into())).is_err());
        }
        #[test]
        fn device_recipient_invariant_blocks_unsafe_matrix() {
            assert!(matrix_admissible(&PROBES));
            assert!(!matrix_admissible(&PROBES[..5]));
            for request_type in [0x00, 0x81, 0x82, 0xc0] {
                let mut bad = PROBES;
                bad[0].setup.0 = request_type;
                assert!(!matrix_admissible(&bad));
            }
            let mut bad = PROBES;
            bad[0].setup.1 = 9;
            assert!(!matrix_admissible(&bad));
            let source = include_str!("ntoseye-kdusb-ep0-control-plane-characterization-r1.rs");
            let run = source
                .split("pub fn run()")
                .nth(1)
                .unwrap()
                .split("#[cfg(test)]")
                .next()
                .unwrap();
            assert!(
                run.find("if !matrix_admissible(&PROBES)").unwrap()
                    < run.find("admission(root)").unwrap()
            );
        }
        #[test]
        fn ioctl_abi() {
            assert_eq!(
                std::mem::offset_of!(Control, data),
                if cfg!(target_pointer_width = "64") {
                    16
                } else {
                    12
                }
            );
            assert_eq!(
                CONTROL_IOCTL,
                if cfg!(target_pointer_width = "64") {
                    0xc0185500
                } else {
                    0xc0105500
                }
            );
            assert_eq!(TIMEOUT_MS, 750);
        }
        #[test]
        fn static_safety() {
            let source = include_str!("ntoseye-kdusb-ep0-control-plane-characterization-r1.rs");
            let production = source.split("#[cfg(test)]").next().unwrap();
            for token in [
                concat!("write_", "control("),
                concat!("write_", "bulk("),
                concat!("read_", "bulk("),
                concat!("set_active_", "configuration("),
                concat!("set_alternate_", "setting("),
                concat!("clear_", "halt("),
                concat!("detach_", "kernel_driver("),
                concat!("claim_", "interface("),
                concat!("libusb_", "reset_device("),
                ".reset(",
                "Backend::",
                concat!("NAME", "?"),
                "USBDEVFS_RESET",
            ] {
                assert!(!production.contains(token), "{token}");
            }
            assert_eq!(production.matches("libc::ioctl(").count(), 1);
            assert!(!production.contains("rusb::devices"));
        }
    }
}
