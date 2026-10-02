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
    const AUTH: &str = "--execute-post-reboot-get-configuration";
    #[derive(Clone, Copy, Debug, PartialEq)]
    struct Probe {
        name: &'static str,
        setup: (u8, u8, u16, u16, u16),
    }
    const PROBES: [Probe; 1] = [Probe {
        name: "GET_CONFIGURATION_POST_REBOOT",
        setup: (0x80, 8, 0, 0, 1),
    }];
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

    #[derive(Default, Debug)]
    struct Record {
        attempted: bool,
        status: Option<&'static str>,
        data: Option<Vec<u8>>,
        errno: Option<i32>,
        rc: Option<i32>,
        begin: Option<u128>,
        end: Option<u128>,
        marker_fault: bool,
    }
    fn epoch() -> u128 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock")
            .as_micros()
    }
    fn errno_class(e: i32) -> &'static str {
        match e {
            libc::ETIMEDOUT => "TIMEOUT",
            libc::EPIPE => "PIPE",
            libc::EIO | libc::EPROTO | libc::EILSEQ => "IO",
            libc::ENODEV | libc::ESHUTDOWN | libc::ENOENT => "NO_DEVICE",
            libc::EACCES | libc::EPERM => "ACCESS",
            libc::EBUSY => "BUSY",
            libc::EINTR => "INTERRUPTED",
            libc::EOVERFLOW => "OVERFLOW",
            _ => "OTHER_ERROR",
        }
    }
    fn errno_name(e: Option<i32>) -> &'static str {
        match e {
            None => "NA",
            Some(libc::EPROTO) => "EPROTO",
            Some(libc::ETIMEDOUT) => "ETIMEDOUT",
            Some(libc::EPIPE) => "EPIPE",
            Some(libc::EIO) => "EIO",
            Some(libc::EILSEQ) => "EILSEQ",
            Some(libc::ENODEV) => "ENODEV",
            Some(libc::ESHUTDOWN) => "ESHUTDOWN",
            Some(libc::ENOENT) => "ENOENT",
            Some(libc::EACCES) => "EACCES",
            Some(libc::EPERM) => "EPERM",
            Some(libc::EBUSY) => "EBUSY",
            Some(libc::EINTR) => "EINTR",
            Some(libc::EOVERFLOW) => "EOVERFLOW",
            _ => "UNKNOWN",
        }
    }
    fn execute<F, M>(mut call: F, mut mark: M) -> Record
    where
        F: FnMut(Probe, &mut [u8]) -> io::Result<usize>,
        M: FnMut(&str) -> io::Result<()>,
    {
        let mut r = Record::default();
        if mark("K_K01_GET_CONFIGURATION_POST_REBOOT_BEGIN").is_err() {
            r.marker_fault = true;
            return r;
        }
        let mut data = [0u8; 1];
        r.attempted = true;
        r.begin = Some(epoch());
        let result = call(PROBES[0], &mut data);
        r.end = Some(epoch());
        match result {
            Ok(n) => {
                r.rc = Some(n as i32);
                r.status = Some(if n == 1 {
                    "OK"
                } else if n == 0 {
                    "SHORT"
                } else {
                    "OVERFLOW"
                });
                if n <= 1 {
                    r.data = Some(data[..n].to_vec());
                }
            }
            Err(e) => {
                r.errno = e.raw_os_error();
                r.rc = Some(-1);
                r.status = Some(errno_class(r.errno.unwrap_or(0)));
            }
        }
        r.marker_fault = mark("K_K01_GET_CONFIGURATION_POST_REBOOT_END").is_err();
        r
    }
    fn recovered(r: &Record) -> bool {
        !r.marker_fault && r.status == Some("OK") && r.data.as_deref() == Some(&[1])
    }
    fn mode(args: &[String]) -> Result<bool, &'static str> {
        if args.is_empty() {
            Ok(false)
        } else if args == [AUTH, "CLSA0102_USB"] {
            Ok(true)
        } else {
            Err("only live form: --execute-post-reboot-get-configuration CLSA0102_USB")
        }
    }
    fn opt<T: std::fmt::Display>(v: Option<T>) -> String {
        v.map(|x| x.to_string()).unwrap_or("NA".into())
    }
    fn report(r: &Record, opened: bool) {
        println!("CONTROL_TRANSPORT_IMPLEMENTATION=USBFS_DIRECT");
        println!("PROBE_K01_NAME=GET_CONFIGURATION_POST_REBOOT");
        println!("PROBE_K01_SETUP=80 08 0000 0000 1");
        println!(
            "PROBE_K01_ATTEMPTED={}\nPROBE_K01_STATUS={}",
            r.attempted,
            r.status.unwrap_or("NOT_ATTEMPTED")
        );
        println!(
            "PROBE_K01_BYTES={}\nPROBE_K01_DATA_HEX={}",
            opt(r.data.as_ref().map(Vec::len)),
            r.data.as_ref().map(hex::encode).unwrap_or("NA".into())
        );
        println!(
            "PROBE_K01_RAW_ERRNO_NUMBER={}\nPROBE_K01_RAW_ERRNO_NAME={}",
            opt(r.errno),
            errno_name(r.errno)
        );
        println!(
            "PROBE_K01_EXPECTATION_VALID={}",
            opt(r.data.as_ref().map(|d| d == &[1]))
        );
        println!(
            "PROBE_K01_USBFS_IOCTL_RETURN={}\nPROBE_K01_BEGIN_EPOCH_US={}\nPROBE_K01_END_EPOCH_US={}",
            opt(r.rc),
            opt(r.begin),
            opt(r.end)
        );
        println!(
            "POST_REBOOT_EP0_RECOVERED={}\nLIVE_USB_ACTIVITY={}\nUSB_DEVICE_OPEN={}\nTRACE_MARKER_FAULT={}",
            recovered(r),
            r.attempted,
            opened,
            r.marker_fault
        );
        println!(
            "MAX_USB_TRANSACTIONS=1\nMAX_CONTROL_IN_PROBES=1\nMAX_CONTROL_OUT_PROBES=0\nMAX_BULK_OUT_PROBES=0\nMAX_BULK_IN_PROBES=0\nMAX_NAME_TX=0\nMAX_KD_PACKET_TX=0\nPER_PROBE_TIMEOUT_MS=750"
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
            "AUTOMATIC_RETRY",
            "PHASE340_CLEANUP_AUTHORIZED",
        ] {
            println!("{key}=false");
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
        require(d.len() >= 18 && d[..2] == [18, 1] && d[8..12] == [0x95, 0x34, 0xe0, 0])?;
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
    fn admission(root: &Path) -> io::Result<u8> {
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
        for (key, value) in [("busnum", "6"), ("bConfigurationValue", "1")] {
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
        let mut eps: Vec<_> = fs::read_dir(&interface)?
            .filter_map(Result::ok)
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .filter(|n| n.starts_with("ep_"))
            .collect();
        eps.sort();
        require(eps == ["ep_01", "ep_81"])?;
        cached_descriptors(&fs::read(p.join("descriptors"))?)?;
        let address = text(p, "devnum")?.parse::<u8>().map_err(io::Error::other)?;
        require((1..=127).contains(&address))?;
        Ok(address)
    }

    fn marker(path: Option<std::ffi::OsString>) -> io::Result<File> {
        OpenOptions::new()
            .write(true)
            .open(path.ok_or_else(|| io::Error::other("NTOSEYE_TRACE_MARKER required"))?)
    }
    fn dispatch<F>(args: &[String], live: F) -> i32
    where
        F: FnOnce() -> i32,
    {
        let empty = Record::default();
        match mode(args) {
            Ok(false) => {
                println!("DEFAULT_MODE=DRY_PLAN");
                report(&empty, false);
                0
            }
            Err(e) => {
                eprintln!("{e}");
                report(&empty, false);
                2
            }
            Ok(true) => live(),
        }
    }
    pub fn run() -> i32 {
        dispatch(&std::env::args().skip(1).collect::<Vec<_>>(), run_live)
    }
    fn run_live() -> i32 {
        let empty = Record::default();
        let mut opened = false;
        let result = (|| -> io::Result<(Record, bool)> {
            let mut trace = marker(std::env::var_os("NTOSEYE_TRACE_MARKER"))?;
            let root = Path::new("/sys/bus/usb/devices");
            let address = admission(root)?;
            let node = format!("/dev/bus/usb/006/{address:03}");
            let file = OpenOptions::new()
                .read(true)
                .write(true)
                .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
                .open(&node)?;
            opened = true;
            // Bind the open fd to the discovered address and recheck cached identity; no extra ioctl.
            let m = file.metadata()?;
            require(
                m.mode() & libc::S_IFMT == libc::S_IFCHR
                    && libc::major(m.rdev()) == 189
                    && libc::minor(m.rdev()) == 5 * 128 + u32::from(address) - 1,
            )?;
            require(admission(root)? == address)?;
            println!(
                "POST_REBOOT_PHYSICAL_PATH=6-1\nPOST_REBOOT_BUS=6\nPOST_REBOOT_ADDRESS={address}"
            );
            Ok((
                execute(|p, d| read_control(&file, p, d), |s| writeln!(trace, "{s}")),
                true,
            ))
        })();
        match result {
            Ok((r, opened)) => {
                report(&r, opened);
                if recovered(&r) { 0 } else { 5 }
            }
            Err(e) => {
                eprintln!("LIVE_BLOCKED: {e}");
                report(&empty, opened);
                3
            }
        }
    }
    #[cfg(test)]
    mod tests {
        use super::*;
        #[test]
        fn exact_one_probe_matrix_and_setup() {
            assert_eq!(PROBES.len(), 1);
            assert_eq!(PROBES[0].setup, (0x80, 8, 0, 0, 1));
            assert_eq!(PROBES[0].name, "GET_CONFIGURATION_POST_REBOOT");
            assert_eq!(TIMEOUT_MS, 750);
        }
        #[test]
        fn one_call_maximum_and_no_retry() {
            for error in [libc::EPROTO, libc::ETIMEDOUT, libc::EINTR, libc::ENODEV] {
                let mut calls = 0;
                let mut marks = Vec::new();
                let r = execute(
                    |_, _| {
                        calls += 1;
                        Err(io::Error::from_raw_os_error(error))
                    },
                    |s| {
                        marks.push(s.to_string());
                        Ok(())
                    },
                );
                assert_eq!(calls, 1);
                assert_eq!(r.errno, Some(error));
                assert_eq!(marks.len(), 2);
                assert_eq!(r.status, Some(errno_class(error)));
                assert!(!recovered(&r));
            }
            assert_eq!(errno_class(71), "IO");
            assert_eq!(errno_name(Some(71)), "EPROTO");
            assert_eq!(errno_class(110), "TIMEOUT");
            assert_eq!(errno_name(Some(110)), "ETIMEDOUT");
        }
        #[test]
        fn exact_success_mismatch_and_short_data() {
            for (size, byte, status, good) in [
                (1, 1, "OK", true),
                (1, 0, "OK", false),
                (0, 1, "SHORT", false),
                (2, 1, "OVERFLOW", false),
            ] {
                let r = execute(
                    |_, d| {
                        d[0] = byte;
                        Ok(size)
                    },
                    |_| Ok(()),
                );
                assert_eq!(r.status, Some(status));
                assert_eq!(recovered(&r), good);
            }
        }
        #[test]
        fn marker_required_before_call() {
            assert!(marker(None).is_err());
            let r = execute(|_, _| panic!("no I/O"), |_| Err(io::Error::other("marker")));
            assert!(!r.attempted);
            assert!(r.marker_fault);
        }
        #[test]
        fn dry_mode_and_exact_authorization() {
            assert_eq!(mode(&[]), Ok(false));
            assert_eq!(
                dispatch(&[], || panic!("dry must not enter USB I/O path")),
                0
            );
            assert_eq!(mode(&[AUTH.into(), "CLSA0102_USB".into()]), Ok(true));
            assert!(mode(&[AUTH.into()]).is_err());
            assert!(mode(&[AUTH.into(), "6-2".into()]).is_err());
        }
        #[test]
        fn dynamic_address_and_exact_cached_topology() {
            let root = std::env::temp_dir().join(format!("phase349k-sysfs-{}", std::process::id()));
            fs::create_dir_all(root.join("6-1")).unwrap();
            let p = root.join("6-1");
            let i = root.join("6-1:1.0");
            fs::create_dir_all(&i).unwrap();
            for (k, v) in [
                ("idVendor", "3495"),
                ("idProduct", "00e0"),
                ("busnum", "6"),
                ("devnum", "19"),
                ("bConfigurationValue", "1"),
            ] {
                fs::write(p.join(k), v).unwrap();
            }
            for (k, v) in [
                ("bInterfaceNumber", "00"),
                ("bAlternateSetting", "0"),
                ("bInterfaceClass", "dc"),
                ("bInterfaceSubClass", "02"),
                ("bInterfaceProtocol", "ff"),
            ] {
                fs::write(i.join(k), v).unwrap();
            }
            for (ep, addr) in [("ep_01", "01"), ("ep_81", "81")] {
                let e = i.join(ep);
                fs::create_dir_all(&e).unwrap();
                for (k, v) in [
                    ("bEndpointAddress", addr),
                    ("bmAttributes", "02"),
                    ("wMaxPacketSize", "0400"),
                ] {
                    fs::write(e.join(k), v).unwrap();
                }
            }
            let d = [
                18, 1, 0, 3, 0, 0, 0, 9, 0x95, 0x34, 0xe0, 0, 0, 0, 0, 0, 0, 1, 9, 2, 32, 0, 1, 1,
                0, 0x80, 0, 9, 4, 0, 0, 2, 0xdc, 2, 0xff, 0, 7, 5, 1, 2, 0, 4, 0, 7, 5, 0x81, 2, 0,
                4, 0,
            ];
            fs::write(p.join("descriptors"), d).unwrap();
            assert_eq!(admission(&root).unwrap(), 19);
            fs::write(p.join("devnum"), "9").unwrap();
            assert_eq!(admission(&root).unwrap(), 9);
            fs::create_dir(i.join("ep_82")).unwrap();
            assert!(admission(&root).is_err());
            fs::remove_dir(i.join("ep_82")).unwrap();
            fs::create_dir(i.join("driver")).unwrap();
            assert!(admission(&root).is_err());
            fs::remove_dir(i.join("driver")).unwrap();
            fs::write(i.join("bInterfaceProtocol"), "00").unwrap();
            assert!(admission(&root).is_err());
            fs::remove_dir_all(root).unwrap();
        }
        #[test]
        fn static_transport_path_rejection() {
            let source = include_str!("ntoseye-kdusb-post-reboot-get-configuration-r1.rs")
                .split("#[cfg(test)]")
                .next()
                .unwrap();
            assert_eq!(source.matches("libc::ioctl(").count(), 1);
            assert_eq!(source.matches("read_control(&file").count(), 1);
            for forbidden in [
                concat!("claim_interface", "("),
                concat!("detach_kernel_driver", "("),
                concat!("clear_halt", "("),
                concat!("write_bulk", "("),
                concat!("read_bulk", "("),
                concat!("set_active_configuration", "("),
                concat!("set_alternate_setting", "("),
                "USBDEVFS_RESET",
                "NAME?",
                "rusb::",
            ] {
                assert!(!source.contains(forbidden));
            }
        }
        #[test]
        fn ioctl_abi() {
            assert_eq!(
                CONTROL_IOCTL,
                if cfg!(target_pointer_width = "64") {
                    0xc0185500
                } else {
                    0xc0105500
                }
            );
        }
    }
}
