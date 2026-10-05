//! One-shot recovered-epoch classic KDUSB NAME admission, direct Linux usbfs.
#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("Linux only");
    std::process::exit(2);
}
#[cfg(target_os = "linux")]
fn main() {
    std::process::exit(linux::run());
}
#[cfg(target_os = "linux")]
mod linux {
    use sha2::{Digest, Sha256};
    use std::fs::{self, File, OpenOptions};
    use std::io::{self, Write};
    use std::os::fd::AsRawFd;
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
    use std::path::Path;
    use std::time::{SystemTime, UNIX_EPOCH};
    const AUTH: &str = "--execute-recovered-name-after-ep0";
    const OUT: &[u8] = b"NAME?";
    const EXPECTED: &[u8] = b"NAME=CLSA0102_USB\0\0";
    const CAPACITY: usize = 4017;
    #[repr(C)]
    struct Bulk {
        endpoint: u32,
        length: u32,
        timeout: u32,
        data: *mut libc::c_void,
    }
    const BULK_IOCTL: libc::c_ulong = (3 << 30)
        | ((std::mem::size_of::<Bulk>() as libc::c_ulong) << 16)
        | ((b'U' as libc::c_ulong) << 8)
        | 2;
    const CLAIM_IOCTL: libc::c_ulong = 0x8004550f;
    const RELEASE_IOCTL: libc::c_ulong = 0x80045510;
    #[derive(Debug, Clone, Copy, PartialEq)]
    enum Action {
        Claim,
        Out,
        In,
        Release,
    }
    fn usbfs(file: &File, action: Action, data: &mut [u8]) -> io::Result<usize> {
        let mut interface: u32 = 0;
        let mut bulk = Bulk {
            endpoint: if action == Action::Out { 1 } else { 129 },
            length: data.len() as u32,
            timeout: if action == Action::Out { 1000 } else { 1500 },
            data: data.as_mut_ptr().cast(),
        };
        let (request, pointer) = match action {
            Action::Claim => (
                CLAIM_IOCTL,
                (&mut interface as *mut u32).cast::<libc::c_void>(),
            ),
            Action::Release => (RELEASE_IOCTL, (&mut interface as *mut u32).cast()),
            Action::Out | Action::In => (BULK_IOCTL, (&mut bulk as *mut Bulk).cast()),
        };
        // SAFETY: native Linux C layout; pointers and buffers remain alive for the synchronous call.
        let rc = unsafe { libc::ioctl(file.as_raw_fd(), request, pointer) };
        if rc < 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(rc as usize)
        }
    }
    #[derive(Default, Debug)]
    struct Transfer {
        attempted: bool,
        status: Option<&'static str>,
        bytes: Option<usize>,
        errno: Option<i32>,
        rc: Option<i32>,
        begin: Option<u128>,
        end: Option<u128>,
        digest: Option<String>,
        exact: Option<bool>,
        prefix: Option<bool>,
    }
    #[derive(Default, Debug)]
    struct Session {
        out: Transfer,
        input: Transfer,
        claimed: bool,
        released: bool,
        marker_fault: bool,
        host_fault: bool,
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
    fn completion(r: &mut Transfer, result: io::Result<usize>, data: &[u8], input: bool) {
        match result {
            Ok(n) => {
                r.rc = Some(n as i32);
                r.bytes = Some(n);
                r.status = Some(if n > data.len() {
                    "OVERFLOW"
                } else if n < if input { 19 } else { 5 } {
                    "SHORT"
                } else {
                    "OK"
                });
                if input && n <= data.len() {
                    let first = &data[..n];
                    r.digest = Some(hex::encode(Sha256::digest(first)));
                    r.exact = Some(first == EXPECTED);
                    r.prefix = Some(first.starts_with(b"NAME="));
                }
            }
            Err(e) => {
                r.rc = Some(-1);
                r.errno = e.raw_os_error();
                r.status = Some(errno_class(r.errno.unwrap_or(0)));
            }
        }
    }
    fn execute<F, M>(mut call: F, mut mark: M) -> Session
    where
        F: FnMut(Action, &mut [u8]) -> io::Result<usize>,
        M: FnMut(&str) -> io::Result<()>,
    {
        let mut s = Session::default();
        if !matches!(call(Action::Claim, &mut []), Ok(0)) {
            s.host_fault = true;
            return s;
        }
        s.claimed = true;
        exchange(&mut s, &mut call, &mut mark);
        s.released = matches!(call(Action::Release, &mut []), Ok(0));
        s.host_fault = !s.released;
        s
    }
    fn exchange<F, M>(s: &mut Session, call: &mut F, mark: &mut M)
    where
        F: FnMut(Action, &mut [u8]) -> io::Result<usize>,
        M: FnMut(&str) -> io::Result<()>,
    {
        if mark("X_NAME_OUT_BEGIN").is_err() {
            s.marker_fault = true;
            return;
        }
        let mut out: [u8; 5] = OUT.try_into().expect("five byte request");
        s.out.attempted = true;
        s.out.begin = Some(epoch());
        let result = call(Action::Out, &mut out);
        s.out.end = Some(epoch());
        completion(&mut s.out, result, &out, false);
        if mark("X_NAME_OUT_END").is_err() {
            s.marker_fault = true;
            return;
        }
        if s.out.status != Some("OK") || s.out.bytes != Some(5) {
            return;
        }
        if mark("X_NAME_IN_BEGIN").is_err() {
            s.marker_fault = true;
            return;
        }
        let mut input = [0u8; CAPACITY];
        s.input.attempted = true;
        s.input.begin = Some(epoch());
        let result = call(Action::In, &mut input);
        s.input.end = Some(epoch());
        completion(&mut s.input, result, &input, true);
        s.marker_fault = mark("X_NAME_IN_END").is_err();
    }
    fn result(s: &Session) -> String {
        if s.marker_fault || s.host_fault {
            return "OTHER_TRANSPORT_FAULT".into();
        }
        for (name, r) in [("OUT", &s.out), ("IN", &s.input)] {
            if r.status != Some("OK") {
                let fault = match r.errno {
                    Some(libc::EPROTO) => "EPROTO",
                    Some(libc::ETIMEDOUT) => "TIMEOUT",
                    Some(libc::EPIPE) => "PIPE",
                    _ if r.status == Some("SHORT") => "SHORT",
                    _ => "OTHER_FAULT",
                };
                return format!("NAME_{name}_{fault}");
            }
        }
        if s.input.exact == Some(true) && s.claimed && s.released {
            "KDUSB_NAME_ADMISSION_OK".into()
        } else if s.input.prefix == Some(false) {
            "NAME_REPLY_NOT_FIRST_COMPLETION".into()
        } else {
            "NAME_REPLY_MISMATCH".into()
        }
    }
    fn opt<T: std::fmt::Display>(v: Option<T>) -> String {
        v.map(|x| x.to_string()).unwrap_or("NA".into())
    }
    fn report(s: &Session, opened: bool) {
        println!(
            "BULK_TRANSPORT_IMPLEMENTATION=USBFS_DIRECT\nPHASE349X_OBSERVER_RESULT={}",
            result(s)
        );
        println!(
            "USB_INTERFACE_CLAIMED={}\nUSB_INTERFACE_RELEASED={}\nUSB_DEVICE_OPEN={}\nLIVE_USB_ACTIVITY={}\nTRACE_MARKER_FAULT={}",
            s.claimed,
            s.released,
            opened,
            s.out.attempted || s.input.attempted,
            s.marker_fault
        );
        for (name, r) in [("OUT", &s.out), ("IN", &s.input)] {
            println!(
                "NAME_{name}_ATTEMPTED={}\nNAME_{name}_STATUS={}\nNAME_{name}_BYTES={}\nNAME_{name}_RAW_ERRNO_NUMBER={}\nNAME_{name}_RAW_ERRNO_NAME={}\nNAME_{name}_USBFS_IOCTL_RETURN={}\nNAME_{name}_BEGIN_EPOCH_US={}\nNAME_{name}_END_EPOCH_US={}",
                r.attempted,
                r.status.unwrap_or("NOT_ATTEMPTED"),
                opt(r.bytes),
                opt(r.errno),
                errno_name(r.errno),
                opt(r.rc),
                opt(r.begin),
                opt(r.end)
            );
        }
        println!(
            "NAME_IN_SHA256={}\nNAME_IN_EXACT_HEX={}\nNAME_IN_BEGINS_NAME_PREFIX={}\nTARGET_NAME_MATCHED={}\nKDUSB_NAME_ADMISSION={}",
            s.input.digest.as_deref().unwrap_or("NA"),
            if s.input.exact == Some(true) {
                hex::encode(EXPECTED)
            } else {
                "NA".into()
            },
            opt(s.input.prefix),
            opt(s.input.exact),
            result(s) == "KDUSB_NAME_ADMISSION_OK"
        );
        println!(
            "MAX_USB_TRANSACTIONS=2\nMAX_BULK_OUT_PROBES=1\nMAX_BULK_IN_PROBES=1\nMAX_CONTROL_IN_PROBES=0\nMAX_CONTROL_OUT_PROBES=0\nMAX_NAME_OUT_TX=1\nMAX_NAME_IN_RX=1\nMAX_KD_PACKET_TX=0\nMAX_KD_PACKET_RX=0\nAUTOMATIC_RETRY=false\nPHASE340_CLEANUP_AUTHORIZED=false"
        );
    }
    fn mode(args: &[String]) -> Result<bool, &'static str> {
        if args.is_empty() {
            Ok(false)
        } else if args == [AUTH, "CLSA0102_USB"] {
            Ok(true)
        } else {
            Err("exact live authorization required")
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
        match fs::symlink_metadata(interface.join("driver")) {
            Err(e) if e.kind() == io::ErrorKind::NotFound => {}
            _ => return Err(io::Error::other("interface driver present or unverifiable")),
        }
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
        let raw = fs::read(p.join("descriptors"))?;
        cached_descriptors(&raw)?;
        require(
            hex::encode(&raw)
                == "12010003000000099534e00000000102030109022c00010100c0000904000002dc02ff000705010200040006300f0000000705810200040006300f000000",
        )?;
        let address = text(p, "devnum")?.parse::<u8>().map_err(io::Error::other)?;
        require(address == 2)?;
        Ok(address)
    }

    fn marker(path: Option<std::ffi::OsString>) -> io::Result<File> {
        OpenOptions::new()
            .write(true)
            .open(path.ok_or_else(|| io::Error::other("NTOSEYE_TRACE_MARKER required"))?)
    }
    fn node(address: u8) -> String {
        format!("/dev/bus/usb/006/{address:03}")
    }
    fn dispatch<F: FnOnce() -> i32>(args: &[String], live: F) -> i32 {
        match mode(args) {
            Ok(false) => {
                println!("DEFAULT_MODE=DRY_PLAN");
                report(&Session::default(), false);
                0
            }
            Err(e) => {
                eprintln!("{e}");
                report(&Session::default(), false);
                2
            }
            Ok(true) => live(),
        }
    }
    pub fn run() -> i32 {
        dispatch(&std::env::args().skip(1).collect::<Vec<_>>(), run_live)
    }
    fn run_live() -> i32 {
        let mut opened = false;
        let observed = (|| -> io::Result<Session> {
            let mut trace = marker(std::env::var_os("NTOSEYE_TRACE_MARKER"))?;
            writeln!(trace, "X_OBSERVER_READY")?;
            let root = Path::new("/sys/bus/usb/devices");
            let address = admission(root)?;
            let file = OpenOptions::new()
                .read(true)
                .write(true)
                .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
                .open(node(address))?;
            opened = true;
            let m = file.metadata()?;
            require(
                m.mode() & libc::S_IFMT == libc::S_IFCHR
                    && libc::major(m.rdev()) == 189
                    && libc::minor(m.rdev()) == 128 * 5 + u32::from(address) - 1,
            )?;
            require(admission(root)? == address)?;
            Ok(execute(
                |a, d| usbfs(&file, a, d),
                |s| writeln!(trace, "{s}"),
            ))
        })();
        let s = observed.unwrap_or_else(|e| {
            eprintln!("observer admission: {e}");
            Session {
                host_fault: true,
                ..Session::default()
            }
        });
        report(&s, opened);
        if result(&s) == "KDUSB_NAME_ADMISSION_OK" {
            0
        } else {
            5
        }
    }
    #[cfg(test)]
    mod tests {
        use super::*;
        fn success(data: &[u8]) -> (Session, Vec<Action>) {
            let mut calls = Vec::new();
            let s = execute(
                |a, d| {
                    calls.push(a);
                    match a {
                        Action::Out => {
                            assert_eq!(d, OUT);
                            Ok(5)
                        }
                        Action::In => {
                            assert_eq!(d.len(), 4017);
                            d[..data.len()].copy_from_slice(data);
                            Ok(data.len())
                        }
                        _ => Ok(0),
                    }
                },
                |_| Ok(()),
            );
            (s, calls)
        }
        #[test]
        fn exact_success_single_claim_release_and_no_read_loop() {
            let (s, calls) = success(EXPECTED);
            assert_eq!(
                calls,
                [Action::Claim, Action::Out, Action::In, Action::Release]
            );
            assert_eq!(result(&s), "KDUSB_NAME_ADMISSION_OK");
            assert_eq!(EXPECTED.len(), 19);
        }
        #[test]
        fn out_faults_suppress_in_and_release_once() {
            for error in [
                libc::EPROTO,
                libc::ETIMEDOUT,
                libc::EPIPE,
                libc::EIO,
                libc::ENODEV,
                libc::EINTR,
            ] {
                let mut calls = Vec::new();
                let s = execute(
                    |a, _| {
                        calls.push(a);
                        if a == Action::Out {
                            Err(io::Error::from_raw_os_error(error))
                        } else {
                            Ok(0)
                        }
                    },
                    |_| Ok(()),
                );
                assert_eq!(calls, [Action::Claim, Action::Out, Action::Release]);
                assert!(!s.input.attempted);
                assert_eq!(s.out.errno, Some(error));
                assert_eq!(s.out.rc, Some(-1));
            }
            assert_eq!(errno_class(libc::EPROTO), "IO");
            assert_eq!(errno_name(Some(libc::EPROTO)), "EPROTO");
            assert_eq!(errno_class(libc::ETIMEDOUT), "TIMEOUT");
        }
        #[test]
        fn out_short_suppresses_in() {
            for n in 0..5 {
                let mut calls = Vec::new();
                let s = execute(
                    |a, _| {
                        calls.push(a);
                        Ok(if a == Action::Out { n } else { 0 })
                    },
                    |_| Ok(()),
                );
                assert_eq!(result(&s), "NAME_OUT_SHORT");
                assert_eq!(calls, [Action::Claim, Action::Out, Action::Release]);
            }
        }
        #[test]
        fn wrong_name_and_nuls_and_arbitrary_first_completion() {
            for data in [
                &EXPECTED[..17],
                b"NAME=CLSA0102_USB\0x",
                b"NAME=OTHER000_USB\0\0",
                b"secret kernel bytes",
            ] {
                let (s, _) = success(data);
                assert_eq!(s.input.exact, Some(false));
                assert_eq!(s.input.digest, Some(hex::encode(Sha256::digest(data))));
                assert_ne!(result(&s), "KDUSB_NAME_ADMISSION_OK");
            }
            let (s, _) = success(b"secret kernel bytes");
            assert_eq!(result(&s), "NAME_REPLY_NOT_FIRST_COMPLETION");
        }
        #[test]
        fn in_faults_stop_after_first_completion() {
            for error in [libc::EPROTO, libc::ETIMEDOUT, libc::EPIPE] {
                let mut calls = Vec::new();
                let s = execute(
                    |a, _| {
                        calls.push(a);
                        match a {
                            Action::Out => Ok(5),
                            Action::In => Err(io::Error::from_raw_os_error(error)),
                            _ => Ok(0),
                        }
                    },
                    |_| Ok(()),
                );
                assert_eq!(calls.len(), 4);
                assert_eq!(s.input.errno, Some(error));
                assert!(s.input.digest.is_none());
            }
        }
        #[test]
        fn marker_failure_suppresses_transfer_and_releases() {
            for fail in [
                "X_NAME_OUT_BEGIN",
                "X_NAME_OUT_END",
                "X_NAME_IN_BEGIN",
                "X_NAME_IN_END",
            ] {
                let mut calls = Vec::new();
                let s = execute(
                    |a, _| {
                        calls.push(a);
                        Ok(if a == Action::Out { 5 } else { 0 })
                    },
                    |m| {
                        if m == fail {
                            Err(io::Error::other("marker"))
                        } else {
                            Ok(())
                        }
                    },
                );
                assert!(s.marker_fault);
                assert_eq!(calls.last(), Some(&Action::Release));
                if fail == "X_NAME_OUT_BEGIN" {
                    assert_eq!(calls, [Action::Claim, Action::Release]);
                }
                if fail == "X_NAME_IN_BEGIN" {
                    assert!(!s.input.attempted);
                }
            }
            assert!(marker(None).is_err());
        }
        #[test]
        fn claim_release_never_retried() {
            let mut calls = Vec::new();
            let s = execute(
                |a, _| {
                    calls.push(a);
                    Err(io::Error::from_raw_os_error(libc::EBUSY))
                },
                |_| Ok(()),
            );
            assert_eq!(calls, [Action::Claim]);
            assert!(!s.claimed);
            let s = execute(
                |a, _| match a {
                    Action::Out => Ok(5),
                    Action::Release => Err(io::Error::from_raw_os_error(libc::EIO)),
                    _ => Ok(0),
                },
                |_| Ok(()),
            );
            assert!(!s.released);
            assert_eq!(result(&s), "OTHER_TRANSPORT_FAULT");
        }
        #[test]
        fn dry_zero_usb_open_and_exact_authorization() {
            assert_eq!(dispatch(&[], || panic!("dry must not enter live")), 0);
            for args in [
                vec![AUTH.into()],
                vec![AUTH.into(), "OTHER".into()],
                vec!["--execute".into(), "CLSA0102_USB".into()],
            ] {
                assert_eq!(dispatch(&args, || panic!("unauthorized")), 2);
            }
            assert_eq!(mode(&[AUTH.into(), "CLSA0102_USB".into()]), Ok(true));
            assert_eq!(node(2), "/dev/bus/usb/006/002");
        }
        #[test]
        fn exact_cached_topology_and_attached_driver() {
            let root =
                std::env::temp_dir().join(format!("phase349l-sysfs-test-{}", std::process::id()));
            fs::create_dir_all(root.join("6-1")).unwrap();
            let i = root.join("6-1:1.0");
            fs::create_dir_all(&i).unwrap();
            let d = root.join("6-1");
            for (p, values) in [
                (
                    &d,
                    vec![
                        ("idVendor", "3495"),
                        ("idProduct", "00e0"),
                        ("busnum", "6"),
                        ("devnum", "2"),
                        ("bConfigurationValue", "1"),
                    ],
                ),
                (
                    &i,
                    vec![
                        ("bInterfaceNumber", "00"),
                        ("bAlternateSetting", "0"),
                        ("bInterfaceClass", "dc"),
                        ("bInterfaceSubClass", "02"),
                        ("bInterfaceProtocol", "ff"),
                    ],
                ),
            ] {
                for (k, v) in values {
                    fs::write(p.join(k), v).unwrap();
                }
            }
            let raw=hex::decode("12010003000000099534e00000000102030109022c00010100c0000904000002dc02ff000705010200040006300f0000000705810200040006300f000000").unwrap();
            fs::write(d.join("descriptors"), &raw).unwrap();
            for (ep, addr) in [("ep_01", "01"), ("ep_81", "81")] {
                let p = i.join(ep);
                fs::create_dir_all(&p).unwrap();
                for (k, v) in [
                    ("bEndpointAddress", addr),
                    ("bmAttributes", "02"),
                    ("wMaxPacketSize", "0400"),
                ] {
                    fs::write(p.join(k), v).unwrap();
                }
            }
            assert_eq!(admission(&root).unwrap(), 10);
            fs::write(d.join("devnum"), "3").unwrap();
            assert!(admission(&root).is_err());
            fs::write(d.join("devnum"), "2").unwrap();
            fs::write(i.join("driver"), "").unwrap();
            assert!(admission(&root).is_err());
            fs::remove_file(i.join("driver")).unwrap();
            fs::write(i.join("ep_81/wMaxPacketSize"), "0200").unwrap();
            assert!(admission(&root).is_err());
            assert!(cached_descriptors(&raw[..20]).is_err());
            fs::remove_dir_all(root).unwrap();
        }
        #[test]
        fn ioctl_abi_and_static_audit() {
            assert_eq!(
                BULK_IOCTL,
                if cfg!(target_pointer_width = "64") {
                    0xc0185502
                } else {
                    0xc0105502
                }
            );
            assert_eq!(CLAIM_IOCTL, 0x8004550f);
            assert_eq!(RELEASE_IOCTL, 0x80045510);
            let source = include_str!("ntoseye-kdusb-recovered-name-after-ep0-r1.rs");
            let p = source.split("#[cfg(test)]").next().unwrap();
            for token in [
                "USBDEVFS_CONTROL",
                "USBDEVFS_RESET",
                "USBDEVFS_SETCONFIGURATION",
                "USBDEVFS_SETINTERFACE",
                "rusb::",
                "libusb_",
                "clear_halt",
                "detach_kernel_driver",
            ] {
                assert!(!p.contains(token));
            }
            assert_eq!(p.matches("libc::ioctl(").count(), 1);
            let e = p
                .split("fn exchange<")
                .nth(1)
                .unwrap()
                .split("fn result(")
                .next()
                .unwrap();
            assert!(!e.contains("loop"));
            assert!(!e.contains("while"));
            assert_eq!(e.matches("call(Action::Out").count(), 1);
            assert_eq!(e.matches("call(Action::In").count(), 1);
        }
    }
}
