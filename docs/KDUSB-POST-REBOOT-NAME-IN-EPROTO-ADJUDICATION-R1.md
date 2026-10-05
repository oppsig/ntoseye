# Post-reboot NAME IN EPROTO adjudication R1

`ntoseye-kdusb-post-reboot-name-in-eproto-adjudication-r1` is a Linux direct-usbfs observer. No arguments means dry mode with zero USB opens or ioctls. Engineering tests use injected callbacks and temporary cached sysfs fixtures. The project gate owns passive freshness admission, capture prearm, published source pins, durable token and one-shot sentinel.

Live authorization must be exactly:

```text
--execute-post-reboot-name-adjudication CLSA0102_USB
```

The observer requires `NTOSEYE_TRACE_MARKER` naming `trace_marker` in a dedicated `/sys/kernel/tracing/instances/phase349y-*` instance, and gate-provided `NTOSEYE_EXPECTED_BUS`, `NTOSEYE_EXPECTED_DEVNUM`, and `NTOSEYE_EXPECTED_SYSFS_INODE`. It resolves the exact cached sysfs target at `6-1`, checks unique VID:PID 3495:00e0, Microsoft / KDUSB USB3 XHCI Debug / serial 123456789, configuration 1, interface 0/alt 0 dc/02/ff, bulk endpoints 01/81 and 1024 MPS, no interface driver, and exact cached descriptors. It validates the controller path before opening the dynamically derived usbfs node with O_NOFOLLOW/O_CLOEXEC. It checks character-device major/minor and repeats cached admission before claim, including the sysfs generation inode.

The allowed sequence is one CLAIMINTERFACE(0), one BULK OUT(0x01, `NAME?`, 5 bytes, 1000 ms), one conditional BULK IN(0x81, capacity 4017, 1500 ms), and one RELEASEINTERFACE(0). IN is attempted only if OUT returns exactly 5. Release is attempted once on every ordinary post-claim result or marker-error path; failed claim does not release. Calls are never retried. There is no read loop and no control/reset/reconfiguration ioctl or KD packet path.

The exact successful envelope is `NAME=CLSA0102_USB\x00\x00` (19 bytes, `4e414d453d434c5341303130325f5553420000`). Other successful completions expose only byte length, SHA-256 and a NAME-prefix boolean. Errors expose raw errno number/name and raw ioctl result; transfer length is NA on an error. EPROTO has its own status and result class. An observer EPROTO marker is provisional: only the project's offline analyzer can establish reproduction after correlating freshness, token, usbmon, strace and target-ring marked xHCI evidence.

Tests cover wire success, OUT error/short completion, conditional-IN suppression, IN EPROTO/timeout/pipe, short/wrong NAME/NULs/arbitrary first completion, marker failures, claim/release counts, cached identity changes, dynamic bus/devnum, dry/authorization behavior, ABI constants and a static forbidden-API/read-loop audit.

```text
rustfmt --edition 2024 --check src/bin/ntoseye-kdusb-post-reboot-name-in-eproto-adjudication-r1.rs
cargo test --locked --offline --bin ntoseye-kdusb-post-reboot-name-in-eproto-adjudication-r1
cargo build --locked --offline --bin ntoseye-kdusb-post-reboot-name-in-eproto-adjudication-r1
```

keep_for_further_analysis=true
phase340_cleanup_authorized=false
