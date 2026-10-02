# Recovered-epoch classic KDUSB NAME admission R1

Linux-only standalone observer:
`src/bin/ntoseye-kdusb-recovered-name-admission-r1.rs`.
The default invocation is dry and performs zero USB node opens or ioctls.
Exact authorization is
`--execute-recovered-name-admission CLSA0102_USB`, with a writable
`NTOSEYE_TRACE_MARKER` supplied by the project L gate.

The project gate owns continuity, publication, capture prearm, exclusive
sentinel and bundling. K's pre-reboot sentinel is historical. Continuity starts
at verified K01 completion `1790937229494376`, after K's valid reboot boundary,
and requires current cached identity equal to K address 10 at path 6-1.

The observer uses cached sysfs only for discovery. It requires the exact retained
device/configuration descriptors: configuration 1, interface 0/alt 0, dc/02/ff,
01/81 bulk endpoints, 1024 MPS, no attached driver, bus 6/address 10. It dynamically
formats the device node from that cached address, verifies major/minor, and
rechecks cached identity before claiming interface 0. The only ioctl requests
are USBDEVFS_CLAIMINTERFACE, USBDEVFS_BULK and USBDEVFS_RELEASEINTERFACE.
No libusb/rusb live path is initialized.

There is exactly one claim attempt. Successful claim is followed by at most one
OUT: endpoint 01, `NAME?`, five bytes, timeout 1000 ms. Only return value exactly
5 enables one IN: endpoint 81, capacity 4017, timeout 1500 ms. The first completion
must equal `NAME=CLSA0102_USB\x00\x00`, nineteen bytes. One release attempt follows
all exchange outcomes; failed claim has no release. Marker failure prevents the
next transfer and successful claim still gets its cleanup release. Nothing is
retried, including EINTR, marker writes, claim/release or bulk operations.

Each attempted operation has begin/end epoch microseconds, raw ioctl return,
errno number/name and status. Trace markers are `L_NAME_OUT_BEGIN/END` and
`L_NAME_IN_BEGIN/END`. Exact successful NAME prints the expected hex. Other
successful IN completions print length, SHA-256, prefix and mismatch
classification without arbitrary payload. Failed ioctls have no claimed
successful payload. EPROTO remains raw EPROTO while its status category is IO.

Tests cover zero-I/O dry dispatch and exact authorization; cached topology,
descriptor corruption, attached driver and address drift; dynamic node; exact
payload and conditional single IN; claim/release limits; wrong name/NULs;
non-NAME privacy; raw protocol/timeout/pipe failures; marker failures and cleanup;
native 32/64-bit ioctl layout; forbidden API/ioctl audit and absence of loops.
Run `cargo test --offline --bin ntoseye-kdusb-recovered-name-admission-r1`.

This observer authorizes no debugger attach, KD break-in, packet traffic,
GetVersion, target controls, reset, clear-halt, reconfiguration, alternate setting,
or transport recovery. Evidence retention is required; cleanup is not authorized.
