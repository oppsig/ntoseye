# KDUSB EP0 characterization R1

The original ten-probe matrix was rejected offline before live execution: pinned
usbfs recipient checks implicitly claim an interface for standard interface and
nonzero endpoint recipients. No USB I/O occurred and no live sentinel was created.
The project retains `kernel-contract-blocker.json` and the exact
`pinned-kernel-usbfs-recipient-checks.c.txt` as genuine discovery evidence.

The revised `matrix-resolution.json` removes those four requests, preserving the
no-claim contract. For standard device-recipient `bmRequestType=0x80`, the pinned
`check_ctrlrecip()` falls through with its initial `ret=0` and never calls
`checkintf()`. Both control-path call sites are retained in the project source
proof. Interface/endpoint-recipient health is **not measured**; it remains an
explicit future unknown. The compiled matrix invariant fails before device open
unless it matches the exact six standard device-recipient control-IN requests.
The project's gate validates retained source hashes, resolution and matrix before
sentinel creation. The final `__NTOSEYE_349I_HEAD__` pin belongs to the resume helper.

This Linux-only binary defaults to a dry plan with six NOT_ATTEMPTED records and
zero USB/sysfs admission access. Its only live form is:

```text
ntoseye-kdusb-ep0-control-plane-characterization-r1 --execute-ep0-control-plane-characterization CLSA0102_USB
```

Live execution requires an existing writable `NTOSEYE_TRACE_MARKER`. The project
gate pre-arms bus-wide usbmon, strace, and a dedicated xHCI tracefs instance.
The gate owns the irreversible one-shot sentinel and bounded capture lifecycle.
Never invoke live during offline engineering.

Admission reads cached sysfs descriptors and topology only: exactly one 3495:00e0,
6-1, bus/address 6/8, configuration 1, interface 0, alt 0, dc/02/ff, exactly bulk
81/01 with MPS 1024. It opens only /dev/bus/usb/006/008, refuses an attached driver
and rechecks identity/driver plus the node's character-device number after open.
Admission mismatch prints IDENTITY_MISMATCH_ABORT with no control submissions.

The C-layout wrapper implements only USBDEVFS_CONTROL (_IOWR('U',0,...)) with
standard control-IN, native endian fields and one synchronous ioctl per probe.
The existing rusb dependency provides conventional error vocabulary; no libusb
context, enumeration, asynchronous transfer or implicit retry occurs. Direct
return and raw_os_error are printed independently. The analyzer adjudicates
EPROTO from usbmon/strace; generic Io text alone never identifies raw errno.

The ordered matrix is exactly:

| Probe | Name | bmRequestType | bRequest | wValue | wIndex | wLength |
| --- | --- | --- | --- | --- | --- | --- |
| P01 | GET_CONFIGURATION_PRE | 0x80 | 0x08 | 0 | 0 | 1 |
| P02 | GET_STATUS_DEVICE_PRE | 0x80 | 0x00 | 0 | 0 | 2 |
| P03 | GET_DESCRIPTOR_DEVICE | 0x80 | 0x06 | 0x0100 | 0 | 18 |
| P04 | GET_DESCRIPTOR_CONFIGURATION_HEADER | 0x80 | 0x06 | 0x0200 | 0 | 9 |
| P05 | GET_STATUS_DEVICE_POST | 0x80 | 0x00 | 0 | 0 | 2 |
| P06 | GET_CONFIGURATION_POST | 0x80 | 0x08 | 0 | 0 | 1 |

P01/P06 expect 01. Complete device descriptors validate length/type and 3495:00e0;
complete configuration headers validate length/type and configuration value 1.
Each request has exactly one direct synchronous ioctl, 750 ms, without retry.
Faults continue; NoDevice or marker failure stops later probes. All six records
remain present even when not attempted. Exact markers are
`I_P01_GET_CONFIGURATION_PRE_BEGIN/END`, `I_P02_GET_STATUS_DEVICE_PRE_BEGIN/END`,
`I_P03_GET_DESCRIPTOR_DEVICE_BEGIN/END`,
`I_P04_GET_DESCRIPTOR_CONFIGURATION_HEADER_BEGIN/END`,
`I_P05_GET_STATUS_DEVICE_POST_BEGIN/END`, and
`I_P06_GET_CONFIGURATION_POST_BEGIN/END` (each suffix is emitted separately).

Successful bytes, including short responses, are preserved as hex. Pre/post
comparisons require complete responses. P05/P06 are independent observations,
not retries. Interface/endpoint response semantics are absent.

```text
MAX_USB_TRANSACTIONS=6
MAX_CONTROL_IN_PROBES=6
MAX_CONTROL_OUT_PROBES=0
MAX_BULK_OUT_PROBES=0
MAX_BULK_IN_PROBES=0
MAX_NAME_TX=0
MAX_KD_PACKET_TX=0
PER_PROBE_TIMEOUT_MS=750
AUTOMATIC_RETRY=false
DEVICE_RECIPIENT_NO_IMPLICIT_CLAIM_PROVEN=true
INTERFACE_RECIPIENT_PROBES=0
ENDPOINT_RECIPIENT_PROBES=0
CONTROL_TRANSPORT_IMPLEMENTATION=USBFS_DIRECT
```

No interface claim, driver detach, configuration/alternate selection, clear-halt,
reset, control OUT, bulk transfer, NAME/KD traffic or debugger activation exists.
Kernel EP0 recovery commands may occur and are observations, not tool actions.

Helper-owned Cargo checks (the inherited build script calls Git):

```text
rustfmt --edition 2024 --check src/bin/ntoseye-kdusb-ep0-control-plane-characterization-r1.rs
cargo test --offline --bin ntoseye-kdusb-ep0-control-plane-characterization-r1
cargo build --offline --bin ntoseye-kdusb-ep0-control-plane-characterization-r1
```

Tests use injected transfer/marker functions; they never access a USB node. They
cover exact ordering/setup/bounds, fault continuation, disappearance, validation,
consistency, classification, marker refusal, ABI and static safety.

Codex validates focused tests and the binary directly with rustc against cached
dependencies, with no Cargo/Git invocation. The sandbox blocks ptrace, so the
resume helper performs mandatory dry strace and full gate validation. No live
execution occurs during Codex. The historical `invoking-helper-fixes.patch` in
the project is superseded by the resume helper.
