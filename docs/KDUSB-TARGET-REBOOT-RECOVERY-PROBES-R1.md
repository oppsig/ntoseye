# KDUSB target-reboot recovery probes r1

Phase 3.44CA reuses the BZ 19-probe matrix after a **Zeus-only Windows
reboot** while Thor, its custom xHCI kernel, controller binding and runtime-PM
state remain unchanged.

The binary does not reboot either machine. The project live gate owns the
recovery boundary and starts this observer only after it has witnessed the
target disappear and re-enumerate on physical path `6-1`.

## Why this exists

BZ established an important state:

- the Linux USB device remained enumerated;
- early standard EP0 control reads produced transaction errors;
- later EP0 reads timed out;
- NAME/bulk operations failed before reaching the HCD;
- no Reset Device, Address Device or re-enumeration occurred.

CA asks whether a **target-only reboot** restores ordinary USB control-plane and
KDUSB bulk behavior while Thor is left untouched.

## Live invocation

Dry by default.

Explicit live form:

```console
sudo NTOSEYE_TRACE_MARKER=/sys/kernel/tracing/instances/<instance>/trace_marker \
  ntoseye-kdusb-target-reboot-recovery-probes-r1 \
  --execute-target-reboot-recovery-probes CLSA0102_USB
```

The observer accepts a dynamic USB address after re-enumeration, but requires:

- VID:PID `3495:00e0`;
- USB bus 6;
- physical port path 1 (`6-1`);
- configuration 1;
- interface 0 / alt 0;
- class/subclass/protocol `dc/02/ff`;
- bulk OUT `0x01`;
- bulk IN `0x81`;
- no attached kernel driver.

## Probe matrix

The post-reboot matrix is intentionally identical to BZ so results are
comparable:

- 14 standard control-IN probes;
- one five-byte `NAME?` bulk OUT;
- four 4016-byte bulk-IN probes.

No probe is automatically retried.

## Error preservation

Unlike BZ, CA does **not** collapse `rusb::Error::Io` and
`rusb::Error::Pipe`.

Per-probe output reports them separately:

```text
STATUS=IO
ERROR=rusb::Error::Io
```

or:

```text
STATUS=PIPE
ERROR=rusb::Error::Pipe
```

This matters because Linux usbfs `-EPROTO` commonly reaches libusb/rusb as
`Error::Io`, while an immediate `Pipe` can describe a different userspace
failure class.

## Safety

The binary has exactly one bulk-write operation: `NAME?`.

It never performs:

- USB device reset;
- SET_CONFIGURATION;
- CLEAR_FEATURE / clear-halt;
- alternate-setting change;
- kernel-driver detach;
- endpoint recreation;
- KD RESET/ACK/RESEND/file-I/O reply;
- break-in;
- debugger manipulation or target-memory access;
- target reboot.

The target reboot is a manually initiated experimental boundary outside the
binary.
