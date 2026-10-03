# KDUSB post-Thor-reboot NAME recovery R1

This observer is a narrow derivative of the Phase 3.49L recovered-epoch NAME
probe. It exists only to repeat the exact classic `NAME?` exchange after a
Thor reboot while Zeus is intentionally left running.

## Invariants

- Linux only.
- Physical path must remain `6-1`, bus 6.
- VID:PID must remain `3495:00e0`.
- Configuration 1, interface 0/alt 0, class/subclass/protocol `dc/02/ff`.
- Bulk OUT `0x01`, Bulk IN `0x81`, MPS 1024.
- No interface driver may be attached.
- Cached descriptor bytes must match the retained KDUSB descriptor exactly.
- The USB device address is dynamic after Thor reboot and may be any valid
  address 1..127.
- The observer issues exactly one interface claim, one 5-byte Bulk OUT
  `NAME?`, at most one Bulk IN, then one release.
- Bulk IN is conditional on exact 5-byte OUT success.
- No retry, read loop, control request, reset, clear-halt, configuration change,
  alternate-setting change, kernel-driver detach, break-in, GetVersion, KD
  packet, or debugger attach exists.

## Live authorization

The only live form is:

```text
--execute-post-thor-reboot-name CLSA0102_USB
```

The caller must provide a writable `NTOSEYE_TRACE_MARKER`.

The observer itself does not reboot Thor or Zeus and does not decide whether the
post-reboot epoch is scientifically admissible. The project-side Phase 3.49M
gate owns that admission, capture, sentinel, evidence and comparison to 3.49L.

Retention: source should remain available for Phase 3.49M adjudication.
