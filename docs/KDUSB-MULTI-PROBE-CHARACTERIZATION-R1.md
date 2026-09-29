# KDUSB multi-probe characterization r1

This Linux-only experiment characterizes the already configured KDUSB transport without configuration reapplication or endpoint recovery. The binary is dry by default:

```text
ntoseye-kdusb-multi-probe-characterization-r1
```

The only live form is:

```text
NTOSEYE_TRACE_MARKER=/sys/kernel/tracing/instances/<instance>/trace_marker \
  ntoseye-kdusb-multi-probe-characterization-r1 \
  --execute-multi-probe-characterization CLSA0102_USB
```

Live admission requires exactly one unbound `3495:00e0` device at path `6-1`, bus/address `6/6`, configuration 1, interface 0, alternate setting 0, with bulk OUT `0x01` and bulk IN `0x81`. The interface is claimed and later released; an attached kernel driver is refused, never detached. The trace marker must be writable before the interface is opened.

The fixed schedule is P01–P19: seven pre-state control reads, one `NAME?` bulk write, four independent bulk reads, and seven post-state control reads. Every transaction is bracketed with `BZ_PNN_<PROBE_NAME>_BEGIN/END`. Control reads have 500 ms timeouts; bulk reads each request 4016 bytes with 1000 ms timeouts. Timeout, pipe/EPROTO-class, short, and generic I/O outcomes do not create retries and do not suppress independent later probes. `NoDevice` and returned identity-invariant mismatches stop the schedule.

Only the exact byte stream `NAME=CLSA0102_USB` followed by one or two NUL bytes is recognized. All non-empty bulk-read bytes and all bytes following the recognized response are emitted as hex. Later reads continue as passive observations and never trigger protocol output.

There is one `write_bulk` callsite and no control write, reset, clear-halt, configuration, alternate-setting, detach, endpoint-recreation, or KD packet path. Top-level result classes summarize the structured per-probe record and make no claim about physical cause.
