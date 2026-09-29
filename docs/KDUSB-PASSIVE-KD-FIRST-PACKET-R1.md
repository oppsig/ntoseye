# KDUSB passive first complete KD packet R1

This binary is the Phase 3.44BU transition from a proven KDUSB `NAME?`
transaction to passive classic-KD observation. Its default invocation is a
pure dry plan: it does not enumerate, open, claim, read, or write USB.

```console
cargo run --bin ntoseye-kdusb-passive-kd-first-packet-r1
```

The sole live form is deliberately exact:

```console
ntoseye-kdusb-passive-kd-first-packet-r1 \
  --execute-passive-first-kd-packet CLSA0102_USB
```

One invocation enumerates exactly one supported dc/02/ff interface, refuses an
attached kernel driver, requires alternate setting zero, claims the interface,
writes the five ASCII bytes `NAME?` once, makes no more than four 4016-byte
bulk-IN calls with one-second per-read timeouts, and releases the interface.
There is no retry or read restart.

The observer consumes a matching `NAME=CLSA0102_USB\0` reply locally. A second
NUL is accepted. Bytes after that reply and subsequent reads are assembled as
one stream. A classic KD data packet is complete only after its 16-byte header,
declared payload, and `0xaa` trailer are present and the payload byte-sum equals
the header checksum. A control packet is complete at 16 bytes only when its
byte count and checksum are both zero. The absolute retained-packet limit is
4017 bytes. Structured output includes every exact packet byte and surplus
count; surplus is not interpreted as a second packet.

Known packet types receive passive semantic labels, including `0x000b` as
`KD_FILE_IO`. When its 64-byte request header is present, the existing
read-only file-I/O parser also classifies the API as create, read, write,
close, or unknown. No response is constructed or sent. The implementation contains
no USB reset, active-configuration selection, endpoint recreation,
kernel-driver detach, KD ACK/RESEND/RESET, file-I/O reply, break-in, debugger
request, or target-memory access path.

Live results are classified as `PASSIVE_COMPLETE_KD_PACKET`,
`PASSIVE_NAME_ONLY_NO_KD_PACKET`, `PASSIVE_BOUNDED_TIMEOUT`,
`PASSIVE_NAME_WRITE_EPROTO`, `PASSIVE_READ_EPROTO`,
`PASSIVE_FRAMING_INVALID`, `IDENTITY_MISMATCH_ABORT`, or
`OTHER_TRANSPORT_FAULT`. Every result is terminal for that invocation.
