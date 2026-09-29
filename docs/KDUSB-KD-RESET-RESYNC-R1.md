# KDUSB KD RESET/resynchronization observer r1

This observer is the first ntoseye experiment that intentionally transmits one
classic-KD control packet after the proven KDUSB `NAME?` bootstrap.

The control packet is **protocol resynchronization**, not a USB device reset and
not a target reboot.

Exact packet:

```text
leader      0x69696969  ("iiii", control)
packet type 0x0006      PACKET_TYPE_KD_RESET
byte count  0
packet id   0
checksum    0
total       16 bytes
hex         69696969060000000000000000000000
```

The design follows the classic KD control-packet semantics used by KDCOM-like
implementations: a debugger initiates resynchronization with a type-6 control
packet and a target answers with the same type.

## Dry mode

With no arguments the binary performs no USB I/O and prints its hard limits:

```console
ntoseye-kdusb-kd-reset-resync-r1
```

## Explicit live mode

```console
sudo ntoseye-kdusb-kd-reset-resync-r1 \
  --execute-kd-reset-resync CLSA0102_USB
```

Live limits:

- exactly one ASCII `NAME?` maximum;
- exactly one 16-byte KD RESET/resync control packet maximum;
- at most eight 4016-byte bulk-IN calls;
- 1000 ms timeout per read;
- no automatic NAME retry;
- no automatic KD RESET retry;
- no automatic read restart;
- no KD ACK;
- no KD RESEND;
- no KD data/manipulate/file-I/O packet transmission;
- no break-in;
- no target-memory access;
- no USB reset;
- no endpoint recreation or configuration selection.

The observer accepts a valid type-6 control reply and continues passive reads.
If a complete data packet follows, it validates leader, length, checksum and
`0xaa` trailer and preserves the exact packet bytes.

Important result classes include:

- `RESYNC_RESET_REPLY_ONLY`
- `RESYNC_RESET_REPLY_AND_DATA_PACKET`
- `RESYNC_DATA_PACKET_BEFORE_RESET_REPLY`
- `RESYNC_NO_REPLY`
- `RESYNC_UNEXPECTED_CONTROL`
- `KD_RESET_WRITE_EPROTO`
- `READ_EPROTO`
- `RESYNC_FRAMING_INVALID`
- `IDENTITY_MISMATCH_ABORT`
- `OTHER_TRANSPORT_FAULT`

This phase deliberately does not advance to break-in or debugger manipulation.
