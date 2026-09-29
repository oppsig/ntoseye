# KDUSB bounded KD RESET retry observer r1

This Phase 3.44BX observer answers only whether a Windows KD target requires
repeated debugger-side classic-KD RESET/resynchronization control packets
before replying. It is dry by default.

The experiment sends ASCII `NAME?` once, requires the exact
`NAME=CLSA0102_USB\0\0` identity response, then explicitly schedules at most
three identical packets:

```text
leader      0x69696969
packet type 0x0006 (PACKET_TYPE_KD_RESET)
byte count  0
packet id   0
checksum    0
hex         69696969060000000000000000000000
```

Three is a deliberately bounded experimental limit, not a claim about the
exact Microsoft WinDbg retry count. A KD RESET is packet-layer
resynchronization; it is not USB reset or target reboot.

## Invocation

Dry plan (no USB open, claim, or transfer):

```console
ntoseye-kdusb-kd-reset-retry-r1
```

The only live form is:

```console
sudo ntoseye-kdusb-kd-reset-retry-r1 \
  --execute-kd-reset-retry CLSA0102_USB
```

Each transmitted RESET receives at most two 4016-byte, 1000 ms read windows.
Any complete valid KD packet immediately suppresses further RESET
transmission. A type-6 reply permits at most four additional passive reads,
stopping after one complete subsequent data packet. The global limit is ten
USB read calls, including NAME acquisition, so it can shorten the passive
post-reply allowance. It never lengthens a timed-out attempt.

The parser assembles packets across read boundaries, preserves exact accepted
bytes, validates the 16-byte header, limits data payload to 4000 bytes, checks
the payload byte-sum and requires the `0xaa` data trailer. Control packets must
have zero byte count and checksum.

The observer sends no ACK, RESEND, break-in, FILE_IO reply, STATE_MANIPULATE,
CONTROL_REQUEST, or memory operation. It does not detach drivers, reset USB,
select a configuration, change alternate settings, recreate endpoints,
change runtime PM, rebind PCI, modify BCD, or reboot either machine.

Result classes distinguish the attempt that elicited a RESET reply, a reply
followed by data, data before a reply, no reply after three attempts,
unexpected/duplicate control traffic, framing failures, identity mismatch,
EPROTO-class failures, and other transport faults. No result automatically
retries the complete BX experiment or authorizes Phase 3.40 cleanup.
