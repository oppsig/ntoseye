# KDUSB passive first-packet observer — transport-r1

This branch is based on `feature/kdusb-transport-recovery-r1` and adds a bounded passive first-KD-packet observer without altering the transport-recovery implementation.

Binary:

`ntoseye-kdusb-passive-packet-observer-transport-r1`

The observer:

- sends exactly one five-byte ASCII `NAME?` bootstrap probe;
- performs at most four bulk-IN reads of at most 4016 bytes each;
- accepts either a matching `NAME=` reply first or already-prefetched KD framing first;
- consumes the matching NAME reply locally;
- assembles at most the first complete KD packet;
- verifies the KD checksum and data-packet `0xAA` trailer;
- releases the interface before exit.

It does not send KD ACK, RESEND, RESET, file-I/O replies, break-in, debugger requests, breakpoint requests, or target-memory requests.

The implementation is ported from the previously validated passive observer lineage so that passive packet work can continue on top of the current transport-recovery branch.

Offline validation:

```fish
cargo fmt --check
cargo test --bin ntoseye-kdusb-passive-packet-observer-transport-r1 -- --nocapture
cargo build --bin ntoseye-kdusb-passive-packet-observer-transport-r1
```

Live execution is intentionally delegated to the CLSA0102 Phase 3.44BN dry-first wrapper, which pins the patched kernel, controller D0/runtime-PM state, KDUSB topology, usbmon and xHCI dynamic-debug evidence collection.
