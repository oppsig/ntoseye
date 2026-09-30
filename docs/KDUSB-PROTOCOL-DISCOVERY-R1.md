# KDUSB protocol discovery r1

`ntoseye-kdusb-protocol-discovery-r1` is a dry-by-default, bounded research
engine for legacy classic KDUSB. It is not a general debugger session.

The reusable `kdusb_discovery` module parses one USB transfer at a time. It
reports declared payload length, actual transfer length (at the caller),
checksum state, optional `0xaa`, extra bytes, NAME replies, state changes,
manipulate APIs and PacketId sync/duplicate state. It never requires NAME to
arrive before KD.

Live mode permits the authoritative initial ACK, exact-once ACKs for valid new
KD data, and one whitelisted `DbgKdGetVersionApi` query. It contains no USB
control transfer, reset, clear-halt, detach, endpoint recreation, break-in,
continue, memory/context write, breakpoint, or FILE_IO reply path.

Replay mode uses the same parser without opening USB:

```text
ntoseye-kdusb-protocol-discovery-r1 --replay INPUT.jsonl OUTPUT.jsonl
```

Live mode is intentionally expected to be called only by the project
orchestrator after its one-time sentinel and continuity gates:

```text
ntoseye-kdusb-protocol-discovery-r1 \
  --execute-campaign CLSA0102_USB --output-dir DIR
```

