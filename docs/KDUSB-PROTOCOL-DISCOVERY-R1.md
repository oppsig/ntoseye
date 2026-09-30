# KDUSB protocol discovery r1

`ntoseye-kdusb-protocol-discovery-r1` is a dry-by-default, bounded research
engine for legacy classic KDUSB. It is not a general debugger session.

The r1 campaign was consumed on 2026-09-30 at 09:45:52 UTC and aborted before
its first bulk transfer. Live mode is now permanently disabled in this r1
binary; dry mode and replay remain available. A separate experiment requires
new explicit authorization, not deletion of either one-time marker.

The reusable `kdusb_discovery` module parses one USB transfer at a time. It
reports declared payload length, actual transfer length (at the caller),
checksum state, optional `0xaa`, extra bytes, NAME replies, state changes,
manipulate APIs and PacketId sync/duplicate state. It never requires NAME to
arrive before KD.

Live mode permits the authoritative initial ACK and exact-once ACKs for valid
new logical KD packets. The GetVersion serializer is tested offline; live query
transmission is disabled until host-to-target legacy KDUSB trailer framing is
verified. It contains no USB
control transfer, reset, clear-halt, detach, endpoint recreation, break-in,
continue, memory/context write, breakpoint, or FILE_IO reply path.

Replay mode uses the same parser without opening USB:

```text
ntoseye-kdusb-protocol-discovery-r1 --replay INPUT.jsonl OUTPUT.jsonl
```

The historical live invocation was restricted to the project orchestrator
after its one-time sentinel and continuity gates (it now returns
`CAMPAIGN_ALREADY_CONSUMED` without opening USB):

```text
ntoseye-kdusb-protocol-discovery-r1 \
  --execute-campaign CLSA0102_USB --output-dir DIR
```

Both the orchestrator and binary enforce exclusive, global one-time guards.
Identity, boot, endpoint descriptors, controller ownership and capture health
are checked before and after every transfer. PacketId tracking permits normal
bit-0 toggling; only repetitions of the immediately prior logical packet are
classified as retransmissions. Replay uses the same conversation policy.

Postmortem: the executed revision required an absent interface driver even
after its successful libusb claim. Linux binds that claim to `usbfs`, so the
guard rejected its own ownership. The offline repair requires no driver before
claim and exactly `/sys/bus/usb/drivers/usbfs` after this handle has successfully
claimed the interface. Missing or different ownership remains fatal. Regression
tests cover both stages without claiming or probing a real USB device.
