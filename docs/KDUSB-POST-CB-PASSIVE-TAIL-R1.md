# KDUSB post-CB passive tail observer r1

This observer is the Phase 3.44CD transport instrument for the CLSA0102
reverse-engineering project.

It exists because consumed Phase 3.44CB received a 346-byte first bulk-IN
transfer beginning with a classic-KD data header:

- leader: `0x30303030`
- packet type: `0x0007` (`KD_STATE_CHANGE64`)
- byte count: `330`
- packet ID: `0x80800800`
- checksum: `0x00004452`
- first state-change value: `0x00003031` (`DbgKdLoadSymbolsStateChange`)

The observed transfer length is exactly `16 + 330 = 346` bytes. Classic KD
data framing requires an additional trailing byte, so Phase 3.44CD performs
only passive bulk-IN reads to determine whether the post-CB stream contains:

- the outstanding trailing `0xaa` byte;
- a retransmission of the same state-change packet;
- another complete KD packet;
- an incomplete KD packet; or
- no additional data.

## Live contract

Live mode:

```text
--execute-post-cb-passive-tail CLSA0102_USB
```

Hard bounds:

- maximum four bulk-IN reads;
- 4016-byte read buffer;
- 1000 ms timeout per read;
- zero bulk-OUT writes;
- zero control writes;
- zero NAME probes;
- zero KD ACK/RESEND/RESET/data packets;
- zero USB reset/configuration/endpoint recovery;
- zero target reboot.

Every non-empty bulk-IN transfer is printed in full as `RXn_HEX`, allowing the
project evidence bundle to retain payload bytes rather than only a prefix.
