# KDUSB post-CD single RESEND observer r1

Phase 3.44CD proved that the post-CB passive queue contained the exact
`NAME=CLSA0102_USB\0\0` response and no trailing byte/retransmit within three
subsequent one-second reads.

Phase 3.44CE therefore performs one protocol-directed active probe:

- send exactly one KD control RESEND packet:
  `69696969050000000000000000000000`
- packet id: `0`
- then perform up to four bulk-IN reads;
- retain every non-empty read in full;
- validate the previously observed state-change header and checksum if it is
  retransmitted;
- record whether an `0xaa` trailer is present or absent.

No NAME, ACK, RESET, data, break-in, USB control, endpoint recovery, device
reset, or reboot operation is emitted.

The expected previous state-change packet is:

- leader `0x30303030`
- type `0x0007` (`KD_STATE_CHANGE64`)
- byte count `330`
- packet id `0x80800800`
- checksum `0x00004452`
- new state `0x00003031` (`DbgKdLoadSymbolsStateChange`)

The observer accepts both a 346-byte header+payload retransmission and a
347-byte header+payload+`0xaa` retransmission as distinct result classes, so
the experiment does not assume serial-style trailing-byte framing on KDUSB.
