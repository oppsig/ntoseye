# KDUSB post-CE single ACK observer r1

Phase 3.44CB observed a coherent KD data packet before the delayed NAME reply:

- leader: `0x30303030`
- type: `0x0007` (`KD_STATE_CHANGE64`)
- byte count: `330`
- packet id: `0x80800800`
- checksum: `0x00004452`

Phase 3.44CD drained the delayed `NAME=CLSA0102_USB\0\0` reply. Phase
3.44CE then sent one KD RESEND and received no reply in four one-second reads.

Phase 3.44CF performs the complementary protocol action: acknowledge the packet
that was actually observed.

The exact control packet is:

```text
69696969040000000008808000000000
```

Decoded:

- leader: `0x69696969`
- type: `4` (`KD_ACKNOWLEDGE`)
- byte count: `0`
- packet id: `0x80800800`
- checksum: `0`

The packet ID is the observed packet's exact ID. In classic KD, received data
packets are acknowledged using their PacketId. `0x80800800` is also
`INITIAL_PACKET_ID | SYNC_PACKET_ID`, consistent with a synchronizing first
packet.

After the one ACK, the observer performs at most four bulk-IN reads and retains
every non-empty transfer in full.

It sends no NAME, RESEND, RESET, KD data, break-in, USB control request,
endpoint recovery, device reset, or reboot operation.
