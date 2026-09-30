# Classic KDUSB transport foundation

This Linux-only library foundation prepares classic USB2DBG transport for the
existing KD engine. It is experimental and **not an attachable debugger backend**.
There is no `--backend kdusb`, enumeration/open/claim helper, or `connect_usb`.
Outbound DATA and break-in output are rejected before any bulk write. GetVersion
cannot run through this adapter. Modern KDNET-over-USB is a separate protocol.

## Boundary adaptation

`kd::kdusb::BulkIo` returns one USB completion per read. `KdUsbStream` classifies
that completion before exposing bytes to `KdFraming`:

| Incoming completion | Internal stream representation |
| --- | --- |
| DATA: 16-byte header + declared payload | Same bytes + synthetic `0xaa` |
| DATA: header + payload + exactly `0xaa` | Same bytes |
| CONTROL: exactly 16 bytes | Same bytes |
| `NAME=<name>\0\0` | Recorded separately; no KD bytes consumed |
| ZLP | Continue reading within the same deadline; never fake EOF |
| Incomplete, oversized, combined, or unknown packet | Error; no guessed reassembly |

The synthetic byte is only an internal adapter detail. It does not establish an
outbound wire contract. Serial framing still requires its real trailer. KDNET
retains its existing datagram adaptation and packet-ID rules. KD framing retains
checksum validation, ACK/RESEND/RESET and packet sequencing.

NAME may be delayed until after KD packets, and may span reads (including the
prefix and terminators). Detection occurs only at a transfer boundary, so a
NAME-like sequence in a KD payload cannot remove payload bytes. Split NAME must
remain contiguous except for ZLPs; interleaving KD into an unfinished NAME and
fragmented/coalesced KD packets are unsupported pending evidence. NAME replies
are retained as ANSI bytes, bounded at 24 name bytes and 16 outstanding replies.
No identity decision or mandatory first-frame rule is made by this module.

The recovered receive quantum is 4016 = 16 + maximum KD payload 4000. The adapter
requests 4017 bytes to also accommodate a maximum packet with a tolerated
trailer; overflow is an error. This capacity is an implementation choice, not a
claim of a captured 4017-byte transfer. Tiny `Read` calls drain one normalized
completion before another bulk read. Clones share unread bytes and NAME state,
so cloning neither duplicates nor drops prefetched data. Empty caller buffers
return zero without I/O. Nonempty reads use a finite deadline, including ZLP and
NAME traffic; a split NAME survives an idle timeout.

Writes stage one CONTROL packet until `flush`. Clones have separate staging and
share a lock across the entire logical write, including ZLP. USB3 logical writes
are chunked at 4096 bytes with a final ZLP for a nonempty exact multiple of the
OUT endpoint maximum packet size. This rule is independent of KD DATA framing.
A partial/error write disables output on all clones until a new stream is
created; it is not automatically replayed. Tests use only `FakeBulk`.

## Integration boundary

The handle adapter preserves libusb's completion status. It does not use rusb's
convenience bulk calls, which can return `Ok(n)` for partially timed-out or
interrupted transfers. Partial errors never become successful transfer boundaries.
Timeouts round up to finite milliseconds so a sub-millisecond remaining budget
cannot become libusb's infinite timeout; out-of-range budgets are rejected.
These decisions are tested without a device. The small synchronous FFI call
borrows a live handle and slice; it does not retain pointers or manipulate
interface state. See [rusb 0.9.4's bulk methods](https://docs.rs/rusb/0.9.4/src/rusb/device_handle.rs.html).

A blanket `BulkIo` implementation for `rusb::DeviceHandle` accepts a handle whose
ownership and endpoints a future admission layer establishes. No code here
obtains a real handle. The generic stream is suitable for testing existing
`KdFraming::new(stream)` receive behavior; it is not added to `KdTransport` or
`KdBackend`. `KdFraming` currently masks SYNC in classic ACKs. The exact-ID ACK
required by the retained control experiment is tested through the stream
serializer, **not claimed as the existing framing engine's ACK policy**.

Future discovery should use the admitted active interface and bulk endpoint
descriptors, followed by target NAME matching. Descriptor enumeration lists
possible alternate settings; it does not show which is active. There is no
source-backed need to select a nonzero alternate setting for the retained model.
Do not detach drivers or change configuration/alternate state automatically.
Opening devices, reconnect/re-enumeration and identity policy remain deferred.

## Evidence and provenance

The retained target completion was 346 bytes: type 7, ByteCount 330, PacketId
`0x80800800`, checksum field `0x4452`. Its 64-byte retained prefix cannot verify
the payload checksum. The synthetic full regression packet uses an explicitly
constructed payload and computed checksum; it never purports to reconstruct the
missing capture. A delayed two-NUL NAME reply and absence of a standalone
trailer in the later retained reads support this inbound adapter.

Transport constants are independently recovered facts from static analysis of
USB2DBG.SYS SHA-256
`3074ae7f9375ed50149fc3ba8b913f54ae85532177acfab12982ba83c135ec0c`
and its target transport. No driver code, disassembly, PDB, or proprietary binary
is included. The retained transport analysis is [available separately](https://github.com/oppsig/CLSA0102-Reverse-Engineering-Project/blob/724b7b01320983e03a5d051591fbe4bb244d6aa0/engineering/phase-3.44/kdusb-host-protocol-static-recovery/KDUSB-WIRE-PROTOCOL-RECOVERY.md);
its earlier assertion that unchanged raw stream framing was sufficient is
superseded by the later 346-byte observation.

[ReactOS KD definitions](https://github.com/reactos/reactos/blob/f06eace89e11b6513afcf65b653f2d360db7ba77/sdk/include/reactos/windbgkd.h)
are a reference for the existing classic header/constants.
[Current ReactOS KDCOM implementation](https://doxygen.reactos.org/d4/d91/kddll_8c_source.html)
requires and emits a serial trailer; that is no proof of classic USB output.
[Microsoft's transport extensibility documentation](https://learn.microsoft.com/en-us/windows-hardware/drivers/debugger/how-to-develop-kdnet-extensibility-modules)
distinguishes packet and byte transports; it does not settle legacy USB2DBG DATA
framing. [KDNET's public dissector](https://github.com/Lekensteyn/kdnet/blob/2ff242f828ca2a5dd29359c7e5201079f20e4792/kdnet.lua)
concerns another transport. No code from those implementations was copied.

Outbound DATA trailer behavior remains unresolved. A successful 16-byte ACK
only demonstrates CONTROL handling. Before normal attach, obtain independent
source evidence or an authorized host-to-target DATA capture, establish USB ACK
and packet-ID semantics, and validate timeout/discovery/reconnect lifecycle.
