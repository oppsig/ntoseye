# KDUSB protocol discovery campaign r2

Terminal result: `SUDO_NONINTERACTIVE_UNAVAILABLE`. The unsandboxed
`sudo -n true` returned exit 1, `sudo: a password is required` on 2026-09-30.
The operator contract requires ending all live work at that prerequisite
failure. No r2 USB claim, capture, sentinel or protocol transaction occurred.
`LIVE_SESSION_CLOSED=true` permanently closes both live binary entrypoints
before device enumeration. This revision is an offline research result, not a
live-admitted campaign. A subsequent explicitly authorized experiment must
review its own source and admission; this task cannot resume automatically.

The new binary is `ntoseye-kdusb-protocol-discovery-r2`. Default mode emits a
zero-I/O plan; `--replay INPUT OUTPUT` deterministically classifies transfers.
The dedicated `--claim-lifecycle CLSA0102_USB --output-dir DIR` implementation
contains open/claim, exact usbfs ownership check, release and no-driver check.
It generates no bulk or control transfer and uses the admitted bus/address
with cached sysfs identity rather than requesting an active USB configuration.
Its real execution remains closed and was not live-validated.

The protocol path uses exclusive `create_new` plus fsync for
`tmp/phase345r2-live-consumed.txt`, immediately before its initial TX; there is
also an exclusive binary-start marker. Direct invocation cannot bypass session
closure. A matching successful lifecycle proof, exact source heads, clean
tracked trees, identity and capture guards precede the dormant protocol path.
The consumed r1 binary, policy, files and sentinel are unchanged.

The r2 policy uses complete USB transfers as observations, retains an optional
`0xaa` separately, validates payload length and wrapping checksum, and
compares duplicates against the immediately previous logical packet. Each
logical packet can receive one duplicate ACK; alternating IDs can be reused.
The initial predecessor retransmission additionally must match CB's retained
header and prefix. Unknown semantics, command-string state, FILE_IO, DEBUG_IO,
unsolicited manipulate packets, invalid checksum and incomplete packets stop
before any ACK. The decoder is shared with r1; r2 has its own policy/budgets.

The initial ACK is exactly `69696969040000000008808000000000`.
Ceilings: 60 seconds, 64 reads, 16 new-data ACKs, 20 control TX, one query.
Initial and duplicate ACKs consume the control budget, not the new-data budget.
The active deadline also limits each submitted transfer's timeout. Intent is
retained before submission, completion and actual length afterward; reservations
are distinguished from successful ACKs.

GetVersion serialization has exact-byte offline tests, but outgoing legacy
KDUSB framing remains unresolved, so no live data query or NAME/RESET is sent.
A pure model tests RESEND of the exact pending source-verified GetVersion data
packet (once per pending packet, two total); the actual walker never registers
host data. A RESEND after our ACK therefore stops without transmission. Target
ACKs with no pending data are recorded without advancing a debugger TX stream.

Project orchestration and reviewed findings are on branch
`phase3-45-kdusb-protocol-discovery-campaign-r2` in
`oppsig/CLSA0102-Reverse-Engineering-Project`, directory
`engineering/phase-3.45/kdusb-protocol-discovery-campaign-r2`.
The Fish entrypoint is also session-closed. Lifecycle/capture orchestration
is retained for review but is not claimed to be live-proven.

`KEEP_FOR_FURTHER_ANALYSIS=true`
`PHASE340_CLEANUP_AUTHORIZED=false`
