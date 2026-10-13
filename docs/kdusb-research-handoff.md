# KDUSB research handoff and product integration boundary

**Status (2026-10-13): design/documentation only, on the `oppsig/ntoseye` fork.** This document is not a claim that upstream [dmaivel/ntoseye](https://github.com/dmaivel/ntoseye), this fork's `master`, or any released crate supports classic USB2DBG/KDUSB attach. It authorizes **no live device probe**, BCD change, PCI policy write, kernel patch installation, reset or debugger attach.

**Cross-project canonical research and evidence ledger:** [CLSA0102 — KDUSB ↔ ntoseye ownership matrix](https://github.com/oppsig/CLSA0102-Reverse-Engineering-Project/blob/docs/kdusb-ntoseye-ownership-and-handoff-r1/docs/KDUSB-NTOSEYE-PROJECT-BOUNDARY.md). The CLSA0102 repo records Windows driver research, THOR/ZEUS observations, kernel trace investigations, failures, source pinning and experiment receipts. This ntoseye document defines the **portable implementation acceptance criteria** and eventual user-facing documentation.

## What belongs here vs what stays in the research lab

| ntoseye contribution | Keep in CLSA0102 (do not clone here) |
| --- | --- |
| Portable classic USB2DBG/KDUSB whole-completion framing, wire-shape and control packet logic | USB2DBG.SYS/dbgeng.dll disassembly, proprietary driver binaries, device-specific trace archives |
| Linux KDUSB adapter and conservative `rusb` error-preserving I/O | Raw THOR/ZEUS host screenshots/logs, local SSH aliases/keys, exact Yoga port history |
| Generic discovery, identity matching, interface ownership, bounded no-retry default | Per-boot controller BDF/power-policy experiments and operator sudo traces |
| Synthetic negative tests: ZLP, partial/error transfer, reset, reuse, stale epochs, lifecycle | Unproven native Linux xHCI instrumentation patches and gigabyte evidence archives |
| User-facing `kdusb doctor` diagnostic design (future) | CLSA0102 R56 physical-admission campaign engine and private operator authorizations |
| Support matrix, setup, operator consent, troubleshooting, examples without machine identifiers | Exact private log bundles and evidence pins that cannot be redistributed |

The generic debugger should **consume validated facts, not rely on a particular research host**. THOR's `0000:74:00.4`, ZEUSWIN's `3.0.4`, serial `123456789`, Windows SSH alias and `CLSA0102_USB` are lab evidence, not universal defaults.

**Do not conflate** classic USB2DBG bulk KDUSB with modern KDNET-over-USB. Existing ntoseye KDNET code and success do not validate the classic protocol.

## Existing fork branches: separate candidates, not an implicit stack

1. **Foundation:** `feature/kdusb-upstreamization-r2` at [`6ef885dd`](https://github.com/oppsig/ntoseye/tree/6ef885dd63ace3e812132e0660e616bd2ee4e61f), the parent of this documentation branch. Has `src/kd/kdusb.rs`, `src/kd/kdusb/tests.rs`, `docs/kdusb.md`, whole-completion normalization, fake bulk I/O, outbound DATA adaptation. Its own documentation explicitly states **no opener/claim and no `--backend kdusb`**.
2. **Experimental named discovery:** `feature/kdusb-windows-4016-receive-r1` at [`9f4c4b39`](https://github.com/oppsig/ntoseye/tree/9f4c4b393e1f3256546c24f84507f6e1649e9b24). Includes an exact-topology `connect_named` opener and `NAME?` discovery on a **different branch lineage**, still not a supported debugger backend. Its local evidence model must be reviewed again before porting.
3. **Offline R39+R40 integration candidate:** `feature/kdusb-r39-r40-offline-candidate-r41` at [`d7cf1498`](https://github.com/oppsig/ntoseye/tree/d7cf1498dd21fa00566f046a71caffd745cb45bf). It documents source-applied corrections and 40 filtered synthetic/offline tests, but its document leaves `stock_kdusb_end_to_end_fix_verified=false`; blocking I/O under shared mutexes, cancellation, per-device one-shot budgets, malformed transfers, and R56 native trace provenance remain unresolved. This is **not live-admitted**.

Choose a verified fork base and reconcile per-file diffs; never simply cherry-pick the newest-sounding branch or turn on an experimental CLI. `master` currently lacks these classic KDUSB additions. The docs branch is deliberately **non-executable**.

## Proposed reusable surface: status-first, attach-last

The proposed interface below is **design syntax, not implemented commands**:

```text
ntoseye kdusb doctor --observe --device <selector> [--json]
ntoseye kdusb doctor --observe --target-evidence <validated-local-file>
ntoseye kdusb doctor --wake-host-controller --pci <BDF>
    --confirm-power-policy-write <same BDF> --evidence-dir <path>
ntoseye --backend kdusb ...             # FUTURE; unsupported until admitted
```

Separate responsibilities:

- **Passive Linux inspector:** read cached sysfs controller presence/vendor/device/driver, PCI `power/control`, `runtime_status`, `power_state`, USB VID/PID, canonical controller ancestry, active configuration/interface/endpoint attributes. If missing, return `UNKNOWN` rather than invent readiness. Never open libusb, perform USBFS descriptor requests, or detach an interface in observation mode.
- **Optional Windows target inventory plugin:** operator-selected SSH/provider or imported **signed/pinned/validated** external observation. It can confirm boot, BCD settings, target controller PCI mapping and known Windows events; BCD alone **never proves** KDUSB target queue readiness. Network input is an explicit opt-in, not part of the default CLI.
- **Explicit Linux power recovery:** an *optional distinct operation*, not `doctor --fix`, not part of attach and never automatic. It should be compiled/installed only after review, take an exact hardware selector and secondary consent, require correct driver/ownership/precondition, save immutable pre/post evidence, attempt at most one narrow `power/control=on` write, emit **separate statuses for controller D0 and device enumeration**, and refuse repeated changes. Policy rollback is distinct and operator-directed. No vendor/device/BDF hard-coded from a single lab.
- **Event/epoch facts:** host boot ID, controller generation, USB device path/busnum/devnum, interface binding, target boot ID and source evidence timestamps. Changes invalidate old attach/transport permissions; an observer's report is a short-lived sample, not an admission token.
- **Transport library:** consumes *separately* admitted candidate/handle ownership; classification and read/write behavior are portable. Never make a device appear merely by running framing tests.

Desired stable JSON status vocabulary should distinguish `CONTROLLER_ABSENT`, `HOST_CONTROLLER_D3COLD_KDUSB_ABSENT` (**correlation only**), `CONTROLLER_ACTIVE_D0`, `KDUSB_ENUMERATED`, `OWNERSHIP_UNKNOWN`, `TARGET_QUEUE_UNKNOWN`, `TRACE_LOSS_UNKNOWN`, `PROBE_NOT_AUTHORIZED`, and typed errors. Distinct boot/device generations and `UNKNOWN` should fail closed. Do not reuse a lab-only schema as stable ntoseye API without a versioned migration.

### Critical recent lesson: power wake is not immediate transport readiness

On 2026-10-13, THOR's AMD `1022:15b7` xHCI controller at `0000:74:00.4` was observed `auto/suspended/D3cold`; KDUSB `3495:00e0` was absent. A single operator-approved write to `power/control=on` was followed by `on/active/D0` and a kernel enumeration of `usb 6-1`, SuperSpeed Plus Gen 2x1 at 10 Gb/s, with bulk IN `0x81` and OUT `0x01` each 1024 bytes. The privileged write and enumeration were logged in the **same journal second, 14:52:19 Europe/Oslo**. A Rust observer's immediate post-write sample still saw zero devices and its follow-up sample saw the device.

Therefore an observer should preserve an **immediate** post-change snapshot and one **bounded settled** snapshot with separate timestamps and `first_seen_in_settled` state, without retrying the power write or claiming causal certainty. This lesson is generalizable; the lab hardware selector and sudo command are not. Detailed provenance remains in the [CLSA0102 incident record](https://github.com/oppsig/CLSA0102-Reverse-Engineering-Project/blob/801c037f0a3a68bffbf921c8ba19b79495416225/docs/KDUSB-D3COLD-ENUMERATION-RECOVERY-2026-10-13.md).

## Porting and release gates

| Step | Required implementable artifact and tests | Current status |
| --- | --- | --- |
| T0 — Foundation | Whole-transfer parser, portable stream normalization, bounded framing, synthetic fixtures, KDNET/KDCOM non-regression | Available *experimentally* on foundation branch |
| T1 — Discovery | No auto detach/alt/reset; exact active interface, endpoint, serial/NAME strategy; stable ownership and cleanup including timeout/exception | **Research candidate only** |
| T2 — I/O safety | Preserve negative libusb statuses, partial semantics, one-shot by physical epoch, clone/cancel reentrancy, terminal failure behavior | **Not fully proven** |
| T3 — Doctor | Portable Linux passive state observer, machine-readable schema, bounded error states, human-readable diagnostics; no live USB opens | **Lab Rust v0.2.1 candidate**, not ported |
| T4 — Optional explicit recovery | Signed-off, platform-specific manual one-policy write with exact confirmation, before/after and rollback | **Lab-only prototype**, not ntoseye feature |
| T5 — Native witness | Exact running xHCI source linkage, direct URB→TD→TRB/retirement and loss accounting, no invisible gaps | **Blocked** in CLSA0102 Stage1H–J |
| T6 — Admitted probe | Exact current boot/device/owner/target queue, native witness, reviewed one-shot budget and cleanup | **NO_GO** |
| T7 — Backend integration | End-to-end tested KD framing, ACK/RESEND, reconnect policy, CLI/docs, supported platforms | **Not implemented or released** |

Before any real `NAME?` or debugging attach, independently close the CLSA0102 R56 G0–G4 safety/provenance gates or a reviewed equivalently strong replacement. Current experimental test results or an enumerated device are **insufficient**.

### Code and documentation standards for eventual upstreamization

- Keep `kdusb` feature Linux-only until other transports are designed; do not surprise macOS users. Keep `rusb` setup explicit.
- Default test suite must use fake bulk/contract fixtures and **never enumerate**, open, reset or control a real USB device. A live hardware test must be explicitly isolated under separate consent and exact fixture settings.
- Document wire/protocol facts with pinned source proofs, distinguish observed bytes vs inferred protocol, cite original public standards without copying proprietary driver code/binaries.
- Preserve all negative and partial transfer statuses; no transparent retry after an uncertain commit or `-EPROTO`.
- Ownership, stream cloning, deadline expiry, cancellation and close must be checked across controller/device generation changes, not only simple happy-path reads.
- Integrate with ntoseye's KD engine and user-facing docs only after capability and safety tests; give the feature an experimental label until actual admitted device tests pass.
- Carry the MIT license and third-party attribution as applicable. Keep private lab captures and machine identifiers in the research evidence store.
- Fork PR first; later prepare a small, reviewed PR against `dmaivel/ntoseye` with links to auditable public/non-sensitive evidence. Do not imply the upstream project has accepted a patch merely because a fork branch exists.

## Maintainer documentation structure after promotion

- `docs/kdusb.md`: protocol, supported/unsupported Windows KD transports, wire behavior, library status.
- `docs/kdusb-doctor.md` (**future**): passive diagnostic taxonomy and versioned JSON schema, privilege boundaries and opt-in recovery.
- `docs/kdusb-setup.md` (**future**): compatible host/target requirements, debug-capable ports, precise owner/claim effects and ordinary attach.
- `docs/kdusb-troubleshooting.md` (**future**): D3cold/PM, missing enumeration vs no NAME response, libusb errors, recovery trees.
- `src/kd/kdusb/` and tests: code behavior and contract tests; no raw/large hardware captures.

**Drift rule:** This file is the ntoseye implementation/release boundary; [CLSA0102's owner document](https://github.com/oppsig/CLSA0102-Reverse-Engineering-Project/blob/docs/kdusb-ntoseye-ownership-and-handoff-r1/docs/KDUSB-NTOSEYE-PROJECT-BOUNDARY.md) remains the history/evidence boundary. Pin commit SHAs when a specific result is promoted and update both sides when a claim or gate changes. Do not silently copy lab-only authorization into a shipping `ntoseye` CLI.
