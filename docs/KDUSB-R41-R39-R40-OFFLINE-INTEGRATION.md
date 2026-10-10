# R41 — R39 + R40 KDUSB offline candidate integration

## Scope and provenance

This branch is a **candidate-only** integration of two already-reviewed patch artifacts; it is not an authorization to execute a debugger, access a USB controller, or attempt native KDUSB communication.

- **Fork baseline (unchanged ancestor):** `9f4c4b393e1f3256546c24f84507f6e1649e9b24` — `feature/kdusb-windows-4016-receive-r1`.
- **CLSA0102 evidence publication:** `b4edde8feb0dd127e98fa24b46c866fd6c5ee01b` — `phase3-49zc-r40-isolated-rust-verification-tty-r1`.
- **R39 artifact:** `engineering/phase-3.49zc/kdusb-windows-4016-receive/r39-stock-offline-remediation/ntoseye-kdusb-offline-remediation.patch`, published SHA-256 `251d2a9ed98ff080a701d1ba6518c8789e35551744b3d8fe54d0d83da7f18a00`.
- **R40 corrective delta:** `engineering/phase-3.49zc/kdusb-windows-4016-receive/r40-isolated-rust-verification/r40-ntoseye-candidate.patch`, published SHA-256 `ff905eda8ae135c596f3ea525fa9b3d08a3dd3daf91428cfa9fce35cbd6e28c2`.
- **Order:** base at exact historical commit → exact R39 patch → exact R40 delta. The R40 patch alone cannot be applied to the historical source.
- **Changed fork files:** `src/kd/kdusb.rs` and `src/kd/framing.rs` only, plus this explanatory document. No changes to `Cargo.toml`, `Cargo.lock`, other source modules, historical test files, or the fork's `master`.
- **Deterministic Git blob identities:** R39-patched `src/kd/kdusb.rs` `c1640c4863e6b216a772863f69202c7dcd687fff`; final R40 `src/kd/kdusb.rs` `fd3c860f71d93510b9f5b250adfce0c6f92c8d81`; R39/R40 `src/kd/framing.rs` `86c05218354794e62018b7d1649767ea8e318e7c`.

The source was reconstructed by a strict line-by-line unified-diff parser that verified hunk context, source positions, old/new line counts and expected patch paths. The intermediate and final kdusb.rs Git blob identities match the exact R40 patch's old/new `index` markers (`c1640c4..fd3c860`).

## Offline evidence and next independent tests

The trusted R40 parent independently compiled/tested the R39-patched baseline (32 filtered tests) and R40 final candidate (40 filtered tests; zero failed), and accepted the nine report artifacts, with `stock_kdusb_end_to_end_fix_verified=false`. **No Cargo invocation is claimed for this new GitHub R41 branch itself.** Verify the checked-out branch on Thor, using exclusively offline commands:

```fish
cargo test --offline --locked --no-default-features --lib kd::kdusb::tests:: -- --test-threads=1
cargo check --offline --locked --no-default-features --lib
```

The `cargo check` command tests the non-`cfg(test)` Rust library compile path (not a running debugger); it is separate from the historical 40-test evidence. Do not run `cargo run`, tests without an exact filter, integration/binary/live tests, or any USB/device discovery tools.

## Security, protocol and release boundary

The final R40 revision makes `admit_packet_io` private and `#[cfg(test)]`; production packet I/O remains denied by default even after receiving `NAME=CLSA0102_USB\0\0`. Read and nonempty flush independently enforce packet admission, and shared clones retain one NAME probe budget and terminal failures. The implementation uses exactly one five-byte NAME? OUT and at most one conditional 4016-byte IN per stream generation. It retains partial failure context and suppresses additional frames after typed terminal transport faults.

**Still unresolved:** blocking libusb under shared mutexes and callback reentry/cancellation; lossy discovery error propagation; extra NAME tails, malformed/partial packet semantics and device-global one-shot enforcement; the R39 passive D3COLD post-terminal classifier counterexample; endpoint/host/target chronology and the physical source of the xHCI/EPROTO failures. New instances can reestablish a one-probe budget, so this is not physical admission. Do not expose packet admission to production until independently authorized.

```text
R22_RELEASE=BLOCKED
R23_NATIVE_ADMISSION=BLOCKED
ONE_SHOT_CONSUMED=NOT_RUN
HOST_USB_RELEASED=NOT_EVALUATED
ZEUS_REBOOT_CLEARANCE=NOT_EVALUATED
ZEUS_REBOOT_SAFE=NOT_EVALUATED
BOOT_ROLLBACK_PROVEN=false
SAFE_PARALLEL_KERNEL_INSTALL_AUTHORIZED=false
ZEUS_POWEROFF_CLEARANCE=NOT_ESTABLISHED
```

**Do not power off Zeus yet.** No hardware use, kernel change, USB action or target action is authorized by this branch. The `master` branch is unchanged. Future rebasing onto newer upstream ntoseye is a separate, evidence-preserving operation; it must not silently overwrite this candidate.
