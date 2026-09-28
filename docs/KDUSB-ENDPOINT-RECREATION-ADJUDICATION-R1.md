# KDUSB endpoint-recreation adjudication R1

Phase 3.44BQ classifies reapplying the already-active USB configuration as
`SAME_CONFIGURATION_PROVEN` on the pinned prepared CachyOS Linux 7.2.8 source
used by `7.2.8-1-cachyos-clsa0102-xhci-r1`.

Linux routes libusb's same-value `USBDEVFS_SETCONFIGURATION` ioctl to
`usb_reset_configuration()`. It flushes and drops non-EP0 endpoints, adds the
current configuration's altsetting-0 endpoints, and invokes xHCI Configure
Endpoint. `xhci_add_endpoint()` allocates each endpoint's `new_ring`; after a
successful command, `xhci_check_bandwidth()` installs it and executes the BL
`err_count = 0` line. The chain does not call USB device reset or Address
Device. It carries a standard SET_CONFIGURATION request over the existing EP0.

The operation fails with busy if this process, another process, or a kernel
driver has any interface claimed. The R1 implementation therefore opens and
validates a unique candidate without claiming, confirms the active
configuration, makes one same-value call, and only then reacquires and claims
the exact same descriptor identity. The compared identity includes stable
bus/device address (to reject re-enumeration before NAME), physical port path,
VID:PID, configuration, interface, altsetting zero, dc/02/ff selection, bulk
type, endpoints 0x01/0x81, and maximum packet size.

## Future validator

`src/bin/ntoseye-kdusb-endpoint-recreation-validation-r1.rs` exists because the
source decision is PROVEN. It defaults to dry-plan mode. Its explicit future
live flag is:

```text
--execute-same-configuration-reapply CLSA0102_USB
```

Phase 3.44BQ does not invoke that flag and does not authorize an operator to do
so. A future separate gate must own authorization and instrumentation.

Hard limits:

```text
MAX_ENDPOINT_RECREATION_ATTEMPTS=1
MAX_USB_DEVICE_RESET_ATTEMPTS=0
MAX_PRE_OPERATION_NAME_TX=0
MAX_POST_OPERATION_NAME_TX=1
MAX_POST_OPERATION_READS=1
AUTOMATIC_OPERATION_RETRY=false
AUTOMATIC_NAME_RETRY=false
USB_DEVICE_RESET=false
ADDRESS_DEVICE_REQUESTED_BY_TOOL=false
KD_PACKET_TX=false
KD_ACK_TX=false
KD_RESEND_TX=false
KD_RESET_TX=false
KD_FILE_IO_REPLY_TX=false
BREAKIN_SENT=false
DEBUGGER_SESSION=false
TARGET_MEMORY_ACCESS=false
PCI_UNBIND_REBIND=false
XHCI_RELOAD=false
RUNTIME_PM_CHANGE=false
HOST_REBOOT=false
TARGET_REBOOT=false
BCD_CHANGE=false
PHASE340_CLEANUP_AUTHORIZED=false
```

There is no pre-operation NAME. An operation failure, busy interface, changed
active configuration, missing device, ambiguous device, kernel driver binding,
or any post-operation identity mismatch stops before NAME. Only after successful
recreation and identity validation can the state machine send one NAME OUT and
perform one bounded bulk-IN read. Raw rusb/libusb/errno transport information
remains structural in the result.

## Future instrumentation boundary

A later gate should use existing xHCI Configure Endpoint/context, command, and
virtual-device tracepoints plus usbmon. It must establish the endpoint drop/add
and Configure Endpoint completion and reject any observed Address Device, Reset
Device, Enable Slot, Disable Slot, or full re-enumeration before permitting
NAME. The kernel does not expose `xhci_virt_ep.err_count` through these
tracepoints, so no direct observation of that field is claimed.

The source operation itself does not require reset/re-addressing. With the
abort-before-NAME trace policy and exact identity check, the prepared design is
classified `safe_to_run_live_later=true`. That classification is not live
authorization.
