# KDUSB same-configuration live validation R1

This Phase 3.44BR tool is dry by default and deliberately separates the only
same-configuration operation from the only optional NAME exchange.

Stage 1 discovers exactly one `3495:00e0`, `dc/02/ff` KDUSB interface, requires
configuration 1, interface/altsetting 0, bulk OUT `0x01`, bulk IN `0x81`, and
physical path `6-1`, opens without claiming, refuses an attached kernel driver,
reads the active configuration, and calls `set_active_configuration(current)`
exactly once. It closes and rediscovers the same port, bus, address, descriptors,
configuration, and endpoints. It writes an atomic JSON state with NAME disabled
and performs no bulk transfer.

The project gate then inspects xHCI, usbmon, identity, and journal evidence. Its
machine-readable barrier must reject Reset Device, Address Device, slot churn,
identity instability, absent Configure Endpoint, or unsuccessful Configure
Endpoint completion. The offline `--authorize-name-from-barrier` transition is
the only way to enable Stage 2 in the state.

Stage 2 reopens and claims only the exact stored identity. It creates a retained
exclusive consumption lock and atomically records authorization consumption
before transmitting exact ASCII `NAME?` once. It performs one bounded bulk-IN
read, releases the interface, and never retries. A crash after consumption also
spends the authorization. Raw libusb/OS error fields remain in the structured
transport fault. The project gate correlates one userspace URB with xHCI-internal
transaction-error events; the binary does not infer retry counts from calls.

The implementation contains no USB reset, SET_INTERFACE, detach-driver,
recovery, debugger, target-memory, or KD reply path. A successful live Configure
Endpoint add/replacement on the pinned patched kernel is indirect evidence that
the success path containing `virt_dev->eps[i].err_count = 0` ran. The field is
not exposed and is never claimed as directly observed.

Default invocation prints the dry plan and all hard limits. Live flags are
reserved for the separately admitted project gate.
