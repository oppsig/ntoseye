# Phase 3.49K single control probe

Linux-only, dry without arguments. The only live authorization is
`--execute-post-reboot-get-configuration CLSA0102_USB`. The helper must first
prove the manually performed Zeus-only disconnect/re-enumeration boundary.

Cached sysfs on exact physical path 6-1 admits 3495:00e0, config 1, interface
0/alt 0 dc/02/ff, bulk endpoints 01/81 with MPS 1024 and no interface driver.
The current address is discovered dynamically and checked again after opening
the corresponding character node. A writable NTOSEYE_TRACE_MARKER is required.

Exactly one synchronous USBDEVFS_CONTROL asks 80 08 0000 0000 1 with 750 ms
timeout. Only one returned byte 01 satisfies the expectation. Raw errno is
preserved independently from status; no retry occurs, including EINTR.
No claim/detach/reset/configuration/alt/clear-halt/bulk/NAME/KD operations exist.
K01 BEGIN/END markers and epoch timestamps correlate the result with usbmon
and xHCI. Failure to write BEGIN prevents the ioctl; failure of END prevents
a recovery conclusion. Stop after the result, even after success.

This observer derives its direct usbfs ABI and cached descriptor admission
from the admitted Phase I observer. It does not infer a physical cause.
