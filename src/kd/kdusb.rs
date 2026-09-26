//! Classic KDUSB transport constants and wire-contract helpers.
//!
//! These helpers are intentionally pure: no USB device is opened or claimed.
//! They encode the transport contract recovered from Windows USB2DBG host
//! driver and the matching target-side KDUSB transport.

use std::io;

pub(crate) const KDUSB_VENDOR_ID: u16 = 0x3495;
pub(crate) const KDUSB_PRODUCT_ID: u16 = 0x00e0;

pub(crate) const KDUSB_INTERFACE_CLASS: u8 = 0xdc;
pub(crate) const KDUSB_INTERFACE_SUBCLASS: u8 = 0x02;
pub(crate) const KDUSB_INTERFACE_PROTOCOL: u8 = 0xff;

pub(crate) const NAME_PROBE: &[u8; 5] = b"NAME?";
pub(crate) const NAME_RESPONSE_PREFIX: &[u8; 5] = b"NAME=";
pub(crate) const NAME_RESPONSE_MIN: usize = 5;
pub(crate) const NAME_RESPONSE_MAX: usize = 37;
pub(crate) const TARGET_NAME_MAX: usize = 24;

pub(crate) const USB_READ_REQUEST: usize = 0x0fb0;
pub(crate) const USB3_WRITE_CHUNK: usize = 0x1000;

/// Parse the USB2DBG bootstrap reply and return its target name.
///
/// The Windows host accepts 5..=37 bytes, requires NAME=, and passes the
/// suffix to RtlInitAnsiString, so a NUL terminator must be present. The
/// target implementation sends two trailing zero bytes; only the first is
/// semantically required by the host parser.
pub(crate) fn parse_name_response(response: &[u8]) -> io::Result<&str> {
    if !(NAME_RESPONSE_MIN..=NAME_RESPONSE_MAX).contains(&response.len()) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "KDUSB NAME response has invalid length {} (expected {}..={})",
                response.len(),
                NAME_RESPONSE_MIN,
                NAME_RESPONSE_MAX
            ),
        ));
    }
    if !response.starts_with(NAME_RESPONSE_PREFIX) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "KDUSB NAME response is missing NAME= prefix",
        ));
    }

    let suffix = &response[NAME_RESPONSE_PREFIX.len()..];
    let nul = suffix.iter().position(|&byte| byte == 0).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "KDUSB NAME response is not NUL terminated",
        )
    })?;
    let name = &suffix[..nul];
    if name.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "KDUSB target name is empty",
        ));
    }
    if name.len() > TARGET_NAME_MAX {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "KDUSB target name is {} bytes (maximum {})",
                name.len(),
                TARGET_NAME_MAX
            ),
        ));
    }
    std::str::from_utf8(name).map_err(|err| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("KDUSB target name is not UTF-8/ASCII: {err}"),
        )
    })
}

/// Validate a NAME reply against the target name requested by the operator.
pub(crate) fn name_response_matches(response: &[u8], expected: &str) -> io::Result<bool> {
    Ok(parse_name_response(response)? == expected)
}

/// USB3 OUT transfer lengths for one logical byte-stream write.
///
/// Windows USB2DBG limits USB3 body URBs to 4096 bytes. If a non-empty logical
/// write ends exactly on the endpoint maximum packet size, it submits an
/// additional zero-length transfer (ZLP).
pub(crate) fn usb3_write_plan(len: usize, max_packet: usize) -> io::Result<Vec<usize>> {
    if max_packet == 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "KDUSB max packet size cannot be zero",
        ));
    }

    let mut remaining = len;
    let mut chunks = Vec::new();
    while remaining != 0 {
        let chunk = remaining.min(USB3_WRITE_CHUNK);
        chunks.push(chunk);
        remaining -= chunk;
    }
    if len != 0 && len % max_packet == 0 {
        chunks.push(0);
    }
    Ok(chunks)
}

#[cfg(test)]
mod tests {
    use super::*;

    const CLSA0102_REPLY: &[u8] = b"NAME=CLSA0102_USB\0\0";

    #[test]
    fn recovered_constants_match_classic_kdusb_contract() {
        assert_eq!(KDUSB_VENDOR_ID, 0x3495);
        assert_eq!(KDUSB_PRODUCT_ID, 0x00e0);
        assert_eq!(
            (
                KDUSB_INTERFACE_CLASS,
                KDUSB_INTERFACE_SUBCLASS,
                KDUSB_INTERFACE_PROTOCOL
            ),
            (0xdc, 0x02, 0xff)
        );
        assert_eq!(NAME_PROBE, b"NAME?");
        assert_eq!(USB_READ_REQUEST, 4016);
        assert_eq!(USB3_WRITE_CHUNK, 4096);
    }

    #[test]
    fn parses_exact_clsa0102_fixture() {
        assert_eq!(CLSA0102_REPLY.len(), 19);
        assert_eq!(parse_name_response(CLSA0102_REPLY).unwrap(), "CLSA0102_USB");
        assert!(name_response_matches(CLSA0102_REPLY, "CLSA0102_USB").unwrap());
        assert!(!name_response_matches(CLSA0102_REPLY, "OTHER").unwrap());
    }

    #[test]
    fn name_reply_requires_prefix_and_nul() {
        assert!(parse_name_response(b"NOPE=CLSA0102_USB\0\0").is_err());
        assert!(parse_name_response(b"NAME=CLSA0102_USB").is_err());
        assert!(parse_name_response(b"NAME=\0").is_err());
    }

    #[test]
    fn name_reply_enforces_recovered_length_bounds() {
        assert!(parse_name_response(b"NAME").is_err());

        let mut too_long = b"NAME=".to_vec();
        too_long.extend_from_slice(&[b'A'; 32]);
        too_long.push(0);
        assert_eq!(too_long.len(), 38);
        assert!(parse_name_response(&too_long).is_err());
    }

    #[test]
    fn target_name_enforces_target_side_24_byte_limit() {
        let mut response = b"NAME=".to_vec();
        response.extend_from_slice(&[b'A'; TARGET_NAME_MAX]);
        response.extend_from_slice(&[0, 0]);
        assert_eq!(parse_name_response(&response).unwrap().len(), TARGET_NAME_MAX);

        let mut too_long_name = b"NAME=".to_vec();
        too_long_name.extend_from_slice(&[b'A'; TARGET_NAME_MAX + 1]);
        too_long_name.push(0);
        assert!(parse_name_response(&too_long_name).is_err());
    }

    #[test]
    fn write_plan_reproduces_usb3_chunk_and_zlp_rules() {
        assert_eq!(usb3_write_plan(0, 1024).unwrap(), Vec::<usize>::new());
        assert_eq!(usb3_write_plan(1, 1024).unwrap(), vec![1]);
        assert_eq!(usb3_write_plan(1023, 1024).unwrap(), vec![1023]);
        assert_eq!(usb3_write_plan(1024, 1024).unwrap(), vec![1024, 0]);
        assert_eq!(usb3_write_plan(4095, 1024).unwrap(), vec![4095]);
        assert_eq!(usb3_write_plan(4096, 1024).unwrap(), vec![4096, 0]);
        assert_eq!(usb3_write_plan(4097, 1024).unwrap(), vec![4096, 1]);
        assert_eq!(usb3_write_plan(8192, 1024).unwrap(), vec![4096, 4096, 0]);
        assert!(usb3_write_plan(1, 0).is_err());
    }

    #[test]
    fn kd_max_packet_can_span_usb_receive_requests() {
        // KdFraming allows 4000 payload bytes, plus 16-byte header and the
        // 0xAA trailer. The USB stream must tolerate a packet crossing one
        // 4016-byte bulk-IN request boundary by one byte.
        assert_eq!(crate::kd::framing::PACKET_MAX_SIZE + 16 + 1, 4017);
        assert_eq!(USB_READ_REQUEST, 4016);
    }
}
