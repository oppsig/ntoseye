use super::*;
use crate::kd::framing::{
    INITIAL_PACKET_ID, KdFraming, PACKET_TYPE_KD_STATE_CHANGE64, PACKET_TYPE_KD_STATE_MANIPULATE,
    SYNC_PACKET_ID,
};

#[derive(Default)]
struct FakeBulk {
    reads: Mutex<VecDeque<Vec<u8>>>,
    writes: Mutex<Vec<Vec<u8>>>,
    capacities: Mutex<Vec<usize>>,
    short_write: bool,
}

impl BulkIo for FakeBulk {
    fn read_bulk(&self, endpoint: u8, bytes: &mut [u8], timeout: Duration) -> io::Result<usize> {
        assert_eq!(endpoint, 0x81);
        assert!(!timeout.is_zero());
        self.capacities.lock().unwrap().push(bytes.len());
        let transfer = self
            .reads
            .lock()
            .unwrap()
            .pop_front()
            .ok_or_else(|| io::Error::new(io::ErrorKind::TimedOut, "fake idle"))?;
        if transfer.len() > bytes.len() {
            return Err(invalid("fake overflow"));
        }
        bytes[..transfer.len()].copy_from_slice(&transfer);
        Ok(transfer.len())
    }
    fn write_bulk(&self, endpoint: u8, bytes: &[u8], _: Duration) -> io::Result<usize> {
        assert_eq!(endpoint, 0x01);
        self.writes.lock().unwrap().push(bytes.to_vec());
        Ok(if self.short_write {
            bytes.len().saturating_sub(1)
        } else {
            bytes.len()
        })
    }
}

fn stream(reads: Vec<Vec<u8>>) -> KdUsbStream<FakeBulk> {
    let io = Arc::new(FakeBulk {
        reads: Mutex::new(reads.into()),
        ..Default::default()
    });
    KdUsbStream::new(
        io,
        BulkEndpoints {
            input: 0x81,
            output: 0x01,
            max_packet: 1024,
        },
        Duration::from_secs(1),
    )
    .unwrap()
}

fn data(id: u32, payload: &[u8], trailer: bool) -> Vec<u8> {
    let mut bytes = Header::data(PACKET_TYPE_KD_STATE_CHANGE64, id, payload)
        .encode()
        .to_vec();
    bytes.extend_from_slice(payload);
    if trailer {
        bytes.push(PACKET_TRAILING_BYTE);
    }
    bytes
}

#[test]
fn cb_shape_is_346_bytes_without_trailer_and_does_not_consume_next_transfer() {
    // Structurally equivalent fixture, NOT the missing captured payload.
    let payload = vec![0x35; 330];
    let bytes = data(INITIAL_PACKET_ID | SYNC_PACKET_ID, &payload, false);
    assert_eq!(bytes.len(), 346);
    assert_eq!(
        classify_transfer(&bytes).unwrap(),
        PacketShape::Data {
            payload_len: 330,
            trailer: false
        }
    );
    let mut kd = KdFraming::new(stream(vec![
        bytes,
        data(INITIAL_PACKET_ID ^ 1, b"next", false),
    ]));
    assert_eq!(kd.recv_data().unwrap().payload, payload);
    assert_eq!(kd.recv_data().unwrap().payload, b"next");
    let writes = kd.transport_ref().io.writes.lock().unwrap();
    assert_eq!(writes.len(), 2);
    assert!(
        writes
            .iter()
            .all(|b| Header::peek(b).unwrap().packet_type == PACKET_TYPE_KD_ACKNOWLEDGE)
    );
}

#[test]
fn retained_prefix_is_incomplete_not_an_invented_checksum_valid_packet() {
    // Retained 64-byte prefix; reported completion length 346. No full payload exists.
    let bytes = hex::decode("3030303007004a0100088080524400003130000019000d00100000000000000040f050980ea7ffff05e02f9b07f8ffff5a0000000000000000000b2a07f8ffff").unwrap();
    assert_eq!(bytes.len(), 64);
    let header = Header::peek(&bytes).unwrap();
    assert!(header.is_data());
    assert_eq!(header.packet_type, 7);
    assert_eq!(header.byte_count, 330);
    assert_eq!(header.packet_id, 0x80800800);
    assert_eq!(header.checksum, 0x4452);
    assert_eq!(HEADER_SIZE + usize::from(header.byte_count), 346);
    assert!(classify_transfer(&bytes).is_err());
}

#[test]
fn tolerates_only_an_exact_in_transfer_aa_trailer() {
    let bytes = data(INITIAL_PACKET_ID, &vec![0x35; 330], true);
    assert_eq!(bytes.len(), 347);
    assert_eq!(
        classify_transfer(&bytes).unwrap(),
        PacketShape::Data {
            payload_len: 330,
            trailer: true
        }
    );
    let mut kd = KdFraming::new(stream(vec![bytes.clone()]));
    assert_eq!(kd.recv_data().unwrap().payload.len(), 330);
    let mut wrong = bytes;
    *wrong.last_mut().unwrap() = 0xbb;
    assert!(classify_transfer(&wrong).is_err());
}

#[test]
fn control_is_exactly_sixteen_bytes_and_ack_bytes_are_preserved() {
    let ack = Header::control(PACKET_TYPE_KD_ACKNOWLEDGE, 0x80800800).encode();
    assert_eq!(hex::encode(ack), "69696969040000000008808000000000");
    assert_eq!(classify_transfer(&ack).unwrap(), PacketShape::Control);
    let mut s = stream(vec![ack.to_vec()]);
    let mut received = [0; 16];
    s.read_exact(&mut received).unwrap();
    assert_eq!(received, ack);
    s.write_all(&ack[..4]).unwrap();
    s.write_all(&ack[4..]).unwrap();
    assert!(s.io.writes.lock().unwrap().is_empty());
    s.flush().unwrap();
    assert_eq!(*s.io.writes.lock().unwrap(), vec![ack.to_vec()]);
    assert!(classify_transfer(&ack[..15]).is_err());
    assert!(classify_transfer(&[ack.as_slice(), &[0xaa]].concat()).is_err());
    assert_eq!(
        hex::encode(Header::control(PACKET_TYPE_KD_RESEND, 0).encode()),
        "69696969050000000000000000000000"
    );
}

#[test]
fn name_probe_preserves_prefetched_kd_before_matching_identity() {
    let payload = b"prefetched-before-name";
    let mut s = stream(vec![
        data(INITIAL_PACKET_ID, payload, false),
        b"NAME=CLSA0102_USB\0\0".to_vec(),
    ]);

    s.probe_name(b"CLSA0102_USB").unwrap();

    {
        let writes = s.io.writes.lock().unwrap();
        assert_eq!(writes.as_slice(), [NAME_PROBE.to_vec()]);
    }

    let mut kd = KdFraming::new(s);
    assert_eq!(kd.recv_data().unwrap().payload, payload);
    let writes = kd.transport_ref().io.writes.lock().unwrap();
    assert_eq!(writes[0], NAME_PROBE);
    assert_eq!(
        Header::peek(&writes[1]).unwrap().packet_type,
        PACKET_TYPE_KD_ACKNOWLEDGE
    );
}

#[test]
fn name_probe_accepts_split_identity_with_zlp_without_losing_deadline() {
    let mut s = stream(vec![
        b"NAME=CLSA".to_vec(),
        vec![],
        b"0102_USB\0\0".to_vec(),
    ]);

    s.probe_name(b"CLSA0102_USB").unwrap();
    assert_eq!(*s.io.writes.lock().unwrap(), vec![NAME_PROBE.to_vec()]);
    assert!(s.take_name().unwrap().is_none());
}

#[test]
fn delayed_name_preserves_entire_pre_name_data_packet() {
    let payload = vec![0x72; 330];
    let mut kd = KdFraming::new(stream(vec![
        data(INITIAL_PACKET_ID, &payload, false),
        b"NAME=TEST_TARGET\0\0".to_vec(),
        data(INITIAL_PACKET_ID ^ 1, b"second", false),
    ]));
    assert_eq!(kd.recv_data().unwrap().payload, payload);
    assert_eq!(kd.transport_ref().take_name().unwrap(), None);
    assert_eq!(kd.recv_data().unwrap().payload, b"second");
    assert_eq!(
        kd.transport_ref().take_name().unwrap().unwrap(),
        b"TEST_TARGET"
    );
}

#[test]
fn split_name_at_every_byte_boundary() {
    let name = b"NAME=TEST_TARGET\0\0";
    for split in 1..name.len() {
        let mut s = stream(vec![
            name[..split].to_vec(),
            name[split..].to_vec(),
            data(INITIAL_PACKET_ID, b"data", false),
        ]);
        let mut kd = KdFraming::new(&mut s);
        assert_eq!(kd.recv_data().unwrap().payload, b"data");
        assert_eq!(s.take_name().unwrap().unwrap(), b"TEST_TARGET");
    }
}

#[test]
fn one_byte_name_reads_and_zlp_do_not_return_fake_eof() {
    let mut reads: Vec<Vec<u8>> = b"NAME=TEST\0\0".iter().map(|b| vec![*b]).collect();
    reads.insert(3, vec![]);
    reads.insert(0, vec![]);
    reads.push(data(INITIAL_PACKET_ID, b"ok", false));
    let mut kd = KdFraming::new(stream(reads));
    assert_eq!(kd.recv_data().unwrap().payload, b"ok");
    assert_eq!(kd.transport_ref().take_name().unwrap().unwrap(), b"TEST");
}

#[test]
fn zlp_only_returns_timeout_and_empty_read_has_no_io() {
    let mut s = stream(vec![vec![], vec![]]);
    assert_eq!(s.read(&mut []).unwrap(), 0);
    assert!(s.io.capacities.lock().unwrap().is_empty());
    assert_eq!(
        s.read(&mut [0]).unwrap_err().kind(),
        io::ErrorKind::TimedOut
    );
}

#[test]
fn tiny_reads_keep_normalized_transfer_boundary() {
    let bytes = data(INITIAL_PACKET_ID, b"whole", false);
    let mut expected = bytes.clone();
    expected.push(0xaa);
    let mut s = stream(vec![bytes]);
    let mut actual = vec![];
    for _ in 0..expected.len() {
        let mut byte = [0];
        assert_eq!(s.read(&mut byte).unwrap(), 1);
        actual.push(byte[0]);
    }
    assert_eq!(actual, expected);
    assert_eq!(*s.io.capacities.lock().unwrap(), vec![RECEIVE_CAPACITY]);
}

#[test]
fn name_like_payload_is_never_discarded_as_discovery() {
    let payload = b"prefixNAME=TEST\0\0suffix";
    let mut kd = KdFraming::new(stream(vec![data(INITIAL_PACKET_ID, payload, false)]));
    assert_eq!(kd.recv_data().unwrap().payload, payload);
    assert_eq!(kd.transport_ref().take_name().unwrap(), None);
}

#[test]
fn maximum_payload_around_4016_quantum() {
    for len in [3999, 4000] {
        for trailer in [false, true] {
            let bytes = data(INITIAL_PACKET_ID, &vec![0x11; len], trailer);
            assert_eq!(bytes.len(), HEADER_SIZE + len + usize::from(trailer));
            let mut kd = KdFraming::new(stream(vec![bytes]));
            assert_eq!(kd.recv_data().unwrap().payload.len(), len);
        }
    }
    assert_eq!(HEADER_SIZE + PACKET_MAX_SIZE, RECEIVE_QUANTUM);
    assert!(classify_transfer(&data(INITIAL_PACKET_ID, &vec![0; 4001], false)).is_err());
}

#[test]
fn incomplete_or_coalesced_transfers_fail_closed() {
    let bytes = data(INITIAL_PACKET_ID, b"whole", false);
    for transfer in [
        bytes[..10].to_vec(),
        bytes[..18].to_vec(),
        [bytes.clone(), bytes].concat(),
    ] {
        let mut s = stream(vec![transfer]);
        assert_eq!(
            s.read(&mut [0]).unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
        assert!(s.io.writes.lock().unwrap().is_empty());
    }
}

#[test]
fn checksums_remain_validated_by_existing_framing() {
    let mut bad = data(INITIAL_PACKET_ID, b"bad", false);
    bad[16] ^= 1;
    let mut kd = KdFraming::new(stream(vec![bad, data(INITIAL_PACKET_ID, b"good", false)]));
    assert_eq!(kd.recv_data().unwrap().payload, b"good");
    let writes = kd.transport_ref().io.writes.lock().unwrap();
    assert_eq!(
        writes[0],
        Header::control(PACKET_TYPE_KD_RESEND, 0).encode()
    );
    assert_eq!(
        writes[1],
        Header::control(PACKET_TYPE_KD_ACKNOWLEDGE, INITIAL_PACKET_ID).encode()
    );
}

#[test]
fn clones_share_unread_data_and_have_independent_write_staging() {
    let mut s = stream(vec![data(INITIAL_PACKET_ID, b"payload", false)]);
    let mut first = [0];
    s.read_exact(&mut first).unwrap();
    let mut clone = s.try_clone().unwrap();
    assert!(Arc::ptr_eq(&s.write_lock, &clone.write_lock));
    let mut rest = vec![0; 16 + 7];
    clone.read_exact(&mut rest).unwrap();
    assert_eq!(rest.last(), Some(&0xaa));
    assert_eq!(s.io.capacities.lock().unwrap().len(), 1);
    let a = Header::control(PACKET_TYPE_KD_ACKNOWLEDGE, 1).encode();
    let b = Header::control(PACKET_TYPE_KD_ACKNOWLEDGE, 2).encode();
    s.write_all(&a[..8]).unwrap();
    clone.write_all(&b).unwrap();
    clone.flush().unwrap();
    s.write_all(&a[8..]).unwrap();
    s.flush().unwrap();
    assert_eq!(*s.io.writes.lock().unwrap(), vec![b.to_vec(), a.to_vec()]);
}

#[test]
fn concurrent_clones_do_not_interleave_control_and_zlp() {
    let mut s = stream(vec![]);
    // Exercise a 16-byte max-packet fake endpoint so each CONTROL needs a ZLP.
    s.endpoints.max_packet = 16;
    let start = Arc::new(std::sync::Barrier::new(3));
    let threads: Vec<_> = (1..=2)
        .map(|id| {
            let mut clone = s.try_clone().unwrap();
            let start = Arc::clone(&start);
            std::thread::spawn(move || {
                start.wait();
                for _ in 0..32 {
                    clone
                        .write_all(&Header::control(PACKET_TYPE_KD_ACKNOWLEDGE, id).encode())
                        .unwrap();
                    clone.flush().unwrap();
                }
            })
        })
        .collect();
    start.wait();
    for thread in threads {
        thread.join().unwrap();
    }
    let writes = s.io.writes.lock().unwrap();
    assert_eq!(writes.len(), 128);
    for pair in writes.chunks_exact(2) {
        assert_eq!(pair[0].len(), 16);
        assert!(pair[1].is_empty());
    }
}

#[test]
fn outbound_data_strips_internal_trailer_before_usb() {
    let payload = [0x35; 56];
    let ack = Header::control(PACKET_TYPE_KD_ACKNOWLEDGE, INITIAL_PACKET_ID)
        .encode()
        .to_vec();
    let mut kd = KdFraming::new(stream(vec![ack]));

    kd.send_data(PACKET_TYPE_KD_STATE_MANIPULATE, &payload)
        .unwrap();

    let mut expected =
        Header::data(PACKET_TYPE_KD_STATE_MANIPULATE, INITIAL_PACKET_ID, &payload)
            .encode()
            .to_vec();
    expected.extend_from_slice(&payload);
    assert_eq!(expected.len(), 72);

    let writes = kd.transport_ref().io.writes.lock().unwrap();
    assert_eq!(*writes, vec![expected]);
    assert_ne!(writes[0].last(), Some(&PACKET_TRAILING_BYTE));
}

#[test]
fn usb_data_uses_wire_length_for_zlp_after_trailer_strip() {
    // 16-byte header + 1008-byte payload = one exact 1024-byte USB transfer.
    // Generic KdFraming stages 1025 bytes including its internal 0xaa; the USB
    // adapter strips it first, so the recovered USB2DBG ZLP rule applies to 1024.
    let payload = vec![0x41; 1008];
    let ack = Header::control(PACKET_TYPE_KD_ACKNOWLEDGE, INITIAL_PACKET_ID)
        .encode()
        .to_vec();
    let mut kd = KdFraming::new(stream(vec![ack]));

    kd.send_data(PACKET_TYPE_KD_STATE_MANIPULATE, &payload)
        .unwrap();

    let writes = kd.transport_ref().io.writes.lock().unwrap();
    assert_eq!(writes.len(), 2);
    assert_eq!(writes[0].len(), 1024);
    assert!(writes[1].is_empty());
    assert_ne!(writes[0].last(), Some(&PACKET_TRAILING_BYTE));
}

#[test]
fn direct_trailerless_data_and_breakin_remain_rejected_at_internal_boundary() {
    let mut s = stream(vec![]);
    let bare = data(INITIAL_PACKET_ID, b"payload", false);
    s.write_all(&bare).unwrap();
    assert_eq!(s.flush().unwrap_err().kind(), io::ErrorKind::InvalidData);
    assert!(s.io.writes.lock().unwrap().is_empty());

    s.write_all(&[BREAKIN_BYTE]).unwrap();
    assert_eq!(s.flush().unwrap_err().kind(), io::ErrorKind::Unsupported);
    assert!(s.io.writes.lock().unwrap().is_empty());
}

#[test]
fn short_write_is_not_replayed_by_this_stream_or_its_clone() {
    let mut s = stream(vec![]);
    Arc::get_mut(&mut s.io).unwrap().short_write = true;
    let mut clone = s.try_clone().unwrap();
    let ack = Header::control(PACKET_TYPE_KD_ACKNOWLEDGE, INITIAL_PACKET_ID).encode();
    s.write_all(&ack).unwrap();
    assert_eq!(s.flush().unwrap_err().kind(), io::ErrorKind::WriteZero);
    clone.write_all(&ack).unwrap();
    assert!(clone.flush().is_err());
    assert_eq!(s.io.writes.lock().unwrap().len(), 1);
}

#[test]
fn write_plan_is_independent_of_outbound_data_trailer() {
    for (len, expected) in [
        (0, vec![]),
        (1, vec![1]),
        (1024, vec![1024, 0]),
        (4096, vec![4096, 0]),
        (4097, vec![4096, 1]),
        (8192, vec![4096, 4096, 0]),
    ] {
        assert_eq!(usb3_write_plan(len, 1024).unwrap(), expected);
    }
    assert!(usb3_write_plan(1, 0).is_err());
}

#[test]
fn name_validation_and_bounded_timeout() {
    for name in [
        b"NAME=\0\0".as_slice(),
        b"NAME=TEST\0",
        b"NAME=bad\0inside\0\0",
    ] {
        assert!(parse_name(name).is_err());
    }
    assert!(parse_name(&[b"NAME=".as_slice(), &[b'X'; 25], &[0, 0]].concat()).is_err());
    let mut s = stream(vec![]);
    assert!(s.set_read_timeout(Duration::ZERO).is_err());
    s.set_read_timeout(Duration::from_millis(20)).unwrap();
    assert_eq!(s.timeout, Duration::from_millis(20));
}

#[test]
fn libusb_timeouts_never_round_to_infinite_or_wrap() {
    assert_eq!(usb_timeout_ms(Duration::from_nanos(1)).unwrap(), 1);
    assert_eq!(usb_timeout_ms(Duration::from_micros(1500)).unwrap(), 2);
    assert_eq!(usb_timeout_ms(Duration::from_millis(20)).unwrap(), 20);
    assert!(usb_timeout_ms(Duration::ZERO).is_err());
    assert!(usb_timeout_ms(Duration::from_millis(u64::from(u32::MAX) + 1)).is_err());
}

#[test]
fn partial_libusb_errors_never_become_successful_transfer_boundaries() {
    use rusb::constants::*;
    assert_eq!(bulk_result(0, 346, 4017).unwrap(), 346);
    assert_eq!(bulk_result(0, 0, 4017).unwrap(), 0);
    assert!(bulk_result(0, -1, 4017).is_err());
    assert!(bulk_result(0, 4018, 4017).is_err());
    assert_eq!(
        bulk_result(LIBUSB_ERROR_TIMEOUT, 0, 4017)
            .unwrap_err()
            .kind(),
        io::ErrorKind::TimedOut
    );
    assert_eq!(
        bulk_result(LIBUSB_ERROR_TIMEOUT, 346, 4017)
            .unwrap_err()
            .kind(),
        io::ErrorKind::InvalidData
    );
    assert_eq!(
        bulk_result(LIBUSB_ERROR_INTERRUPTED, 346, 4017)
            .unwrap_err()
            .kind(),
        io::ErrorKind::InvalidData
    );
    assert_eq!(
        bulk_result(LIBUSB_ERROR_OVERFLOW, 346, 4017)
            .unwrap_err()
            .kind(),
        io::ErrorKind::InvalidData
    );
}
