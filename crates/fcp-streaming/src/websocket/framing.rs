//! Bounded visibility into inbound frame boundaries.
//!
//! The WebSocket codec still validates RFC 6455 headers, payload limits and
//! message contents. This tracker closes a dependency gap: a Close frame must
//! not silently discard an unfinished fragmented data message. It retains no
//! payload bytes and also distinguishes truncated frames/messages from EOF
//! between complete messages.

use std::io;

#[derive(Clone, Copy, Debug)]
enum FramingFailure {
    InterruptedMessage,
    IncompleteFrame,
    IncompleteMessage,
}

impl FramingFailure {
    fn error(self) -> io::Error {
        let (kind, message) = match self {
            Self::InterruptedMessage => (
                io::ErrorKind::InvalidData,
                "WebSocket close interrupted a fragmented message",
            ),
            Self::IncompleteFrame => (
                io::ErrorKind::UnexpectedEof,
                "WebSocket connection ended during an incomplete frame",
            ),
            Self::IncompleteMessage => (
                io::ErrorKind::UnexpectedEof,
                "WebSocket connection ended during an incomplete fragmented message",
            ),
        };
        io::Error::new(kind, message)
    }
}

#[derive(Debug)]
pub(crate) struct InboundFraming {
    header: [u8; 14],
    header_len: usize,
    header_needed: usize,
    payload_remaining: u64,
    fragmented: bool,
    failure: Option<FramingFailure>,
}

impl InboundFraming {
    pub(crate) const fn new() -> Self {
        Self {
            header: [0; 14],
            header_len: 0,
            header_needed: 2,
            payload_remaining: 0,
            fragmented: false,
            failure: None,
        }
    }

    /// Stop each read at the next header or payload boundary. Besides bounding
    /// state, this lets the codec deliver an earlier complete message before a
    /// later invalid frame that arrived in the same TCP/TLS read.
    pub(crate) fn read_limit(&self) -> io::Result<usize> {
        self.check_valid()?;
        if self.payload_remaining > 0 {
            Ok(usize::try_from(self.payload_remaining).unwrap_or(usize::MAX))
        } else {
            Ok(self.header_needed - self.header_len)
        }
    }

    pub(crate) fn observe(&mut self, mut bytes: &[u8]) -> io::Result<()> {
        self.check_valid()?;
        while !bytes.is_empty() {
            if self.payload_remaining > 0 {
                let count = usize::try_from(self.payload_remaining)
                    .unwrap_or(usize::MAX)
                    .min(bytes.len());
                // count is bounded by the u64 payload length above.
                self.payload_remaining -= u64::try_from(count).unwrap_or(u64::MAX);
                bytes = &bytes[count..];
                if self.payload_remaining == 0 {
                    self.finish_frame();
                }
                continue;
            }

            let count = (self.header_needed - self.header_len).min(bytes.len());
            self.header[self.header_len..self.header_len + count]
                .copy_from_slice(&bytes[..count]);
            self.header_len += count;
            bytes = &bytes[count..];
            if self.header_len < self.header_needed {
                continue;
            }
            if self.header_len == 2 {
                if self.header[0] & 0x0f == 0x08 && self.fragmented {
                    return self.fail(FramingFailure::InterruptedMessage);
                }
                self.header_needed = 2
                    + match self.header[1] & 0x7f {
                        126 => 2,
                        127 => 8,
                        _ => 0,
                    }
                    + if self.header[1] & 0x80 != 0 { 4 } else { 0 };
                if self.header_needed > 2 {
                    continue;
                }
            }

            self.payload_remaining = match self.header[1] & 0x7f {
                126 => u64::from(u16::from_be_bytes([self.header[2], self.header[3]])),
                127 => u64::from_be_bytes([
                    self.header[2],
                    self.header[3],
                    self.header[4],
                    self.header[5],
                    self.header[6],
                    self.header[7],
                    self.header[8],
                    self.header[9],
                ]),
                length => u64::from(length),
            };
            if self.payload_remaining == 0 {
                self.finish_frame();
            }
        }
        Ok(())
    }

    pub(crate) fn end_of_stream(&mut self) -> io::Result<()> {
        self.check_valid()?;
        if self.header_len != 0 || self.payload_remaining != 0 {
            self.fail(FramingFailure::IncompleteFrame)
        } else if self.fragmented {
            self.fail(FramingFailure::IncompleteMessage)
        } else {
            Ok(())
        }
    }

    fn finish_frame(&mut self) {
        let opcode = self.header[0] & 0x0f;
        let final_fragment = self.header[0] & 0x80 != 0;
        if opcode == 0 && final_fragment {
            self.fragmented = false;
        } else if matches!(opcode, 1 | 2) && !final_fragment {
            self.fragmented = true;
        }
        // Interleaved Ping/Pong frames cannot complete the pending message.
        self.header_len = 0;
        self.header_needed = 2;
    }

    fn check_valid(&self) -> io::Result<()> {
        self.failure.map_or(Ok(()), |failure| Err(failure.error()))
    }

    fn fail(&mut self, failure: FramingFailure) -> io::Result<()> {
        self.failure = Some(failure);
        Err(failure.error())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn frame(first: u8, payload: &[u8]) -> Vec<u8> {
        let mut frame = vec![first];
        if payload.len() < 126 {
            frame.push(u8::try_from(payload.len()).unwrap());
        } else if let Ok(length) = u16::try_from(payload.len()) {
            frame.push(126);
            frame.extend_from_slice(&length.to_be_bytes());
        } else {
            frame.push(127);
            frame.extend_from_slice(&u64::try_from(payload.len()).unwrap().to_be_bytes());
        }
        frame.extend_from_slice(payload);
        frame
    }

    #[test]
    fn close_cannot_discard_fragmented_text_or_binary_after_control_frames() {
        for opcode in [1, 2] {
            for controls in [vec![], vec![0x89, 1, b'p', 0x8a, 0]] {
                let mut wire = frame(opcode, b"partial");
                wire.extend(controls);
                wire.extend(frame(0, b"still partial"));
                wire.extend([0x88, 2, 0x03, 0xe8]);
                for chunk_size in 1..=wire.len() {
                    let mut framing = InboundFraming::new();
                    let error = wire
                        .chunks(chunk_size)
                        .try_for_each(|chunk| framing.observe(chunk))
                        .unwrap_err();
                    assert_eq!(error.kind(), io::ErrorKind::InvalidData);
                    assert!(error.to_string().contains("fragmented message"));
                    assert!(framing.observe(&[0x80, 0]).is_err());
                    assert!(framing.end_of_stream().is_err());
                    assert!(framing.read_limit().is_err());
                }
            }
        }
    }

    #[test]
    fn complete_fragmented_messages_allow_ping_pong_and_normal_close() {
        for opcode in [1, 2] {
            let mut wire = frame(opcode, b"first");
            wire.extend([0x89, 1, b'p', 0x8a, 0]);
            wire.extend(frame(0, b"middle"));
            wire.extend(frame(0x80, b"last"));
            wire.extend(frame(0x82, b"next complete message"));
            wire.extend([0x88, 2, 0x03, 0xe8]);
            for chunk_size in 1..=wire.len() {
                let mut framing = InboundFraming::new();
                for chunk in wire.chunks(chunk_size) {
                    framing.observe(chunk).unwrap();
                    assert!(framing.read_limit().unwrap() > 0);
                }
                framing.end_of_stream().unwrap();
            }
        }
    }

    #[test]
    fn eof_rejects_every_partial_header_and_body_length() {
        for header in [
            vec![0x82, 3],
            vec![0x82, 126, 0, 126],
            vec![0x82, 127, 0, 0, 0, 0, 0, 1, 0, 0],
            // The codec separately rejects masked server frames; tracking the
            // mask key still must not confuse its bytes with payload/headers.
            vec![0x82, 0x83, 1, 2, 3, 4],
            vec![0x82, 0xfe, 0, 126, 1, 2, 3, 4],
            vec![0x82, 0xff, 0, 0, 0, 0, 0, 1, 0, 0, 1, 2, 3, 4],
        ] {
            for prefix in 1..header.len() {
                let mut framing = InboundFraming::new();
                framing.observe(&header[..prefix]).unwrap();
                assert_eq!(
                    framing.end_of_stream().unwrap_err().kind(),
                    io::ErrorKind::UnexpectedEof,
                    "{header:?}, prefix {prefix}"
                );
            }
            for body_length in 0..3 {
                let mut framing = InboundFraming::new();
                framing.observe(&header).unwrap();
                framing.observe(&vec![b'x'; body_length]).unwrap();
                assert_eq!(
                    framing.end_of_stream().unwrap_err().kind(),
                    io::ErrorKind::UnexpectedEof
                );
            }
        }
    }

    #[test]
    fn final_continuation_is_complete_only_after_its_whole_payload() {
        let mut framing = InboundFraming::new();
        framing.observe(&[0x02, 1, b'a']).unwrap();
        framing.observe(&[0x80, 2, b'b']).unwrap();
        assert!(framing.fragmented);
        assert_eq!(framing.read_limit().unwrap(), 1);
        framing.observe(&[b'c']).unwrap();
        assert!(!framing.fragmented);
        framing.observe(&[0x88, 0]).unwrap();
        framing.end_of_stream().unwrap();
    }

    #[test]
    fn empty_frames_do_not_create_zero_capacity_reads_or_complete_fragments() {
        let mut framing = InboundFraming::new();
        for bytes in [[0x81, 0], [0x02, 0], [0x89, 0], [0x8a, 0], [0x00, 0]] {
            framing.observe(&bytes).unwrap();
            assert_eq!(framing.read_limit().unwrap(), 2);
        }
        assert!(framing.fragmented);
        framing.observe(&[0x80, 0]).unwrap();
        framing.observe(&[0x88, 0]).unwrap();
        assert_eq!(framing.read_limit().unwrap(), 2);
        framing.end_of_stream().unwrap();
    }

    #[test]
    fn payload_close_bytes_and_extended_lengths_do_not_change_framing() {
        for length in [4, 126, 65_536] {
            let mut payload = vec![0; length];
            payload[..4].copy_from_slice(&[0x88, 2, 0x03, 0xe8]);
            let mut wire = frame(0x02, &payload);
            wire.extend([0x80, 0, 0x88, 2, 0x03, 0xe8]);
            for chunk_size in [1, 2, 3, 7, 4096, wire.len()] {
                let mut framing = InboundFraming::new();
                for chunk in wire.chunks(chunk_size) {
                    framing.observe(chunk).unwrap();
                }
                framing.end_of_stream().unwrap();
                assert_eq!(framing.read_limit().unwrap(), 2);
            }
        }
    }

    #[test]
    fn frame_header_never_allocates_from_a_peer_length() {
        let mut framing = InboundFraming::new();
        let mut header = vec![0x82, 127];
        header.extend_from_slice(&u64::MAX.to_be_bytes());
        framing.observe(&header).unwrap();
        assert_eq!(framing.header.len(), 14);
        assert_eq!(framing.payload_remaining, u64::MAX);
        assert_eq!(
            framing.read_limit().unwrap(),
            usize::try_from(u64::MAX).unwrap_or(usize::MAX)
        );
        assert!(framing.end_of_stream().is_err());
    }

    #[test]
    fn eof_between_messages_is_preserved_but_pending_message_is_rejected() {
        let mut framing = InboundFraming::new();
        framing.end_of_stream().unwrap();
        framing.observe(&frame(0x81, b"complete")).unwrap();
        framing.end_of_stream().unwrap();
        framing.observe(&frame(0x02, b"unfinished")).unwrap();
        let error = framing.end_of_stream().unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::UnexpectedEof);
        assert!(error.to_string().contains("incomplete fragmented message"));
    }
}
