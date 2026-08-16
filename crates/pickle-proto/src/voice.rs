//! Voice datagram encoding.
//!
//! Voice rides on QUIC datagrams, which are unreliable and unordered. That is
//! deliberate: a 20 ms audio frame that arrives late is useless, and asking for
//! it again would stall every frame behind it. Loss is handled where it belongs
//! — in the jitter buffer and Opus's own packet-loss concealment.
//!
//! These headers are hand-rolled rather than serde-encoded. This is the hot
//! path, one packet every 20 ms per speaker, and the layout should be obvious
//! from the wire bytes alone.
//!
//! # Why there is no channel id
//!
//! An upstream packet says nothing about which channel it belongs to. The
//! server already knows which channel the sender is in and routes on that. If
//! the client named the channel instead, anyone could transmit into a channel
//! they had never joined.

use crate::ClientId;
use bytes::{BufMut, Bytes, BytesMut};

/// Opus is used at 48 kHz throughout; it is the codec's native rate and avoids
/// a resampling stage on both ends.
pub const SAMPLE_RATE: u32 = 48_000;

/// Mono. Voice chat gains nothing from stereo capture, and halving the payload
/// matters more.
pub const CHANNELS: usize = 1;

/// 20 ms per frame — the usual balance between per-packet overhead and latency.
pub const FRAME_MS: u32 = 20;

/// Samples in one frame, per channel: 960 at 48 kHz.
pub const SAMPLES_PER_FRAME: usize = (SAMPLE_RATE as usize / 1000) * FRAME_MS as usize;

/// Largest packet Opus will emit for a single frame.
pub const MAX_OPUS_PACKET: usize = 1275;

pub const UPSTREAM_HEADER_LEN: usize = 6;
pub const DOWNSTREAM_HEADER_LEN: usize = 10;

/// Enough for the biggest downstream packet; sizes the datagram send buffer.
pub const MAX_DATAGRAM_LEN: usize = DOWNSTREAM_HEADER_LEN + MAX_OPUS_PACKET;

const TAG_UPSTREAM: u8 = 1;
const TAG_DOWNSTREAM: u8 = 2;

/// Marks the first packet of a talk burst. Receivers reset their jitter buffer
/// on it rather than trying to reconcile the silence gap as loss.
pub const FLAG_BURST_START: u8 = 1 << 0;
/// Marks the last packet of a talk burst, letting receivers drain and release
/// the buffer instead of waiting for a timeout.
pub const FLAG_BURST_END: u8 = 1 << 1;

#[derive(Debug, thiserror::Error)]
pub enum VoiceDecodeError {
    #[error("voice datagram of {0} bytes is too short for its header")]
    TooShort(usize),
    #[error("unknown voice datagram tag {0}")]
    UnknownTag(u8),
    #[error("voice payload of {0} bytes exceeds the maximum Opus packet size")]
    PayloadTooLarge(usize),
}

/// Client to server: one encoded Opus frame.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VoiceUpstream {
    /// Per-sender, wrapping. Drives loss detection and reordering.
    pub seq: u32,
    pub flags: u8,
    pub payload: Bytes,
}

/// Server to client: the same frame, stamped with who sent it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VoiceDownstream {
    pub sender: ClientId,
    pub seq: u32,
    pub flags: u8,
    pub payload: Bytes,
}

impl VoiceUpstream {
    pub fn encode(&self) -> Bytes {
        let mut buf = BytesMut::with_capacity(UPSTREAM_HEADER_LEN + self.payload.len());
        buf.put_u8(TAG_UPSTREAM);
        buf.put_u32_le(self.seq);
        buf.put_u8(self.flags);
        buf.put_slice(&self.payload);
        buf.freeze()
    }

    pub fn decode(datagram: Bytes) -> Result<Self, VoiceDecodeError> {
        if datagram.len() < UPSTREAM_HEADER_LEN {
            return Err(VoiceDecodeError::TooShort(datagram.len()));
        }
        if datagram[0] != TAG_UPSTREAM {
            return Err(VoiceDecodeError::UnknownTag(datagram[0]));
        }

        let seq = u32::from_le_bytes(datagram[1..5].try_into().expect("checked length"));
        let flags = datagram[5];
        let payload = datagram.slice(UPSTREAM_HEADER_LEN..);
        if payload.len() > MAX_OPUS_PACKET {
            return Err(VoiceDecodeError::PayloadTooLarge(payload.len()));
        }

        Ok(Self {
            seq,
            flags,
            payload,
        })
    }

    /// Relay this frame to listeners, attributing it to `sender`.
    ///
    /// The payload is a `Bytes` slice of the original datagram, so forwarding
    /// does not re-copy the audio.
    pub fn into_downstream(self, sender: ClientId) -> VoiceDownstream {
        VoiceDownstream {
            sender,
            seq: self.seq,
            flags: self.flags,
            payload: self.payload,
        }
    }
}

impl VoiceDownstream {
    pub fn encode(&self) -> Bytes {
        let mut buf = BytesMut::with_capacity(DOWNSTREAM_HEADER_LEN + self.payload.len());
        buf.put_u8(TAG_DOWNSTREAM);
        buf.put_u32_le(self.sender);
        buf.put_u32_le(self.seq);
        buf.put_u8(self.flags);
        buf.put_slice(&self.payload);
        buf.freeze()
    }

    pub fn decode(datagram: Bytes) -> Result<Self, VoiceDecodeError> {
        if datagram.len() < DOWNSTREAM_HEADER_LEN {
            return Err(VoiceDecodeError::TooShort(datagram.len()));
        }
        if datagram[0] != TAG_DOWNSTREAM {
            return Err(VoiceDecodeError::UnknownTag(datagram[0]));
        }

        let sender = u32::from_le_bytes(datagram[1..5].try_into().expect("checked length"));
        let seq = u32::from_le_bytes(datagram[5..9].try_into().expect("checked length"));
        let flags = datagram[9];
        let payload = datagram.slice(DOWNSTREAM_HEADER_LEN..);
        if payload.len() > MAX_OPUS_PACKET {
            return Err(VoiceDecodeError::PayloadTooLarge(payload.len()));
        }

        Ok(Self {
            sender,
            seq,
            flags,
            payload,
        })
    }

    pub fn starts_burst(&self) -> bool {
        self.flags & FLAG_BURST_START != 0
    }

    pub fn ends_burst(&self) -> bool {
        self.flags & FLAG_BURST_END != 0
    }
}

/// True when `a` is newer than `b`, tolerating `u32` wraparound.
///
/// Sequence numbers wrap after roughly 994 days of continuous speech, but they
/// also restart per talk burst, so plain `>` would mishandle the rollover.
/// Comparing the signed difference treats anything within half the space as
/// "ahead".
pub fn seq_newer_than(a: u32, b: u32) -> bool {
    a != b && a.wrapping_sub(b) < (u32::MAX / 2)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frame_geometry_matches_opus_expectations() {
        assert_eq!(SAMPLES_PER_FRAME, 960);
    }

    #[test]
    fn upstream_roundtrips() {
        let packet = VoiceUpstream {
            seq: 1234,
            flags: FLAG_BURST_START,
            payload: Bytes::from_static(&[1, 2, 3, 4, 5]),
        };
        assert_eq!(VoiceUpstream::decode(packet.encode()).unwrap(), packet);
    }

    #[test]
    fn downstream_roundtrips() {
        let packet = VoiceDownstream {
            sender: 42,
            seq: u32::MAX,
            flags: FLAG_BURST_END,
            payload: Bytes::from_static(&[9; 60]),
        };
        let back = VoiceDownstream::decode(packet.encode()).unwrap();
        assert_eq!(back, packet);
        assert!(back.ends_burst() && !back.starts_burst());
    }

    #[test]
    fn relaying_preserves_sequence_and_flags() {
        let up = VoiceUpstream {
            seq: 77,
            flags: FLAG_BURST_START,
            payload: Bytes::from_static(&[7; 20]),
        };
        let down = up.clone().into_downstream(5);
        assert_eq!(down.sender, 5);
        assert_eq!(down.seq, up.seq);
        assert_eq!(down.flags, up.flags);
        assert_eq!(down.payload, up.payload);
    }

    #[test]
    fn an_empty_payload_is_valid() {
        // Opus emits tiny packets for silence; a zero-length one must not be
        // mistaken for a truncated header.
        let packet = VoiceUpstream {
            seq: 1,
            flags: 0,
            payload: Bytes::new(),
        };
        let encoded = packet.encode();
        assert_eq!(encoded.len(), UPSTREAM_HEADER_LEN);
        assert_eq!(VoiceUpstream::decode(encoded).unwrap(), packet);
    }

    #[test]
    fn a_truncated_datagram_is_rejected() {
        for len in 0..UPSTREAM_HEADER_LEN {
            let short = Bytes::from(vec![TAG_UPSTREAM; len]);
            assert!(matches!(
                VoiceUpstream::decode(short),
                Err(VoiceDecodeError::TooShort(_))
            ));
        }
    }

    #[test]
    fn the_two_directions_do_not_decode_as_each_other() {
        // A client must not be able to pass off a downstream packet as its own
        // upstream, or it could forge the sender field.
        let down = VoiceDownstream {
            sender: 1,
            seq: 2,
            flags: 0,
            payload: Bytes::from_static(&[0; 10]),
        }
        .encode();
        assert!(matches!(
            VoiceUpstream::decode(down),
            Err(VoiceDecodeError::UnknownTag(TAG_DOWNSTREAM))
        ));
    }

    #[test]
    fn an_oversized_payload_is_rejected() {
        let packet = VoiceUpstream {
            seq: 0,
            flags: 0,
            payload: Bytes::from(vec![0u8; MAX_OPUS_PACKET + 1]),
        };
        assert!(matches!(
            VoiceUpstream::decode(packet.encode()),
            Err(VoiceDecodeError::PayloadTooLarge(_))
        ));
    }

    #[test]
    fn sequence_comparison_handles_wraparound() {
        assert!(seq_newer_than(5, 4));
        assert!(!seq_newer_than(4, 5));
        assert!(!seq_newer_than(5, 5));
        // Straddling the rollover.
        assert!(seq_newer_than(1, u32::MAX));
        assert!(!seq_newer_than(u32::MAX, 1));
    }

    #[test]
    fn max_datagram_len_covers_the_largest_encodable_packet() {
        let packet = VoiceDownstream {
            sender: u32::MAX,
            seq: u32::MAX,
            flags: 0xff,
            payload: Bytes::from(vec![0u8; MAX_OPUS_PACKET]),
        };
        assert_eq!(packet.encode().len(), MAX_DATAGRAM_LEN);
    }
}
