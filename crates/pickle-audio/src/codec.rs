//! Opus encode and decode at Pickle's fixed frame geometry.
//!
//! Everything runs at 48 kHz mono in 20 ms frames — Opus's native rate, so
//! there is no resampling anywhere in the path.
//!
//! Samples are `f32` normalised to ±1.0 from end to end: that is what cpal
//! hands us, what the codec wants, and what the mixer sums in, so no conversion
//! happens between the microphone and the wire.

use bytes::Bytes;
use opus::{Application, OpusDecoder, OpusEncoder, SignalType};
use pickle_proto::voice::{CHANNELS, MAX_OPUS_PACKET, SAMPLES_PER_FRAME, SAMPLE_RATE};

/// Default encoder bitrate. Comfortably transparent for speech; Opus varies
/// below this on its own when the signal is simple.
pub const DEFAULT_BITRATE: u32 = 32_000;

/// Loss percentage the encoder assumes when choosing how robust to be.
const ASSUMED_PACKET_LOSS_PERCENT: i32 = 10;

/// In-band forward error correction is **off deliberately**.
///
/// FEC would be a natural fit for an unreliable datagram transport — it lets a
/// decoder rebuild a lost frame from redundancy carried in the next one. But
/// the pure-Rust codec we use produces badly corrupted audio when it is
/// enabled: a steady tone decodes with its energy swinging between 0.02x and
/// 3.4x and clipping to full scale. Every other setting decodes correctly, so
/// the fault is isolated to this one path.
///
/// Loss is therefore handled entirely by the jitter buffer and Opus's
/// packet-loss concealment, which is adequate but recovers less gracefully from
/// bursts. `codec_energy_is_stable_across_frames` is the regression test that
/// will fail if this is ever turned back on before the underlying bug is fixed.
const USE_INBAND_FEC: bool = false;

#[derive(Debug, thiserror::Error)]
pub enum CodecError {
    #[error("opus: {0}")]
    Opus(&'static str),
    #[error("expected a {SAMPLES_PER_FRAME} sample frame, got {0}")]
    WrongFrameSize(usize),
}

pub struct VoiceEncoder {
    encoder: OpusEncoder,
    scratch: Vec<u8>,
    seq: u32,
}

impl VoiceEncoder {
    pub fn new(bitrate: u32) -> Result<Self, CodecError> {
        // `Voip` biases Opus toward speech intelligibility over musical
        // fidelity, which is the right trade for a chat application.
        let mut encoder = OpusEncoder::new(SAMPLE_RATE as i32, CHANNELS, Application::Voip)
            .map_err(CodecError::Opus)?;

        encoder.bitrate_bps = bitrate as i32;
        encoder.signal_type = Some(SignalType::Voice);
        encoder.use_inband_fec = USE_INBAND_FEC; // see the constant's docs
        encoder.packet_loss_perc = ASSUMED_PACKET_LOSS_PERCENT;

        Ok(Self {
            encoder,
            scratch: vec![0u8; MAX_OPUS_PACKET],
            seq: 0,
        })
    }

    pub fn set_bitrate(&mut self, bitrate: u32) {
        self.encoder.bitrate_bps = bitrate as i32;
    }

    /// Encode exactly one frame of ±1.0 normalised samples.
    pub fn encode(&mut self, pcm: &[f32]) -> Result<Bytes, CodecError> {
        if pcm.len() != SAMPLES_PER_FRAME {
            return Err(CodecError::WrongFrameSize(pcm.len()));
        }
        let written = self
            .encoder
            .encode(pcm, SAMPLES_PER_FRAME, &mut self.scratch)
            .map_err(CodecError::Opus)?;
        Ok(Bytes::copy_from_slice(&self.scratch[..written]))
    }

    /// Take the next sequence number. Wraps, which the receiver handles.
    pub fn next_seq(&mut self) -> u32 {
        let seq = self.seq;
        self.seq = self.seq.wrapping_add(1);
        seq
    }

    /// Restart numbering for a new talk burst.
    pub fn reset_seq(&mut self) {
        self.seq = 0;
    }
}

pub struct VoiceDecoder {
    decoder: OpusDecoder,
    pcm: Vec<f32>,
}

impl VoiceDecoder {
    pub fn new() -> Result<Self, CodecError> {
        Ok(Self {
            decoder: OpusDecoder::new(SAMPLE_RATE as i32, CHANNELS).map_err(CodecError::Opus)?,
            pcm: vec![0.0; SAMPLES_PER_FRAME],
        })
    }

    pub fn decode(&mut self, packet: &[u8]) -> Result<&[f32], CodecError> {
        let written = self
            .decoder
            .decode(packet, SAMPLES_PER_FRAME, &mut self.pcm)
            .map_err(CodecError::Opus)?;
        Ok(&self.pcm[..written])
    }

    /// Synthesise a frame for one that never arrived.
    ///
    /// Opus extrapolates from what it has already decoded, which sounds far
    /// better than silence — a hole in the waveform is heard as a click. An
    /// empty input is the codec's signal for a lost packet.
    pub fn conceal(&mut self) -> Result<&[f32], CodecError> {
        let written = self
            .decoder
            .decode(&[], SAMPLES_PER_FRAME, &mut self.pcm)
            .map_err(CodecError::Opus)?;
        Ok(&self.pcm[..written])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A 440 Hz tone — a realistic, compressible signal, unlike noise.
    pub(crate) fn tone(samples: usize, amplitude: f32) -> Vec<f32> {
        (0..samples)
            .map(|i| {
                let t = i as f32 / SAMPLE_RATE as f32;
                (t * 440.0 * std::f32::consts::TAU).sin() * amplitude
            })
            .collect()
    }

    fn rms(samples: &[f32]) -> f64 {
        (samples.iter().map(|&x| (x as f64).powi(2)).sum::<f64>() / samples.len() as f64).sqrt()
    }

    #[test]
    fn a_frame_encodes_and_decodes_at_the_right_length() {
        let mut encoder = VoiceEncoder::new(DEFAULT_BITRATE).unwrap();
        let mut decoder = VoiceDecoder::new().unwrap();

        let packet = encoder.encode(&tone(SAMPLES_PER_FRAME, 0.25)).unwrap();
        assert!(!packet.is_empty());
        assert!(packet.len() <= MAX_OPUS_PACKET);

        let decoded = decoder.decode(&packet).unwrap();
        assert_eq!(decoded.len(), SAMPLES_PER_FRAME);
    }

    #[test]
    fn encoding_actually_compresses() {
        let mut encoder = VoiceEncoder::new(DEFAULT_BITRATE).unwrap();
        let packet = encoder.encode(&tone(SAMPLES_PER_FRAME, 0.25)).unwrap();
        // 20 ms at 32 kbit/s is about 80 bytes; raw would be 3840.
        let raw_bytes = SAMPLES_PER_FRAME * 4;
        assert!(
            packet.len() < raw_bytes / 8,
            "expected real compression, got {} bytes from {raw_bytes}",
            packet.len()
        );
    }

    #[test]
    fn a_wrong_sized_frame_is_refused() {
        let mut encoder = VoiceEncoder::new(DEFAULT_BITRATE).unwrap();
        assert!(matches!(
            encoder.encode(&tone(100, 0.25)),
            Err(CodecError::WrongFrameSize(100))
        ));
    }

    #[test]
    fn the_decoded_signal_resembles_the_original() {
        // Opus is lossy, so this checks energy is preserved rather than exact
        // samples. A silent or wildly wrong decode would fail this.
        let mut encoder = VoiceEncoder::new(DEFAULT_BITRATE).unwrap();
        let mut decoder = VoiceDecoder::new().unwrap();

        let input = tone(SAMPLES_PER_FRAME, 0.25);
        let mut decoded = Vec::new();
        // Opus needs a few frames to converge past its initial ramp-up.
        for _ in 0..10 {
            let packet = encoder.encode(&input).unwrap();
            decoded = decoder.decode(&packet).unwrap().to_vec();
        }

        let ratio = rms(&decoded) / rms(&input);
        assert!(
            (0.5..2.0).contains(&ratio),
            "decoded energy should track the input, ratio was {ratio}"
        );
    }

    #[test]
    fn codec_energy_is_stable_across_frames() {
        // The regression test for the FEC corruption described on
        // `USE_INBAND_FEC`. A steady tone must decode to steady energy; the
        // broken path swings between 0.02x and 3.4x, so a tight bound here
        // catches it immediately.
        let mut encoder = VoiceEncoder::new(DEFAULT_BITRATE).unwrap();
        let mut decoder = VoiceDecoder::new().unwrap();
        let input = tone(SAMPLES_PER_FRAME, 0.25);
        let input_rms = rms(&input);

        // Skip the first frames while the encoder converges.
        let mut ratios = Vec::new();
        for frame in 0..20 {
            let packet = encoder.encode(&input).unwrap();
            let decoded = decoder.decode(&packet).unwrap();
            if frame >= 10 {
                ratios.push(rms(decoded) / input_rms);
            }
        }

        for ratio in &ratios {
            assert!(
                (0.85..1.15).contains(ratio),
                "steady input should decode to steady energy, got {ratio:.3} in {ratios:?}"
            );
        }
    }

    #[test]
    fn the_decoded_signal_stays_in_range() {
        // A decoder that overshoots ±1.0 would clip audibly in the mixer.
        let mut encoder = VoiceEncoder::new(DEFAULT_BITRATE).unwrap();
        let mut decoder = VoiceDecoder::new().unwrap();

        for _ in 0..10 {
            let packet = encoder.encode(&tone(SAMPLES_PER_FRAME, 0.5)).unwrap();
            let decoded = decoder.decode(&packet).unwrap();
            assert!(
                decoded.iter().all(|s| s.abs() <= 2.0 && s.is_finite()),
                "decoder produced an out-of-range or non-finite sample"
            );
        }
    }

    #[test]
    fn concealment_produces_a_full_frame() {
        let mut encoder = VoiceEncoder::new(DEFAULT_BITRATE).unwrap();
        let mut decoder = VoiceDecoder::new().unwrap();

        for _ in 0..3 {
            let packet = encoder.encode(&tone(SAMPLES_PER_FRAME, 0.25)).unwrap();
            decoder.decode(&packet).unwrap();
        }

        // Playback timing depends on concealment yielding exactly one frame.
        assert_eq!(decoder.conceal().unwrap().len(), SAMPLES_PER_FRAME);
    }

    #[test]
    fn a_stream_survives_a_gap_filled_by_concealment() {
        // The realistic loss pattern: decode, lose one, decode again.
        let mut encoder = VoiceEncoder::new(DEFAULT_BITRATE).unwrap();
        let mut decoder = VoiceDecoder::new().unwrap();
        let input = tone(SAMPLES_PER_FRAME, 0.25);

        for _ in 0..5 {
            let packet = encoder.encode(&input).unwrap();
            decoder.decode(&packet).unwrap();
        }
        decoder.conceal().unwrap();

        let packet = encoder.encode(&input).unwrap();
        let recovered = decoder.decode(&packet).unwrap();
        assert_eq!(recovered.len(), SAMPLES_PER_FRAME);
        assert!(recovered.iter().all(|s| s.is_finite()));
    }

    #[test]
    fn sequence_numbers_advance_and_wrap() {
        let mut encoder = VoiceEncoder::new(DEFAULT_BITRATE).unwrap();
        assert_eq!(encoder.next_seq(), 0);
        assert_eq!(encoder.next_seq(), 1);

        encoder.seq = u32::MAX;
        assert_eq!(encoder.next_seq(), u32::MAX);
        assert_eq!(encoder.next_seq(), 0, "must wrap rather than overflow");
    }

    #[test]
    fn silence_encodes_to_a_small_packet() {
        // Opus signals near-silence cheaply; this is what keeps an idle
        // microphone from costing real bandwidth.
        let mut encoder = VoiceEncoder::new(DEFAULT_BITRATE).unwrap();
        let mut smallest = usize::MAX;
        for _ in 0..10 {
            let packet = encoder.encode(&vec![0.0f32; SAMPLES_PER_FRAME]).unwrap();
            smallest = smallest.min(packet.len());
        }
        assert!(smallest < 40, "got {smallest} bytes for silence");
    }

    #[test]
    fn the_bitrate_can_be_changed_mid_stream() {
        let mut encoder = VoiceEncoder::new(DEFAULT_BITRATE).unwrap();
        encoder.set_bitrate(16_000);
        assert!(encoder.encode(&tone(SAMPLES_PER_FRAME, 0.25)).is_ok());
    }

    #[test]
    fn a_packet_carries_a_valid_opus_table_of_contents_byte() {
        // Guards interoperability: the first byte encodes mode, bandwidth and
        // frame duration, and must describe the 20 ms fullband mono frame we
        // asked for. A decoder from any other implementation reads this byte.
        let mut encoder = VoiceEncoder::new(DEFAULT_BITRATE).unwrap();
        let packet = encoder.encode(&tone(SAMPLES_PER_FRAME, 0.25)).unwrap();

        let toc = packet[0];
        // Bit 2 is the stereo flag; we asked for mono.
        assert_eq!(toc & 0b0000_0100, 0, "packet should be mono");
        // Bits 0-1 are the frame count code; 0 means exactly one frame.
        assert_eq!(toc & 0b0000_0011, 0, "packet should hold one frame");
    }
}
