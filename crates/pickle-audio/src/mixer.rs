//! Client-side mixing of every speaker in a channel.
//!
//! The server relays each speaker as a separate stream rather than mixing them
//! together. That costs a little bandwidth and hands the client something
//! valuable in return: independent per-speaker volume, independent jitter
//! buffering (one person on bad wifi does not degrade everyone), and the option
//! of positional audio later. Mixing is the last step before playback.
//!
//! Each speaker gets a jitter buffer and its own decoder — Opus decoders carry
//! per-stream state, so sharing one across senders would corrupt every stream.

use crate::codec::{CodecError, VoiceDecoder};
use crate::jitter::{JitterBuffer, JitterOutput, JitterStats};
use pickle_proto::voice::{VoiceDownstream, SAMPLES_PER_FRAME};
use pickle_proto::ClientId;
use std::collections::HashMap;

/// Frames of silence after which a speaker's stream is torn down. At 20 ms a
/// frame, this is two seconds.
const IDLE_FRAMES_BEFORE_RELEASE: u32 = 100;

struct SenderStream {
    jitter: JitterBuffer,
    decoder: VoiceDecoder,
    gain: f32,
    muted: bool,
    /// True while this speaker contributed audio to the last rendered frame.
    speaking: bool,
    idle_frames: u32,
}

/// Mixes all incoming speakers into one output frame.
pub struct VoiceMixer {
    streams: HashMap<ClientId, SenderStream>,
    master_gain: f32,
    deafened: bool,
}

impl Default for VoiceMixer {
    fn default() -> Self {
        Self::new()
    }
}

impl VoiceMixer {
    pub fn new() -> Self {
        Self {
            streams: HashMap::new(),
            master_gain: 1.0,
            deafened: false,
        }
    }

    /// Take an incoming frame, creating a stream for a new speaker.
    pub fn accept(&mut self, packet: VoiceDownstream) -> Result<(), CodecError> {
        let stream = match self.streams.get_mut(&packet.sender) {
            Some(stream) => stream,
            None => {
                let stream = SenderStream {
                    jitter: JitterBuffer::default(),
                    decoder: VoiceDecoder::new()?,
                    gain: 1.0,
                    muted: false,
                    speaking: false,
                    idle_frames: 0,
                };
                self.streams.entry(packet.sender).or_insert(stream)
            }
        };

        // A new burst is not a continuation, so the gap in sequence numbers
        // must not be mistaken for packet loss.
        if packet.starts_burst() {
            stream.jitter.reset();
        }

        stream.idle_frames = 0;
        stream.jitter.push(packet.seq, packet.payload);
        Ok(())
    }

    /// Render one 20 ms frame into `out`, which must hold exactly
    /// [`SAMPLES_PER_FRAME`] samples. Returns how many speakers contributed.
    ///
    /// Always fills the buffer, with silence if nothing is playing — the audio
    /// callback cannot be left holding stale samples.
    pub fn render(&mut self, out: &mut [f32]) -> usize {
        out.iter_mut().for_each(|s| *s = 0.0);

        if out.len() != SAMPLES_PER_FRAME || self.deafened {
            return 0;
        }

        let mut contributors = 0;
        let mut finished: Vec<ClientId> = Vec::new();

        for (client, stream) in self.streams.iter_mut() {
            let frame = stream.jitter.pop();

            let decoded = match frame {
                Some(JitterOutput::Frame(payload)) => stream.decoder.decode(&payload).ok(),
                // Conceal rather than skip, so playback keeps its timing.
                Some(JitterOutput::Lost) => stream.decoder.conceal().ok(),
                None => None,
            };

            let Some(pcm) = decoded else {
                stream.speaking = false;
                stream.idle_frames = stream.idle_frames.saturating_add(1);
                if stream.idle_frames > IDLE_FRAMES_BEFORE_RELEASE {
                    finished.push(*client);
                }
                continue;
            };

            stream.speaking = true;
            stream.idle_frames = 0;

            if stream.muted {
                continue;
            }

            contributors += 1;
            let gain = stream.gain * self.master_gain;
            for (slot, &sample) in out.iter_mut().zip(pcm.iter()) {
                *slot += sample * gain;
            }
        }

        // Summing can exceed full scale when several people talk at once.
        // Clipping here is crude but predictable; a limiter would be the
        // refinement.
        for sample in out.iter_mut() {
            *sample = sample.clamp(-1.0, 1.0);
        }

        for client in finished {
            self.streams.remove(&client);
        }

        contributors
    }

    pub fn set_gain(&mut self, client: ClientId, gain: f32) {
        if let Some(stream) = self.streams.get_mut(&client) {
            stream.gain = gain.max(0.0);
        }
    }

    pub fn set_muted(&mut self, client: ClientId, muted: bool) {
        if let Some(stream) = self.streams.get_mut(&client) {
            stream.muted = muted;
        }
    }

    pub fn set_master_gain(&mut self, gain: f32) {
        self.master_gain = gain.max(0.0);
    }

    /// When deafened, streams keep flowing but nothing is rendered — so
    /// undeafening resumes instantly instead of re-buffering.
    pub fn set_deafened(&mut self, deafened: bool) {
        self.deafened = deafened;
    }

    pub fn is_deafened(&self) -> bool {
        self.deafened
    }

    pub fn remove(&mut self, client: ClientId) {
        self.streams.remove(&client);
    }

    pub fn clear(&mut self) {
        self.streams.clear();
    }

    /// Who contributed audio to the last rendered frame — drives the "speaking"
    /// ring in the UI.
    pub fn speaking(&self) -> Vec<ClientId> {
        self.streams
            .iter()
            .filter(|(_, stream)| stream.speaking)
            .map(|(client, _)| *client)
            .collect()
    }

    pub fn stats(&self, client: ClientId) -> Option<JitterStats> {
        self.streams.get(&client).map(|s| s.jitter.stats())
    }

    pub fn active_streams(&self) -> usize {
        self.streams.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::codec::{VoiceEncoder, DEFAULT_BITRATE};
    use bytes::Bytes;
    use pickle_proto::voice::{FLAG_BURST_START, SAMPLE_RATE};

    fn tone(samples: usize) -> Vec<f32> {
        (0..samples)
            .map(|i| {
                let t = i as f32 / SAMPLE_RATE as f32;
                (t * 440.0 * std::f32::consts::TAU).sin() * 0.35
            })
            .collect()
    }

    /// Encode a run of real frames for one speaker.
    fn frames(count: u32) -> Vec<Bytes> {
        let mut encoder = VoiceEncoder::new(DEFAULT_BITRATE).unwrap();
        (0..count)
            .map(|_| encoder.encode(&tone(SAMPLES_PER_FRAME)).unwrap())
            .collect()
    }

    fn packet(sender: ClientId, seq: u32, payload: Bytes, flags: u8) -> VoiceDownstream {
        VoiceDownstream {
            sender,
            seq,
            flags,
            payload,
        }
    }

    /// Feed enough frames to get past the jitter buffer's initial fill.
    fn prime(mixer: &mut VoiceMixer, sender: ClientId) {
        for (seq, payload) in frames(6).into_iter().enumerate() {
            let flags = if seq == 0 { FLAG_BURST_START } else { 0 };
            mixer
                .accept(packet(sender, seq as u32, payload, flags))
                .unwrap();
        }
    }

    fn energy(buffer: &[f32]) -> f32 {
        buffer.iter().map(|s| s.abs()).sum::<f32>() / buffer.len() as f32
    }

    #[test]
    fn a_single_speaker_is_rendered() {
        let mut mixer = VoiceMixer::new();
        prime(&mut mixer, 1);

        let mut out = vec![0.0f32; SAMPLES_PER_FRAME];
        assert_eq!(mixer.render(&mut out), 1);
        assert!(energy(&out) > 0.0, "audio should have been produced");
    }

    #[test]
    fn an_empty_mixer_renders_silence() {
        let mut mixer = VoiceMixer::new();
        let mut out = vec![0.5f32; SAMPLES_PER_FRAME];
        assert_eq!(mixer.render(&mut out), 0);
        assert!(
            out.iter().all(|&s| s == 0.0),
            "the buffer must be cleared, not left holding stale samples"
        );
    }

    #[test]
    fn two_speakers_both_contribute() {
        let mut mixer = VoiceMixer::new();
        prime(&mut mixer, 1);
        prime(&mut mixer, 2);

        let mut out = vec![0.0f32; SAMPLES_PER_FRAME];
        assert_eq!(mixer.render(&mut out), 2);
        assert_eq!(mixer.active_streams(), 2);
    }

    #[test]
    fn each_speaker_gets_an_independent_decoder() {
        // Sharing one decoder across senders would corrupt both streams, since
        // Opus decoders carry per-stream state.
        let mut mixer = VoiceMixer::new();
        prime(&mut mixer, 1);
        prime(&mut mixer, 2);

        let mut both = vec![0.0f32; SAMPLES_PER_FRAME];
        mixer.render(&mut both);

        let mut solo_mixer = VoiceMixer::new();
        prime(&mut solo_mixer, 1);
        let mut solo = vec![0.0f32; SAMPLES_PER_FRAME];
        solo_mixer.render(&mut solo);

        assert!(
            energy(&both) > energy(&solo) * 1.2,
            "two speakers should be louder than one"
        );
    }

    #[test]
    fn muting_a_speaker_silences_only_them() {
        let mut mixer = VoiceMixer::new();
        prime(&mut mixer, 1);
        prime(&mut mixer, 2);
        mixer.set_muted(1, true);

        let mut out = vec![0.0f32; SAMPLES_PER_FRAME];
        assert_eq!(mixer.render(&mut out), 1, "only the unmuted speaker counts");
        assert!(energy(&out) > 0.0);
    }

    #[test]
    fn a_zero_gain_speaker_contributes_nothing_audible() {
        let mut mixer = VoiceMixer::new();
        prime(&mut mixer, 1);
        mixer.set_gain(1, 0.0);

        let mut out = vec![0.0f32; SAMPLES_PER_FRAME];
        mixer.render(&mut out);
        assert!(energy(&out) < 1e-6);
    }

    #[test]
    fn gain_cannot_be_negative() {
        // A negative gain would invert the phase rather than reduce volume.
        let mut mixer = VoiceMixer::new();
        prime(&mut mixer, 1);
        mixer.set_gain(1, -5.0);

        let mut out = vec![0.0f32; SAMPLES_PER_FRAME];
        mixer.render(&mut out);
        assert!(energy(&out) < 1e-6);
    }

    #[test]
    fn deafening_renders_silence_without_dropping_streams() {
        let mut mixer = VoiceMixer::new();
        prime(&mut mixer, 1);
        mixer.set_deafened(true);

        let mut out = vec![0.0f32; SAMPLES_PER_FRAME];
        assert_eq!(mixer.render(&mut out), 0);
        assert!(out.iter().all(|&s| s == 0.0));
        assert_eq!(
            mixer.active_streams(),
            1,
            "the stream should survive so undeafening resumes instantly"
        );
    }

    #[test]
    fn the_output_never_clips_past_full_scale() {
        // Several loud speakers at once must not wrap around into distortion.
        let mut mixer = VoiceMixer::new();
        for sender in 1..=6 {
            prime(&mut mixer, sender);
            mixer.set_gain(sender, 4.0);
        }

        let mut out = vec![0.0f32; SAMPLES_PER_FRAME];
        mixer.render(&mut out);
        assert!(out.iter().all(|s| (-1.0..=1.0).contains(s)));
    }

    #[test]
    fn a_wrongly_sized_output_buffer_is_refused() {
        let mut mixer = VoiceMixer::new();
        prime(&mut mixer, 1);
        let mut out = vec![0.0f32; SAMPLES_PER_FRAME / 2];
        assert_eq!(mixer.render(&mut out), 0);
    }

    #[test]
    fn speaking_reports_who_made_sound() {
        let mut mixer = VoiceMixer::new();
        prime(&mut mixer, 7);

        let mut out = vec![0.0f32; SAMPLES_PER_FRAME];
        mixer.render(&mut out);
        assert_eq!(mixer.speaking(), vec![7]);
    }

    #[test]
    fn a_silent_stream_is_eventually_released() {
        let mut mixer = VoiceMixer::new();
        prime(&mut mixer, 1);

        let mut out = vec![0.0f32; SAMPLES_PER_FRAME];
        // Drain everything, then keep rendering into silence.
        for _ in 0..(IDLE_FRAMES_BEFORE_RELEASE + 20) {
            mixer.render(&mut out);
        }
        assert_eq!(
            mixer.active_streams(),
            0,
            "idle streams should be reclaimed"
        );
    }

    #[test]
    fn removing_a_speaker_drops_their_stream() {
        let mut mixer = VoiceMixer::new();
        prime(&mut mixer, 1);
        mixer.remove(1);
        assert_eq!(mixer.active_streams(), 0);

        let mut out = vec![0.0f32; SAMPLES_PER_FRAME];
        assert_eq!(mixer.render(&mut out), 0);
    }

    #[test]
    fn a_burst_start_resets_the_jitter_buffer() {
        // Otherwise the sequence jump between bursts reads as massive loss.
        let mut mixer = VoiceMixer::new();
        prime(&mut mixer, 1);
        let mut out = vec![0.0f32; SAMPLES_PER_FRAME];
        mixer.render(&mut out);

        for (offset, payload) in frames(4).into_iter().enumerate() {
            let flags = if offset == 0 { FLAG_BURST_START } else { 0 };
            mixer
                .accept(packet(1, 9000 + offset as u32, payload, flags))
                .unwrap();
        }

        let stats = mixer.stats(1).unwrap();
        assert_eq!(stats.lost, 0, "a new burst is not packet loss");
    }
}
