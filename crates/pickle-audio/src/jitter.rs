//! Per-sender jitter buffer.
//!
//! Packets are sent every 20 ms but do not arrive that way: the network
//! reorders them, bunches them up, and loses some. Playback, meanwhile, must
//! consume exactly one frame every 20 ms forever — the sound card will not
//! wait. The jitter buffer absorbs that mismatch by holding a small backlog
//! before starting playback.
//!
//! The backlog is the whole tradeoff. Too little and every hiccup becomes an
//! audible gap; too much and the conversation feels laggy. A few frames — 40 to
//! 80 ms — is the usual compromise, and it is why the buffer deliberately
//! *waits* before it starts playing.
//!
//! When a frame never shows up, the buffer reports [`JitterOutput::Lost`]
//! rather than stalling. The decoder turns that into concealment noise, which
//! is far less objectionable than a click or a stutter.

use bytes::Bytes;
use std::collections::BTreeMap;

/// Frames buffered before playback starts: 3 × 20 ms = 60 ms of slack.
pub const DEFAULT_TARGET_FRAMES: usize = 3;

/// Hard cap on the backlog. Beyond this the sender is running ahead of us —
/// usually a clock mismatch — and holding more would only add latency, so the
/// oldest frames are discarded.
pub const DEFAULT_MAX_FRAMES: usize = 16;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum JitterOutput {
    /// A frame ready to decode.
    Frame(Bytes),
    /// The frame for this slot never arrived. Decode with packet-loss
    /// concealment rather than skipping, so the stream keeps its timing.
    Lost,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct JitterStats {
    pub received: u64,
    /// Arrived after their slot had already played. Consistently non-zero means
    /// the target depth is too small for this path.
    pub late: u64,
    pub lost: u64,
    /// Times playback ran dry and had to re-buffer.
    pub underruns: u64,
    /// Dropped because the backlog hit its cap.
    pub overflows: u64,
}

/// Reference point mapping wire sequence numbers onto extended ones.
#[derive(Debug, Clone, Copy)]
struct Anchor {
    seq: u32,
    extended: i64,
}

pub struct JitterBuffer {
    target_frames: usize,
    max_frames: usize,
    /// Keyed by *extended* sequence, not the wire value.
    ///
    /// Ordering is the whole point of this map, and raw `u32` sequence numbers
    /// do not order correctly across their rollover — a `BTreeMap` would sort
    /// sequence 0 before `u32::MAX`, silently reversing playback at the wrap.
    /// Extending to a monotonic `i64` removes the discontinuity.
    packets: BTreeMap<i64, Bytes>,
    anchor: Option<Anchor>,
    /// Extended sequence the next `pop` will emit. `None` before the first frame.
    next_extended: Option<i64>,
    /// False while filling the initial backlog.
    playing: bool,
    stats: JitterStats,
}

impl Default for JitterBuffer {
    fn default() -> Self {
        Self::new(DEFAULT_TARGET_FRAMES, DEFAULT_MAX_FRAMES)
    }
}

impl JitterBuffer {
    pub fn new(target_frames: usize, max_frames: usize) -> Self {
        Self {
            target_frames: target_frames.max(1),
            max_frames: max_frames.max(target_frames.max(1)),
            packets: BTreeMap::new(),
            anchor: None,
            next_extended: None,
            playing: false,
            stats: JitterStats::default(),
        }
    }

    /// Map a wire sequence number onto the monotonic extended space.
    ///
    /// The difference between consecutive sequence numbers is tiny, so
    /// reinterpreting the wrapping subtraction as a *signed* 32-bit value
    /// recovers the true offset — forwards or backwards — even when the raw
    /// numbers straddle the rollover. The anchor then advances with the stream,
    /// keeping every offset small no matter how long the call runs.
    fn extend(&mut self, seq: u32) -> i64 {
        let extended = match self.anchor {
            None => 0,
            Some(anchor) => anchor.extended + (seq.wrapping_sub(anchor.seq) as i32) as i64,
        };
        self.anchor = Some(Anchor { seq, extended });
        extended
    }

    pub fn stats(&self) -> JitterStats {
        self.stats
    }

    pub fn buffered(&self) -> usize {
        self.packets.len()
    }

    pub fn is_playing(&self) -> bool {
        self.playing
    }

    /// Discard everything and re-buffer.
    ///
    /// Called at the start of a talk burst: the silence before it is not packet
    /// loss, and treating the sequence gap as loss would emit a burst of
    /// concealment noise.
    pub fn reset(&mut self) {
        self.packets.clear();
        self.anchor = None;
        self.next_extended = None;
        self.playing = false;
    }

    pub fn push(&mut self, seq: u32, payload: Bytes) {
        self.stats.received += 1;

        let extended = self.extend(seq);

        // Anything before the slot we are about to play is too late to use;
        // its moment has passed.
        if let Some(next) = self.next_extended {
            if extended < next {
                self.stats.late += 1;
                return;
            }
        }

        self.packets.insert(extended, payload);

        while self.packets.len() > self.max_frames {
            // Drop from the front: the oldest frame is the one closest to being
            // too late anyway.
            let Some(&oldest) = self.packets.keys().next() else {
                break;
            };
            self.packets.remove(&oldest);
            self.stats.overflows += 1;

            // Playback position follows, or we would emit a run of Lost for
            // frames we deliberately threw away.
            if let Some(next) = self.next_extended {
                if next <= oldest {
                    self.next_extended = Some(oldest + 1);
                }
            }
        }
    }

    /// Take the next frame, or `None` if playback should stay silent.
    ///
    /// `None` means either "still filling the buffer" or "nothing left to
    /// play" — both of which the caller renders as silence.
    pub fn pop(&mut self) -> Option<JitterOutput> {
        if !self.playing {
            if self.packets.len() < self.target_frames {
                return None;
            }
            self.playing = true;
            // Start at the oldest frame we hold.
            self.next_extended = self.packets.keys().next().copied();
        }

        let next = self.next_extended?;

        if let Some(payload) = self.packets.remove(&next) {
            self.next_extended = Some(next + 1);
            return Some(JitterOutput::Frame(payload));
        }

        if self.packets.is_empty() {
            // Ran dry. Re-buffer rather than emitting endless concealment.
            self.stats.underruns += 1;
            self.playing = false;
            self.next_extended = None;
            return None;
        }

        // Held frames are all newer, so this slot is genuinely missing.
        self.stats.lost += 1;
        self.next_extended = Some(next + 1);
        Some(JitterOutput::Lost)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn payload(byte: u8) -> Bytes {
        Bytes::from(vec![byte; 4])
    }

    fn buffer() -> JitterBuffer {
        JitterBuffer::new(3, 16)
    }

    #[test]
    fn playback_waits_for_the_target_backlog() {
        let mut jb = buffer();
        jb.push(0, payload(0));
        jb.push(1, payload(1));
        assert_eq!(jb.pop(), None, "must not start before the buffer fills");

        jb.push(2, payload(2));
        assert_eq!(jb.pop(), Some(JitterOutput::Frame(payload(0))));
    }

    #[test]
    fn frames_come_out_in_order() {
        let mut jb = buffer();
        for seq in 0..3 {
            jb.push(seq, payload(seq as u8));
        }
        for seq in 0..3 {
            assert_eq!(jb.pop(), Some(JitterOutput::Frame(payload(seq as u8))));
        }
    }

    #[test]
    fn reordered_arrivals_are_played_in_sequence() {
        // The single most common network behaviour the buffer exists for.
        let mut jb = buffer();
        jb.push(2, payload(2));
        jb.push(0, payload(0));
        jb.push(1, payload(1));

        assert_eq!(jb.pop(), Some(JitterOutput::Frame(payload(0))));
        assert_eq!(jb.pop(), Some(JitterOutput::Frame(payload(1))));
        assert_eq!(jb.pop(), Some(JitterOutput::Frame(payload(2))));
    }

    #[test]
    fn a_missing_frame_is_reported_as_lost_not_skipped() {
        // Skipping would shorten the stream and drift the timing; concealment
        // keeps playback aligned.
        let mut jb = buffer();
        jb.push(0, payload(0));
        jb.push(2, payload(2));
        jb.push(3, payload(3));

        assert_eq!(jb.pop(), Some(JitterOutput::Frame(payload(0))));
        assert_eq!(jb.pop(), Some(JitterOutput::Lost));
        assert_eq!(jb.pop(), Some(JitterOutput::Frame(payload(2))));
        assert_eq!(jb.stats().lost, 1);
    }

    #[test]
    fn a_late_frame_is_discarded_rather_than_played_out_of_order() {
        let mut jb = buffer();
        for seq in 0..3 {
            jb.push(seq, payload(seq as u8));
        }
        jb.pop();
        jb.pop();

        // Sequence 0 turning up now is far too late.
        jb.push(0, payload(0));
        assert_eq!(jb.stats().late, 1);
        assert_eq!(jb.pop(), Some(JitterOutput::Frame(payload(2))));
    }

    #[test]
    fn an_underrun_pauses_and_rebuffers() {
        let mut jb = buffer();
        for seq in 0..3 {
            jb.push(seq, payload(seq as u8));
        }
        for _ in 0..3 {
            jb.pop();
        }

        assert_eq!(jb.pop(), None, "nothing left to play");
        assert_eq!(jb.stats().underruns, 1);
        assert!(!jb.is_playing());

        // A single new frame must not restart playback on its own; the buffer
        // has to refill or it will underrun immediately again.
        jb.push(3, payload(3));
        assert_eq!(jb.pop(), None);
        jb.push(4, payload(4));
        jb.push(5, payload(5));
        assert_eq!(jb.pop(), Some(JitterOutput::Frame(payload(3))));
    }

    #[test]
    fn the_backlog_is_capped() {
        let mut jb = JitterBuffer::new(2, 4);
        for seq in 0..10 {
            jb.push(seq, payload(seq as u8));
        }
        assert_eq!(jb.buffered(), 4);
        assert!(jb.stats().overflows > 0);
    }

    #[test]
    fn overflow_does_not_produce_a_run_of_phantom_losses() {
        // Discarded frames were thrown away on purpose; reporting them as loss
        // would make the decoder conceal audio that was never coming.
        let mut jb = JitterBuffer::new(2, 4);
        for seq in 0..4 {
            jb.push(seq, payload(seq as u8));
        }
        jb.pop();
        for seq in 4..12 {
            jb.push(seq, payload(seq as u8));
        }

        let mut losses = 0;
        for _ in 0..4 {
            if jb.pop() == Some(JitterOutput::Lost) {
                losses += 1;
            }
        }
        assert_eq!(losses, 0, "trimming the backlog should not look like loss");
    }

    #[test]
    fn reset_clears_the_buffer_for_a_new_talk_burst() {
        let mut jb = buffer();
        for seq in 0..3 {
            jb.push(seq, payload(seq as u8));
        }
        jb.pop();

        jb.reset();
        assert_eq!(jb.buffered(), 0);
        assert!(!jb.is_playing());

        // A burst starting at an unrelated sequence number is fine.
        for seq in 500..503 {
            jb.push(seq, payload(0));
        }
        assert_eq!(jb.pop(), Some(JitterOutput::Frame(payload(0))));
    }

    #[test]
    fn playback_survives_sequence_wraparound() {
        let mut jb = buffer();
        let start = u32::MAX - 1;
        for offset in 0..3u32 {
            let seq = start.wrapping_add(offset);
            jb.push(seq, payload(offset as u8));
        }

        assert_eq!(jb.pop(), Some(JitterOutput::Frame(payload(0))));
        assert_eq!(jb.pop(), Some(JitterOutput::Frame(payload(1))));
        assert_eq!(jb.pop(), Some(JitterOutput::Frame(payload(2))));
        assert_eq!(jb.stats().lost, 0, "wraparound must not read as loss");
    }

    #[test]
    fn statistics_track_what_happened() {
        let mut jb = buffer();
        jb.push(0, payload(0));
        jb.push(2, payload(2));
        jb.push(3, payload(3));
        jb.pop();
        jb.pop();

        let stats = jb.stats();
        assert_eq!(stats.received, 3);
        assert_eq!(stats.lost, 1);
    }
}
