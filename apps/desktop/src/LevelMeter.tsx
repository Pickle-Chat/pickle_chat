import { useEffect, useState } from "react";
import { api } from "./api";

/// Below this, speech is indistinguishable from silence, so it anchors the
/// bottom of the bar rather than dBFS running to negative infinity.
const FLOOR_DBFS = -60;

/// A live microphone meter with a transmit indicator.
///
/// The two are one widget because they answer different halves of the same
/// question. The bar says the microphone hears you; the indicator says you are
/// actually being sent. They disagree exactly when it matters — a shut gate, a
/// muted microphone, or push-to-talk not held — which is the case a bare meter
/// leaves a user guessing about.
///
/// Polled rather than pushed, for the same reason the speaking indicator is: the
/// value changes every audio frame, and an event per change would flood the
/// bridge for something purely cosmetic.
export function LevelMeter({
  label = "Microphone level",
  /// Whether a server is on the other end. While disconnected the gate still
  /// opens, but nothing leaves the machine, so the indicator must not claim it
  /// does.
  connected = true,
}: {
  label?: string;
  connected?: boolean;
}) {
  const [level, setLevel] = useState(Number.NEGATIVE_INFINITY);
  const [transmitting, setTransmitting] = useState(false);

  useEffect(() => {
    const timer = setInterval(() => {
      api
        .inputActivity()
        .then((activity) => {
          setLevel(activity.levelDbfs);
          setTransmitting(activity.transmitting);
        })
        .catch(() => {});
    }, 100);
    return () => clearInterval(timer);
  }, []);

  const filled = Number.isFinite(level)
    ? Math.max(0, Math.min(100, ((level - FLOOR_DBFS) / -FLOOR_DBFS) * 100))
    : 0;

  const status = !transmitting
    ? { className: "idle", text: "Not transmitting" }
    : connected
      ? { className: "live", text: "Transmitting" }
      : { className: "open", text: "Mic open — not connected" };

  return (
    <div className="level-meter">
      <div
        className="meter"
        role="meter"
        aria-label={label}
        aria-valuenow={Math.round(filled)}
        aria-valuemin={0}
        aria-valuemax={100}
      >
        <div className={transmitting ? "meter-fill transmitting" : "meter-fill"} style={{ width: `${filled}%` }} />
      </div>
      {/* Announced politely so a screen reader says when transmission starts
          and stops without interrupting whatever else is being read. */}
      <span className={`transmit ${status.className}`} role="status" aria-live="polite">
        <span className="transmit-dot" aria-hidden="true" />
        {status.text}
      </span>
    </div>
  );
}
