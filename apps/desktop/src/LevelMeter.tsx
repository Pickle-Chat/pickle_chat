import { useEffect, useState } from "react";
import { api } from "./api";

/// Below this, speech is indistinguishable from silence, so it anchors the
/// bottom of the bar rather than dBFS running to negative infinity.
const FLOOR_DBFS = -60;

/// A live microphone level bar.
///
/// Polled rather than pushed, for the same reason the speaking indicator is: the
/// value changes every audio frame, and an event per change would flood the
/// bridge for something purely cosmetic.
export function LevelMeter({ label = "Microphone level" }: { label?: string }) {
  const [level, setLevel] = useState(Number.NEGATIVE_INFINITY);

  useEffect(() => {
    const timer = setInterval(() => {
      api.inputLevel().then(setLevel).catch(() => {});
    }, 100);
    return () => clearInterval(timer);
  }, []);

  const filled = Number.isFinite(level)
    ? Math.max(0, Math.min(100, ((level - FLOOR_DBFS) / -FLOOR_DBFS) * 100))
    : 0;

  return (
    <div
      className="meter"
      role="meter"
      aria-label={label}
      aria-valuenow={Math.round(filled)}
      aria-valuemin={0}
      aria-valuemax={100}
    >
      <div className="meter-fill" style={{ width: `${filled}%` }} />
    </div>
  );
}
