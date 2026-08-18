import { useEffect, useState } from "react";
import {
  api,
  type AudioDevice,
  type AudioDevices,
  type AudioSettings,
  type GateMode,
} from "../api";
import { LevelMeter } from "../LevelMeter";

/// Opus is transparent enough for speech well below its default, so the range
/// is offered as named steps rather than a raw number nobody can calibrate.
const BITRATES: { value: number; label: string }[] = [
  { value: 16_000, label: "16 kbps — narrow, for a poor connection" },
  { value: 24_000, label: "24 kbps" },
  { value: 32_000, label: "32 kbps — default" },
  { value: 48_000, label: "48 kbps" },
  { value: 64_000, label: "64 kbps — best quality" },
];

const GATE_MODES: { value: GateMode; label: string; help: string }[] = [
  {
    value: "voiceActivity",
    label: "Voice activity",
    help: "Transmit when the microphone hears speech.",
  },
  {
    value: "pushToTalk",
    label: "Push to talk",
    help: "Transmit only while the push-to-talk key is held.",
  },
  {
    value: "continuous",
    label: "Always on",
    help: "Transmit constantly. Useful if you gate your microphone yourself.",
  },
];

export function AudioTab({
  audio,
  connected,
  onChange,
  onError,
}: {
  audio: AudioSettings;
  connected: boolean;
  onChange: (audio: AudioSettings) => void;
  onError: (error: string) => void;
}) {
  const [devices, setDevices] = useState<AudioDevices | null>(null);

  useEffect(() => {
    api.audioDevices().then(setDevices).catch((e) => onError(String(e)));
  }, [onError]);

  // While connected the engine is already running and wired to the server.
  // Only when disconnected does the meter need one started on its behalf.
  useEffect(() => {
    if (connected) return;
    api.startAudioPreview().catch((e) => onError(String(e)));
    return () => {
      api.stopAudioPreview().catch(() => {});
    };
  }, [connected, onError]);

  const update = (patch: Partial<AudioSettings>) => {
    const next = { ...audio, ...patch };
    onChange(next);
    api.setAudioSettings(next).catch((e) => onError(String(e)));
  };

  return (
    <div className="settings-pane">
      <label>
        Microphone
        <DeviceSelect
          devices={devices?.inputs}
          value={audio.inputDevice}
          onChange={(inputDevice) => update({ inputDevice })}
        />
      </label>

      <label>
        Speakers
        <DeviceSelect
          devices={devices?.outputs}
          value={audio.outputDevice}
          onChange={(outputDevice) => update({ outputDevice })}
        />
      </label>

      <div className="settings-field">
        <span className="settings-label">Input level</span>
        <LevelMeter connected={connected} />
        <p className="muted">
          {connected
            ? "The indicator lights while your voice is actually going out."
            : "The indicator shows when the gate opens. Nothing leaves this machine while disconnected."}
        </p>
      </div>

      <fieldset className="settings-field">
        <legend className="settings-label">When to transmit</legend>
        {GATE_MODES.map((mode) => (
          <label key={mode.value} className="row">
            <input
              type="radio"
              name="gate-mode"
              checked={audio.gateMode === mode.value}
              onChange={() => update({ gateMode: mode.value })}
            />
            {mode.label}
            <span className="muted"> — {mode.help}</span>
          </label>
        ))}
      </fieldset>

      <label>
        Quality
        <select
          value={audio.bitrate}
          onChange={(e) => update({ bitrate: Number(e.target.value) })}
        >
          {/* A file written by another build may sit between the named steps. */}
          {!BITRATES.some((b) => b.value === audio.bitrate) && (
            <option value={audio.bitrate}>{Math.round(audio.bitrate / 1000)} kbps</option>
          )}
          {BITRATES.map((bitrate) => (
            <option key={bitrate.value} value={bitrate.value}>
              {bitrate.label}
            </option>
          ))}
        </select>
      </label>

      <p className="muted">
        Changing a device or the quality reopens the audio devices, which causes a
        short gap. Your connection is not interrupted.
      </p>
    </div>
  );
}

/// Pickle runs its pipeline at 48 kHz. A device at any other rate works, but
/// passes through a conversion, and the menu says so rather than pretending the
/// two are identical.
const NATIVE_RATE = 48_000;

function deviceNote(device: AudioDevice): string {
  if (!device.usable) return " — unsupported format";
  if (device.sampleRate === null || device.sampleRate === NATIVE_RATE) return "";
  return ` — ${device.sampleRate / 1000} kHz, resampled`;
}

function DeviceSelect({
  devices,
  value,
  onChange,
}: {
  devices: AudioDevice[] | undefined;
  value: string | null;
  onChange: (device: string | null) => void;
}) {
  if (!devices) {
    return <select disabled aria-busy="true" />;
  }

  // A device saved earlier may be unplugged now. Keeping it in the list means
  // the selection still reads back correctly instead of silently appearing to
  // be the system default.
  const missing = value !== null && !devices.some((device) => device.name === value);

  return (
    <select value={value ?? ""} onChange={(e) => onChange(e.target.value || null)}>
      <option value="">System default</option>
      {missing && <option value={value}>{value} — not connected</option>}
      {devices.map((device) => (
        <option key={device.name} value={device.name} disabled={!device.usable}>
          {device.name}
          {device.isDefault ? " (default)" : ""}
          {deviceNote(device)}
        </option>
      ))}
    </select>
  );
}
