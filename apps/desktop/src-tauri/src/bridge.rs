//! Carrying audio between the sound card and the network.
//!
//! Two paths, each on its own thread, neither touching JavaScript:
//!
//! * **Outbound** — a plain OS thread blocking on the encoder's channel. The
//!   audio callback produces a frame every 20 ms and this thread puts it
//!   straight on the wire. Blocking is deliberate: polling on a timer would add
//!   up to a full poll interval of latency for no benefit, and
//!   `send_datagram` does not block, so there is nothing to await.
//!
//! * **Inbound** — an async task draining the client's event stream. Voice
//!   frames go directly to the mixer; everything else is translated and emitted
//!   to the UI. Keeping voice off the JavaScript bridge matters: at 50 packets
//!   a second per speaker, serialising them would dominate the app's work for
//!   no reason.

use crate::dto::EventDto;
use pickle_audio::AudioEngine;
use pickle_client::{Client, ClientEvent};
use std::sync::Arc;
use tauri::{AppHandle, Emitter};
use tokio::sync::mpsc;
use tracing::debug;

/// Channel the frontend listens on.
pub const EVENT_CHANNEL: &str = "pickle:event";

/// Forward encoded microphone frames to the server until the engine stops.
///
/// Returns the thread handle; dropping the engine closes the channel, which
/// ends the loop and lets the thread exit on its own.
pub fn spawn_capture_pump(
    client: Arc<Client>,
    frames: std::sync::mpsc::Receiver<pickle_audio::engine::CapturedFrame>,
) -> std::thread::JoinHandle<()> {
    std::thread::Builder::new()
        .name("pickle-capture-pump".into())
        .spawn(move || {
            // Ends when the engine is dropped and the sender disconnects.
            while let Ok(frame) = frames.recv() {
                client.send_voice(frame.seq, frame.flags, frame.payload);
            }
            debug!("capture pump finished");
        })
        .expect("could not start the capture pump thread")
}

/// Route incoming events: voice to the mixer, everything else to the UI.
pub fn spawn_event_pump(
    app: AppHandle,
    engine: Arc<AudioEngine>,
    mut events: mpsc::UnboundedReceiver<ClientEvent>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        while let Some(event) = events.recv().await {
            // Voice never reaches JavaScript — straight into the mixer.
            if let ClientEvent::Voice(packet) = event {
                engine.accept(packet);
                continue;
            }

            let terminal = matches!(event, ClientEvent::Disconnected { .. });

            if let Some(payload) = EventDto::from_event(&event) {
                if let Err(e) = app.emit(EVENT_CHANNEL, payload) {
                    debug!(error = %e, "could not emit an event to the frontend");
                }
            }

            if terminal {
                break;
            }
        }
        debug!("event pump finished");
    })
}
