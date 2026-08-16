//! The Pickle desktop client.
//!
//! This layer is glue and nothing else. The protocol lives in `pickle-client`,
//! the signal path in `pickle-audio`, and identity in `pickle-identity`; all of
//! them are testable without a window. What happens here is wiring those three
//! together and exposing them to the web frontend.
//!
//! The one piece of real design is [`bridge`]: the two paths that carry audio
//! between the sound card and the network without going anywhere near
//! JavaScript.

mod bridge;
mod commands;
mod dto;
mod state;

pub use state::AppState;

use tracing_subscriber::EnvFilter;

pub fn run() {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    tauri::Builder::default()
        .manage(AppState::load().expect("could not open the local identity"))
        .invoke_handler(tauri::generate_handler![
            commands::identity_info,
            commands::set_nickname,
            commands::mine_identity,
            commands::audio_devices,
            commands::connect,
            commands::disconnect,
            commands::join_channel,
            commands::send_message,
            commands::set_muted,
            commands::set_deafened,
            commands::set_push_to_talk_held,
            commands::input_level,
            commands::speaking,
            commands::known_servers,
            commands::forget_server,
        ])
        .run(tauri::generate_context!())
        .expect("error while running the Pickle desktop app");
}
