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

mod bookmarks;
mod bridge;
mod commands;
mod dto;
mod mouse_grab;
mod settings;
mod shortcuts;
mod state;

pub use state::AppState;

use tracing::warn;
use tracing_subscriber::EnvFilter;

pub fn run() {
    disable_dmabuf_renderer_on_nvidia();

    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    tauri::Builder::default()
        .manage(AppState::load().expect("could not open the local identity"))
        .manage(shortcuts::Registry::default())
        .plugin(
            tauri_plugin_global_shortcut::Builder::new()
                .with_handler(|app, shortcut, event| {
                    shortcuts::handle(app, shortcut, event.state());
                })
                .build(),
        )
        .setup(|app| {
            // Grab whatever was bound last time. A failure here is reported in
            // the settings tab rather than stopping startup: the app is still
            // perfectly usable with the in-window fallback.
            for status in shortcuts::apply(app.handle()) {
                if !status.registered {
                    warn!(
                        action = %status.action,
                        accelerator = %status.accelerator,
                        error = status.error.as_deref().unwrap_or("unknown"),
                        "a saved shortcut could not be grabbed",
                    );
                }
            }
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            commands::identity_info,
            commands::identities,
            commands::set_nickname,
            commands::add_identity,
            commands::set_active_identity,
            commands::set_identity_label,
            commands::remove_identity,
            commands::mine_identity,
            commands::audio_devices,
            commands::settings,
            commands::set_audio_settings,
            commands::set_keybinds,
            commands::start_audio_preview,
            commands::stop_audio_preview,
            commands::connect,
            commands::disconnect,
            commands::join_channel,
            commands::send_message,
            commands::set_muted,
            commands::set_deafened,
            commands::set_push_to_talk_held,
            commands::voice_state,
            commands::keybind_status,
            commands::input_activity,
            commands::speaking,
            commands::known_servers,
            commands::forget_server,
            commands::bookmarks,
            commands::add_bookmark,
            commands::update_bookmark,
            commands::remove_bookmark,
        ])
        .run(tauri::generate_context!())
        .expect("error while running the Pickle desktop app");
}

/// WebKitGTK's DMA-BUF renderer does not work with NVIDIA's proprietary driver.
/// The webview never paints and GTK dies during startup with `Error 71
/// (Protocol error) dispatching to Wayland display`, so the app fails to open
/// at all rather than merely rendering badly.
///
/// Falling back to the older renderer costs some compositing performance, which
/// is why this is narrowed to the machines that actually need it instead of
/// being set for every Linux build. `nouveau` is unaffected and deliberately
/// not matched: only the proprietary module registers `/sys/module/nvidia`.
///
/// Must run before the webview initialises, and before any thread is spawned —
/// setting an environment variable is only sound while the process is still
/// single-threaded.
fn disable_dmabuf_renderer_on_nvidia() {
    #[cfg(target_os = "linux")]
    {
        // Never override an explicit setting; someone debugging the renderer
        // should get what they asked for. Note that WebKit only checks whether
        // this variable is present, so setting it to an empty string disables
        // the renderer just as "1" does — there is no value that forces it on.
        if std::env::var_os("WEBKIT_DISABLE_DMABUF_RENDERER").is_some() {
            return;
        }

        if std::path::Path::new("/sys/module/nvidia").exists() {
            std::env::set_var("WEBKIT_DISABLE_DMABUF_RENDERER", "1");
        }
    }
}
