use tauri::Manager;

/// Native IPC is the only desktop filesystem adapter. The web build has no
/// localhost mutation endpoint and cannot invoke this command.
#[tauri::command]
async fn local_command(
    app: tauri::AppHandle,
    request: serde_json::Value,
) -> Result<serde_json::Value, String> {
    let state_dir = app
        .path()
        .app_data_dir()
        .map_err(|_| "The local app data directory is unavailable.".to_string())?
        .join("local");
    tauri::async_runtime::spawn_blocking(move || {
        devdrop_core::local::dispatch(&state_dir, request).map_err(|e| e.to_string())
    })
    .await
    .map_err(|_| {
        "The local operation was interrupted. Inspect recovery before retrying.".to_string()
    })?
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .invoke_handler(tauri::generate_handler![local_command])
        .run(tauri::generate_context!())
        .expect("error while running DevDrop desktop shell");
}

fn main() {
    run();
}
