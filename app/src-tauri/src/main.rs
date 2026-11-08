#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]
mod pipes;
mod updater;

use moveit_core::api::{App, RouteChoice};
use serde::Serialize;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use tauri::{AppHandle, Emitter, Manager, State};
use tauri_plugin_dialog::DialogExt;

type Reply = Result<serde_json::Value, String>;

// One engine instance retains its redacted log and configuration across commands.
#[derive(Clone)]
struct Desktop {
    engine: Arc<Mutex<App>>,
}

impl Desktop {
    fn engine_idle(&self) -> bool {
        self.engine.try_lock().is_ok()
    }
}

#[tauri::command]
fn engine_idle(state: State<'_, Desktop>) -> bool {
    state.engine_idle()
}

#[tauri::command]
async fn updater_install(app: AppHandle, state: State<'_, Desktop>) -> Result<(), String> {
    let engine = state.engine.clone();
    tauri::async_runtime::spawn_blocking(move || {
        let _guard = engine
            .try_lock()
            .map_err(|_| "Move It is busy. Please wait for it to finish.")?;
        tokio::runtime::Handle::current().block_on(updater::install_update(app))
    })
    .await
    .map_err(|_| "The update could not finish.")?
}

fn json<T: Serialize>(value: moveit_core::Result<T>) -> Reply {
    value
        .map_err(|e| {
            // Keep NeverLaunched / BrowserOpen wording intact for the shell's
            // blocked screen. Still run the same redactor so paths and secrets
            // cannot leak into the IPC error string.
            let raw = e.to_string();
            let mut log = moveit_core::logbuf::LogBuffer::new();
            log.error(0, &raw);
            log.recent(1)
                .first()
                .map(|line| line.message.clone())
                .unwrap_or(raw)
        })
        .and_then(|v| serde_json::to_value(v).map_err(|e| e.to_string()))
}

async fn run(state: Desktop, action: impl FnOnce(&mut App) -> Reply + Send + 'static) -> Reply {
    tauri::async_runtime::spawn_blocking(move || {
        let mut engine = state.engine.try_lock().map_err(|_| "Move It is busy. Please wait for it to finish.".to_string())?;
        action(&mut engine)
    }).await.map_err(|_| "The operation could not finish.".to_string())?
}

macro_rules! simple_command {
    ($name:ident) => {
        #[tauri::command]
        async fn $name(state: State<'_, Desktop>) -> Reply {
            run(state.inner().clone(), |app| json(app.$name())).await
        }
    }
}
simple_command!(welcome_start);
simple_command!(home_state);
simple_command!(browser_open_check);
simple_command!(pair_show_code);

#[tauri::command]
async fn pair_enter_code(state: State<'_, Desktop>, code: String) -> Reply {
    run(state.inner().clone(), move |app| json(app.pair_enter_code(&code))).await
}
#[tauri::command]
async fn use_pipe(state: State<'_, Desktop>, path: PathBuf, expected_kind: Option<String>) -> Reply {
    if expected_kind.as_deref() == Some("git") && !path.join(".git").exists() {
        return Err("Choose an existing git clone.".into());
    }
    run(state.inner().clone(), move |app| json(app.use_pipe(&path))).await
}
#[tauri::command]
async fn preview_counts(state: State<'_, Desktop>, excluded: Vec<String>, routes: Vec<RouteChoice>) -> Reply {
    run(state.inner().clone(), move |app| json(app.preview_counts(&excluded, &routes))).await
}
#[tauri::command]
async fn move_start(state: State<'_, Desktop>, window: tauri::WebviewWindow, excluded: Vec<String>, routes: Vec<RouteChoice>) -> Reply {
    run(state.inner().clone(), move |app| {
        json(app.move_start(Some(&excluded), &routes, &mut |progress| { let _ = window.emit("move-progress", progress); }))
    }).await
}
#[tauri::command]
async fn undo_last(state: State<'_, Desktop>, force: bool) -> Reply {
    run(state.inner().clone(), move |app| json(app.undo_last(force))).await
}
#[tauri::command]
async fn local_browsers(state: State<'_, Desktop>) -> Reply {
    run(state.inner().clone(), |app| json(Ok(app.local_browsers()))).await
}
#[tauri::command]
async fn local_preview(state: State<'_, Desktop>, source: String, target: String) -> Reply {
    run(state.inner().clone(), move |app| json(app.local_preview(&source, &target))).await
}
#[tauri::command]
async fn local_open_check(state: State<'_, Desktop>, source: String, target: String) -> Reply {
    run(state.inner().clone(), move |app| json(app.local_open_check(&source, &target))).await
}
#[tauri::command]
async fn local_move(state: State<'_, Desktop>, window: tauri::WebviewWindow, source: String, target: String) -> Reply {
    run(state.inner().clone(), move |app| {
        json(app.local_move(&source, &target, &mut |progress| { let _ = window.emit("move-progress", progress); }))
    }).await
}
#[tauri::command]
async fn logs_recent(state: State<'_, Desktop>) -> Reply {
    run(state.inner().clone(), |app| json(Ok(app.logs_recent(500)))).await
}
#[tauri::command]
async fn export_logs(state: State<'_, Desktop>, handle: tauri::AppHandle) -> Result<bool, String> {
    // Only a native save dialog grants a destination for the redacted report.
    let report = run(state.inner().clone(), |app| json(Ok(app.export_logs()))).await?;
    tauri::async_runtime::spawn_blocking(move || {
        let Some(path) = handle.dialog().file().set_file_name("move-it-logs.txt").blocking_save_file() else { return Ok(false) };
        let path = path.into_path().map_err(|_| "Choose a local file.".to_string())?;
        std::fs::write(path, report.as_str().unwrap_or_default()).map_err(|_| "Could not save the log report.".to_string())?;
        Ok(true)
    }).await.map_err(|_| "Could not open the save dialog.".to_string())?
}
#[tauri::command]
async fn pick_folder(handle: tauri::AppHandle) -> Result<Option<PathBuf>, String> {
    tauri::async_runtime::spawn_blocking(move || {
        handle.dialog().file().blocking_pick_folder().map(|p| p.into_path()).transpose()
            .map_err(|_| "Choose a local folder.".to_string())
    }).await.map_err(|_| "Could not open the folder picker.".to_string())?
}
#[tauri::command]
async fn pipe_candidates(handle: tauri::AppHandle) -> Result<Vec<pipes::Candidate>, String> {
    let home = handle.path().home_dir().map_err(|_| "Cannot find your home folder.".to_string())?;
    tauri::async_runtime::spawn_blocking(move || {
        let local = std::env::var_os("LOCALAPPDATA").map(PathBuf::from);
        let roaming = std::env::var_os("APPDATA").map(PathBuf::from);
        pipes::candidates(&home, local.as_deref(), roaming.as_deref())
    }).await.map_err(|_| "Could not check sync folders.".to_string())
}

fn main() {
    tauri::Builder::default()
        .plugin(tauri_plugin_single_instance::init(|app, _, _| {
            if let Some(window) = app.get_webview_window("main") { let _ = window.show(); let _ = window.set_focus(); }
        }))
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_updater::Builder::new().build())
        .setup(|app| {
            let handle = app.handle().clone();
            // Debug fixture mode isolates both browser discovery and the keychain.
            // Production binaries have no fixture switch or memory-key fallback.
            let mut fixture: Option<PathBuf> = None;
            if cfg!(debug_assertions) {
                let args: Vec<_> = std::env::args_os().collect();
                if let Some(index) = args.iter().position(|s| s == "--fixture-root") {
                    fixture = Some(PathBuf::from(args.get(index + 1).ok_or("missing fixture root")?));
                }
            }
            let state_dir = match &fixture { Some(root) => root.join("state"), None => handle.path().app_data_dir()? };
            let mut engine = App::open(&state_dir)?;
            if let Some(root) = fixture {
                std::fs::create_dir_all(root.join("browsers"))?;
                engine = engine.with_browser_base(&root.join("browsers"))
                    .with_key_store(Arc::new(moveit_core::keychain::MemoryStore::default()));
            }
            handle.manage(Desktop { engine: Arc::new(Mutex::new(engine)) });
            updater::spawn_checker(app.handle().clone());
            Ok(())
        })
        .on_window_event(|window, event| {
            if let tauri::WindowEvent::CloseRequested { api, .. } = event {
                if let Some(state) = window.try_state::<Desktop>() {
                    if state.engine.try_lock().is_err() { api.prevent_close(); }
                }
            }
        })
        .invoke_handler(tauri::generate_handler![welcome_start, home_state, browser_open_check,
            pair_show_code, pair_enter_code, use_pipe, pipe_candidates, pick_folder,
            preview_counts, move_start, undo_last, local_browsers, local_preview,
            local_open_check, local_move, logs_recent, export_logs, engine_idle,
            updater::updater_context, updater::updater_check, updater_install,
            updater::open_release_page])
        .run(tauri::generate_context!())
        .expect("could not start Move It");
}

#[cfg(test)]
mod install_gate {
    use super::*;
    use moveit_core::api::App;
    use std::sync::{Arc, Mutex};
    use tempfile::tempdir;

    #[test]
    fn held_engine_lock_blocks_moves_during_install() {
        let dir = tempdir().unwrap();
        let app = App::open(dir.path()).unwrap();
        let desktop = Desktop {
            engine: Arc::new(Mutex::new(app)),
        };
        let held = desktop.engine.try_lock().expect("engine starts free");
        assert!(!desktop.engine_idle());
        assert!(desktop.engine.try_lock().is_err());
        drop(held);
        assert!(desktop.engine_idle());
    }
}
