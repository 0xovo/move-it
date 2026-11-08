use std::path::Path;
use std::time::Duration;
use tauri::{AppHandle, Emitter};
use tauri_plugin_updater::UpdaterExt;

pub const GITHUB_RELEASE: &str = "https://github.com/0xovo/move-it/releases/latest";

pub fn package_managed_for_exe(exe: &Path) -> bool {
    if package_managed_linux_path(exe) {
        return true;
    }
    if std::env::var_os("APPIMAGE").is_some() {
        return false;
    }
    false
}

pub fn package_managed_install() -> bool {
    #[cfg(not(target_os = "linux"))]
    {
        return false;
    }
    #[cfg(target_os = "linux")]
    {
        let Ok(exe) = std::env::current_exe() else {
            return false;
        };
        package_managed_for_exe(&exe)
    }
}

pub fn package_managed_linux_path(exe: &Path) -> bool {
    let path = exe.to_string_lossy();
    path.starts_with("/usr/") || path.starts_with("/opt/")
}

pub fn spawn_checker(app: AppHandle) {
    tauri::async_runtime::spawn(async move {
        loop {
            if let Some(version) = check_for_update(&app).await {
                let _ = app.emit("update-available", version);
            }
            tokio::time::sleep(Duration::from_secs(86_400)).await;
        }
    });
}

async fn check_for_update(app: &AppHandle) -> Option<String> {
    let updater = app.updater().ok()?;
    let update = updater.check().await.ok()??;
    let current = app.package_info().version.to_string();
    if update.version == current {
        return None;
    }
    Some(update.version)
}

#[tauri::command]
pub fn updater_context() -> serde_json::Value {
    serde_json::json!({
        "packageManaged": package_managed_install(),
        "githubUrl": GITHUB_RELEASE,
    })
}

#[tauri::command]
pub async fn updater_check(app: AppHandle) -> Result<Option<String>, String> {
    Ok(check_for_update(&app).await)
}

pub async fn install_update(app: AppHandle) -> Result<(), String> {
    if package_managed_install() {
        return Err("Updates for this install are on GitHub.".into());
    }
    let Some(update) = app
        .updater()
        .map_err(|e| e.to_string())?
        .check()
        .await
        .map_err(|e| e.to_string())?
    else {
        return Err("No update is available.".into());
    };
    update
        .download_and_install(|_, _| {}, || {})
        .await
        .map_err(|e| e.to_string())?;
    Ok(())
}

#[tauri::command]
pub fn open_release_page(url: String) -> Result<(), String> {
    if url != GITHUB_RELEASE {
        return Err("That link cannot be opened from here.".into());
    }
    open::that(url).map_err(|_| "Could not open the release page.".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn linux_package_paths_are_managed() {
        assert!(package_managed_linux_path(Path::new("/usr/bin/move-it")));
        assert!(package_managed_linux_path(Path::new("/opt/move-it/move-it")));
        assert!(!package_managed_linux_path(Path::new("/home/user/.local/bin/move-it")));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn appimage_env_is_not_package_managed() {
        std::env::set_var("APPIMAGE", "/tmp/MoveIt.AppImage");
        assert!(!package_managed_install());
        std::env::remove_var("APPIMAGE");
    }

    #[test]
    fn inherited_appimage_does_not_unmanage_system_install() {
        std::env::set_var("APPIMAGE", "/tmp/MoveIt.AppImage");
        assert!(package_managed_for_exe(Path::new("/opt/move-it/move-it")));
        assert!(package_managed_for_exe(Path::new("/usr/bin/move-it")));
        std::env::remove_var("APPIMAGE");
    }
}
