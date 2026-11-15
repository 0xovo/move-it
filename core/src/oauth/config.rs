use std::path::{Path, PathBuf};

use serde::Deserialize;

use crate::{Error, Result};

#[derive(Debug, Clone, Deserialize)]
pub struct OAuthFile {
    pub dropbox: Option<DropboxSection>,
    pub google: Option<GoogleSection>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct DropboxSection {
    pub app_key: String,
    pub flow: String,
    pub scopes: Vec<String>,
    pub access: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct GoogleSection {
    pub client_id: String,
    pub client_file: String,
    pub flow: String,
    pub scopes: Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct GoogleInstalled {
    pub installed: GoogleInstalledInner,
}

#[derive(Debug, Clone, Deserialize)]
pub struct GoogleInstalledInner {
    pub client_id: String,
    pub client_secret: String,
    #[allow(dead_code)]
    pub redirect_uris: Vec<String>,
}

/// XDG-style config dir for built-in OAuth files in dev builds.
pub fn moveit_config_dir() -> PathBuf {
    if let Ok(p) = std::env::var("XDG_CONFIG_HOME") {
        if !p.trim().is_empty() {
            return PathBuf::from(p).join("moveit");
        }
    }
  #[cfg(windows)]
    {
        if let Ok(p) = std::env::var("LOCALAPPDATA") {
            return PathBuf::from(p).join("moveit");
        }
    }
    dirs_home().join(".config").join("moveit")
}

fn dirs_home() -> PathBuf {
    std::env::var_os("HOME")
        .or_else(|| std::env::var_os("USERPROFILE"))
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."))
}

pub fn bundled_oauth_dir() -> Option<PathBuf> {
    std::env::var_os("MOVEIT_BUNDLE_OAUTH_DIR").map(PathBuf::from)
}

fn bundle_has_real_builtin_oauth(dir: &Path) -> bool {
    match load_oauth_file(&dir.join("oauth.json")) {
        Ok(file) => !is_placeholder_oauth(&file),
        Err(_) => false,
    }
}

/// Placeholder values shipped in example copies; must not be used for real sign-in.
pub fn is_placeholder_oauth(file: &OAuthFile) -> bool {
    if let Some(d) = &file.dropbox {
        if d.app_key == "example-dropbox-key" {
            return true;
        }
    }
    if let Some(g) = &file.google {
        if g.client_id.starts_with("example.") {
            return true;
        }
    }
    false
}

/// Resolve the built-in OAuth directory from explicit paths (tests) or env (runtime).
pub(crate) fn resolve_builtin_oauth_dir(
    oauth_dir_override: Option<&Path>,
    bundle_dir: Option<&Path>,
) -> PathBuf {
    if cfg!(any(debug_assertions, test)) {
        if let Some(dir) = oauth_dir_override {
            return dir.to_path_buf();
        }
    }
    if let Some(dir) = bundle_dir {
        if cfg!(any(debug_assertions, test)) {
            if bundle_has_real_builtin_oauth(dir) {
                return dir.to_path_buf();
            }
        } else {
            return dir.to_path_buf();
        }
    }
    moveit_config_dir()
}

/// Directory holding built-in `oauth.json` and the Google client sidecar.
pub fn builtin_oauth_dir() -> PathBuf {
  let oauth_override = if cfg!(any(debug_assertions, test)) {
        std::env::var_os("MOVEIT_OAUTH_DIR").map(PathBuf::from)
    } else {
        None
    };
    let bundle = bundled_oauth_dir();
    resolve_builtin_oauth_dir(
        oauth_override.as_deref(),
        bundle.as_deref(),
    )
}

pub fn builtin_oauth_path() -> PathBuf {
    builtin_oauth_dir().join("oauth.json")
}

fn validate_client_file_name(name: &str) -> Result<()> {
    let file = Path::new(name);
    if file.is_absolute() || name.contains("..") || name.contains('/') || name.contains('\\') {
        return Err(Error::Refused("google client_file must be a simple file name in the config folder".into()));
    }
    Ok(())
}

pub fn byok_oauth_path(app_config: &Path) -> PathBuf {
    app_config.join("oauth-byok.json")
}

pub fn load_oauth_file(path: &Path) -> Result<OAuthFile> {
    let bytes = std::fs::read(path).map_err(|e| {
        if e.kind() == std::io::ErrorKind::NotFound {
            Error::Refused("provider sign-in is not configured on this build".into())
        } else {
            Error::Io(e.to_string())
        }
    })?;
    let mut file: OAuthFile = serde_json::from_slice(&bytes)
        .map_err(|e| Error::Corrupt(format!("provider config is not valid: {e}")))?;
    normalize_flow(&mut file);
    validate(&file)?;
    Ok(file)
}

/// "pkce+loopback" is the spelling used in the setup notes; it is the same flow as "pkce".
fn normalize_flow(file: &mut OAuthFile) {
    if let Some(d) = file.dropbox.as_mut() {
        if d.flow == "pkce+loopback" {
            d.flow = "pkce".into();
        }
    }
    if let Some(g) = file.google.as_mut() {
        if g.flow == "pkce+loopback" {
            g.flow = "pkce".into();
        }
    }
}

/// The built-in Google client file always sits next to oauth.json; keep only its file name.
fn builtin_client_file_name(file: &mut OAuthFile) {
    if let Some(g) = file.google.as_mut() {
        let base = g
            .client_file
            .rsplit(['/', '\\'])
            .next()
            .unwrap_or_default()
            .to_string();
        if !base.is_empty() && base != ".." {
            g.client_file = base;
        }
    }
}

pub fn load_builtin_oauth() -> Result<OAuthFile> {
    let mut file = load_oauth_file(&builtin_oauth_path())?;
    builtin_client_file_name(&mut file);
    if is_placeholder_oauth(&file) && !cfg!(any(debug_assertions, test)) {
        return Err(Error::Refused(
            "provider sign-in is not configured on this build".into(),
        ));
    }
    Ok(file)
}

fn validate(file: &OAuthFile) -> Result<()> {
    if file.dropbox.is_none() && file.google.is_none() {
        return Err(Error::Refused("provider config lists no providers".into()));
    }
    if let Some(d) = &file.dropbox {
        if d.app_key.trim().is_empty() {
            return Err(Error::Corrupt("dropbox app_key is empty".into()));
        }
        if d.flow != "pkce" {
            return Err(Error::Corrupt("dropbox flow must be pkce".into()));
        }
    }
    if let Some(g) = &file.google {
        if g.client_id.trim().is_empty() {
            return Err(Error::Corrupt("google client_id is empty".into()));
        }
        if g.flow != "pkce" {
            return Err(Error::Corrupt("google flow must be pkce".into()));
        }
        for scope in &g.scopes {
            if scope != "https://www.googleapis.com/auth/drive.file" {
                return Err(Error::Refused("google scopes must be drive.file only".into()));
            }
        }
    }
    if let Some(d) = &file.dropbox {
        let allowed = [
            "files.metadata.read",
            "files.content.read",
            "files.content.write",
        ];
        for scope in &d.scopes {
            if !allowed.contains(&scope.as_str()) {
                return Err(Error::Refused("dropbox scopes are not allowed".into()));
            }
        }
        if d.access != "app_folder" {
            return Err(Error::Refused("dropbox access must be app_folder".into()));
        }
    }
    Ok(())
}

pub fn resolve_google_secret(oauth: &OAuthFile, oauth_dir: &Path) -> Result<(String, String)> {
    let g = oauth
        .google
        .as_ref()
        .ok_or_else(|| Error::Refused("google is not configured".into()))?;
    let file = Path::new(&g.client_file);
    if file.is_absolute() || g.client_file.contains("..") {
        return Err(Error::Refused("google client_file must be a simple file name in the config folder".into()));
    }
    let client_path = oauth_dir.join(file);
    let bytes = std::fs::read(&client_path)
        .map_err(|e| Error::Io(format!("cannot read google client file: {e}")))?;
    let installed: GoogleInstalled = serde_json::from_slice(&bytes)
        .map_err(|e| Error::Corrupt(format!("google client file is damaged: {e}")))?;
    let secret = installed.installed.client_secret.trim().to_string();
    if secret.is_empty() {
        return Err(Error::Corrupt("google client_secret is empty".into()));
    }
    Ok((g.client_id.clone(), secret))
}

/// Copy a user-chosen BYOK file into the app config dir with mode 600.
pub fn install_byok_config(src: &Path, app_config: &Path) -> Result<PathBuf> {
    let parsed = load_oauth_file(src)?;
    if let Some(g) = &parsed.google {
        validate_client_file_name(&g.client_file)?;
    }
    std::fs::create_dir_all(app_config).map_err(|e| Error::Io(e.to_string()))?;
    let dest = byok_oauth_path(app_config);
    let src_canon = std::fs::canonicalize(src).map_err(|e| Error::Io(e.to_string()))?;
    if let Ok(dest_canon) = std::fs::canonicalize(&dest) {
        if src_canon == dest_canon {
            return Err(Error::Refused("choose a different oauth config file".into()));
        }
    }
    std::fs::copy(src, &dest).map_err(|e| Error::Io(e.to_string()))?;
    restrict_permissions(&dest)?;
    if let Some(g) = &parsed.google {
        let sidecar = src.parent().unwrap_or(src).join(&g.client_file);
        if sidecar.is_file() {
            let target = app_config.join(&g.client_file);
            if let (Ok(a), Ok(b)) = (std::fs::canonicalize(&sidecar), std::fs::canonicalize(&target)) {
                if a == b {
                    return Err(Error::Refused("google client_file must not point at itself".into()));
                }
            }
            std::fs::copy(&sidecar, &target).map_err(|e| Error::Io(e.to_string()))?;
            restrict_permissions(&target)?;
        }
    }
    validate(&parsed)?;
    Ok(dest)
}

#[cfg(unix)]
fn restrict_permissions(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
        .map_err(|e| Error::Io(e.to_string()))
}

#[cfg(not(unix))]
fn restrict_permissions(_path: &Path) -> Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const FIXTURE: &str = r#"{
      "dropbox": {"app_key":"test-dropbox-key","flow":"pkce","scopes":["files.metadata.read","files.content.read","files.content.write"],"access":"app_folder"},
      "google": {"client_id":"test-google-id","client_file":"google-client.json","flow":"pkce","scopes":["https://www.googleapis.com/auth/drive.file"]}
    }"#;

    #[test]
    fn accepts_setup_notes_spelling_and_path_client_file() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("oauth.json");
        std::fs::write(
            &path,
            br#"{"dropbox":{"app_key":"k","flow":"pkce+loopback","scopes":["files.content.read"],"access":"app_folder"},
                "google":{"client_id":"id.apps.googleusercontent.com","client_file":"~/.config/moveit/google-client.json","flow":"pkce+loopback","scopes":["https://www.googleapis.com/auth/drive.file"]}}"#,
        )
        .unwrap();
        let mut file = super::load_oauth_file(&path).expect("setup-notes spelling loads");
        assert_eq!(file.google.as_ref().unwrap().flow, "pkce");
        assert_eq!(file.dropbox.as_ref().unwrap().flow, "pkce");
        super::builtin_client_file_name(&mut file);
        assert_eq!(file.google.as_ref().unwrap().client_file, "google-client.json");
    }

    #[test]
    fn validates_fixture_shape() {
        let file: OAuthFile = serde_json::from_str(FIXTURE).unwrap();
        validate(&file).unwrap();
    }

    #[test]
    fn bundled_oauth_dir_wins_when_fixture_env_unset() {
        let tmp = tempfile::tempdir().unwrap();
        let bundle = tmp.path().join("bundle");
        std::fs::create_dir_all(&bundle).unwrap();
        std::fs::write(bundle.join("oauth.json"), FIXTURE).unwrap();
        assert_eq!(
            super::resolve_builtin_oauth_dir(None, Some(&bundle)),
            bundle
        );
    }

    #[test]
    fn debug_skips_placeholder_bundle_for_user_config_dir() {
        let tmp = tempfile::tempdir().unwrap();
        let bundle = tmp.path().join("bundle");
        std::fs::create_dir_all(&bundle).unwrap();
        std::fs::write(
            bundle.join("oauth.json"),
            br#"{"dropbox":{"app_key":"example-dropbox-key","flow":"pkce","scopes":["files.metadata.read"],"access":"app_folder"}}"#,
        )
        .unwrap();
        assert_ne!(super::resolve_builtin_oauth_dir(None, Some(&bundle)), bundle);
    }
}
