use std::path::{Path, PathBuf};
use std::sync::Arc;

use crate::cloud::dropbox::DropboxPipe;
use crate::cloud::google::GoogleDrivePipe;
use crate::cloud::http::{HttpClient, SharedHttp};
use crate::cloud::session::open_session;
use crate::keychain::TokenStore;
use crate::oauth::config::{
    builtin_oauth_dir, byok_oauth_path, install_byok_config, load_builtin_oauth, load_oauth_file, OAuthFile,
};
use crate::cloud::session::refresh_access;
use crate::oauth::flow::{begin_sign_in, exchange_and_store_token, revoke_tokens, wait_sign_in_code, SignInOutcome};
use crate::oauth::tokens::{delete_provider_token, load_provider_token, Provider};
use crate::pipe::Pipe;
use crate::{Error, Result};

use super::App;
use super::PipeInfo;

pub struct CloudPaths {
    pub byok_config: PathBuf,
}

#[derive(Debug, Clone)]
pub struct CloudPipeStatus {
    pub google_connected: bool,
    pub dropbox_connected: bool,
    pub google_byok_connected: bool,
    pub dropbox_byok_connected: bool,
    pub byok_installed: bool,
    pub active_byok: bool,
}

impl App {
    pub fn cloud_status_paths(&self) -> Option<CloudPaths> {
        let dir = self.app_config_dir.as_ref()?;
        Some(CloudPaths {
            byok_config: byok_oauth_path(dir),
        })
    }

    pub fn cloud_pipe_status(&self) -> CloudPipeStatus {
        let byok_installed = self
            .cloud_status_paths()
            .map(|p| p.byok_config.exists())
            .unwrap_or(false);
        CloudPipeStatus {
            google_connected: self.cloud_connected("google", false).unwrap_or(false),
            dropbox_connected: self.cloud_connected("dropbox", false).unwrap_or(false),
            google_byok_connected: self.cloud_connected("google", true).unwrap_or(false),
            dropbox_byok_connected: self.cloud_connected("dropbox", true).unwrap_or(false),
            byok_installed,
            active_byok: self.config.pipe_byok.unwrap_or(false),
        }
    }

    pub(crate) fn http(&self) -> SharedHttp {
        self.http.clone()
    }

    pub fn token_store(&self) -> Arc<dyn TokenStore + Send + Sync> {
        self.token_store.clone()
    }

    fn oauth_for(&self, byok: bool) -> Result<(OAuthFile, PathBuf)> {
        if byok {
            let dir = self
                .app_config_dir
                .as_ref()
                .ok_or_else(|| Error::Refused("app config is not available".into()))?;
            let path = byok_oauth_path(dir);
            Ok((load_oauth_file(&path)?, dir.clone()))
        } else {
            let dir = self
                .builtin_oauth_dir
                .clone()
                .unwrap_or_else(builtin_oauth_dir);
            let oauth = if self.builtin_oauth_dir.is_some() {
                load_oauth_file(&dir.join("oauth.json"))?
            } else {
                load_builtin_oauth()?
            };
            Ok((oauth, dir))
        }
    }

    pub fn cloud_connected(&self, provider: &str, byok: bool) -> Result<bool> {
        let p = Provider::parse(provider)?;
        Ok(load_provider_token(self.token_store.as_ref(), p, byok)?.is_some())
    }

    pub fn prepare_cloud_sign_in(&self, provider: &str, byok: bool) -> Result<(String, SignInOutcome)> {
        let p = Provider::parse(provider)?;
        let (oauth, dir) = self.oauth_for(byok)?;
        let start = begin_sign_in(p, &oauth, &dir)?;
        Ok((start.authorize_url.clone(), start))
    }

    pub fn wait_cloud_sign_in_code(
        start: SignInOutcome,
        timeout: std::time::Duration,
        cancel: Option<&std::sync::atomic::AtomicBool>,
    ) -> Result<(String, String, String)> {
        wait_sign_in_code(start, timeout, cancel)
    }

    pub fn finish_cloud_sign_in_after_code(
        &self,
        provider: &str,
        byok: bool,
        redirect_uri: &str,
        verifier: &str,
        code: &str,
    ) -> Result<()> {
        let p = Provider::parse(provider)?;
        let (oauth, dir) = self.oauth_for(byok)?;
        let _token = exchange_and_store_token(
            &self.access_cache,
            self.token_store.as_ref(),
            p,
            byok,
            &oauth,
            &dir,
            self.http.as_ref(),
            redirect_uri,
            verifier,
            code,
        )?;
        Ok(())
    }

    pub fn abandon_byok(&mut self) -> Result<()> {
        if let Some(dir) = &self.app_config_dir {
            let path = byok_oauth_path(dir);
            if let Ok(oauth) = load_oauth_file(&path) {
                if let Some(g) = &oauth.google {
                    let _ = std::fs::remove_file(dir.join(&g.client_file));
                }
            }
            let _ = std::fs::remove_file(path);
        }
        for p in [Provider::Google, Provider::Dropbox] {
            let _ = delete_provider_token(self.token_store.as_ref(), p, true);
            self.access_cache.clear_provider(p);
        }
        Ok(())
    }

    pub fn install_byok(&mut self, src: &Path) -> Result<()> {
        let dir = self
            .app_config_dir
            .clone()
            .ok_or_else(|| Error::Refused("app config is not available".into()))?;
        install_byok_config(src, &dir)?;
        self.clear_builtin_byok_tokens()
    }

    fn clear_builtin_byok_tokens(&mut self) -> Result<()> {
        for p in [Provider::Google, Provider::Dropbox] {
            let _ = delete_provider_token(self.token_store.as_ref(), p, true);
        }
        Ok(())
    }

    pub fn use_cloud_pipe(&mut self, provider: &str, byok: bool) -> Result<PipeInfo> {
        let p = Provider::parse(provider)?;
        if load_provider_token(self.token_store.as_ref(), p, byok)?.is_none() {
            return Err(Error::Refused("sign in to this provider first".into()));
        }
        if !byok {
            self.abandon_byok()?;
        }
        let staging = self.cloud_staging(p, byok)?;
        std::fs::create_dir_all(&staging).map_err(|e| Error::Io(e.to_string()))?;
        self.config.pipe_kind = Some(p.as_str().to_string());
        self.config.pipe_path = Some(staging.to_string_lossy().into_owned());
        self.config.pipe_byok = Some(byok);
        self.save_config()?;
        let pipe = self.require_pipe()?;
        Ok(PipeInfo {
            kind: p.as_str().to_string(),
            place: pipe.place().to_string_lossy().into_owned(),
        })
    }

    /// Drop the token for one provider variant after the user cancels a connected sign-in attempt.
    pub fn pipe_sign_in_discard(&mut self, provider: &str, byok: bool) -> Result<()> {
        let p = Provider::parse(provider)?;
        if let Some(token) = load_provider_token(self.token_store.as_ref(), p, byok)? {
            if let Ok(material) = self.revoke_material(p, byok, &token) {
                let _ = revoke_tokens(p, self.http.as_ref(), &material);
            }
        }
        let _ = delete_provider_token(self.token_store.as_ref(), p, byok);
        self.access_cache.clear_variant(p, byok);
        if let Ok(staging) = self.cloud_staging(p, byok) {
            if staging.exists() {
                let _ = std::fs::remove_dir_all(staging);
            }
        }
        Ok(())
    }

    pub fn pipe_sign_out(&mut self, provider: &str) -> Result<()> {
        let p = Provider::parse(provider)?;
        for byok in [false, true] {
            if let Some(token) = load_provider_token(self.token_store.as_ref(), p, byok)? {
                if let Ok(material) = self.revoke_material(p, byok, &token) {
                    let _ = revoke_tokens(p, self.http.as_ref(), &material);
                }
            }
            let _ = delete_provider_token(self.token_store.as_ref(), p, byok);
            if let Ok(staging) = self.cloud_staging(p, byok) {
                if staging.exists() {
                    let _ = std::fs::remove_dir_all(staging);
                }
            }
        }
        self.access_cache.clear_provider(p);
        if self.config.pipe_kind.as_deref() == Some(p.as_str()) {
            self.config.pipe_kind = None;
            self.config.pipe_path = None;
            self.config.pipe_byok = None;
            self.save_config()?;
        }
        Ok(())
    }

    fn revoke_material(&self, provider: Provider, byok: bool, token: &crate::oauth::tokens::ProviderToken) -> Result<String> {
        if let Some(access) = self.access_cache.get(provider, byok) {
            return Ok(access);
        }
        match provider {
            Provider::Google => Ok(token.refresh_token.clone()),
            Provider::Dropbox => {
                let (oauth, dir) = self.oauth_for(byok)?;
                let mint = refresh_access(provider, self.http.as_ref(), &oauth, &dir, token)?;
                Ok(mint.access)
            }
        }
    }

    pub(crate) fn cloud_staging(&self, provider: Provider, byok: bool) -> Result<PathBuf> {
        let name = if byok {
            format!("{}-byok", provider.as_str())
        } else {
            provider.as_str().to_string()
        };
        Ok(self.state_dir.join("cloud-staging").join(name))
    }

    pub fn build_cloud_pipe(&self, kind: &str, staging: &Path) -> Result<Box<dyn Pipe>> {
        let byok = self.config.pipe_byok.unwrap_or(false);
        let provider = Provider::parse(kind)?;
        let (oauth, dir) = self.oauth_for(byok)?;
        let session = open_session(
            &self.access_cache,
            self.token_store.as_ref(),
            provider,
            byok,
            &oauth,
            &dir,
            self.http.as_ref(),
        )?;
        let http = self.http();
        let pipe: Box<dyn Pipe> = match provider {
            Provider::Google => Box::new(GoogleDrivePipe::new(staging.to_path_buf(), http, session.access)?),
            Provider::Dropbox => Box::new(DropboxPipe::new(staging.to_path_buf(), http, session.access)?),
        };
        let _ = (session.refreshed, dir, oauth);
        Ok(pipe)
    }
}
