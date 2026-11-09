use std::path::{Path, PathBuf};
use std::sync::Arc;

use crate::cloud::dropbox::DropboxPipe;
use crate::cloud::google::GoogleDrivePipe;
use crate::cloud::http::{HttpClient, SharedHttp};
use crate::cloud::session::open_session;
use crate::keychain::TokenStore;
use crate::oauth::access_cache;
use crate::oauth::config::{
    builtin_oauth_dir, byok_oauth_path, install_byok_config, load_builtin_oauth, load_oauth_file, OAuthFile,
};
use crate::oauth::flow::{begin_sign_in, complete_sign_in, revoke_tokens, SignInOutcome};
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
            let dir = builtin_oauth_dir();
            Ok((load_builtin_oauth().or_else(|_| load_oauth_file(&dir.join("oauth.json")))?, dir))
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

    pub fn finish_cloud_sign_in(&self, provider: &str, byok: bool, start: SignInOutcome) -> Result<()> {
        let p = Provider::parse(provider)?;
        let (oauth, dir) = self.oauth_for(byok)?;
        let _token = complete_sign_in(self.token_store.as_ref(), p, byok, &oauth, &dir, self.http.as_ref(), start)?;
        Ok(())
    }

    pub fn cloud_sign_in_clones(
        &self,
        provider: &str,
        byok: bool,
    ) -> Result<(Provider, OAuthFile, PathBuf, std::sync::Arc<dyn TokenStore + Send + Sync>, SharedHttp)> {
        let p = Provider::parse(provider)?;
        let (oauth, dir) = self.oauth_for(byok)?;
        Ok((p, oauth, dir, self.token_store.clone(), self.http.clone()))
    }

    pub fn abandon_byok(&mut self) -> Result<()> {
        if let Some(dir) = &self.app_config_dir {
            let _ = std::fs::remove_file(byok_oauth_path(dir));
        }
        for p in [Provider::Google, Provider::Dropbox] {
            let _ = delete_provider_token(self.token_store.as_ref(), p, true);
            access_cache::clear_provider(p);
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

    pub fn pipe_sign_out(&mut self, provider: &str) -> Result<()> {
        let p = Provider::parse(provider)?;
        for byok in [false, true] {
            if let Some(token) = load_provider_token(self.token_store.as_ref(), p, byok)? {
                let material = access_cache::get(p, byok).unwrap_or_else(|| token.refresh_token.clone());
                let _ = revoke_tokens(p, self.http.as_ref(), &material);
            }
            let _ = delete_provider_token(self.token_store.as_ref(), p, byok);
            if let Ok(staging) = self.cloud_staging(p, byok) {
                if staging.exists() {
                    let _ = std::fs::remove_dir_all(staging);
                }
            }
        }
        access_cache::clear_provider(p);
        if self.config.pipe_kind.as_deref() == Some(p.as_str()) {
            self.config.pipe_kind = None;
            self.config.pipe_path = None;
            self.config.pipe_byok = None;
            self.save_config()?;
        }
        Ok(())
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
        let session = open_session(self.token_store.as_ref(), provider, byok, &oauth, &dir, self.http.as_ref())?;
        let http = self.http();
        let pipe: Box<dyn Pipe> = match provider {
            Provider::Google => Box::new(GoogleDrivePipe::new(staging.to_path_buf(), http, session.access)?),
            Provider::Dropbox => Box::new(DropboxPipe::new(staging.to_path_buf(), http, session.access)?),
        };
        let _ = (session.refreshed, dir, oauth);
        Ok(pipe)
    }
}
