use std::path::Path;
use std::time::Duration;

use crate::cloud::http::{HttpClient, HttpRequest, Method};
use crate::keychain::TokenStore;
use crate::oauth::config::{resolve_google_secret, OAuthFile};
use crate::oauth::loopback::LoopbackRedirect;
use crate::oauth::pkce::{new_pkce, random_state};
use crate::oauth::tokens::{store_provider_token, Provider, ProviderToken};
use crate::{Error, Result};

pub const SIGN_IN_TIMEOUT: Duration = Duration::from_secs(300);

pub struct SignInOutcome {
    pub authorize_url: String,
    pub redirect: LoopbackRedirect,
    pub state: String,
    pub pkce_verifier: String,
}

pub fn begin_sign_in(provider: Provider, oauth: &OAuthFile, _oauth_dir: &Path) -> Result<SignInOutcome> {
    let pkce = new_pkce()?;
    let state = random_state()?;
    let redirect = LoopbackRedirect::bind()?;
    let authorize_url = match provider {
        Provider::Google => google_authorize_url(oauth, &redirect.redirect_uri, &pkce.challenge, &state)?,
        Provider::Dropbox => dropbox_authorize_url(oauth, &redirect.redirect_uri, &pkce.challenge, &state)?,
    };
    Ok(SignInOutcome {
        authorize_url,
        redirect,
        state,
        pkce_verifier: pkce.verifier,
    })
}

pub fn complete_sign_in(
    store: &dyn TokenStore,
    provider: Provider,
    byok: bool,
    oauth: &OAuthFile,
    oauth_dir: &Path,
    http: &dyn HttpClient,
    outcome: SignInOutcome,
) -> Result<ProviderToken> {
    let redirect_uri = outcome.redirect.redirect_uri.clone();
    let verifier = outcome.pkce_verifier.clone();
    let code = outcome.redirect.wait_for_code(&outcome.state, SIGN_IN_TIMEOUT)?;
    let token = match provider {
        Provider::Google => exchange_google(http, oauth, oauth_dir, &redirect_uri, &code, &verifier)?,
        Provider::Dropbox => exchange_dropbox(http, oauth, &redirect_uri, &code, &verifier)?,
    };
    store_provider_token(store, provider, byok, &token)?;
    Ok(token)
}

pub fn sign_in(
    store: &dyn TokenStore,
    provider: Provider,
    byok: bool,
    oauth: &OAuthFile,
    oauth_dir: &Path,
    http: &dyn HttpClient,
) -> Result<(String, ProviderToken)> {
    let start = begin_sign_in(provider, oauth, oauth_dir)?;
    let url = start.authorize_url.clone();
    let token = complete_sign_in(store, provider, byok, oauth, oauth_dir, http, start)?;
    Ok((url, token))
}

pub fn revoke_tokens(provider: Provider, http: &dyn HttpClient, access: &str) -> Result<()> {
    match provider {
        Provider::Google => {
            let _ = http.request(HttpRequest {
                method: Method::Post,
                url: "https://oauth2.googleapis.com/revoke".into(),
                headers: vec![("Content-Type".into(), "application/x-www-form-urlencoded".into())],
                body: Some(format!("token={}", url_encode(access)).into_bytes()),
            });
        }
        Provider::Dropbox => {
            let _ = http.request(HttpRequest {
                method: Method::Post,
                url: "https://api.dropboxapi.com/2/auth/token/revoke".into(),
                headers: vec![("Authorization".into(), format!("Bearer {access}"))],
                body: None,
            });
        }
    }
    Ok(())
}

fn google_authorize_url(oauth: &OAuthFile, redirect: &str, challenge: &str, state: &str) -> Result<String> {
    let g = oauth
        .google
        .as_ref()
        .ok_or_else(|| Error::Refused("google is not configured".into()))?;
    let scope = g.scopes.join(" ");
    Ok(format!(
        "https://accounts.google.com/o/oauth2/v2/auth?response_type=code&client_id={}&redirect_uri={}&scope={}&state={}&code_challenge={}&code_challenge_method=S256&access_type=offline&prompt=consent",
        url_encode(&g.client_id),
        url_encode(redirect),
        url_encode(&scope),
        url_encode(state),
        url_encode(challenge),
    ))
}

fn dropbox_authorize_url(oauth: &OAuthFile, redirect: &str, challenge: &str, state: &str) -> Result<String> {
    let d = oauth
        .dropbox
        .as_ref()
        .ok_or_else(|| Error::Refused("dropbox is not configured".into()))?;
    let scope = d.scopes.join(" ");
    Ok(format!(
        "https://www.dropbox.com/oauth2/authorize?response_type=code&client_id={}&redirect_uri={}&state={}&code_challenge={}&code_challenge_method=S256&token_access_type=offline&scope={}",
        url_encode(&d.app_key),
        url_encode(redirect),
        url_encode(state),
        url_encode(challenge),
        url_encode(&scope),
    ))
}

fn exchange_google(
    http: &dyn HttpClient,
    oauth: &OAuthFile,
    oauth_dir: &Path,
    redirect: &str,
    code: &str,
    verifier: &str,
) -> Result<ProviderToken> {
    let (client_id, client_secret) = resolve_google_secret(oauth, oauth_dir)?;
    let body = format!(
        "grant_type=authorization_code&code={}&client_id={}&client_secret={}&redirect_uri={}&code_verifier={}",
        url_encode(code),
        url_encode(&client_id),
        url_encode(&client_secret),
        url_encode(redirect),
        url_encode(verifier),
    );
    let resp = http.request(HttpRequest {
        method: Method::Post,
        url: "https://oauth2.googleapis.com/token".into(),
        headers: vec![("Content-Type".into(), "application/x-www-form-urlencoded".into())],
        body: Some(body.into_bytes()),
    })?;
    parse_token_response(&resp.body)
}

fn exchange_dropbox(http: &dyn HttpClient, oauth: &OAuthFile, redirect: &str, code: &str, verifier: &str) -> Result<ProviderToken> {
    let d = oauth
        .dropbox
        .as_ref()
        .ok_or_else(|| Error::Refused("dropbox is not configured".into()))?;
    let body = format!(
        "grant_type=authorization_code&code={}&client_id={}&redirect_uri={}&code_verifier={}",
        url_encode(code),
        url_encode(&d.app_key),
        url_encode(redirect),
        url_encode(verifier),
    );
    let resp = http.request(HttpRequest {
        method: Method::Post,
        url: "https://api.dropboxapi.com/oauth2/token".into(),
        headers: vec![("Content-Type".into(), "application/x-www-form-urlencoded".into())],
        body: Some(body.into_bytes()),
    })?;
    parse_token_response(&resp.body)
}

fn parse_token_response(body: &[u8]) -> Result<ProviderToken> {
    let v: serde_json::Value = serde_json::from_slice(body)
        .map_err(|e| Error::Refused(format!("provider token response was not valid: {e}")))?;
    if let Some(err) = v.get("error").and_then(|x| x.as_str()) {
        return Err(Error::Refused(format!("provider sign-in failed ({err})")));
    }
    let refresh = v
        .get("refresh_token")
        .and_then(|x| x.as_str())
        .ok_or_else(|| Error::Refused("provider did not return a refresh token".into()))?;
    let access = v.get("access_token").and_then(|x| x.as_str()).map(str::to_string);
    let expires_at_unix = v.get("expires_in").and_then(|x| x.as_u64()).map(|secs| {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs() + secs)
            .unwrap_or(0)
    });
    Ok(ProviderToken {
        refresh_token: refresh.to_string(),
        access_token: access,
        expires_at_unix,
    })
}

fn url_encode(s: &str) -> String {
    let mut out = String::new();
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => out.push(b as char),
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}
