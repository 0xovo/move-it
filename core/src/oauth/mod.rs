//! Provider sign-in: PKCE, loopback redirect, token storage. No async runtime.

pub mod access_cache;
pub mod config;
pub mod flow;
pub mod loopback;
mod pkce;
pub mod tokens;

pub use config::{
    builtin_oauth_dir, load_builtin_oauth, load_oauth_file, install_byok_config, resolve_google_secret, OAuthFile,
};
pub use flow::{begin_sign_in, complete_sign_in, revoke_tokens, sign_in, SignInOutcome};
pub use tokens::{
    access_from_stored, delete_provider_token, load_provider_token, store_provider_token, token_account,
    Provider, ProviderToken,
};
