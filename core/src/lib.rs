//! Move It engine.

pub mod api;
pub mod bookmarks;
pub mod cookies;
pub mod engine;
pub mod extstate;
pub mod history;
pub mod keychain;
pub mod localstorage;
pub mod logbuf;
pub mod logins;
pub mod paths;
pub mod oscrypt;
pub mod pairing;
pub mod pipe;
pub mod profiles;
pub mod sealed;
pub mod txn;
mod util;

/// Every failure the engine reports. The app maps each kind to a friendly screen.
#[derive(Debug, thiserror::Error, PartialEq)]
pub enum Error {
    /// Wrong sync key, or the box was changed on the way. Deliberately one case.
    #[error("bundle failed its integrity check (wrong sync key, or the file was tampered with)")]
    WrongKeyOrTampered,
    /// A browser value did not unlock: the browser's own password (keyring/Keychain) is not the one we used.
    /// Never silently fall back and re-lock with a guessed password.
    #[error("a browser value did not unlock; the browser's own password was not found")]
    WrongBrowserPassword,
    /// Windows Chrome/Edge App-Bound values (v20): we refuse rather than guess.
    #[error("this browser locks values to itself (App-Bound, v20); it cannot be read from outside")]
    AppBound,
    /// macOS would not hand over a Keychain item: the keychain is locked, or the
    /// read needs the person at the keyboard (an SSH session always lands here).
    /// A clean refusal, never a panic and never a silent empty result.
    #[error("macOS did not allow reading the Keychain (it may be locked, or needs you at the keyboard); unlock it and try again")]
    KeychainLocked,
    /// The OS keychain that holds the sync key could not be used: it is
    /// locked, its daemon did not answer, or it refused the request. A
    /// plain-language refusal the shell can show as-is.
    #[error("the system keychain could not be used: {0}")]
    KeychainUnavailable(String),
    /// Another Move It is already working on this browser.
    #[error("Move It is already working on this browser")]
    Busy,
    /// A store is locked because the browser is still open: close it and try again.
    #[error("the browser is still open; close it completely and try again")]
    BrowserOpen,
    /// The profile folder exists but the browser was never opened there: no
    /// cookie store and no Login Data yet. Refuse cleanly; never plant stores
    /// into a never-launched profile.
    #[error("Open {browser} once, then come back")]
    NeverLaunched { browser: String },
    #[error("{0}")]
    Corrupt(String),
    #[error("{0}")]
    Refused(String),
    #[error("{0}")]
    Io(String),
}

pub type Result<T> = std::result::Result<T, Error>;
