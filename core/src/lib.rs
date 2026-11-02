//! Move It engine.

pub mod bookmarks;
pub mod cookies;
pub mod engine;
pub mod extstate;
pub mod history;
pub mod localstorage;
pub mod logins;
pub mod paths;
pub mod oscrypt;
pub mod pairing;
pub mod pipe;
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
    /// Another Move It is already working on this browser.
    #[error("Move It is already working on this browser")]
    Busy,
    /// A store is locked because the browser is still open: close it and try again.
    #[error("the browser is still open; close it completely and try again")]
    BrowserOpen,
    #[error("{0}")]
    Corrupt(String),
    #[error("{0}")]
    Refused(String),
    #[error("{0}")]
    Io(String),
}

pub type Result<T> = std::result::Result<T, Error>;
