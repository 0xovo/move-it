//! Cloud API pipes and a mockable HTTP layer.

pub mod dropbox;
pub mod google;
pub mod http;
pub mod index;
pub mod session;

pub use dropbox::DropboxPipe;
pub use google::GoogleDrivePipe;
