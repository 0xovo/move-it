//! Cloud API pipes and a mockable HTTP layer.

pub mod dropbox;
pub mod google;
pub mod http;
pub mod index;
pub mod session;
pub mod sync_files;

pub use dropbox::DropboxPipe;
pub use google::GoogleDrivePipe;
