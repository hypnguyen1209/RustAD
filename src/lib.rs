#![recursion_limit = "512"]

pub mod args;
pub mod banner;
pub mod transport;
pub mod utils;
pub mod api;
pub mod modules;

pub mod enums;
pub mod json;
pub mod objects;
pub mod analyze;
pub mod kerberos;
pub mod snaffler;
pub(crate) mod storage;

extern crate bitflags;
extern crate chrono;
extern crate regex;

#[doc(inline)]
pub use transport::ldap::ldap_auth;
#[doc(inline)]
pub use ldap3::SearchEntry;

pub use json::maker::make_result;
pub use api::{prepare_results_from_source, prepare_results_from_disk};
pub use storage::{Storage, EntrySource, DiskStorage, DiskStorageReader};
