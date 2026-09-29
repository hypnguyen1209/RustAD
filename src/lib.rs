#![recursion_limit = "512"]

pub mod api;
pub mod args;
pub mod banner;
pub mod modules;
pub mod transport;
pub mod utils;

pub mod analyze;
pub mod enums;
pub mod json;
pub mod kerberos;
pub mod objects;
pub mod snaffler;
pub(crate) mod storage;

extern crate bitflags;
extern crate chrono;
extern crate regex;

#[doc(inline)]
pub use ldap3::SearchEntry;
#[doc(inline)]
pub use transport::ldap::ldap_auth;

pub use api::{prepare_results_from_disk, prepare_results_from_source};
pub use json::maker::make_result;
pub use storage::{DiskStorage, DiskStorageReader, EntrySource, Storage};
