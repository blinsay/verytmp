#![doc = include_str!("../README.md")]

#[cfg(not(target_os = "linux"))]
pub fn verytmp() {
    compile_error!("verytmp is linux-only")
}

#[cfg(target_os = "linux")]
pub mod linux;

#[cfg(target_os = "linux")]
pub use linux::*;

#[cfg(all(target_os = "linux", not(feature = "cap-std")))]
mod no_cap; // fr fr
