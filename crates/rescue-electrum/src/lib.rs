//! The default I/O for Winnow Rescue: an Electrum protocol client over TLS and
//! an Esplora adapter, each implementing the core's source traits. Optional:
//! a host with its own network stack implements the traits itself.

/// The core this adapter speaks for.
pub const CORE_VERSION: &str = rescue_core::VERSION;
