use crate::identity::FourWordAddress;
use crate::messaging::user_handle::UserHandle;

/// Resolve a display handle for a given network address.
///
/// Placeholder implementation: maps to a string representation until a
/// directory/profile service is available.
pub fn resolve_handle(addr: &FourWordAddress) -> UserHandle {
    // TODO: Replace with directory/profile lookup when available
    UserHandle::from(addr.to_string())
}

