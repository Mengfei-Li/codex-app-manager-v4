use std::path::Path;

use crate::error::DeliveryError;

/// Restrict a V4-owned control path to the current user and verify the result
/// where the native platform exposes a readback API.
pub fn harden_control_path(path: &Path, directory: bool) -> Result<(), DeliveryError> {
    crate::config::owner_only_permissions(path, directory)
}
