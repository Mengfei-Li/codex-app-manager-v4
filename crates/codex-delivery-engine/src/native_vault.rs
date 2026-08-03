use keyring::v1::{Entry, Error as KeyringError};

use crate::credential::{CredentialHandle, CredentialVault};
use crate::error::DeliveryError;

/// Native per-user credential storage. The platform crate selects Windows
/// Credential Manager or the macOS Keychain; secret bytes never enter the UI.
#[derive(Default)]
pub struct NativeCredentialVault;

impl NativeCredentialVault {
    pub fn available() -> Result<(), DeliveryError> {
        Entry::store_status()
            .as_ref()
            .map_err(|error| {
                DeliveryError::ConfigTransaction(format!("native-vault-unavailable:{error}"))
            })
            .copied()
    }

    fn entry(handle: &CredentialHandle) -> Result<Entry, DeliveryError> {
        if handle.service.is_empty() || handle.account.is_empty() {
            return Err(DeliveryError::ConfigTransaction(
                "native-vault-handle-invalid".to_string(),
            ));
        }
        Entry::new(&handle.service, &handle.account).map_err(map_error)
    }
}

impl CredentialVault for NativeCredentialVault {
    fn get(&self, handle: &CredentialHandle) -> Result<Option<Vec<u8>>, DeliveryError> {
        match Self::entry(handle)?.get_secret() {
            Ok(secret) => Ok(Some(secret)),
            Err(KeyringError::NoEntry) => Ok(None),
            Err(error) => Err(map_error(error)),
        }
    }

    fn set(&mut self, handle: &CredentialHandle, secret: &[u8]) -> Result<(), DeliveryError> {
        if secret.is_empty() {
            return Err(DeliveryError::ConfigTransaction(
                "native-vault-secret-empty".to_string(),
            ));
        }
        Self::entry(handle)?.set_secret(secret).map_err(map_error)
    }

    fn delete(&mut self, handle: &CredentialHandle) -> Result<(), DeliveryError> {
        match Self::entry(handle)?.delete_credential() {
            Ok(()) | Err(KeyringError::NoEntry) => Ok(()),
            Err(error) => Err(map_error(error)),
        }
    }
}

fn map_error(error: KeyringError) -> DeliveryError {
    DeliveryError::ConfigTransaction(format!("native-vault-error:{error}"))
}
