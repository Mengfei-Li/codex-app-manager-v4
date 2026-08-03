use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::error::DeliveryError;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CredentialHandle {
    pub service: String,
    pub account: String,
}

pub trait CredentialVault {
    fn get(&self, handle: &CredentialHandle) -> Result<Option<Vec<u8>>, DeliveryError>;
    fn set(&mut self, handle: &CredentialHandle, secret: &[u8]) -> Result<(), DeliveryError>;
    fn delete(&mut self, handle: &CredentialHandle) -> Result<(), DeliveryError>;
}

#[derive(Default)]
pub struct MemoryCredentialVault {
    entries: BTreeMap<(String, String), Vec<u8>>,
}

impl MemoryCredentialVault {
    pub fn contains(&self, handle: &CredentialHandle) -> bool {
        self.entries
            .contains_key(&(handle.service.clone(), handle.account.clone()))
    }
}

impl CredentialVault for MemoryCredentialVault {
    fn get(&self, handle: &CredentialHandle) -> Result<Option<Vec<u8>>, DeliveryError> {
        Ok(self
            .entries
            .get(&(handle.service.clone(), handle.account.clone()))
            .cloned())
    }

    fn set(&mut self, handle: &CredentialHandle, secret: &[u8]) -> Result<(), DeliveryError> {
        if secret.is_empty() {
            return Err(DeliveryError::ConfigTransaction(
                "refusing to store an empty credential".to_string(),
            ));
        }
        self.entries.insert(
            (handle.service.clone(), handle.account.clone()),
            secret.to_vec(),
        );
        Ok(())
    }

    fn delete(&mut self, handle: &CredentialHandle) -> Result<(), DeliveryError> {
        self.entries
            .remove(&(handle.service.clone(), handle.account.clone()));
        Ok(())
    }
}
