use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::error::DeliveryError;

const FINGERPRINT_DOMAIN: &[u8] = b"provider-codex-v4-device-v1\0";

/// Returns only the domain-separated digest. Raw OS identifiers never cross
/// this function boundary and must not be logged or persisted.
#[cfg(target_os = "windows")]
pub fn native_device_hash() -> Result<String, DeliveryError> {
    use winreg::enums::{HKEY_LOCAL_MACHINE, KEY_READ, KEY_WOW64_64KEY};
    use winreg::RegKey;

    let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
    let key = hklm
        .open_subkey_with_flags(
            "SOFTWARE\\Microsoft\\Cryptography",
            KEY_READ | KEY_WOW64_64KEY,
        )
        .map_err(|_| DeliveryError::InvalidClaim("device-id-unavailable".to_string()))?;
    let machine_guid: String = key
        .get_value("MachineGuid")
        .map_err(|_| DeliveryError::InvalidClaim("device-id-unavailable".to_string()))?;
    let machine_guid = Zeroizing::new(machine_guid.trim().to_ascii_lowercase());
    if machine_guid.len() < 16 || machine_guid.len() > 256 {
        return Err(DeliveryError::InvalidClaim("device-id-invalid".to_string()));
    }

    let sid = crate::windows_security::current_user_sid_bytes()
        .map_err(|_| DeliveryError::InvalidClaim("device-user-unavailable".to_string()))?;
    fingerprint_hash_parts("windows-machine-user", &[machine_guid.as_bytes(), &sid])
}

#[cfg(target_os = "macos")]
pub fn native_device_hash() -> Result<String, DeliveryError> {
    use std::process::{Command, Stdio};

    let output = Command::new("/usr/sbin/ioreg")
        .args(["-rd1", "-c", "IOPlatformExpertDevice"])
        .stdin(Stdio::null())
        .stderr(Stdio::null())
        .output()
        .map_err(|_| DeliveryError::InvalidClaim("device-id-unavailable".to_string()))?;
    if !output.status.success() || output.stdout.len() > 256 * 1024 {
        return Err(DeliveryError::InvalidClaim(
            "device-id-unavailable".to_string(),
        ));
    }
    let text = Zeroizing::new(
        String::from_utf8(output.stdout)
            .map_err(|_| DeliveryError::InvalidClaim("device-id-invalid".to_string()))?,
    );
    let marker = "\"IOPlatformUUID\" = \"";
    let start = text
        .find(marker)
        .ok_or_else(|| DeliveryError::InvalidClaim("device-id-unavailable".to_string()))?
        + marker.len();
    let tail = &text[start..];
    let end = tail
        .find('"')
        .ok_or_else(|| DeliveryError::InvalidClaim("device-id-invalid".to_string()))?;
    fingerprint_hash("macos-io-platform-uuid", &tail.as_bytes()[..end])
}

#[cfg(not(any(target_os = "windows", target_os = "macos")))]
pub fn native_device_hash() -> Result<String, DeliveryError> {
    Err(DeliveryError::InvalidClaim(
        "device-platform-unsupported".to_string(),
    ))
}

#[cfg(any(target_os = "macos", test))]
fn fingerprint_hash(kind: &str, raw: &[u8]) -> Result<String, DeliveryError> {
    let normalized = Zeroizing::new(
        std::str::from_utf8(raw)
            .map_err(|_| DeliveryError::InvalidClaim("device-id-invalid".to_string()))?
            .trim()
            .to_ascii_lowercase(),
    );
    if normalized.len() < 16 || normalized.len() > 256 {
        return Err(DeliveryError::InvalidClaim("device-id-invalid".to_string()));
    }
    fingerprint_hash_parts(kind, &[normalized.as_bytes()])
}

fn fingerprint_hash_parts(kind: &str, values: &[&[u8]]) -> Result<String, DeliveryError> {
    if values.is_empty()
        || values.len() > 8
        || values
            .iter()
            .any(|value| value.is_empty() || value.len() > 512)
    {
        return Err(DeliveryError::InvalidClaim("device-id-invalid".to_string()));
    }
    let mut hasher = Sha256::new();
    hasher.update(FINGERPRINT_DOMAIN);
    hasher.update(kind.as_bytes());
    for value in values {
        hasher.update((value.len() as u64).to_be_bytes());
        hasher.update(value);
    }
    let digest = hasher.finalize();
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(digest.len() * 2);
    for byte in digest {
        output.push(HEX[(byte >> 4) as usize] as char);
        output.push(HEX[(byte & 0x0f) as usize] as char);
    }
    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::{fingerprint_hash, fingerprint_hash_parts};

    #[test]
    fn fingerprint_is_stable_but_domain_and_value_sensitive() {
        let a = fingerprint_hash("windows-machine-guid", b" ABCDEF0123456789 ").unwrap();
        let b = fingerprint_hash("windows-machine-guid", b"abcdef0123456789").unwrap();
        let other_value = fingerprint_hash("windows-machine-guid", b"abcdef0123456780").unwrap();
        let other_kind = fingerprint_hash("macos-io-platform-uuid", b"abcdef0123456789").unwrap();
        assert_eq!(a, b);
        assert_ne!(a, other_value);
        assert_ne!(a, other_kind);
        assert_eq!(a.len(), 64);
    }

    #[test]
    fn windows_machine_and_original_user_material_are_both_bound() {
        let base = fingerprint_hash_parts(
            "windows-machine-user",
            &[b"machine-guid-a", b"sid-original-user"],
        )
        .unwrap();
        let other_machine = fingerprint_hash_parts(
            "windows-machine-user",
            &[b"machine-guid-b", b"sid-original-user"],
        )
        .unwrap();
        let other_user = fingerprint_hash_parts(
            "windows-machine-user",
            &[b"machine-guid-a", b"sid-other-user"],
        )
        .unwrap();
        assert_ne!(base, other_machine);
        assert_ne!(base, other_user);
    }
}
