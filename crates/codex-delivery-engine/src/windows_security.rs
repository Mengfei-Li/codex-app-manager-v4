use std::ffi::c_void;
use std::os::windows::ffi::OsStrExt as _;
use std::path::Path;
use std::ptr;

use windows_sys::Win32::Foundation::{CloseHandle, HANDLE};
use windows_sys::Win32::Security::Authorization::{SetNamedSecurityInfoW, SE_FILE_OBJECT};
use windows_sys::Win32::Security::{
    AclSizeInformation, AddAccessAllowedAceEx, EqualSid, GetAce, GetAclInformation,
    GetFileSecurityW, GetLengthSid, GetSecurityDescriptorDacl, GetTokenInformation, InitializeAcl,
    SetFileSecurityW, TokenUser, ACCESS_ALLOWED_ACE, ACL, ACL_REVISION, ACL_SIZE_INFORMATION,
    DACL_SECURITY_INFORMATION, INHERITED_ACE, NO_INHERITANCE, PROTECTED_DACL_SECURITY_INFORMATION,
    SUB_CONTAINERS_AND_OBJECTS_INHERIT, TOKEN_QUERY, TOKEN_USER,
};
use windows_sys::Win32::Storage::FileSystem::FILE_ALL_ACCESS;
use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};
use zeroize::Zeroizing;

use crate::error::DeliveryError;

struct TokenHandle(HANDLE);

impl Drop for TokenHandle {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: the handle was returned by OpenProcessToken and is owned
            // exclusively by this guard.
            unsafe { CloseHandle(self.0) };
        }
    }
}

pub(crate) fn current_user_sid_bytes() -> Result<Zeroizing<Vec<u8>>, DeliveryError> {
    let mut token = ptr::null_mut();
    // SAFETY: token is an out-parameter and the pseudo process handle is valid
    // for the duration of the call.
    if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) } == 0 {
        return Err(security_error("user-token-unavailable"));
    }
    let token = TokenHandle(token);
    let mut required = 0_u32;
    // The first call intentionally discovers the required buffer size.
    unsafe {
        GetTokenInformation(token.0, TokenUser, ptr::null_mut(), 0, &mut required);
    }
    if required < std::mem::size_of::<TOKEN_USER>() as u32 || required > 64 * 1024 {
        return Err(security_error("user-token-invalid"));
    }
    let mut buffer = Zeroizing::new(vec![0_u8; required as usize]);
    // SAFETY: buffer is writable for `required` bytes and remains alive while
    // the TOKEN_USER and SID are read.
    if unsafe {
        GetTokenInformation(
            token.0,
            TokenUser,
            buffer.as_mut_ptr().cast(),
            required,
            &mut required,
        )
    } == 0
    {
        return Err(security_error("user-token-unavailable"));
    }
    // SAFETY: GetTokenInformation populated a TOKEN_USER at the start of the
    // validated buffer.
    let token_user = unsafe { &*(buffer.as_ptr().cast::<TOKEN_USER>()) };
    let sid_length = unsafe { GetLengthSid(token_user.User.Sid) };
    if sid_length == 0 || sid_length > required {
        return Err(security_error("user-sid-invalid"));
    }
    // SAFETY: GetLengthSid validated the SID and supplied its byte length. The
    // SID remains owned by `buffer` during this copy.
    let sid = unsafe {
        std::slice::from_raw_parts(token_user.User.Sid.cast::<u8>(), sid_length as usize)
    };
    Ok(Zeroizing::new(sid.to_vec()))
}

pub(crate) fn apply_owner_only_dacl(path: &Path, directory: bool) -> Result<(), DeliveryError> {
    let sid = current_user_sid_bytes()?;
    let sid_pointer = sid.as_ptr().cast_mut().cast::<c_void>();
    let acl_size =
        std::mem::size_of::<ACL>() + std::mem::size_of::<ACCESS_ALLOWED_ACE>() + sid.len()
            - std::mem::size_of::<u32>();
    let words = acl_size.div_ceil(std::mem::size_of::<u32>());
    let mut acl_storage = Zeroizing::new(vec![0_u32; words]);
    let acl = acl_storage.as_mut_ptr().cast::<ACL>();
    let acl_bytes = u32::try_from(words * std::mem::size_of::<u32>())
        .map_err(|_| security_error("acl-size-invalid"))?;
    // SAFETY: acl points to a zeroed, aligned, writable allocation of
    // `acl_bytes`; sid_pointer points to the validated current-user SID.
    if unsafe { InitializeAcl(acl, acl_bytes, ACL_REVISION) } == 0 {
        return Err(security_error("acl-initialize-failed"));
    }
    let inheritance = if directory {
        SUB_CONTAINERS_AND_OBJECTS_INHERIT
    } else {
        NO_INHERITANCE
    };
    // SAFETY: the ACL and SID allocations remain alive through the call.
    if unsafe {
        AddAccessAllowedAceEx(acl, ACL_REVISION, inheritance, FILE_ALL_ACCESS, sid_pointer)
    } == 0
    {
        return Err(security_error("acl-entry-failed"));
    }
    let wide: Vec<u16> = path.as_os_str().encode_wide().chain(Some(0)).collect();
    // SAFETY: wide is a NUL-terminated path and acl remains valid for the call.
    let status = unsafe {
        SetNamedSecurityInfoW(
            wide.as_ptr(),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
            ptr::null_mut(),
            ptr::null_mut(),
            acl,
            ptr::null(),
        )
    };
    if status != 0 {
        return Err(security_error("acl-apply-failed"));
    }
    verify_owner_only_dacl(path)
}

fn verify_owner_only_dacl(path: &Path) -> Result<(), DeliveryError> {
    const ACCESS_ALLOWED_ACE_TYPE: u8 = 0;
    let wide: Vec<u16> = path.as_os_str().encode_wide().chain(Some(0)).collect();
    let mut required = 0_u32;
    // The first call intentionally discovers the required descriptor size.
    unsafe {
        GetFileSecurityW(
            wide.as_ptr(),
            DACL_SECURITY_INFORMATION,
            ptr::null_mut(),
            0,
            &mut required,
        );
    }
    if required == 0 || required > 1024 * 1024 {
        return Err(security_error("acl-readback-size"));
    }
    let mut descriptor = Zeroizing::new(vec![0_u8; required as usize]);
    // SAFETY: descriptor is a writable buffer of the requested size.
    if unsafe {
        GetFileSecurityW(
            wide.as_ptr(),
            DACL_SECURITY_INFORMATION,
            descriptor.as_mut_ptr().cast(),
            required,
            &mut required,
        )
    } == 0
    {
        return Err(security_error("acl-readback-failed"));
    }
    let mut present = 0;
    let mut defaulted = 0;
    let mut acl = ptr::null_mut();
    // SAFETY: descriptor was populated by GetFileSecurityW and remains alive.
    if unsafe {
        GetSecurityDescriptorDacl(
            descriptor.as_mut_ptr().cast(),
            &mut present,
            &mut acl,
            &mut defaulted,
        )
    } == 0
        || present == 0
        || acl.is_null()
    {
        return Err(security_error("acl-readback-missing"));
    }
    let mut information = ACL_SIZE_INFORMATION::default();
    // SAFETY: acl points into descriptor and information has the exact shape
    // requested by AclSizeInformation.
    if unsafe {
        GetAclInformation(
            acl,
            (&mut information as *mut ACL_SIZE_INFORMATION).cast(),
            std::mem::size_of::<ACL_SIZE_INFORMATION>() as u32,
            AclSizeInformation,
        )
    } == 0
        || information.AceCount != 1
    {
        return Err(security_error("acl-readback-entry-count"));
    }
    let mut ace_pointer = ptr::null_mut();
    // SAFETY: the ACL reports one entry at index zero.
    if unsafe { GetAce(acl, 0, &mut ace_pointer) } == 0 || ace_pointer.is_null() {
        return Err(security_error("acl-readback-entry"));
    }
    // SAFETY: AddAccessAllowedAceEx created the sole ACE and GetAce returned a
    // pointer into the live descriptor.
    let ace = unsafe { &*(ace_pointer.cast::<ACCESS_ALLOWED_ACE>()) };
    if ace.Header.AceType != ACCESS_ALLOWED_ACE_TYPE
        || u32::from(ace.Header.AceFlags) & INHERITED_ACE != 0
        || ace.Mask & FILE_ALL_ACCESS != FILE_ALL_ACCESS
    {
        return Err(security_error("acl-readback-permissions"));
    }
    let expected_sid = current_user_sid_bytes()?;
    let actual_sid = ptr::addr_of!(ace.SidStart).cast_mut().cast::<c_void>();
    // SAFETY: actual_sid is the variable SID at the tail of the validated ACE;
    // expected_sid is a validated token SID.
    if unsafe {
        EqualSid(
            actual_sid,
            expected_sid.as_ptr().cast_mut().cast::<c_void>(),
        )
    } == 0
    {
        return Err(security_error("acl-readback-principal"));
    }
    Ok(())
}

pub(crate) fn copy_dacl(source: &Path, target: &Path) -> Result<(), DeliveryError> {
    let source_wide: Vec<u16> = source.as_os_str().encode_wide().chain(Some(0)).collect();
    let target_wide: Vec<u16> = target.as_os_str().encode_wide().chain(Some(0)).collect();
    let mut required = 0_u32;
    // This sizing call intentionally fails with an insufficient-buffer status.
    unsafe {
        GetFileSecurityW(
            source_wide.as_ptr(),
            DACL_SECURITY_INFORMATION,
            ptr::null_mut(),
            0,
            &mut required,
        );
    }
    if required == 0 || required > 1024 * 1024 {
        return Err(security_error("source-dacl-size-invalid"));
    }
    let mut descriptor = Zeroizing::new(vec![0_u8; required as usize]);
    // SAFETY: descriptor is a writable buffer of the requested size and both
    // paths are NUL-terminated.
    if unsafe {
        GetFileSecurityW(
            source_wide.as_ptr(),
            DACL_SECURITY_INFORMATION,
            descriptor.as_mut_ptr().cast(),
            required,
            &mut required,
        )
    } == 0
    {
        return Err(security_error("source-dacl-read-failed"));
    }
    // SAFETY: descriptor was populated by GetFileSecurityW and remains alive.
    if unsafe {
        SetFileSecurityW(
            target_wide.as_ptr(),
            DACL_SECURITY_INFORMATION,
            descriptor.as_mut_ptr().cast(),
        )
    } == 0
    {
        return Err(security_error("target-dacl-write-failed"));
    }
    Ok(())
}

fn security_error(code: &str) -> DeliveryError {
    DeliveryError::ConfigTransaction(code.to_string())
}
