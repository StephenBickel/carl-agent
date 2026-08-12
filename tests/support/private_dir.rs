use std::io;
use std::path::Path;

#[cfg(unix)]
use std::fs;

pub fn make_owner_only_directory(path: &Path) -> io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        return fs::set_permissions(path, fs::Permissions::from_mode(0o700));
    }

    #[cfg(windows)]
    {
        return make_windows_directory_owner_only(path);
    }

    #[allow(unreachable_code)]
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "owner-only test directories are unsupported on this platform",
    ))
}

#[cfg(windows)]
fn make_windows_directory_owner_only(path: &Path) -> io::Result<()> {
    use std::mem::size_of;
    use std::os::windows::ffi::OsStrExt;
    use std::ptr;

    use windows_sys::Win32::Foundation::{CloseHandle, HANDLE};
    use windows_sys::Win32::Security::Authorization::{SE_FILE_OBJECT, SetNamedSecurityInfoW};
    use windows_sys::Win32::Security::{
        ACCESS_ALLOWED_ACE, ACL, ACL_REVISION, AddAccessAllowedAceEx, CONTAINER_INHERIT_ACE,
        DACL_SECURITY_INFORMATION, GetLengthSid, GetTokenInformation, InitializeAcl, IsValidSid,
        OBJECT_INHERIT_ACE, OWNER_SECURITY_INFORMATION, PROTECTED_DACL_SECURITY_INFORMATION,
        TOKEN_QUERY, TOKEN_USER, TokenUser,
    };
    use windows_sys::Win32::Storage::FileSystem::FILE_ALL_ACCESS;
    use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

    struct ProcessToken(HANDLE);

    impl Drop for ProcessToken {
        fn drop(&mut self) {
            if !self.0.is_null() {
                // SAFETY: OpenProcessToken returned this owned handle and it is closed once.
                let _ = unsafe { CloseHandle(self.0) };
            }
        }
    }

    let invalid = |message: &'static str| io::Error::other(message);
    let mut token = ptr::null_mut();
    // SAFETY: token points to writable handle storage.
    if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) } == 0
        || token.is_null()
    {
        return Err(invalid("could not open the Windows process token"));
    }
    let token = ProcessToken(token);
    let mut required = 0_u32;
    // SAFETY: the first call intentionally queries the required byte count.
    let _ = unsafe { GetTokenInformation(token.0, TokenUser, ptr::null_mut(), 0, &mut required) };
    if usize::try_from(required)
        .ok()
        .is_none_or(|bytes| bytes < size_of::<TOKEN_USER>())
    {
        return Err(invalid("Windows did not report a usable token user"));
    }
    let word = size_of::<usize>();
    let words = usize::try_from(required)
        .map_err(|_| invalid("Windows token size overflow"))?
        .div_ceil(word);
    let mut user_storage = vec![0_usize; words];
    // SAFETY: user_storage is aligned and large enough for the reported TOKEN_USER bytes.
    if unsafe {
        GetTokenInformation(
            token.0,
            TokenUser,
            user_storage.as_mut_ptr().cast(),
            required,
            &mut required,
        )
    } == 0
    {
        return Err(invalid("could not query the Windows token user"));
    }
    // SAFETY: the successful query initialized TOKEN_USER at the buffer start.
    let sid = unsafe { (*(user_storage.as_ptr().cast::<TOKEN_USER>())).User.Sid };
    // SAFETY: sid points inside the live, successfully initialized token buffer.
    if unsafe { IsValidSid(sid) } == 0 {
        return Err(invalid("Windows returned an invalid token SID"));
    }
    // SAFETY: IsValidSid succeeded and the token buffer remains live.
    let sid_bytes = usize::try_from(unsafe { GetLengthSid(sid) })
        .map_err(|_| invalid("Windows SID size overflow"))?;
    let acl_bytes = size_of::<ACL>()
        .checked_add(size_of::<ACCESS_ALLOWED_ACE>())
        .and_then(|bytes| bytes.checked_sub(size_of::<u32>()))
        .and_then(|bytes| bytes.checked_add(sid_bytes))
        .ok_or_else(|| invalid("Windows ACL size overflow"))?;
    let mut acl = vec![0_usize; acl_bytes.div_ceil(word)];
    let acl_pointer = acl.as_mut_ptr().cast::<ACL>();
    let acl_length = u32::try_from(acl_bytes).map_err(|_| invalid("Windows ACL size overflow"))?;
    // SAFETY: acl is aligned writable storage of acl_bytes bytes.
    if unsafe { InitializeAcl(acl_pointer, acl_length, ACL_REVISION) } == 0 {
        return Err(invalid("could not initialize the Windows ACL"));
    }
    // SAFETY: the initialized ACL has room for this ACE and sid remains live.
    if unsafe {
        AddAccessAllowedAceEx(
            acl_pointer,
            ACL_REVISION,
            OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE,
            FILE_ALL_ACCESS,
            sid,
        )
    } == 0
    {
        return Err(invalid("could not add the Windows owner ACL entry"));
    }
    let wide_path = path
        .as_os_str()
        .encode_wide()
        .chain(Some(0))
        .collect::<Vec<_>>();
    // SAFETY: wide_path is NUL-terminated; the ACL and SID storage remain live.
    let result = unsafe {
        SetNamedSecurityInfoW(
            wide_path.as_ptr(),
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION
                | DACL_SECURITY_INFORMATION
                | PROTECTED_DACL_SECURITY_INFORMATION,
            sid,
            ptr::null_mut(),
            acl_pointer,
            ptr::null_mut(),
        )
    };
    if result != 0 {
        return Err(io::Error::other(format!(
            "could not protect the Windows data directory: {result}"
        )));
    }
    Ok(())
}
