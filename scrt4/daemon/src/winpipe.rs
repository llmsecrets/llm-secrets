// scrt4/src/winpipe.rs — Windows named-pipe transport.
//
// The Unix build listens on a 0600 Unix socket; this is the Windows
// equivalent: a named pipe whose DACL grants access only to the daemon's
// user and SYSTEM. Requests are dispatched through the same generic
// handlers::handle_connection loop the Unix socket uses.
#![cfg(windows)]

use std::ffi::c_void;

use windows_sys::Win32::Foundation::{CloseHandle, LocalFree, HANDLE};
use windows_sys::Win32::Security::Authorization::{
    ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
};
use windows_sys::Win32::Security::{
    GetTokenInformation, TokenUser, SECURITY_ATTRIBUTES, TOKEN_QUERY, TOKEN_USER,
};
use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

/// Pipe name: SCRT4_PIPE_NAME override (tests), else per-user default.
pub fn pipe_name() -> String {
    if let Ok(name) = std::env::var("SCRT4_PIPE_NAME") {
        if name.starts_with(r"\\.\pipe\") {
            return name;
        }
        return format!(r"\\.\pipe\{}", name);
    }
    let user = std::env::var("USERNAME").unwrap_or_else(|_| "default".to_string());
    format!(r"\\.\pipe\scrt4-{}", user)
}

/// String SID of the user this process runs as.
fn current_user_sid_string() -> Result<String, String> {
    unsafe {
        let mut token: HANDLE = std::ptr::null_mut();
        if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) == 0 {
            return Err("OpenProcessToken failed".to_string());
        }

        let mut len: u32 = 0;
        GetTokenInformation(token, TokenUser, std::ptr::null_mut(), 0, &mut len);
        if len == 0 {
            CloseHandle(token);
            return Err("GetTokenInformation size query failed".to_string());
        }

        let mut buf = vec![0u8; len as usize];
        let ok = GetTokenInformation(token, TokenUser, buf.as_mut_ptr() as *mut c_void, len, &mut len);
        CloseHandle(token);
        if ok == 0 {
            return Err("GetTokenInformation failed".to_string());
        }

        let token_user = &*(buf.as_ptr() as *const TOKEN_USER);
        let mut sid_ptr: *mut u16 = std::ptr::null_mut();
        if ConvertSidToStringSidW(token_user.User.Sid, &mut sid_ptr) == 0 {
            return Err("ConvertSidToStringSidW failed".to_string());
        }

        let mut n = 0usize;
        while *sid_ptr.add(n) != 0 {
            n += 1;
        }
        let sid = String::from_utf16_lossy(std::slice::from_raw_parts(sid_ptr, n));
        LocalFree(sid_ptr as *mut c_void);
        Ok(sid)
    }
}

/// SECURITY_ATTRIBUTES carrying a protected DACL: full access for the
/// current user and SYSTEM, nothing else — the named-pipe equivalent of
/// the Unix socket's chmod 0600 (default pipe DACLs let Everyone read).
struct OwnerOnlySecurity {
    psd: *mut c_void,
    sa: SECURITY_ATTRIBUTES,
}

// The descriptor is owned exclusively by this struct and LocalFree may be
// called from any thread, so holding it across awaits is safe.
unsafe impl Send for OwnerOnlySecurity {}

impl OwnerOnlySecurity {
    fn new() -> Result<Self, String> {
        let sid = current_user_sid_string()?;
        let sddl = format!("D:P(A;;GA;;;{})(A;;GA;;;SY)", sid);
        let sddl_w: Vec<u16> = sddl.encode_utf16().chain(std::iter::once(0)).collect();

        let mut psd: *mut c_void = std::ptr::null_mut();
        let ok = unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                sddl_w.as_ptr(),
                SDDL_REVISION_1,
                &mut psd,
                std::ptr::null_mut(),
            )
        };
        if ok == 0 || psd.is_null() {
            return Err(format!("Failed to build security descriptor from SDDL: {}", sddl));
        }

        Ok(Self {
            psd,
            sa: SECURITY_ATTRIBUTES {
                nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
                lpSecurityDescriptor: psd,
                bInheritHandle: 0,
            },
        })
    }

    fn attrs_ptr(&mut self) -> *mut c_void {
        &mut self.sa as *mut SECURITY_ATTRIBUTES as *mut c_void
    }
}

impl Drop for OwnerOnlySecurity {
    fn drop(&mut self) {
        unsafe {
            LocalFree(self.psd);
        }
    }
}

/// Accept loop — the Windows counterpart of the UnixListener loop in main.
pub async fn serve() -> Result<(), Box<dyn std::error::Error>> {
    use tokio::net::windows::named_pipe::ServerOptions;

    let name = pipe_name();
    let mut security = OwnerOnlySecurity::new()?;

    // first_pipe_instance: if the name is already taken (a squatter), fail
    // loudly at startup instead of silently sharing it.
    let mut server = unsafe {
        ServerOptions::new()
            .first_pipe_instance(true)
            .create_with_security_attributes_raw(&name, security.attrs_ptr())
    }?;

    tracing::info!("Daemon listening on {}", name);

    loop {
        if let Err(e) = server.connect().await {
            tracing::error!("Pipe connect error: {}", e);
            continue;
        }

        let connected = server;
        // Create the next instance before handing off the connected one so
        // there is no window with no listening instance.
        server = unsafe {
            ServerOptions::new().create_with_security_attributes_raw(&name, security.attrs_ptr())
        }?;

        crate::audit::log_simple(
            crate::audit::EventType::ClientConnect,
            crate::audit::EventResult::Success,
        );
        tokio::spawn(crate::handlers::handle_connection(connected));
    }
}
