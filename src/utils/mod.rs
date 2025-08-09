pub mod logger;
pub mod system;
pub mod crypto;
pub mod backup;

use anyhow::Result;
use std::process::Command;

/// Check if running with administrator/root privileges
pub fn is_elevated() -> bool {
    #[cfg(windows)]
    {
        use std::ptr;
        use winapi::um::processthreadsapi::{GetCurrentProcess, OpenProcessToken};
        use winapi::um::securitybaseapi::GetTokenInformation;
        use winapi::um::winnt::{TokenElevation, TOKEN_ELEVATION, TOKEN_QUERY};
        
        unsafe {
            let mut handle = ptr::null_mut();
            if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut handle) == 0 {
                return false;
            }
            
            let mut elevation = TOKEN_ELEVATION { TokenIsElevated: 0 };
            let mut size = 0;
            
            let result = GetTokenInformation(
                handle,
                TokenElevation,
                &mut elevation as *mut _ as *mut _,
                std::mem::size_of::<TOKEN_ELEVATION>() as u32,
                &mut size,
            );
            
            result != 0 && elevation.TokenIsElevated != 0
        }
    }
    
    #[cfg(unix)]
    {
        nix::unistd::getuid().is_root()
    }
}

/// Execute command and return output
pub async fn execute_command(command: &str, args: &[&str]) -> Result<String> {
    let output = Command::new(command)
        .args(args)
        .output()
        .map_err(|e| anyhow::anyhow!("Failed to execute command '{}': {}", command, e))?;
    
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        anyhow::bail!("Command '{}' failed: {}", command, stderr);
    }
    
    Ok(String::from_utf8_lossy(&output.stdout).to_string())
}

/// Check if a port is open on localhost
pub async fn is_port_open(port: u16) -> bool {
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    use tokio::net::TcpStream;
    use tokio::time::{timeout, Duration};
    
    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), port);
    timeout(Duration::from_secs(1), TcpStream::connect(addr))
        .await
        .is_ok()
}

/// Get current username
pub fn get_current_user() -> Result<String> {
    #[cfg(windows)]
    {
        std::env::var("USERNAME")
            .map_err(|_| anyhow::anyhow!("Failed to get current username"))
    }
    
    #[cfg(unix)]
    {
        users::get_current_username()
            .and_then(|name| name.into_string().ok())
            .ok_or_else(|| anyhow::anyhow!("Failed to get current username"))
    }
}