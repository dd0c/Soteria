//! Minimal sd_notify(3) client: readiness, watchdog and status messages for
//! `Type=notify` units. Without NOTIFY_SOCKET (not under systemd) every call
//! is a no-op.

use std::ffi::OsStr;
use std::os::linux::net::SocketAddrExt;
use std::os::unix::net::{SocketAddr, UnixDatagram};
use std::time::Duration;

pub fn notify(message: &str) {
    if let Some(socket) = std::env::var_os("NOTIFY_SOCKET")
        && let Err(e) = notify_to(&socket, message)
    {
        tracing::warn!("cannot notify systemd: {e}");
    }
}

/// Send one notification to `socket`, a filesystem path or an abstract
/// socket name starting with '@'.
fn notify_to(socket: &OsStr, message: &str) -> std::io::Result<()> {
    let sock = UnixDatagram::unbound()?;
    match socket.as_encoded_bytes().strip_prefix(b"@") {
        Some(name) => {
            let addr = SocketAddr::from_abstract_name(name)?;
            sock.send_to_addr(message.as_bytes(), &addr)?;
        }
        None => {
            sock.send_to(message.as_bytes(), socket)?;
        }
    }
    Ok(())
}

/// The watchdog period requested by systemd (WatchdogSec=), if any and if
/// it is meant for this process.
pub fn watchdog_interval() -> Option<Duration> {
    if let Some(pid) = std::env::var("WATCHDOG_PID")
        .ok()
        .and_then(|p| p.parse::<u32>().ok())
        && pid != std::process::id()
    {
        return None;
    }
    let usec: u64 = std::env::var("WATCHDOG_USEC").ok()?.parse().ok()?;
    (usec > 0).then(|| Duration::from_micros(usec))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn recv(receiver: &UnixDatagram) -> Vec<u8> {
        let mut buf = [0u8; 64];
        let n = receiver.recv(&mut buf).unwrap();
        buf[..n].to_vec()
    }

    #[test]
    fn delivers_to_a_path_socket() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("notify.sock");
        let receiver = UnixDatagram::bind(&path).unwrap();
        notify_to(path.as_os_str(), "READY=1").unwrap();
        assert_eq!(recv(&receiver), b"READY=1");
    }

    #[test]
    fn delivers_to_an_abstract_socket() {
        let name = format!("soteria-test-{}", std::process::id());
        let addr = SocketAddr::from_abstract_name(name.as_bytes()).unwrap();
        let receiver = UnixDatagram::bind_addr(&addr).unwrap();
        notify_to(OsStr::new(&format!("@{name}")), "WATCHDOG=1").unwrap();
        assert_eq!(recv(&receiver), b"WATCHDOG=1");
    }
}
