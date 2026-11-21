//! Alert notifications by email and webhook (FR-031).
//!
//! Both are optional, and core monitoring never waits for them: the agent
//! delivers from a separate thread, and a failed delivery is retried and
//! reported without blocking detection.
//!
//! - **Email** goes to an SMTP relay over TLS (STARTTLS or implicit TLS),
//!   optionally with `AUTH PLAIN`. There is no plain-text fallback.
//! - **Webhooks** are a JSON `POST` to an `https://` URL, optionally with a
//!   bearer token.
//!
//! Server certificates are checked against the system trust store, or a
//! configured CA file.

use std::io::{Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use rustls::pki_types::{CertificateDer, ServerName, pem::PemObject};
use rustls::{ClientConfig, ClientConnection, RootCertStore, StreamOwned};
use serde::Serialize;

mod smtp;
mod webhook;

pub use smtp::send_email;
pub use webhook::post_webhook;

#[derive(Debug, thiserror::Error)]
pub enum NotifyError {
    #[error("{0}")]
    Config(String),
    #[error("cannot connect to {target}: {source}")]
    Connect {
        target: String,
        #[source]
        source: std::io::Error,
    },
    #[error("TLS: {0}")]
    Tls(String),
    #[error("{0}")]
    Io(#[from] std::io::Error),
    #[error("SMTP server refused {stage}: {reply}")]
    Smtp { stage: String, reply: String },
    #[error("webhook answered {0}")]
    Http(String),
}

pub type Result<T> = std::result::Result<T, NotifyError>;

/// One alert as sent to people and systems.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct AlertNote {
    pub id: i64,
    pub uuid: String,
    pub created_at: String,
    pub severity: String,
    #[serde(rename = "type")]
    pub alert_type: String,
    pub status: String,
    pub hostname: String,
    pub object: Option<String>,
    pub rule_id: String,
    pub reason: String,
    pub recommendation: String,
    pub incident_id: Option<i64>,
}

/// TLS client settings: the system trust store, or the CA file if given.
pub fn tls_config(ca_file: &Path) -> Result<Arc<ClientConfig>> {
    let mut roots = RootCertStore::empty();
    if ca_file.as_os_str().is_empty() {
        let found = rustls_native_certs::load_native_certs();
        for cert in found.certs {
            // Unparsable system certificates are skipped, as browsers do.
            let _ = roots.add(cert);
        }
        if roots.is_empty() {
            return Err(NotifyError::Tls(
                "no trusted CA certificates found in the system store; set ca_file".into(),
            ));
        }
    } else {
        let certs = CertificateDer::pem_file_iter(ca_file)
            .map_err(|e| NotifyError::Config(format!("cannot read {}: {e}", ca_file.display())))?;
        for cert in certs {
            let cert =
                cert.map_err(|e| NotifyError::Config(format!("{}: {e}", ca_file.display())))?;
            roots
                .add(cert)
                .map_err(|e| NotifyError::Config(format!("{}: {e}", ca_file.display())))?;
        }
        if roots.is_empty() {
            return Err(NotifyError::Config(format!(
                "{} holds no certificates",
                ca_file.display()
            )));
        }
    }
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let config = ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|e| NotifyError::Tls(e.to_string()))?
        .with_root_certificates(roots)
        .with_no_client_auth();
    Ok(Arc::new(config))
}

/// A TCP connection with read and write timeouts.
fn connect(host: &str, port: u16, timeout: Duration) -> Result<TcpStream> {
    let target = format!("{host}:{port}");
    let addrs: Vec<_> = (host, port)
        .to_socket_addrs()
        .map_err(|source| NotifyError::Connect {
            target: target.clone(),
            source,
        })?
        .collect();
    let mut last = std::io::Error::new(std::io::ErrorKind::NotFound, "no addresses");
    for addr in addrs {
        match TcpStream::connect_timeout(&addr, timeout) {
            Ok(s) => {
                s.set_read_timeout(Some(timeout))?;
                s.set_write_timeout(Some(timeout))?;
                return Ok(s);
            }
            Err(e) => last = e,
        }
    }
    Err(NotifyError::Connect {
        target,
        source: last,
    })
}

/// Start TLS on a connected socket and finish the handshake, so
/// certificate problems are reported as such.
fn start_tls(
    tcp: TcpStream,
    host: &str,
    tls: &Arc<ClientConfig>,
) -> Result<StreamOwned<ClientConnection, TcpStream>> {
    let name = ServerName::try_from(host.to_owned())
        .map_err(|e| NotifyError::Tls(format!("{host}: {e}")))?;
    let conn = ClientConnection::new(Arc::clone(tls), name)
        .map_err(|e| NotifyError::Tls(e.to_string()))?;
    let mut stream = StreamOwned::new(conn, tcp);
    while stream.conn.is_handshaking() {
        stream
            .conn
            .complete_io(&mut stream.sock)
            .map_err(|e| NotifyError::Tls(e.to_string()))?;
    }
    Ok(stream)
}

/// Read a secret from a file, trimmed. Empty path: no secret.
pub fn read_secret(path: &Path) -> Result<Option<String>> {
    if path.as_os_str().is_empty() {
        return Ok(None);
    }
    let text = std::fs::read_to_string(path)
        .map_err(|e| NotifyError::Config(format!("cannot read {}: {e}", path.display())))?;
    let secret = text.trim().to_owned();
    if secret.is_empty() {
        return Err(NotifyError::Config(format!("{} is empty", path.display())));
    }
    Ok(Some(secret))
}

/// Read until the peer closes or `limit` bytes.
fn read_limited(r: &mut impl Read, limit: usize) -> std::io::Result<Vec<u8>> {
    let mut buf = Vec::new();
    r.take(limit as u64).read_to_end(&mut buf)?;
    Ok(buf)
}

fn write_all(w: &mut impl Write, data: &[u8]) -> Result<()> {
    w.write_all(data)?;
    w.flush()?;
    Ok(())
}

const B64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// Standard base64 with padding.
pub(crate) fn base64(data: &[u8]) -> String {
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    for chunk in data.chunks(3) {
        let b = [
            chunk[0],
            *chunk.get(1).unwrap_or(&0),
            *chunk.get(2).unwrap_or(&0),
        ];
        let n = (u32::from(b[0]) << 16) | (u32::from(b[1]) << 8) | u32::from(b[2]);
        for i in 0..4 {
            if i <= chunk.len() {
                out.push(B64[(n >> (18 - 6 * i) & 63) as usize] as char);
            } else {
                out.push('=');
            }
        }
    }
    out
}

/// Email subject and plain-text body for a batch of alerts (SRS 6.2).
pub fn email_text(host: &str, alerts: &[AlertNote]) -> (String, String) {
    let top = alerts
        .iter()
        .map(|a| a.severity.as_str())
        .max_by_key(|s| {
            ["info", "low", "medium", "high", "critical"]
                .iter()
                .position(|x| x == s)
        })
        .unwrap_or("info")
        .to_uppercase();
    let subject = match alerts {
        [one] => format!(
            "[Soteria] {top} on {host}: {} {}",
            one.rule_id,
            one.object.as_deref().unwrap_or("")
        ),
        _ => format!("[Soteria] {top}: {} new alerts on {host}", alerts.len()),
    };
    let mut body = String::new();
    for (i, a) in alerts.iter().enumerate() {
        if i > 0 {
            body.push_str("\n------------------------------------------------------------\n\n");
        }
        body.push_str(&format!(
            "Alert: {} | Severity: {} | Status: {}\n",
            a.id,
            a.severity.to_uppercase(),
            a.status.to_uppercase()
        ));
        body.push_str(&format!(
            "Host: {}\nTime: {}\nRule: {}\nType: {}\n",
            a.hostname, a.created_at, a.rule_id, a.alert_type
        ));
        if let Some(o) = &a.object {
            body.push_str(&format!("Object: {o}\n"));
        }
        if let Some(i) = a.incident_id {
            body.push_str(&format!("Incident: {i}\n"));
        }
        body.push_str(&format!(
            "Reason: {}\nInvestigation: {}\n",
            a.reason, a.recommendation
        ));
        body.push_str(&format!("Evidence: soteria alerts show {}\n", a.id));
    }
    // Keep the subject on one line and printable.
    let subject: String = subject
        .chars()
        .map(|c| {
            if c.is_ascii_graphic() || c == ' ' {
                c
            } else {
                '?'
            }
        })
        .take(200)
        .collect();
    (subject, body)
}

/// JSON body for a webhook.
pub fn webhook_body(host: &str, alerts: &[AlertNote]) -> serde_json::Value {
    serde_json::json!({
        "source": "soteria",
        "version": soteria_core::VERSION,
        "hostname": host,
        "alerts": alerts,
    })
}

#[cfg(test)]
pub(crate) mod testutil;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base64_matches_rfc4648() {
        for (i, o) in [
            ("", ""),
            ("f", "Zg=="),
            ("fo", "Zm8="),
            ("foo", "Zm9v"),
            ("foobar", "Zm9vYmFy"),
        ] {
            assert_eq!(base64(i.as_bytes()), o);
        }
    }

    pub(crate) fn note(id: i64, sev: &str) -> AlertNote {
        AlertNote {
            id,
            uuid: format!("u{id}"),
            created_at: "2026-11-21T10:00:00.000Z".into(),
            severity: sev.into(),
            alert_type: "execution".into(),
            status: "open".into(),
            hostname: "web-1".into(),
            object: Some("/tmp/.x\r\nBcc: evil".into()),
            rule_id: "EXE-001".into(),
            reason: "A program ran from an unusual location.".into(),
            recommendation: "Check who started it.".into(),
            incident_id: Some(3),
        }
    }

    #[test]
    fn email_text_lists_alerts_and_keeps_the_subject_on_one_line() {
        let (s, b) = email_text("web-1", &[note(1, "high")]);
        assert_eq!(s, "[Soteria] HIGH on web-1: EXE-001 /tmp/.x??Bcc: evil");
        assert!(b.contains("Alert: 1 | Severity: HIGH") && b.contains("Incident: 3"));
        let (s, _) = email_text("web-1", &[note(1, "medium"), note(2, "critical")]);
        assert_eq!(s, "[Soteria] CRITICAL: 2 new alerts on web-1");
    }
}
