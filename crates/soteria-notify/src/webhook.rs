//! Webhook delivery: one JSON `POST` over HTTPS.

use soteria_config::{Webhook, split_host_port};

use crate::{NotifyError, Result, connect, read_limited, read_secret, start_tls, tls_config};

struct Url {
    host: String,
    port: u16,
    /// Path and query, starting with `/`.
    target: String,
}

fn parse(url: &str) -> Result<Url> {
    let bad = || {
        NotifyError::Config(format!(
            "invalid webhook URL '{url}'; it must start with https://"
        ))
    };
    let rest = url.strip_prefix("https://").ok_or_else(bad)?;
    if rest
        .bytes()
        .any(|b| b.is_ascii_whitespace() || b.is_ascii_control())
    {
        return Err(bad());
    }
    let (authority, target) = match rest.find(['/', '?']) {
        Some(i) if rest.as_bytes()[i] == b'/' => (&rest[..i], rest[i..].to_owned()),
        Some(i) => (&rest[..i], format!("/{}", &rest[i..])),
        None => (rest, "/".to_owned()),
    };
    if authority.contains('@') {
        return Err(NotifyError::Config(
            "credentials in the webhook URL are not supported; use token_file".into(),
        ));
    }
    let (host, port) = split_host_port(authority, 443).ok_or_else(bad)?;
    Ok(Url { host, port, target })
}

/// POST `body` as JSON. Any 2xx status is success; redirects are not
/// followed.
pub fn post_webhook(cfg: &Webhook, body: &serde_json::Value) -> Result<()> {
    let url = parse(&cfg.url)?;
    let token = read_secret(&cfg.token_file)?;
    let tls = tls_config(&cfg.ca_file)?;
    let tcp = connect(&url.host, url.port, cfg.timeout.0)?;
    let mut stream = start_tls(tcp, &url.host, &tls)?;
    let payload = body.to_string();
    let host_header = if url.port == 443 {
        url.host.clone()
    } else if url.host.contains(':') {
        format!("[{}]:{}", url.host, url.port)
    } else {
        format!("{}:{}", url.host, url.port)
    };
    let mut request = format!(
        "POST {} HTTP/1.1\r\nHost: {host_header}\r\nUser-Agent: soteria/{}\r\n\
         Content-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n",
        url.target,
        soteria_core::VERSION,
        payload.len()
    );
    if let Some(t) = token {
        if t.bytes().any(|b| b.is_ascii_control()) {
            return Err(NotifyError::Config(
                "the webhook token contains control characters".into(),
            ));
        }
        request.push_str(&format!("Authorization: Bearer {t}\r\n"));
    }
    request.push_str("\r\n");
    request.push_str(&payload);
    crate::write_all(&mut stream, request.as_bytes())?;
    // The status line is all we need; read a little more for the message.
    let reply = match read_limited(&mut stream, 4096) {
        Ok(r) => r,
        // Servers that close without close_notify still answered.
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => Vec::new(),
        Err(e) => return Err(e.into()),
    };
    let text = String::from_utf8_lossy(&reply);
    let status_line = text.lines().next().unwrap_or("");
    let code = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|c| c.parse::<u16>().ok());
    match code {
        Some(c) if (200..300).contains(&c) => Ok(()),
        Some(_) => Err(NotifyError::Http(status_line.to_owned())),
        None => Err(NotifyError::Http(format!(
            "no HTTP response ({} bytes)",
            reply.len()
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::{Pki, tls_server};
    use soteria_config::HumanDuration;
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::sync::Arc;

    #[test]
    fn urls() {
        let u = parse("https://hooks.example.com:8443/a/b?x=1").unwrap();
        assert_eq!(
            (u.host.as_str(), u.port, u.target.as_str()),
            ("hooks.example.com", 8443, "/a/b?x=1")
        );
        let u = parse("https://h.example.com?x").unwrap();
        assert_eq!((u.port, u.target.as_str()), (443, "/?x"));
        assert!(parse("http://h/").is_err());
        assert!(parse("https://user:pw@h/").is_err());
        assert!(parse("https://h/a b").is_err());
    }

    fn serve(status: &'static str) -> (u16, std::thread::JoinHandle<String>, Pki) {
        let pki = Pki::new();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let cfg = Arc::clone(&pki.server);
        let h = std::thread::spawn(move || {
            let (tcp, _) = listener.accept().unwrap();
            let mut s = tls_server(tcp, &cfg);
            let mut req = Vec::new();
            let mut buf = [0u8; 4096];
            // Read headers, then the body by Content-Length.
            loop {
                let n = s.read(&mut buf).unwrap();
                req.extend_from_slice(&buf[..n]);
                let text = String::from_utf8_lossy(&req).to_string();
                if let Some(i) = text.find("\r\n\r\n") {
                    let len: usize = text
                        .lines()
                        .find_map(|l| l.strip_prefix("Content-Length: "))
                        .unwrap()
                        .parse()
                        .unwrap();
                    if req.len() >= i + 4 + len {
                        break;
                    }
                }
            }
            s.write_all(format!("HTTP/1.1 {status}\r\nContent-Length: 0\r\n\r\n").as_bytes())
                .unwrap();
            s.conn.send_close_notify();
            let _ = s.flush();
            String::from_utf8(req).unwrap()
        });
        (port, h, pki)
    }

    fn hook(port: u16, pki: &Pki) -> Webhook {
        Webhook {
            url: format!("https://localhost:{port}/soteria"),
            ca_file: pki.ca_file.clone(),
            timeout: HumanDuration::from_secs(5),
            ..Webhook::default()
        }
    }

    #[test]
    fn posts_json_with_a_bearer_token() {
        let (port, h, pki) = serve("204 No Content");
        let token = pki.dir.path().join("token");
        std::fs::write(&token, "abc123\n").unwrap();
        let mut cfg = hook(port, &pki);
        cfg.token_file = token;
        post_webhook(&cfg, &serde_json::json!({ "alerts": [1] })).unwrap();
        let req = h.join().unwrap();
        assert!(req.starts_with("POST /soteria HTTP/1.1\r\n"), "{req}");
        assert!(req.contains(&format!("Host: localhost:{port}\r\n")));
        assert!(req.contains("Authorization: Bearer abc123\r\n"));
        assert!(req.ends_with("{\"alerts\":[1]}"));
    }

    #[test]
    fn error_status_is_a_failure() {
        let (port, h, pki) = serve("500 Internal Server Error");
        let err = post_webhook(&hook(port, &pki), &serde_json::json!({})).unwrap_err();
        assert_eq!(
            err.to_string(),
            "webhook answered HTTP/1.1 500 Internal Server Error"
        );
        h.join().unwrap();
    }
}
