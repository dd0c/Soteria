//! A small SMTP client: one message per connection, TLS required.

use std::io::{Read, Write};
use std::net::TcpStream;

use rustls::{ClientConnection, StreamOwned};
use soteria_config::{Email, SmtpTls, split_host_port};

use crate::{NotifyError, Result, base64, connect, read_secret, start_tls, tls_config};

enum Stream {
    Plain(TcpStream),
    Tls(Box<StreamOwned<ClientConnection, TcpStream>>),
}

impl Read for Stream {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        match self {
            Stream::Plain(s) => s.read(buf),
            Stream::Tls(s) => s.read(buf),
        }
    }
}

impl Write for Stream {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        match self {
            Stream::Plain(s) => s.write(buf),
            Stream::Tls(s) => s.write(buf),
        }
    }
    fn flush(&mut self) -> std::io::Result<()> {
        match self {
            Stream::Plain(s) => s.flush(),
            Stream::Tls(s) => s.flush(),
        }
    }
}

struct Session {
    stream: Stream,
    buf: Vec<u8>,
}

/// A reply: code and its text lines.
struct Reply {
    code: u16,
    lines: Vec<String>,
}

impl Reply {
    fn text(&self) -> String {
        format!("{} {}", self.code, self.lines.join(" / "))
    }
}

impl Session {
    fn line(&mut self) -> Result<String> {
        loop {
            if let Some(i) = self.buf.iter().position(|b| *b == b'\n') {
                let line: Vec<u8> = self.buf.drain(..=i).collect();
                return Ok(String::from_utf8_lossy(&line).trim_end().to_owned());
            }
            if self.buf.len() > 64 * 1024 {
                return Err(NotifyError::Smtp {
                    stage: "reply".into(),
                    reply: "line too long".into(),
                });
            }
            let mut chunk = [0u8; 4096];
            let n = self.stream.read(&mut chunk)?;
            if n == 0 {
                return Err(NotifyError::Io(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "SMTP server closed the connection",
                )));
            }
            self.buf.extend_from_slice(&chunk[..n]);
        }
    }

    fn reply(&mut self) -> Result<Reply> {
        let mut lines = Vec::new();
        loop {
            let l = self.line()?;
            let code = l.get(..3).and_then(|c| c.parse::<u16>().ok());
            let Some(code) = code else {
                return Err(NotifyError::Smtp {
                    stage: "reply".into(),
                    reply: format!("malformed reply '{l}'"),
                });
            };
            lines.push(l.get(4..).unwrap_or("").to_owned());
            if l.as_bytes().get(3) != Some(&b'-') {
                return Ok(Reply { code, lines });
            }
        }
    }

    fn expect(&mut self, stage: &str, ok: &[u16]) -> Result<Reply> {
        let r = self.reply()?;
        if ok.contains(&r.code) {
            Ok(r)
        } else {
            Err(NotifyError::Smtp {
                stage: stage.into(),
                reply: r.text(),
            })
        }
    }

    fn command(&mut self, cmd: &str, stage: &str, ok: &[u16]) -> Result<Reply> {
        crate::write_all(&mut self.stream, format!("{cmd}\r\n").as_bytes())?;
        self.expect(stage, ok)
    }
}

/// Lines with a leading dot doubled, CRLF line ends, long lines wrapped
/// for base64.
fn message(cfg: &Email, hostname: &str, subject: &str, body: &str) -> String {
    let date = chrono::Utc::now().to_rfc2822();
    let id = format!(
        "<{}.{}@{}>",
        chrono::Utc::now().timestamp_nanos_opt().unwrap_or_default(),
        std::process::id(),
        hostname
    );
    let mut m = format!(
        "From: Soteria <{}>\r\nTo: {}\r\nSubject: {subject}\r\nDate: {date}\r\nMessage-ID: {id}\r\n\
         MIME-Version: 1.0\r\nContent-Type: text/plain; charset=utf-8\r\nAuto-Submitted: auto-generated\r\n",
        cfg.from,
        cfg.to.join(", ")
    );
    if body.is_ascii() {
        m.push_str("Content-Transfer-Encoding: 7bit\r\n\r\n");
        for line in body.lines() {
            if line.starts_with('.') {
                m.push('.');
            }
            // Bare CRs from evidence would end lines early.
            m.push_str(&line.replace('\r', ""));
            m.push_str("\r\n");
        }
    } else {
        m.push_str("Content-Transfer-Encoding: base64\r\n\r\n");
        let encoded = base64(body.as_bytes());
        for chunk in encoded.as_bytes().chunks(76) {
            m.push_str(std::str::from_utf8(chunk).expect("base64 is ASCII"));
            m.push_str("\r\n");
        }
    }
    m
}

/// Send one message to the configured relay.
pub fn send_email(cfg: &Email, hostname: &str, subject: &str, body: &str) -> Result<()> {
    let default_port = match cfg.tls {
        SmtpTls::Starttls => 587,
        SmtpTls::Implicit => 465,
    };
    let (host, port) = split_host_port(&cfg.relay, default_port)
        .ok_or_else(|| NotifyError::Config(format!("invalid relay '{}'", cfg.relay)))?;
    let password = read_secret(&cfg.password_file)?;
    let tls = tls_config(&cfg.ca_file)?;
    let tcp = connect(&host, port, cfg.timeout.0)?;
    let stream = match cfg.tls {
        SmtpTls::Implicit => Stream::Tls(Box::new(start_tls(tcp, &host, &tls)?)),
        SmtpTls::Starttls => Stream::Plain(tcp),
    };
    let mut s = Session {
        stream,
        buf: Vec::new(),
    };
    s.expect("the connection", &[220])?;
    // EHLO names this host; a bare name is fine for relays.
    let helo: String = hostname
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || "-.".contains(*c))
        .collect();
    let helo = if helo.is_empty() {
        "localhost".to_owned()
    } else {
        helo
    };
    let mut ehlo = s.command(&format!("EHLO {helo}"), "EHLO", &[250])?;
    if cfg.tls == SmtpTls::Starttls {
        if !ehlo
            .lines
            .iter()
            .any(|l| l.eq_ignore_ascii_case("STARTTLS"))
        {
            return Err(NotifyError::Tls(format!(
                "{host} does not offer STARTTLS; refusing to send alerts unencrypted"
            )));
        }
        s.command("STARTTLS", "STARTTLS", &[220])?;
        if !s.buf.is_empty() {
            // Data sent before the handshake could be injected by an attacker.
            return Err(NotifyError::Tls(
                "unexpected data before the TLS handshake".into(),
            ));
        }
        let Stream::Plain(tcp) = s.stream else {
            unreachable!("STARTTLS starts on a plain stream")
        };
        s.stream = Stream::Tls(Box::new(start_tls(tcp, &host, &tls)?));
        ehlo = s.command(&format!("EHLO {helo}"), "EHLO", &[250])?;
    }
    if let Some(password) = password {
        let plain = ehlo.lines.iter().any(|l| {
            let u = l.to_ascii_uppercase();
            u.starts_with("AUTH") && u.split([' ', '=']).any(|m| m == "PLAIN")
        });
        if !plain {
            return Err(NotifyError::Smtp {
                stage: "login".into(),
                reply: "server does not offer AUTH PLAIN".into(),
            });
        }
        let token = base64(format!("\0{}\0{password}", cfg.username).as_bytes());
        s.command(&format!("AUTH PLAIN {token}"), "login", &[235])?;
    }
    s.command(&format!("MAIL FROM:<{}>", cfg.from), "the sender", &[250])?;
    for to in &cfg.to {
        s.command(
            &format!("RCPT TO:<{to}>"),
            &format!("recipient {to}"),
            &[250, 251],
        )?;
    }
    s.command("DATA", "DATA", &[354])?;
    let mut data = message(cfg, &helo, subject, body);
    data.push_str(".\r\n");
    crate::write_all(&mut s.stream, data.as_bytes())?;
    s.expect("the message", &[250])?;
    // The message is accepted; a failed QUIT does not matter.
    let _ = s.command("QUIT", "QUIT", &[221]);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::{Pki, tls_server};
    use soteria_config::HumanDuration;
    use std::io::BufRead;
    use std::net::TcpListener;
    use std::sync::Arc;
    use std::thread;

    fn email(port: u16, pki: &Pki, tls: SmtpTls) -> Email {
        Email {
            relay: format!("localhost:{port}"),
            tls,
            from: "soteria@web-1.example.com".into(),
            to: vec!["secops@example.com".into(), "oncall@example.com".into()],
            ca_file: pki.ca_file.clone(),
            timeout: HumanDuration::from_secs(5),
            ..Email::default()
        }
    }

    /// A minimal relay: logs what it receives and accepts the message.
    fn serve<S: Read + Write>(mut s: S, log: &mut Vec<String>, starttls: bool) -> Option<S> {
        let mut r = std::io::BufReader::new(&mut s);
        let mut line = String::new();
        loop {
            line.clear();
            if r.read_line(&mut line).ok()? == 0 {
                return None;
            }
            let cmd = line.trim_end().to_owned();
            log.push(cmd.clone());
            let reply: &[u8] = if cmd.starts_with("EHLO") {
                if starttls {
                    b"250-relay\r\n250-8BITMIME\r\n250 STARTTLS\r\n"
                } else {
                    b"250-relay\r\n250 AUTH LOGIN PLAIN\r\n"
                }
            } else if cmd == "STARTTLS" {
                r.get_mut().write_all(b"220 go ahead\r\n").ok()?;
                drop(r);
                return Some(s);
            } else if cmd == "DATA" {
                r.get_mut().write_all(b"354 send\r\n").ok()?;
                loop {
                    line.clear();
                    r.read_line(&mut line).ok()?;
                    if line == ".\r\n" {
                        break;
                    }
                    log.push(format!("> {}", line.trim_end()));
                }
                b"250 queued\r\n"
            } else if cmd.starts_with("AUTH PLAIN") {
                b"235 ok\r\n"
            } else if cmd == "QUIT" {
                r.get_mut().write_all(b"221 bye\r\n").ok()?;
                return None;
            } else {
                b"250 ok\r\n"
            };
            r.get_mut().write_all(reply).ok()?;
        }
    }

    #[test]
    fn starttls_delivery_with_login() {
        let pki = Pki::new();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let server_cfg = Arc::clone(&pki.server);
        let server = thread::spawn(move || {
            let (mut tcp, _) = listener.accept().unwrap();
            tcp.write_all(b"220 relay ready\r\n").unwrap();
            let mut log = Vec::new();
            let tcp = serve(tcp, &mut log, true).expect("STARTTLS");
            let tls = tls_server(tcp, &server_cfg);
            serve(tls, &mut log, false);
            log
        });
        let pw = pki.dir.path().join("pw");
        std::fs::write(&pw, "s3cret\n").unwrap();
        let mut cfg = email(port, &pki, SmtpTls::Starttls);
        cfg.username = "soteria".into();
        cfg.password_file = pw;
        send_email(&cfg, "web-1", "[Soteria] HIGH", "line one\n.dot line\n").unwrap();
        let log = server.join().unwrap();
        assert_eq!(log[0], "EHLO web-1");
        assert_eq!(log[1], "STARTTLS");
        assert_eq!(log[2], "EHLO web-1");
        assert_eq!(
            log[3],
            format!("AUTH PLAIN {}", base64(b"\0soteria\0s3cret"))
        );
        assert_eq!(log[4], "MAIL FROM:<soteria@web-1.example.com>");
        assert_eq!(log[5], "RCPT TO:<secops@example.com>");
        assert_eq!(log[6], "RCPT TO:<oncall@example.com>");
        assert!(
            log.contains(&"> Subject: [Soteria] HIGH".to_owned()),
            "{log:?}"
        );
        assert!(log.contains(&"> ..dot line".to_owned()), "{log:?}");
        assert_eq!(log.last().unwrap(), "QUIT");
    }

    #[test]
    fn refuses_a_relay_without_starttls() {
        let pki = Pki::new();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = thread::spawn(move || {
            let (mut tcp, _) = listener.accept().unwrap();
            tcp.write_all(b"220 relay ready\r\n").unwrap();
            let mut log = Vec::new();
            serve(tcp, &mut log, false);
            log
        });
        let err = send_email(&email(port, &pki, SmtpTls::Starttls), "web-1", "s", "b").unwrap_err();
        assert!(err.to_string().contains("does not offer STARTTLS"), "{err}");
        let log = server.join().unwrap();
        assert!(!log.iter().any(|l| l.starts_with("MAIL")), "{log:?}");
    }

    #[test]
    fn implicit_tls_rejects_an_untrusted_certificate() {
        let pki = Pki::new();
        let other = Pki::new();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let server_cfg = Arc::clone(&pki.server);
        let server = thread::spawn(move || {
            let (tcp, _) = listener.accept().unwrap();
            let mut tls = tls_server(tcp, &server_cfg);
            let _ = tls.write_all(b"220 relay ready\r\n");
        });
        let err =
            send_email(&email(port, &other, SmtpTls::Implicit), "web-1", "s", "b").unwrap_err();
        assert!(matches!(err, NotifyError::Tls(_)), "{err}");
        let _ = server.join();
    }
}
