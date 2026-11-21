//! Path globs for administrator rules.

/// Match `text` against a glob: `?` is one byte other than `/`, `*` is any
/// run of bytes other than `/`, and `**` is any run of bytes including `/`
/// (so `/etc/**` matches everything below `/etc`). Other bytes match
/// themselves.
pub fn glob_match(pattern: &[u8], text: &[u8]) -> bool {
    match pattern.split_first() {
        None => text.is_empty(),
        Some((b'*', rest)) if rest.first() == Some(&b'*') => {
            let rest = &rest[1..];
            (0..=text.len()).any(|i| glob_match(rest, &text[i..]))
        }
        Some((b'*', rest)) => {
            let limit = text.iter().position(|b| *b == b'/').unwrap_or(text.len());
            (0..=limit).any(|i| glob_match(rest, &text[i..]))
        }
        Some((b'?', rest)) => {
            matches!(text.split_first(), Some((c, t)) if *c != b'/' && glob_match(rest, t))
        }
        Some((c, rest)) => {
            matches!(text.split_first(), Some((t0, t)) if t0 == c && glob_match(rest, t))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::glob_match;

    #[test]
    fn globs() {
        let m = |p: &str, t: &str| glob_match(p.as_bytes(), t.as_bytes());
        assert!(m("/etc/passwd", "/etc/passwd"));
        assert!(!m("/etc/passwd", "/etc/passwd-"));
        assert!(m("/etc/*.conf", "/etc/a.conf"));
        assert!(!m("/etc/*.conf", "/etc/x/a.conf"));
        assert!(m("/etc/**", "/etc/x/y/z"));
        assert!(m("/etc/**/*.conf", "/etc/x/y/a.conf"));
        assert!(m(
            "/home/*/.ssh/authorized_keys",
            "/home/bob/.ssh/authorized_keys"
        ));
        assert!(!m(
            "/home/*/.ssh/authorized_keys",
            "/home/a/b/.ssh/authorized_keys"
        ));
        assert!(m("/tmp/?", "/tmp/x"));
        assert!(!m("/tmp/?", "/tmp/"));
        assert!(m("nc*", "ncat"));
        assert!(m("*", ""));
        assert!(!m("/a*", "/b"));
    }
}
