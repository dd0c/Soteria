//! Baseline signing keys (FR-006).
//!
//! Baselines are signed with an Ed25519 key that only root can read. The
//! daemon, running as the `soteria` user, only ever loads the public key, so
//! a compromised service account cannot forge an approved baseline. Local
//! root can still replace both keys (SRS 10.2); remote forwarding is the
//! planned mitigation.

use std::fs::OpenOptions;
use std::io::{Read, Write};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use soteria_inventory::{hex, sha256_hex};

const PRIVATE_HEADER: &str = "SOTERIA-ED25519-PRIVATE-KEY-V1";
const PUBLIC_HEADER: &str = "SOTERIA-ED25519-PUBLIC-KEY-V1";

/// Domain separation for baseline signatures.
const SIGNATURE_CONTEXT: &[u8] = b"soteria-baseline-signature-v1\0";

#[derive(Debug, thiserror::Error)]
pub enum KeyError {
    #[error("signing key {0} not found; run 'sudo soteria init' to create it")]
    PrivateMissing(PathBuf),
    #[error("public key {0} not found; run 'sudo soteria init' to create it")]
    PublicMissing(PathBuf),
    #[error("permission denied reading {0}; baseline approval requires root")]
    PermissionDenied(PathBuf),
    #[error("signing key {path} is accessible to group or others (mode {mode:o}); it must be 0600")]
    InsecurePermissions { path: PathBuf, mode: u32 },
    #[error("{path} already exists; refusing to overwrite an existing key")]
    Exists { path: PathBuf },
    #[error("{path} is not a valid Soteria key file: {reason}")]
    Malformed { path: PathBuf, reason: String },
    #[error("cannot access {path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
}

/// Fingerprint of a public key: the first 16 hex digits of its SHA-256.
pub fn key_id(key: &VerifyingKey) -> String {
    sha256_hex(key.as_bytes())[..16].to_owned()
}

pub struct BaselineSigner {
    key: SigningKey,
}

impl BaselineSigner {
    pub fn key_id(&self) -> String {
        key_id(&self.key.verifying_key())
    }

    pub fn sign(&self, digest: &[u8; 32]) -> Vec<u8> {
        self.key.sign(&message(digest)).to_bytes().to_vec()
    }

    pub fn verifying_key(&self) -> VerifyingKey {
        self.key.verifying_key()
    }
}

pub fn verify_signature(key: &VerifyingKey, digest: &[u8; 32], signature: &[u8]) -> bool {
    let Ok(sig) = Signature::from_slice(signature) else {
        return false;
    };
    key.verify(&message(digest), &sig).is_ok()
}

fn message(digest: &[u8; 32]) -> Vec<u8> {
    let mut m = SIGNATURE_CONTEXT.to_vec();
    m.extend_from_slice(digest);
    m
}

/// Create a new key pair. The private key is written 0600 and the public key
/// 0644; neither file may already exist.
pub fn generate(private_path: &Path, public_path: &Path) -> Result<VerifyingKey, KeyError> {
    for p in [private_path, public_path] {
        if p.exists() {
            return Err(KeyError::Exists { path: p.to_owned() });
        }
    }
    let mut seed = [0u8; 32];
    std::fs::File::open("/dev/urandom")
        .and_then(|mut f| f.read_exact(&mut seed))
        .map_err(|source| KeyError::Io {
            path: "/dev/urandom".into(),
            source,
        })?;
    let key = SigningKey::from_bytes(&seed);
    seed.fill(0);

    for p in [private_path, public_path] {
        if let Some(dir) = p.parent() {
            std::fs::create_dir_all(dir).map_err(|source| KeyError::Io {
                path: dir.to_owned(),
                source,
            })?;
        }
    }
    write_new(
        private_path,
        0o600,
        &format!("{PRIVATE_HEADER}\n{}\n", hex(key.as_bytes())),
    )?;
    write_new(
        public_path,
        0o644,
        &format!("{PUBLIC_HEADER}\n{}\n", hex(key.verifying_key().as_bytes())),
    )?;
    Ok(key.verifying_key())
}

fn write_new(path: &Path, mode: u32, text: &str) -> Result<(), KeyError> {
    let io = |source| KeyError::Io {
        path: path.to_owned(),
        source,
    };
    let mut f = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(mode)
        .open(path)
        .map_err(io)?;
    // The umask may have removed bits; set the intended mode explicitly.
    f.set_permissions(std::fs::Permissions::from_mode(mode))
        .map_err(io)?;
    f.write_all(text.as_bytes()).map_err(io)?;
    f.sync_all().map_err(io)
}

/// Load the signing key. Refuses a key file readable by group or others.
pub fn load_signer(path: &Path) -> Result<BaselineSigner, KeyError> {
    let meta = std::fs::metadata(path).map_err(|e| match e.kind() {
        std::io::ErrorKind::NotFound => KeyError::PrivateMissing(path.to_owned()),
        std::io::ErrorKind::PermissionDenied => KeyError::PermissionDenied(path.to_owned()),
        _ => KeyError::Io {
            path: path.to_owned(),
            source: e,
        },
    })?;
    let mode = meta.permissions().mode() & 0o777;
    if mode & 0o077 != 0 {
        return Err(KeyError::InsecurePermissions {
            path: path.to_owned(),
            mode,
        });
    }
    let bytes = read_key_file(path, PRIVATE_HEADER, KeyError::PrivateMissing)?;
    Ok(BaselineSigner {
        key: SigningKey::from_bytes(&bytes),
    })
}

/// Load the public key used to verify baselines.
pub fn load_verifier(path: &Path) -> Result<VerifyingKey, KeyError> {
    let bytes = read_key_file(path, PUBLIC_HEADER, KeyError::PublicMissing)?;
    VerifyingKey::from_bytes(&bytes).map_err(|e| KeyError::Malformed {
        path: path.to_owned(),
        reason: e.to_string(),
    })
}

fn read_key_file(
    path: &Path,
    header: &str,
    missing: fn(PathBuf) -> KeyError,
) -> Result<[u8; 32], KeyError> {
    let text = std::fs::read_to_string(path).map_err(|e| match e.kind() {
        std::io::ErrorKind::NotFound => missing(path.to_owned()),
        std::io::ErrorKind::PermissionDenied => KeyError::PermissionDenied(path.to_owned()),
        _ => KeyError::Io {
            path: path.to_owned(),
            source: e,
        },
    })?;
    let malformed = |reason: &str| KeyError::Malformed {
        path: path.to_owned(),
        reason: reason.to_owned(),
    };
    let mut lines = text.lines();
    if lines.next() != Some(header) {
        return Err(malformed("unexpected header"));
    }
    let hex_key = lines.next().ok_or_else(|| malformed("missing key"))?.trim();
    if hex_key.len() != 64 {
        return Err(malformed("key must be 64 hex digits"));
    }
    let mut out = [0u8; 32];
    for (i, chunk) in hex_key.as_bytes().chunks(2).enumerate() {
        let s = std::str::from_utf8(chunk).map_err(|_| malformed("invalid hex"))?;
        out[i] = u8::from_str_radix(s, 16).map_err(|_| malformed("invalid hex"))?;
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pair(dir: &Path) -> (PathBuf, PathBuf) {
        (dir.join("keys/baseline.key"), dir.join("keys/baseline.pub"))
    }

    #[test]
    fn generate_sign_verify() {
        let dir = tempfile::tempdir().unwrap();
        let (sk, pk) = pair(dir.path());
        let generated = generate(&sk, &pk).unwrap();
        let signer = load_signer(&sk).unwrap();
        let verifier = load_verifier(&pk).unwrap();
        assert_eq!(generated, verifier);
        assert_eq!(signer.key_id(), key_id(&verifier));

        let digest = [7u8; 32];
        let sig = signer.sign(&digest);
        assert!(verify_signature(&verifier, &digest, &sig));
        assert!(!verify_signature(&verifier, &[8u8; 32], &sig));
        let mut bad = sig.clone();
        bad[0] ^= 1;
        assert!(!verify_signature(&verifier, &digest, &bad));
        assert!(!verify_signature(&verifier, &digest, &[1, 2, 3]));
    }

    #[test]
    fn key_files_have_strict_modes() {
        let dir = tempfile::tempdir().unwrap();
        let (sk, pk) = pair(dir.path());
        generate(&sk, &pk).unwrap();
        let mode = |p: &Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode(&sk), 0o600);
        assert_eq!(mode(&pk), 0o644);
    }

    #[test]
    fn refuses_to_overwrite_keys() {
        let dir = tempfile::tempdir().unwrap();
        let (sk, pk) = pair(dir.path());
        generate(&sk, &pk).unwrap();
        assert!(matches!(generate(&sk, &pk), Err(KeyError::Exists { .. })));
    }

    #[test]
    fn refuses_world_readable_signing_key() {
        let dir = tempfile::tempdir().unwrap();
        let (sk, pk) = pair(dir.path());
        generate(&sk, &pk).unwrap();
        std::fs::set_permissions(&sk, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(matches!(
            load_signer(&sk),
            Err(KeyError::InsecurePermissions { .. })
        ));
    }

    #[test]
    fn rejects_malformed_and_swapped_files() {
        let dir = tempfile::tempdir().unwrap();
        let (sk, pk) = pair(dir.path());
        generate(&sk, &pk).unwrap();
        // A public key file is not accepted as a private key and vice versa.
        assert!(matches!(
            load_verifier(&sk),
            Err(KeyError::Malformed { .. })
        ));
        let fake = dir.path().join("fake.key");
        write_new(&fake, 0o600, "SOTERIA-ED25519-PRIVATE-KEY-V1\nzz\n").unwrap();
        assert!(matches!(
            load_signer(&fake),
            Err(KeyError::Malformed { .. })
        ));
    }

    #[test]
    fn missing_keys_are_reported() {
        let dir = tempfile::tempdir().unwrap();
        let (sk, pk) = pair(dir.path());
        assert!(matches!(load_signer(&sk), Err(KeyError::PrivateMissing(_))));
        assert!(matches!(
            load_verifier(&pk),
            Err(KeyError::PublicMissing(_))
        ));
    }
}
