//! Test certificates and TLS servers.

use std::net::TcpStream;
use std::path::PathBuf;
use std::sync::Arc;

use rcgen::{BasicConstraints, CertificateParams, IsCa, KeyPair};
use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::{ServerConfig, ServerConnection, StreamOwned};

/// A private CA (written to `ca_file`) and a server certificate for
/// `localhost` signed by it.
pub struct Pki {
    pub dir: tempfile::TempDir,
    pub ca_file: PathBuf,
    pub server: Arc<ServerConfig>,
}

impl Pki {
    pub fn new() -> Pki {
        let mut ca_params = CertificateParams::new(Vec::<String>::new()).unwrap();
        ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        let ca_key = KeyPair::generate().unwrap();
        let ca = ca_params.self_signed(&ca_key).unwrap();
        let leaf_key = KeyPair::generate().unwrap();
        let leaf = CertificateParams::new(vec!["localhost".to_owned()])
            .unwrap()
            .signed_by(&leaf_key, &ca, &ca_key)
            .unwrap();
        let dir = tempfile::tempdir().unwrap();
        let ca_file = dir.path().join("ca.pem");
        std::fs::write(&ca_file, ca.pem()).unwrap();
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let server = ServerConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(
                vec![leaf.der().clone()],
                PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(leaf_key.serialize_der())),
            )
            .unwrap();
        Pki {
            dir,
            ca_file,
            server: Arc::new(server),
        }
    }
}

pub fn tls_server(
    tcp: TcpStream,
    cfg: &Arc<ServerConfig>,
) -> StreamOwned<ServerConnection, TcpStream> {
    StreamOwned::new(ServerConnection::new(Arc::clone(cfg)).unwrap(), tcp)
}
