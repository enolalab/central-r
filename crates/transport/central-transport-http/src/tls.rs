//! `tls` — the application listener's TLS termination (B06): TLS 1.3
//! only, no client authentication, terminating on the bound loopback
//! `TcpListener` before axum sees a byte.
//!
//! Upstream shape (`internal/kernel/serve.go` +
//! `cmd/central/serve_composition.go`): the serve composition binds a
//! raw `net.Listener` and wraps it in `tls.NewListener` with
//! `MinVersion = MaxVersion = tls.VersionTLS13`; the operations
//! listener stays plain HTTP on its own loopback port. Here
//! [`tls13_server_config`] builds the 1.3-only `rustls::ServerConfig`
//! and [`TlsListener`] adapts it onto axum's [`serve::Listener`] seam
//! so `axum::serve` consumes it exactly like the plain listener.

use std::net::SocketAddr;
use std::sync::Arc;

use axum::serve::Listener;
use central_foundation::failure::Failure;
use rustls::ServerConfig;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::TlsAcceptor;
use tokio_rustls::server::TlsStream;

/// One accept's TLS-handshake budget. [`Listener::accept`] is awaited
/// serially by `axum::serve`, so the handshake happens inline here;
/// the bound keeps a deliberately stalled client (a peer that connects
/// and never answers the ServerHello) from freezing the accept loop —
/// upstream's lazy per-conn handshake in `tls.NewListener` never
/// blocks accepts, and this preserves that liveness property with a
/// bounded inline handshake instead.
const HANDSHAKE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

fn tls_invalid(msg: impl Into<String>) -> Failure {
    Failure::invalid("transport_tls_invalid", msg.into())
}

/// `tls.Config{MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13,
/// Certificates: …}` — the 1.3-only server configuration.
///
/// The `ring` provider is named explicitly (rather than
/// `ServerConfig::builder()`'s process-default lookup) so the choice
/// can never panic on an ambiguous default when both `ring` and
/// `aws-lc-rs` are compiled into the process.
///
/// # Errors
/// `transport_tls_invalid` on an empty chain, an unusable key, or a
/// provider that cannot offer TLS 1.3.
pub fn tls13_server_config(
    certs: Vec<CertificateDer<'static>>,
    key: PrivateKeyDer<'static>,
) -> Result<Arc<ServerConfig>, Failure> {
    if certs.is_empty() {
        return Err(tls_invalid("certificate chain is empty"));
    }
    let config =
        ServerConfig::builder_with_provider(rustls::crypto::ring::default_provider().into())
            .with_protocol_versions(&[&rustls::version::TLS13])
            .map_err(|e| tls_invalid(format!("TLS 1.3-only provider: {e}")))?
            .with_no_client_auth()
            .with_single_cert(certs, key)
            .map_err(|e| tls_invalid(format!("server certificate: {e}")))?;
    Ok(Arc::new(config))
}

/// The TLS 1.3-terminating [`Listener`]: a bound loopback
/// `TcpListener` whose accepted `TcpStream`s are wrapped by the
/// `TlsAcceptor` before axum dispatches them. `Addr` stays
/// `SocketAddr` and [`TlsPeerAddr`] is the `Connected` projection the
/// composition names so `ConnectInfo` keeps carrying the peer address
/// the admission middleware's loopback check reads.
pub struct TlsListener {
    tcp: TcpListener,
    acceptor: TlsAcceptor,
}

impl TlsListener {
    /// `tls.NewListener(listener, config)` — wrap the already-bound
    /// application listener.
    #[must_use]
    pub fn new(tcp: TcpListener, config: Arc<ServerConfig>) -> Self {
        Self {
            tcp,
            acceptor: TlsAcceptor::from(config),
        }
    }
}

impl Listener for TlsListener {
    type Io = TlsStream<TcpStream>;
    type Addr = SocketAddr;

    fn local_addr(&self) -> std::io::Result<Self::Addr> {
        self.tcp.local_addr()
    }

    async fn accept(&mut self) -> (Self::Io, Self::Addr) {
        loop {
            // A transient `accept` error retries, exactly like axum's
            // own `TcpListener` impl; a failed or timed-out handshake
            // drops the stream and takes the next connection.
            let Ok((stream, addr)) = self.tcp.accept().await else {
                continue;
            };
            if let Ok(Ok(tls)) =
                tokio::time::timeout(HANDSHAKE_TIMEOUT, self.acceptor.accept(stream)).await
            {
                return (tls, addr);
            }
        }
    }
}

/// The `Connected` projection for [`TlsListener`]. axum implements
/// `Connected<IncomingStream<'_, TcpListener>> for SocketAddr`
/// itself; the orphan rule keeps `SocketAddr` from gaining the same
/// impl for this foreign-listener parameter, so the TLS listener
/// carries the peer through a crate-local newtype. The composition
/// (`central-kernel::serve`) projects it back into the canonical
/// `ConnectInfo<SocketAddr>` extension before the admission
/// middleware runs, so the loopback-peer check is unchanged.
#[derive(Debug, Clone, Copy)]
pub struct TlsPeerAddr(pub SocketAddr);

impl axum::extract::connect_info::Connected<axum::serve::IncomingStream<'_, TlsListener>>
    for TlsPeerAddr
{
    fn connect_info(target: axum::serve::IncomingStream<'_, TlsListener>) -> Self {
        Self(*target.remote_addr())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
    use rustls::pki_types::{PrivatePkcs8KeyDer, ServerName, UnixTime};

    fn fixture() -> (Vec<CertificateDer<'static>>, PrivateKeyDer<'static>) {
        let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519).expect("keygen");
        let mut params = rcgen::CertificateParams::default();
        params.subject_alt_names = vec![rcgen::SanType::IpAddress(Ipv4Addr::LOCALHOST.into())];
        params.is_ca = rcgen::IsCa::NoCa;
        let cert = params.self_signed(&key).expect("self-signed");
        let certs = vec![cert.der().clone()];
        let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.serialize_der()));
        (certs, key)
    }

    /// Accept-anything verifier — the handshake tests exercise the
    /// protocol version, not certificate trust (chain validation is
    /// the kernel's `validate_tls`).
    #[derive(Debug)]
    struct AcceptAll;
    impl ServerCertVerifier for AcceptAll {
        fn verify_server_cert(
            &self,
            _end_entity: &CertificateDer<'_>,
            _intermediates: &[CertificateDer<'_>],
            _server_name: &ServerName<'_>,
            _ocsp_response: &[u8],
            _now: UnixTime,
        ) -> Result<ServerCertVerified, rustls::Error> {
            Ok(ServerCertVerified::assertion())
        }
        fn verify_tls12_signature(
            &self,
            _message: &[u8],
            _cert: &CertificateDer<'_>,
            _dss: &rustls::DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, rustls::Error> {
            Ok(HandshakeSignatureValid::assertion())
        }
        fn verify_tls13_signature(
            &self,
            _message: &[u8],
            _cert: &CertificateDer<'_>,
            _dss: &rustls::DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, rustls::Error> {
            Ok(HandshakeSignatureValid::assertion())
        }
        fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
            vec![rustls::SignatureScheme::ED25519]
        }
    }

    fn client_config(
        versions: &[&'static rustls::SupportedProtocolVersion],
    ) -> Arc<rustls::ClientConfig> {
        Arc::new(
            rustls::ClientConfig::builder_with_provider(
                rustls::crypto::ring::default_provider().into(),
            )
            .with_protocol_versions(versions)
            .expect("client versions")
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(AcceptAll))
            .with_no_client_auth(),
        )
    }

    /// B06: the application listener negotiates TLS 1.3 and nothing
    /// older — a 1.2-only client is refused at the handshake.
    #[tokio::test]
    async fn listener_negotiates_tls13_only() {
        let (certs, key) = fixture();
        let config = tls13_server_config(certs, key).expect("server config");
        let tcp = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let port = tcp.local_addr().expect("local_addr").port();
        let mut listener = TlsListener::new(tcp, config);
        let (tx, rx) = tokio::sync::oneshot::channel::<TlsStream<TcpStream>>();
        tokio::spawn(async move {
            let (tls, _addr) = listener.accept().await;
            let _ = tx.send(tls);
            // Keep the port bound for the refused TLS 1.2 probe below
            // (the task — and the listener — outlive this await only
            // while the test runtime does; the refused handshake loops
            // back to `tcp.accept`).
            let _ = listener.accept().await;
        });

        // TLS 1.3 client → handshake completes and one byte round-trips.
        let stream = TcpStream::connect(("127.0.0.1", port))
            .await
            .expect("connect");
        let conn = tokio_rustls::TlsConnector::from(client_config(&[&rustls::version::TLS13]));
        let mut tls = conn
            .connect(ServerName::IpAddress(Ipv4Addr::LOCALHOST.into()), stream)
            .await
            .expect("TLS 1.3 handshake");
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        tls.write_all(b"x").await.expect("write");
        let mut accepted = rx.await.expect("accepted stream");
        let mut byte = [0u8; 1];
        accepted.read_exact(&mut byte).await.expect("read");
        assert_eq!(byte, *b"x");

        // TLS 1.2-only client → the server refuses the handshake.
        let stream = TcpStream::connect(("127.0.0.1", port))
            .await
            .expect("connect");
        let conn12 = tokio_rustls::TlsConnector::from(client_config(&[&rustls::version::TLS12]));
        let result = conn12
            .connect(ServerName::IpAddress(Ipv4Addr::LOCALHOST.into()), stream)
            .await;
        assert!(
            result.is_err(),
            "a TLS 1.2-only client must be refused at the handshake"
        );
    }

    /// An empty chain cannot build a server config.
    #[test]
    fn empty_chain_refused() {
        let key =
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(vec![0x30, 0x05, 0x02, 0x01, 0x00]));
        assert!(tls13_server_config(Vec::new(), key).is_err());
    }
}
