//! Loopback-only by default: TLS1.3 mutual authentication and one bounded proposal.
//! The off-default VM fixture adapter is a fixed, isolated two-guest test only.
//! Authentication permits durable queueing only: no API reads or applies projects.
use crate::{
    pairing::{Paired, ALPN, SERVER_NAME},
    store::Inbox,
    wire::{Envelope, Receipt, MAX_FRAME_BYTES},
    PeerError, PeerResult,
};
use rustls::{pki_types::ServerName, ProtocolVersion};
use std::{
    fmt,
    net::SocketAddr,
    sync::{Arc, Mutex},
    time::Duration,
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    time::timeout,
};
use tokio_rustls::{TlsAcceptor, TlsConnector};

pub const REQUEST_TIMEOUT: Duration = Duration::from_secs(5);
async fn read_frame(stream: &mut (impl AsyncRead + Unpin)) -> PeerResult<Vec<u8>> {
    let length = stream
        .read_u32()
        .await
        .map_err(|_| PeerError("Peer frame header unavailable."))? as usize;
    if length == 0 || length > MAX_FRAME_BYTES {
        return Err(PeerError("Peer frame exceeds hard limit."));
    }
    let mut bytes = vec![0u8; length];
    stream
        .read_exact(&mut bytes)
        .await
        .map_err(|_| PeerError("Peer frame was interrupted."))?;
    Ok(bytes)
}
async fn write_frame(stream: &mut (impl AsyncWrite + Unpin), bytes: &[u8]) -> PeerResult<()> {
    if bytes.is_empty() || bytes.len() > MAX_FRAME_BYTES {
        return Err(PeerError("Peer frame exceeds hard limit."));
    }
    stream
        .write_u32(bytes.len() as u32)
        .await
        .map_err(|_| PeerError("Peer frame header could not be written."))?;
    stream
        .write_all(bytes)
        .await
        .map_err(|_| PeerError("Peer frame could not be written."))?;
    stream
        .flush()
        .await
        .map_err(|_| PeerError("Peer frame could not be flushed."))?;
    Ok(())
}
fn loopback(address: SocketAddr) -> PeerResult<()> {
    if address.ip().is_loopback() {
        Ok(())
    } else {
        Err(PeerError("Peer prototype permits loopback addresses only."))
    }
}
fn tls_properties(protocol: Option<ProtocolVersion>, alpn: Option<&[u8]>) -> PeerResult<()> {
    if protocol != Some(ProtocolVersion::TLSv1_3) || alpn != Some(ALPN) {
        Err(PeerError(
            "Required TLS1.3 or application protocol was not negotiated.",
        ))
    } else {
        Ok(())
    }
}

pub struct PeerClient {
    pair: Paired,
    connector: TlsConnector,
}
impl fmt::Debug for PeerClient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("PeerClient { identity: [REDACTED] }")
    }
}
impl PeerClient {
    pub fn new(pair: Paired) -> PeerResult<Self> {
        let connector = TlsConnector::from(pair.client_config()?);
        Ok(Self { pair, connector })
    }
    /// A failed/lost acknowledgement can leave a proposal durably queued.
    /// Retry the identical envelope; never infer working-tree mutation from this API.
    pub async fn send(&self, address: SocketAddr, envelope: &Envelope) -> PeerResult<Receipt> {
        loopback(address)?;
        self.pair.ensure_active()?;
        envelope.validate_outgoing(&self.pair)?;
        timeout(REQUEST_TIMEOUT, self.send_inner(address, envelope))
            .await
            .map_err(|_| PeerError("Peer request exceeded five seconds; queue outcome is uncertain. Retry the exact proposal."))?
    }
    async fn send_inner(&self, address: SocketAddr, envelope: &Envelope) -> PeerResult<Receipt> {
        let stream = TcpStream::connect(address)
            .await
            .map_err(|_| PeerError("Loopback peer connection unavailable."))?;
        self.exchange(stream, envelope).await
    }
    async fn exchange(&self, stream: TcpStream, envelope: &Envelope) -> PeerResult<Receipt> {
        let mut tls = self
            .connector
            .connect(
                ServerName::try_from(SERVER_NAME)
                    .map_err(|_| PeerError("Internal server name is invalid."))?
                    .to_owned(),
                stream,
            )
            .await
            .map_err(|_| PeerError("Mutual TLS server authentication failed."))?;
        let session = tls.get_ref().1;
        tls_properties(session.protocol_version(), session.alpn_protocol())?;
        self.pair
            .check_presented_certificate(session.peer_certificates())?;
        // No application proposal bytes are sent until WebPKI, negotiated protocol,
        // exact approved leaf pin and active local approval have all succeeded.
        self.pair.ensure_active()?;
        write_frame(&mut tls, &envelope.encode()?).await?;
        let receipt: Receipt = serde_json::from_slice(&read_frame(&mut tls).await?)
            .map_err(|_| PeerError("Peer returned an invalid bounded receipt."))?;
        if receipt.pairing_id != self.pair.id()
            || receipt.sequence != envelope.sequence
            || receipt.digest != envelope.digest()?
            || receipt.pending_count == 0
            || receipt.pending_count > self.pair.scope().max_messages
        {
            return Err(PeerError(
                "Peer acknowledgement is not bound to this proposal.",
            ));
        }
        self.pair.ensure_active()?;
        Ok(receipt)
    }
}

pub struct PeerServer {
    pair: Paired,
    inbox: Arc<Mutex<Inbox>>,
    listener: TcpListener,
    acceptor: TlsAcceptor,
}
impl fmt::Debug for PeerServer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("PeerServer { identity: [REDACTED], endpoint: [LOOPBACK ONLY] }")
    }
}
impl PeerServer {
    pub async fn bind(
        pair: Paired,
        inbox: Arc<Mutex<Inbox>>,
        address: SocketAddr,
    ) -> PeerResult<Self> {
        loopback(address)?;
        pair.ensure_active()?;
        let acceptor = TlsAcceptor::from(pair.server_config()?);
        let listener = TcpListener::bind(address)
            .await
            .map_err(|_| PeerError("Loopback peer listener unavailable."))?;
        Ok(Self {
            pair,
            inbox,
            listener,
            acceptor,
        })
    }
    pub fn local_addr(&self) -> PeerResult<SocketAddr> {
        self.listener
            .local_addr()
            .map_err(|_| PeerError("Loopback listener address unavailable."))
    }
    /// One caller-controlled request, bounded across accept, TLS, frame and ack.
    /// An acknowledgement lost after commit is handled by exact duplicate replay.
    /// Timeout does not cancel an already-admitted blocking queue transaction.
    pub async fn serve_one(&self) -> PeerResult<Receipt> {
        self.pair.ensure_active()?;
        timeout(REQUEST_TIMEOUT, self.serve_inner())
            .await
            .map_err(|_| PeerError("Peer request exceeded five seconds; an admitted queue transaction may still finish."))?
    }
    async fn serve_inner(&self) -> PeerResult<Receipt> {
        let (stream, address) = self
            .listener
            .accept()
            .await
            .map_err(|_| PeerError("Loopback peer accept failed."))?;
        loopback(address)?;
        self.authenticated_request(stream).await
    }
    async fn authenticated_request(&self, stream: TcpStream) -> PeerResult<Receipt> {
        let mut tls = self
            .acceptor
            .accept(stream)
            .await
            .map_err(|_| PeerError("Mandatory mutual TLS client authentication failed."))?;
        let session = tls.get_ref().1;
        tls_properties(session.protocol_version(), session.alpn_protocol())?;
        self.pair
            .check_presented_certificate(session.peer_certificates())?;
        self.pair.ensure_active()?;
        let envelope: Envelope = serde_json::from_slice(&read_frame(&mut tls).await?)
            .map_err(|_| PeerError("Peer proposal framing or schema is invalid."))?;
        envelope.validate_incoming(&self.pair)?;
        self.pair.ensure_active()?;
        let inbox = self.inbox.clone();
        let pair = self.pair.clone();
        let receipt = tokio::task::spawn_blocking(move || {
            pair.ensure_active()?;
            let mut inbox = inbox
                .try_lock()
                .map_err(|_| PeerError("Peer queue is busy or unavailable."))?;
            inbox.accept(&pair, &envelope)
        })
        .await
        .map_err(|_| PeerError("Peer queue worker failed."))??;
        self.pair.ensure_active()?;
        write_frame(
            &mut tls,
            &serde_json::to_vec(&receipt)
                .map_err(|_| PeerError("Peer receipt encoding failed."))?,
        )
        .await?;
        Ok(receipt)
    }
}

/// Separately compiled, off by default. This is the exact disposable two-guest
/// cable fixture, not a general private-network endpoint or product LAN mode.
#[cfg(feature = "vm-fixture")]
pub mod vm_fixture {
    use super::*;
    use crate::{pairing::Scope, wire::Change};
    use std::{
        collections::BTreeSet,
        net::{IpAddr, Ipv4Addr},
    };
    use tokio::net::TcpSocket;
    pub const CLIENT_IP: Ipv4Addr = Ipv4Addr::new(10, 77, 0, 1);
    pub const SERVER_ADDRESS: SocketAddr =
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 77, 0, 2)), 37431);
    pub const FIXTURE_PATH: &str = "src/shared.txt";
    pub const FIXTURE_BYTES: &[u8] = b"generated private guest TLS fixture\n";
    pub fn scope() -> Scope {
        Scope {
            channel: "isolated-two-guest-fixture".into(),
            paths: BTreeSet::from([FIXTURE_PATH.into()]),
            allow_delete: false,
            max_messages: 1,
            max_bytes_per_proposal: 4096,
            max_total_bytes: 4096,
        }
    }
    fn validate_scope(pair: &Paired) -> PeerResult<()> {
        pair.ensure_active()?;
        if pair.scope() != &scope() {
            return Err(PeerError("Isolated VM fixture scope must match exactly."));
        }
        Ok(())
    }
    fn admitted(address: SocketAddr) -> PeerResult<()> {
        if address.ip() != IpAddr::V4(CLIENT_IP) {
            Err(PeerError("Isolated VM fixture accepts guest A only."))
        } else {
            Ok(())
        }
    }
    fn selected(envelope: &Envelope) -> PeerResult<()> {
        match envelope.changes.as_slice() {
            [Change::Put { path, bytes, .. }] if path == FIXTURE_PATH && bytes == FIXTURE_BYTES => {
                Ok(())
            }
            _ => Err(PeerError(
                "Isolated VM fixture sends fixed generated content only.",
            )),
        }
    }
    #[derive(Clone, Copy)]
    pub enum Fault {
        HashMismatch,
        DeleteOutsideScope,
        SequenceQuota,
    }
    pub struct Client(PeerClient);
    impl Client {
        pub fn new(pair: Paired) -> PeerResult<Self> {
            validate_scope(&pair)?;
            Ok(Self(PeerClient::new(pair)?))
        }
        pub async fn send(&self, envelope: &Envelope) -> PeerResult<Receipt> {
            envelope.validate_outgoing(&self.0.pair)?;
            selected(envelope)?;
            self.send_selected(envelope).await
        }
        /// Fixed negative mutations for this isolated fixture only. The receiver
        /// still runs the complete production TLS/pin/schema/scope/hash checks.
        pub async fn send_fault(&self, envelope: &Envelope, fault: Fault) -> PeerResult<Receipt> {
            envelope.validate_outgoing(&self.0.pair)?;
            selected(envelope)?;
            let mut changed = envelope.clone();
            match fault {
                Fault::HashMismatch => {
                    if let Change::Put { bytes, .. } = &mut changed.changes[0] {
                        bytes[0] ^= 1;
                    }
                }
                Fault::DeleteOutsideScope => {
                    if let Change::Put { path, hash, .. } = &changed.changes[0] {
                        changed.changes = vec![Change::Delete {
                            path: path.clone(),
                            previous_hash: hash.clone(),
                        }];
                    }
                }
                Fault::SequenceQuota => {
                    changed.sequence = u64::from(self.0.pair.scope().max_messages) + 1
                }
            }
            self.send_selected(&changed).await
        }
        async fn send_selected(&self, envelope: &Envelope) -> PeerResult<Receipt> {
            validate_scope(&self.0.pair)?;
            timeout(REQUEST_TIMEOUT, async {
                let socket = TcpSocket::new_v4()
                    .map_err(|_| PeerError("Guest fixture socket unavailable."))?;
                socket
                    .bind(SocketAddr::new(IpAddr::V4(CLIENT_IP), 0))
                    .map_err(|_| {
                        PeerError("Guest A fixture address is unavailable; no fallback is allowed.")
                    })?;
                let stream = socket
                    .connect(SERVER_ADDRESS)
                    .await
                    .map_err(|_| PeerError("Exact guest B fixture connection unavailable."))?;
                if stream
                    .local_addr()
                    .map_err(|_| PeerError("Guest local address unavailable."))?
                    .ip()
                    != IpAddr::V4(CLIENT_IP)
                    || stream
                        .peer_addr()
                        .map_err(|_| PeerError("Guest peer address unavailable."))?
                        != SERVER_ADDRESS
                {
                    return Err(PeerError(
                        "Guest fixture socket is outside the exact cable scope.",
                    ));
                }
                self.0.exchange(stream, envelope).await
            })
            .await
            .map_err(|_| {
                PeerError("Guest fixture request timed out; queue outcome may be uncertain.")
            })?
        }
    }
    pub struct Server(PeerServer);
    impl Server {
        pub async fn bind(pair: Paired, inbox: Arc<Mutex<Inbox>>) -> PeerResult<Self> {
            validate_scope(&pair)?;
            let acceptor = TlsAcceptor::from(pair.server_config()?);
            let listener = TcpListener::bind(SERVER_ADDRESS).await.map_err(|_| {
                PeerError("Exact guest B fixture bind unavailable; no fallback is allowed.")
            })?;
            Ok(Self(PeerServer {
                pair,
                inbox,
                listener,
                acceptor,
            }))
        }
        pub fn local_addr(&self) -> PeerResult<SocketAddr> {
            self.0.local_addr()
        }
        pub async fn serve_one(&self) -> PeerResult<Receipt> {
            self.0.pair.ensure_active()?;
            timeout(REQUEST_TIMEOUT, async {
                let (stream, address) = self
                    .0
                    .listener
                    .accept()
                    .await
                    .map_err(|_| PeerError("Guest fixture accept failed."))?;
                admitted(address)?; // Reject every source except A before TLS.
                self.0.authenticated_request(stream).await
            })
            .await
            .map_err(|_| {
                PeerError(
                    "Guest fixture request timed out; an admitted queue transaction may finish.",
                )
            })?
        }
    }
    #[cfg(test)]
    mod tests {
        use super::*;
        #[test]
        fn exact_cable_guard_has_no_private_range_wildcard_or_loopback_exception() {
            assert!(admitted("10.77.0.1:50000".parse().unwrap()).is_ok());
            for address in [
                "10.77.0.2:50000",
                "10.77.0.3:50000",
                "10.77.1.1:50000",
                "127.0.0.1:50000",
                "0.0.0.0:50000",
                "192.168.1.1:50000",
            ] {
                assert!(admitted(address.parse().unwrap()).is_err());
            }
            assert_eq!(SERVER_ADDRESS, "10.77.0.2:37431".parse().unwrap());
            assert!(super::super::loopback(SERVER_ADDRESS).is_err());
            assert!(super::super::loopback(SocketAddr::new(IpAddr::V4(CLIENT_IP), 0)).is_err());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        pairing::{
            tests::{pair, scope},
            PairingFlow,
        },
        wire::{tests::put, Change, ReceiptStatus, ZERO_DIGEST},
    };
    use rustls::{pki_types::CertificateDer, ClientConfig, RootCertStore};
    use std::{path::Path, time::Instant};
    #[test]
    fn default_transport_refuses_both_private_fixture_endpoints() {
        for address in ["10.77.0.1:1", "10.77.0.2:37431", "0.0.0.0:37431"] {
            assert!(loopback(address.parse().unwrap()).is_err());
        }
    }
    fn temp() -> tempfile::TempDir {
        let temp = tempfile::tempdir().unwrap();
        #[cfg(windows)]
        devdrop_core::file_permissions::make_disposable_test_directory_private(
            &std::fs::canonicalize(temp.path()).unwrap(),
        )
        .unwrap();
        temp
    }
    fn queue(root: &Path) -> Arc<Mutex<Inbox>> {
        let root = std::fs::canonicalize(root).unwrap();
        Arc::new(Mutex::new(Inbox::create_new(&root.join("queue")).unwrap()))
    }
    async fn start_server(pair: Paired, inbox: Arc<Mutex<Inbox>>) -> Arc<PeerServer> {
        Arc::new(
            PeerServer::bind(pair, inbox, "127.0.0.1:0".parse().unwrap())
                .await
                .unwrap(),
        )
    }
    async fn raw(pair: &Paired, address: SocketAddr) -> tokio_rustls::client::TlsStream<TcpStream> {
        let stream = TcpStream::connect(address).await.unwrap();
        let tls = TlsConnector::from(pair.client_config().unwrap())
            .connect(
                ServerName::try_from(SERVER_NAME).unwrap().to_owned(),
                stream,
            )
            .await
            .unwrap();
        pair.check_presented_certificate(tls.get_ref().1.peer_certificates())
            .unwrap();
        tls
    }
    async fn rejected_frame(pair: &Paired, server: &Arc<PeerServer>, bytes: &[u8]) {
        let task = tokio::spawn({
            let server = server.clone();
            async move { server.serve_one().await }
        });
        let mut tls = raw(pair, server.local_addr().unwrap()).await;
        write_frame(&mut tls, bytes).await.unwrap();
        let _ = read_frame(&mut tls).await;
        assert!(task.await.unwrap().is_err());
    }
    #[tokio::test]
    async fn paired_transfer_dropped_connection_retry_and_duplicate_queue_only() {
        let temp = temp();
        let (a, b) = pair();
        let inbox = queue(temp.path());
        let server = start_server(b, inbox.clone()).await;
        let envelope =
            Envelope::new(&a, 1, ZERO_DIGEST, vec![put(b"generated selected payload")]).unwrap();
        let task = tokio::spawn({
            let server = server.clone();
            async move { server.serve_one().await }
        });
        let mut tls = raw(&a, server.local_addr().unwrap()).await;
        write_frame(&mut tls, &envelope.encode().unwrap())
            .await
            .unwrap();
        drop(tls);
        let _ = task.await.unwrap();
        assert_eq!(inbox.lock().unwrap().pending_count().unwrap(), 1);
        let task = tokio::spawn({
            let server = server.clone();
            async move { server.serve_one().await }
        });
        let receipt = PeerClient::new(a.clone())
            .unwrap()
            .send(server.local_addr().unwrap(), &envelope)
            .await
            .unwrap();
        assert_eq!(receipt.status, ReceiptStatus::Duplicate);
        assert_eq!(receipt.digest, envelope.digest().unwrap());
        task.await.unwrap().unwrap();
        assert_eq!(inbox.lock().unwrap().pending_count().unwrap(), 1);
        assert!(!temp.path().join("src/shared.txt").exists());
    }
    #[tokio::test]
    async fn two_approved_one_message_sessions_share_queue_without_ack_collision() {
        fn one_message_pair() -> (Paired, Paired) {
            let a = PairingFlow::new_ephemeral().unwrap();
            let b = PairingFlow::new_ephemeral().unwrap();
            let ao = a.offer();
            let bo = b.offer();
            let mut bounded = scope();
            bounded.max_messages = 1;
            (
                a.approve(&bo, &bo.fingerprint, bounded.clone()).unwrap(),
                b.approve(&ao, &ao.fingerprint, bounded).unwrap(),
            )
        }
        let temp = temp();
        let inbox = queue(temp.path());
        let (a1, b1) = one_message_pair();
        let (a2, b2) = one_message_pair();
        let server1 = start_server(b1, inbox.clone()).await;
        let server2 = start_server(b2, inbox.clone()).await;
        let envelope1 =
            Envelope::new(&a1, 1, ZERO_DIGEST, vec![put(b"first generated pairing")]).unwrap();
        let envelope2 =
            Envelope::new(&a2, 1, ZERO_DIGEST, vec![put(b"second generated pairing")]).unwrap();
        for (server, pair, envelope, status) in [
            (
                server1.clone(),
                a1.clone(),
                &envelope1,
                ReceiptStatus::Queued,
            ),
            (server2, a2, &envelope2, ReceiptStatus::Queued),
            (server1, a1, &envelope1, ReceiptStatus::Duplicate),
        ] {
            let task = tokio::spawn({
                let server = server.clone();
                async move { server.serve_one().await }
            });
            let receipt = PeerClient::new(pair)
                .unwrap()
                .send(server.local_addr().unwrap(), envelope)
                .await
                .unwrap();
            assert_eq!(receipt.pending_count, 1);
            assert_eq!(receipt.status, status);
            task.await.unwrap().unwrap();
        }
        assert_eq!(inbox.lock().unwrap().pending_count().unwrap(), 2);
    }
    #[tokio::test]
    async fn authenticated_malformed_oversize_hash_and_raw_apply_are_refused() {
        let temp = temp();
        let (a, b) = pair();
        let inbox = queue(temp.path());
        let server = start_server(b, inbox.clone()).await;
        rejected_frame(&a, &server, b"{\"apply\":true,\"path\":\"../outside\"}").await;
        let mut tampered = Envelope::new(&a, 1, ZERO_DIGEST, vec![put(b"generated")]).unwrap();
        if let Change::Put { bytes, .. } = &mut tampered.changes[0] {
            bytes.push(7);
        }
        rejected_frame(&a, &server, &tampered.encode().unwrap()).await;
        let task = tokio::spawn({
            let server = server.clone();
            async move { server.serve_one().await }
        });
        let mut tls = raw(&a, server.local_addr().unwrap()).await;
        tls.write_u32(MAX_FRAME_BYTES as u32 + 1).await.unwrap();
        tls.flush().await.unwrap();
        let _ = read_frame(&mut tls).await;
        assert!(task.await.unwrap().is_err());
        assert_eq!(inbox.lock().unwrap().pending_count().unwrap(), 0);
    }
    #[tokio::test]
    async fn unpaired_client_and_missing_certificate_cannot_queue() {
        let temp = temp();
        let a = PairingFlow::new_ephemeral().unwrap();
        let b = PairingFlow::new_ephemeral().unwrap();
        let ao = a.offer();
        let bo = b.offer();
        let pa = a.approve(&bo, &bo.fingerprint, scope()).unwrap();
        let pb = b.approve(&ao, &ao.fingerprint, scope()).unwrap();
        let inbox = queue(temp.path());
        let server = start_server(pb, inbox.clone()).await;
        let outsider = PairingFlow::new_ephemeral()
            .unwrap()
            .approve(&bo, &bo.fingerprint, scope())
            .unwrap();
        let task = tokio::spawn({
            let server = server.clone();
            async move { server.serve_one().await }
        });
        let envelope = Envelope::new(&outsider, 1, ZERO_DIGEST, vec![put(b"fixture")]).unwrap();
        assert!(PeerClient::new(outsider)
            .unwrap()
            .send(server.local_addr().unwrap(), &envelope)
            .await
            .is_err());
        assert_eq!(
            task.await.unwrap().unwrap_err().0,
            "Mandatory mutual TLS client authentication failed."
        );
        let mut roots = RootCertStore::empty();
        roots.add(CertificateDer::from(bo.certificate_der)).unwrap();
        let mut config =
            ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
                .with_protocol_versions(&[&rustls::version::TLS13])
                .unwrap()
                .with_root_certificates(roots)
                .with_no_client_auth();
        config.alpn_protocols = vec![ALPN.to_vec()];
        let task = tokio::spawn({
            let server = server.clone();
            async move { server.serve_one().await }
        });
        let stream = TcpStream::connect(server.local_addr().unwrap())
            .await
            .unwrap();
        if let Ok(mut tls) = TlsConnector::from(Arc::new(config))
            .connect(
                ServerName::try_from(SERVER_NAME).unwrap().to_owned(),
                stream,
            )
            .await
        {
            let _ = write_frame(&mut tls, b"{}").await;
            let _ = read_frame(&mut tls).await;
        }
        assert_eq!(
            task.await.unwrap().unwrap_err().0,
            "Mandatory mutual TLS client authentication failed."
        );
        assert_eq!(inbox.lock().unwrap().pending_count().unwrap(), 0);
        assert!(pa
            .check_presented_certificate(Some(&[CertificateDer::from(vec![1, 2, 3])]))
            .is_err());
    }
    #[tokio::test]
    async fn mismatched_scopes_and_no_delete_scope_are_refused() {
        let temp = temp();
        let a = PairingFlow::new_ephemeral().unwrap();
        let b = PairingFlow::new_ephemeral().unwrap();
        let ao = a.offer();
        let bo = b.offer();
        let mut restricted = scope();
        restricted.allow_delete = false;
        let pa = a.approve(&bo, &bo.fingerprint, scope()).unwrap();
        let pb = b.approve(&ao, &ao.fingerprint, restricted).unwrap();
        let inbox = queue(temp.path());
        let server = start_server(pb, inbox.clone()).await;
        let envelope = Envelope::new(&pa, 1, ZERO_DIGEST, vec![put(b"fixture")]).unwrap();
        rejected_frame(&pa, &server, &envelope.encode().unwrap()).await;
        assert_eq!(inbox.lock().unwrap().pending_count().unwrap(), 0);
        let a = PairingFlow::new_ephemeral().unwrap();
        let b = PairingFlow::new_ephemeral().unwrap();
        let ao = a.offer();
        let bo = b.offer();
        let mut restricted = scope();
        restricted.allow_delete = false;
        let pa = a.approve(&bo, &bo.fingerprint, restricted.clone()).unwrap();
        let pb = b.approve(&ao, &ao.fingerprint, restricted).unwrap();
        let other = temp.path().join("other");
        std::fs::create_dir(&other).unwrap();
        #[cfg(windows)]
        devdrop_core::file_permissions::make_disposable_test_directory_private(
            &std::fs::canonicalize(&other).unwrap(),
        )
        .unwrap();
        let other_inbox = queue(&other);
        let server = start_server(pb, other_inbox.clone()).await;
        let mut envelope = Envelope::new(&pa, 1, ZERO_DIGEST, vec![put(b"fixture")]).unwrap();
        envelope.changes = vec![Change::Delete {
            path: "src/shared.txt".into(),
            previous_hash: crate::pairing::hash(b"fixture"),
        }];
        rejected_frame(&pa, &server, &envelope.encode().unwrap()).await;
        assert_eq!(other_inbox.lock().unwrap().pending_count().unwrap(), 0);
    }
    #[tokio::test]
    async fn revoke_after_handshake_prevents_queue_and_idle_request_is_bounded() {
        let temp = temp();
        let (a, b) = pair();
        let revoke = b.clone();
        let inbox = queue(temp.path());
        let server = start_server(b, inbox.clone()).await;
        let task = tokio::spawn({
            let server = server.clone();
            async move { server.serve_one().await }
        });
        let mut tls = raw(&a, server.local_addr().unwrap()).await;
        revoke.revoke();
        let envelope = Envelope::new(&a, 1, ZERO_DIGEST, vec![put(b"fixture")]).unwrap();
        let _ = write_frame(&mut tls, &envelope.encode().unwrap()).await;
        let _ = read_frame(&mut tls).await;
        assert!(task.await.unwrap().is_err());
        assert_eq!(inbox.lock().unwrap().pending_count().unwrap(), 0);
        let other = temp.path().join("idle");
        std::fs::create_dir(&other).unwrap();
        #[cfg(windows)]
        devdrop_core::file_permissions::make_disposable_test_directory_private(
            &std::fs::canonicalize(&other).unwrap(),
        )
        .unwrap();
        let (a, b) = pair();
        let server = start_server(b, queue(&other)).await;
        let started = Instant::now();
        let task = tokio::spawn({
            let server = server.clone();
            async move { server.serve_one().await }
        });
        let _idle = raw(&a, server.local_addr().unwrap()).await;
        assert!(task.await.unwrap().is_err());
        assert!(
            started.elapsed() >= Duration::from_secs(4)
                && started.elapsed() < Duration::from_secs(7)
        );
    }
    #[tokio::test]
    async fn receipt_binding_and_non_loopback_listener_are_refused() {
        let temp = temp();
        let (a, b) = pair();
        let inbox = queue(temp.path());
        assert!(
            PeerServer::bind(b.clone(), inbox, "0.0.0.0:0".parse().unwrap())
                .await
                .is_err()
        );
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let acceptor = TlsAcceptor::from(b.server_config().unwrap());
        let btask = b.clone();
        let task = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let mut tls = acceptor.accept(stream).await.unwrap();
            btask
                .check_presented_certificate(tls.get_ref().1.peer_certificates())
                .unwrap();
            let envelope: Envelope =
                serde_json::from_slice(&read_frame(&mut tls).await.unwrap()).unwrap();
            let wrong = Receipt {
                pairing_id: btask.id().into(),
                sequence: envelope.sequence,
                digest: ZERO_DIGEST.into(),
                status: ReceiptStatus::Queued,
                pending_count: 1,
            };
            write_frame(&mut tls, &serde_json::to_vec(&wrong).unwrap())
                .await
                .unwrap();
        });
        let envelope = Envelope::new(&a, 1, ZERO_DIGEST, vec![put(b"fixture")]).unwrap();
        assert!(PeerClient::new(a)
            .unwrap()
            .send(address, &envelope)
            .await
            .is_err());
        task.await.unwrap();
    }
}
