//! Explicit, short-lived, memory-only pairing. Certificate pins identify the
//! operator-approved peer; a content digest alone never establishes trust.
use crate::{PeerError, PeerResult};
use ring::rand::{SecureRandom, SystemRandom};
use rustls::{
    pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer},
    ClientConfig, RootCertStore, ServerConfig,
};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeSet,
    fmt,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

pub const PAIRING_TTL: Duration = Duration::from_secs(300);
pub const ALPN: &[u8] = b"devdrop-peer/1";
pub(crate) const SERVER_NAME: &str = "devdrop.local";
const MAX_CERT_BYTES: usize = 8192;

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Scope {
    pub channel: String,
    pub paths: BTreeSet<String>,
    pub allow_delete: bool,
    pub max_messages: u32,
    pub max_bytes_per_proposal: u32,
    pub max_total_bytes: u32,
}
impl fmt::Debug for Scope {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Scope")
            .field("paths_count", &self.paths.len())
            .field("max_messages", &self.max_messages)
            .finish_non_exhaustive()
    }
}
impl Scope {
    pub fn validate(&self) -> PeerResult<()> {
        if self.channel.is_empty()
            || self.channel.len() > 64
            || !self
                .channel
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-'))
        {
            return Err(PeerError("Invalid pairing channel."));
        }
        if self.paths.is_empty()
            || self.paths.len() > 16
            || self.max_messages == 0
            || self.max_messages > 16
            || self.max_bytes_per_proposal == 0
            || self.max_bytes_per_proposal > 32 * 1024
            || self.max_total_bytes == 0
            || self.max_total_bytes > 256 * 1024
        {
            return Err(PeerError("Pairing scope exceeds hard limits."));
        }
        let mut folded = BTreeSet::new();
        for path in &self.paths {
            validate_path(path)?;
            if !folded.insert(path.to_ascii_lowercase()) {
                return Err(PeerError("Case-colliding scope paths are refused."));
            }
        }
        Ok(())
    }
}
pub(crate) fn validate_path(path: &str) -> PeerResult<()> {
    if path.is_empty()
        || path.len() > 240
        || path.starts_with('/')
        || path.ends_with('/')
        || !path
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'.' | b'/'))
    {
        return Err(PeerError("Unsafe or nonportable proposal path."));
    }
    for component in path.split('/') {
        let lower = component.to_ascii_lowercase();
        let stem = lower.split('.').next().unwrap_or("").to_ascii_uppercase();
        if component.is_empty()
            || component.starts_with('.')
            || component.ends_with('.')
            || matches!(
                lower.as_str(),
                "node_modules"
                    | "target"
                    | "dist"
                    | "build"
                    | "logs"
                    | "env"
                    | "envrc"
                    | "tokens"
                    | "token"
                    | "api_key"
                    | "apikey"
                    | "id_rsa"
                    | "id_ed25519"
                    | "authorized_keys"
            )
            || lower.contains("secret")
            || lower.contains("credential")
            || lower.contains("password")
            || lower.contains("private_key")
            || [".pem", ".key", ".p12", ".pfx", ".log", ".keystore"]
                .iter()
                .any(|suffix| lower.ends_with(suffix))
            || matches!(
                stem.as_str(),
                "CON"
                    | "PRN"
                    | "AUX"
                    | "NUL"
                    | "COM1"
                    | "COM2"
                    | "COM3"
                    | "COM4"
                    | "COM5"
                    | "COM6"
                    | "COM7"
                    | "COM8"
                    | "COM9"
                    | "LPT1"
                    | "LPT2"
                    | "LPT3"
                    | "LPT4"
                    | "LPT5"
                    | "LPT6"
                    | "LPT7"
                    | "LPT8"
                    | "LPT9"
            )
        {
            return Err(PeerError(
                "Hidden, generated, credential or reserved paths are refused.",
            ));
        }
    }
    Ok(())
}
pub(crate) fn hash(bytes: &[u8]) -> String {
    blake3::hash(bytes).to_hex().to_string()
}
pub(crate) fn is_hash(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn now_millis() -> PeerResult<u64> {
    let millis = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| PeerError("System clock is unavailable."))?
        .as_millis();
    u64::try_from(millis).map_err(|_| PeerError("System clock is outside supported range."))
}

/// Public offer only. No private key is serializable or accessible through it.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PairingOffer {
    pub certificate_der: Vec<u8>,
    pub fingerprint: String,
    pub nonce: String,
    pub expires_at_unix_ms: u64,
}
impl fmt::Debug for PairingOffer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PairingOffer")
            .field("fingerprint", &self.fingerprint)
            .field("expires_at_unix_ms", &self.expires_at_unix_ms)
            .finish_non_exhaustive()
    }
}
impl PairingOffer {
    fn validate(&self, now: u64) -> PeerResult<()> {
        if self.certificate_der.len() < 64
            || self.certificate_der.len() > MAX_CERT_BYTES
            || !is_hash(&self.fingerprint)
            || self.fingerprint != hash(&self.certificate_der)
            || !is_hash(&self.nonce)
            || self.expires_at_unix_ms <= now
            || self.expires_at_unix_ms.saturating_sub(now) > PAIRING_TTL.as_millis() as u64
        {
            return Err(PeerError("Invalid or expired pairing offer."));
        }
        let mut roots = RootCertStore::empty();
        roots
            .add(CertificateDer::from(self.certificate_der.clone()))
            .map_err(|_| PeerError("Invalid pairing certificate."))?;
        Ok(())
    }
}
struct Identity {
    certificate: CertificateDer<'static>,
    key: PrivateKeyDer<'static>,
}
/// Consuming approval prevents reuse of a local offer for a second authorization.
pub struct PairingFlow {
    offer: PairingOffer,
    identity: Arc<Identity>,
    created: Instant,
}
impl fmt::Debug for PairingFlow {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("PairingFlow { identity: [REDACTED], offer: [PUBLIC OFFER] }")
    }
}
impl PairingFlow {
    pub fn new_ephemeral() -> PeerResult<Self> {
        let rcgen::CertifiedKey { cert, key_pair } =
            rcgen::generate_simple_self_signed(vec![SERVER_NAME.to_owned()])
                .map_err(|_| PeerError("Ephemeral certificate generation failed."))?;
        let certificate = cert.der().clone();
        // This strictly in-RAM conversion is consumed by standard rustls. No key
        // export, persistence, logging or public serde implementation exists.
        let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key_pair.serialize_der()));
        let mut nonce = [0u8; 32];
        SystemRandom::new()
            .fill(&mut nonce)
            .map_err(|_| PeerError("Secure ephemeral randomness unavailable."))?;
        let offer = PairingOffer {
            certificate_der: certificate.as_ref().to_vec(),
            fingerprint: hash(certificate.as_ref()),
            nonce: hash(&nonce),
            expires_at_unix_ms: now_millis()?
                .checked_add(PAIRING_TTL.as_millis() as u64)
                .ok_or(PeerError("Pairing expiry overflow."))?,
        };
        Ok(Self {
            offer,
            identity: Arc::new(Identity { certificate, key }),
            created: Instant::now(),
        })
    }
    pub fn offer(&self) -> PairingOffer {
        self.offer.clone()
    }
    pub fn approve(
        self,
        remote: &PairingOffer,
        confirmed_remote_fingerprint: &str,
        scope: Scope,
    ) -> PeerResult<Paired> {
        scope.validate()?;
        let now = now_millis()?;
        self.offer.validate(now)?;
        remote.validate(now)?;
        if self.created.elapsed() >= PAIRING_TTL
            || confirmed_remote_fingerprint != remote.fingerprint
            || self.offer.fingerprint == remote.fingerprint
        {
            return Err(PeerError(
                "Exact remote fingerprint confirmation is required.",
            ));
        }
        let mut offers = [self.offer.clone(), remote.clone()];
        offers.sort_by(|a, b| {
            a.fingerprint
                .cmp(&b.fingerprint)
                .then(a.nonce.cmp(&b.nonce))
        });
        let id = hash(
            &serde_json::to_vec(&(1u32, offers, &scope))
                .map_err(|_| PeerError("Pairing context encoding failed."))?,
        );
        let expires_at_unix_ms = self.offer.expires_at_unix_ms.min(remote.expires_at_unix_ms);
        let remaining = Duration::from_millis(expires_at_unix_ms - now)
            .min(PAIRING_TTL.saturating_sub(self.created.elapsed()));
        Ok(Paired {
            id,
            scope,
            identity: self.identity,
            local_fingerprint: self.offer.fingerprint,
            remote_fingerprint: remote.fingerprint.clone(),
            remote_certificate: CertificateDer::from(remote.certificate_der.clone()),
            expires_at_unix_ms,
            deadline: Instant::now() + remaining,
            revoked: Arc::new(AtomicBool::new(false)),
        })
    }
}
#[derive(Clone)]
pub struct Paired {
    id: String,
    scope: Scope,
    identity: Arc<Identity>,
    local_fingerprint: String,
    remote_fingerprint: String,
    remote_certificate: CertificateDer<'static>,
    expires_at_unix_ms: u64,
    deadline: Instant,
    revoked: Arc<AtomicBool>,
}
impl fmt::Debug for Paired {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Paired")
            .field("id", &self.id)
            .field("scope", &self.scope)
            .field("identity", &"[REDACTED]")
            .finish_non_exhaustive()
    }
}
impl Paired {
    pub fn id(&self) -> &str {
        &self.id
    }
    pub fn scope(&self) -> &Scope {
        &self.scope
    }
    pub fn local_fingerprint(&self) -> &str {
        &self.local_fingerprint
    }
    pub fn remote_fingerprint(&self) -> &str {
        &self.remote_fingerprint
    }
    /// Reject new local admissions; already-admitted queue transactions may finish.
    /// This does not promise synchronized cancellation of remote/in-flight work.
    pub fn revoke(&self) {
        self.revoked.store(true, Ordering::SeqCst);
    }
    pub fn ensure_active(&self) -> PeerResult<()> {
        if self.revoked.load(Ordering::SeqCst)
            || Instant::now() >= self.deadline
            || now_millis()? >= self.expires_at_unix_ms
        {
            Err(PeerError("Pairing is revoked or expired."))
        } else {
            Ok(())
        }
    }
    pub(crate) fn client_config(&self) -> PeerResult<Arc<ClientConfig>> {
        self.ensure_active()?;
        let mut roots = RootCertStore::empty();
        roots
            .add(self.remote_certificate.clone())
            .map_err(|_| PeerError("Approved server certificate is invalid."))?;
        let mut config =
            ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
                .with_protocol_versions(&[&rustls::version::TLS13])
                .map_err(|_| PeerError("TLS1.3 configuration unavailable."))?
                .with_root_certificates(roots)
                .with_client_auth_cert(
                    vec![self.identity.certificate.clone()],
                    self.identity.key.clone_key(),
                )
                .map_err(|_| PeerError("Ephemeral client identity unavailable."))?;
        config.alpn_protocols = vec![ALPN.to_vec()];
        config.enable_early_data = false;
        config.resumption = rustls::client::Resumption::disabled();
        config.key_log = Arc::new(rustls::NoKeyLog {});
        Ok(Arc::new(config))
    }
    pub(crate) fn server_config(&self) -> PeerResult<Arc<ServerConfig>> {
        self.ensure_active()?;
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let mut roots = RootCertStore::empty();
        roots
            .add(self.remote_certificate.clone())
            .map_err(|_| PeerError("Approved client certificate is invalid."))?;
        let verifier = rustls::server::WebPkiClientVerifier::builder_with_provider(
            Arc::new(roots),
            provider.clone(),
        )
        .build()
        .map_err(|_| PeerError("Mandatory client verification unavailable."))?;
        let mut config = ServerConfig::builder_with_provider(provider)
            .with_protocol_versions(&[&rustls::version::TLS13])
            .map_err(|_| PeerError("TLS1.3 configuration unavailable."))?
            .with_client_cert_verifier(verifier)
            .with_single_cert(
                vec![self.identity.certificate.clone()],
                self.identity.key.clone_key(),
            )
            .map_err(|_| PeerError("Ephemeral server identity unavailable."))?;
        config.alpn_protocols = vec![ALPN.to_vec()];
        config.max_early_data_size = 0;
        config.send_tls13_tickets = 0;
        config.send_half_rtt_data = false;
        config.session_storage = Arc::new(rustls::server::NoServerSessionStorage {});
        config.key_log = Arc::new(rustls::NoKeyLog {});
        Ok(Arc::new(config))
    }
    pub(crate) fn check_presented_certificate(
        &self,
        certificates: Option<&[CertificateDer<'_>]>,
    ) -> PeerResult<()> {
        self.ensure_active()?;
        let presented = certificates
            .and_then(|chain| chain.first())
            .ok_or(PeerError("Peer certificate is required."))?;
        if hash(presented.as_ref()) != self.remote_fingerprint {
            return Err(PeerError(
                "Presented peer certificate does not match approved pin.",
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    pub fn scope() -> Scope {
        Scope {
            channel: "disposable-fixtures".into(),
            paths: BTreeSet::from(["src/shared.txt".into()]),
            allow_delete: true,
            max_messages: 16,
            max_bytes_per_proposal: 32 * 1024,
            max_total_bytes: 256 * 1024,
        }
    }
    pub fn pair() -> (Paired, Paired) {
        let a = PairingFlow::new_ephemeral().unwrap();
        let b = PairingFlow::new_ephemeral().unwrap();
        let ao = a.offer();
        let bo = b.offer();
        (
            a.approve(&bo, &bo.fingerprint, scope()).unwrap(),
            b.approve(&ao, &ao.fingerprint, scope()).unwrap(),
        )
    }
    #[test]
    fn explicit_approval_binding_expiry_revocation_and_redacted_debug() {
        let (a, b) = pair();
        assert_eq!(a.id(), b.id());
        assert_eq!(a.local_fingerprint(), b.remote_fingerprint());
        let clone = a.clone();
        a.revoke();
        assert!(clone.ensure_active().is_err());
        assert!(b.ensure_active().is_ok());
        let flow = PairingFlow::new_ephemeral().unwrap();
        let remote = PairingFlow::new_ephemeral().unwrap().offer();
        assert!(flow.approve(&remote, "wrong-pin", scope()).is_err());
        let flow = PairingFlow::new_ephemeral().unwrap();
        let mut remote = PairingFlow::new_ephemeral().unwrap().offer();
        remote.expires_at_unix_ms = 0;
        assert!(flow.approve(&remote, &remote.fingerprint, scope()).is_err());
        let (mut expired, _) = pair();
        expired.deadline = Instant::now() - Duration::from_secs(1);
        assert!(expired.ensure_active().is_err());
        let (a, _) = pair();
        let debug = format!("{a:?}");
        assert!(debug.contains("REDACTED"));
        assert!(!debug.contains("PRIVATE KEY"));
        assert!(!debug.contains("certificate_der"));
    }
    #[test]
    fn scope_hardcaps_paths_and_mismatched_approval() {
        for path in [
            "../outside",
            "/absolute",
            "src/.env",
            "node_modules/a",
            "target/a",
            "credentials.txt",
            "src/private.key",
            "src/CON.txt",
            "src//a",
            "src/file.",
            "src\\a",
        ] {
            let mut s = scope();
            s.paths = BTreeSet::from([path.into()]);
            assert!(s.validate().is_err());
        }
        let mut s = scope();
        s.max_messages = 17;
        assert!(s.validate().is_err());
        let a = PairingFlow::new_ephemeral().unwrap();
        let b = PairingFlow::new_ephemeral().unwrap();
        let ao = a.offer();
        let bo = b.offer();
        let mut different = scope();
        different.allow_delete = false;
        let pa = a.approve(&bo, &bo.fingerprint, scope()).unwrap();
        let pb = b.approve(&ao, &ao.fingerprint, different).unwrap();
        assert_ne!(pa.id(), pb.id());
    }
    #[test]
    fn tls_config_disables_early_data_tickets_and_session_cache() {
        let (a, _) = pair();
        let client = a.client_config().unwrap();
        let server = a.server_config().unwrap();
        assert!(!client.enable_early_data);
        assert_eq!(server.max_early_data_size, 0);
        assert_eq!(server.send_tls13_tickets, 0);
        assert!(!server.session_storage.can_cache());
        assert!(!server.ticketer.enabled());
        assert!(!server.send_half_rtt_data);
    }
    #[tokio::test]
    async fn exact_leaf_pin_is_checked_after_standard_tls_on_both_ends() {
        use crate::{
            store::Inbox,
            transport::{PeerClient, PeerServer},
            wire::{tests::put, Envelope, ZERO_DIGEST},
        };
        use std::sync::Mutex;
        for wrong_side in 0..2 {
            let temp = tempfile::tempdir().unwrap();
            #[cfg(windows)]
            devdrop_core::file_permissions::make_disposable_test_directory_private(
                &std::fs::canonicalize(temp.path()).unwrap(),
            )
            .unwrap();
            let (mut a, mut b) = pair();
            // Deliberately corrupt only the stored pin, retaining valid WebPKI
            // roots and keys, to prove the independent exact-leaf check executes.
            if wrong_side == 0 {
                a.remote_fingerprint = ZERO_DIGEST.into();
            } else {
                b.remote_fingerprint = ZERO_DIGEST.into();
            }
            let root = std::fs::canonicalize(temp.path()).unwrap();
            let inbox = Arc::new(Mutex::new(Inbox::create_new(&root.join("queue")).unwrap()));
            let server = Arc::new(
                PeerServer::bind(b, inbox.clone(), "127.0.0.1:0".parse().unwrap())
                    .await
                    .unwrap(),
            );
            let task = tokio::spawn({
                let server = server.clone();
                async move { server.serve_one().await }
            });
            let envelope =
                Envelope::new(&a, 1, ZERO_DIGEST, vec![put(b"disposable pin fixture")]).unwrap();
            let client_error = PeerClient::new(a)
                .unwrap()
                .send(server.local_addr().unwrap(), &envelope)
                .await
                .unwrap_err();
            let server_error = task.await.unwrap().unwrap_err();
            let pin_error = "Presented peer certificate does not match approved pin.";
            if wrong_side == 0 {
                assert_eq!(client_error.0, pin_error);
            } else {
                assert_eq!(server_error.0, pin_error);
            }
            assert_eq!(inbox.lock().unwrap().pending_count().unwrap(), 0);
        }
    }
}
