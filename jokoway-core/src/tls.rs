use arc_swap::ArcSwap;
use boring::ssl::{
    AlpnError, ClientHello, SelectCertError, SniError, SslAlert, SslContextRef, SslRef, SslSession,
    SslSessionRef,
};
use boring::x509::X509StoreContextRef;
use std::any::Any;
use std::sync::Arc;

/// Known ALPN protocols.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AlpnProtocol {
    H1,
    H2,
    AcmeTls,
}

impl AlpnProtocol {
    pub fn as_bytes(&self) -> &'static [u8] {
        match self {
            AlpnProtocol::H1 => b"http/1.1",
            AlpnProtocol::H2 => b"h2",
            AlpnProtocol::AcmeTls => b"acme-tls/1",
        }
    }
}

/// Helper to check if a specific ALPN protocol is present in the client's offered list.
pub fn contains_alpn_protocol(client_protos: &[u8], target: AlpnProtocol) -> bool {
    let target_bytes = target.as_bytes();
    let mut pos = 0;
    while pos < client_protos.len() {
        let len = client_protos[pos] as usize;
        pos += 1;
        if pos + len > client_protos.len() {
            break;
        }
        let proto = &client_protos[pos..pos + len];
        if proto == target_bytes {
            return true;
        }
        pos += len;
    }
    false
}

/// Trait for handling all BoringSSL TLS events.
///
/// Default implementations return "pass-through" or "not handled" values, allowing
/// extensions to implement only the callbacks they need.
pub trait TlsCallbackHandler: Send + Sync + Any {
    // --- Handshake & Certificate Selection ---

    /// SNI Callback: Called when ClientHello SNI extension is parsed.
    fn servername_callback(
        &self,
        _ssl: &mut SslRef,
        _alert: &mut SslAlert,
    ) -> Result<(), SniError> {
        Ok(())
    }

    /// Application-Layer Protocol Negotiation (ALPN) selection.
    fn alpn_select_callback<'a>(
        &self,
        _ssl: &mut SslRef,
        _client_protos: &'a [u8],
    ) -> Result<&'a [u8], AlpnError> {
        Err(AlpnError::NOACK)
    }

    /// Certificate Selection Callback (ClientHello inspection).
    fn select_certificate_callback(
        &self,
        _client_hello: ClientHello<'_>,
    ) -> Result<(), SelectCertError> {
        Ok(())
    }

    // --- Verification ---

    /// Custom certificate verification logic.
    /// Returns true if verification succeeds.
    fn verify_callback(&self, preverify_ok: bool, _x509_ctx: &mut X509StoreContextRef) -> bool {
        // Default: trust the pre-verification result
        preverify_ok
    }

    // --- Session Management ---

    /// Called when a new session is negotiated (for caching).
    fn new_session_callback(&self, _ssl: &mut SslRef, _session: SslSession) {}

    /// Called when a session is removed from the cache.
    fn remove_session_callback(&self, _ctx: &SslContextRef, _session: &SslSessionRef) {}

    /// Called to look up a session by ID (server-side resume).
    fn get_session_callback(
        &self,
        _ssl: &mut SslRef,
        _session_id: &[u8],
    ) -> Result<Option<SslSession>, boring::ssl::GetSessionPendingError> {
        Ok(None)
    }

    // --- PSK (Pre-Shared Key) ---

    fn psk_server_callback(
        &self,
        _ssl: &mut SslRef,
        _identity: Option<&[u8]>,
        _psk: &mut [u8],
    ) -> Result<usize, boring::error::ErrorStack> {
        // Return 0 to indicate no PSK
        Ok(0)
    }

    // --- OCSP ---

    fn status_callback(&self, _ssl: &mut SslRef) -> Result<bool, boring::error::ErrorStack> {
        Ok(true)
    }

    // --- Key Logging ---

    fn keylog_callback(&self, _ssl: &SslRef, _line: &str) {}
}

/// Thread-safe container for dynamic TLS callback handlers.
///
/// Uses ArcSwap to allow lock-free replacement of the handler at runtime.
#[derive(Clone)]
pub struct TlsCallback {
    inner: Arc<ArcSwap<Option<Box<dyn TlsCallbackHandler>>>>,
}

impl Default for TlsCallback {
    fn default() -> Self {
        Self::new()
    }
}

impl TlsCallback {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(ArcSwap::from_pointee(None)),
        }
    }

    pub fn set_handler(&self, handler: impl TlsCallbackHandler + 'static) {
        self.inner.store(Arc::new(Some(
            Box::new(handler) as Box<dyn TlsCallbackHandler>
        )));
    }

    pub fn get_handler(&self) -> Arc<Option<Box<dyn TlsCallbackHandler>>> {
        self.inner.load().clone()
    }
}
