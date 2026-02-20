use boring::ssl::{AlpnError, SniError, SslAlert, SslRef};
use jokoway_core::tls::{AlpnProtocol, TlsCallbackHandler, contains_alpn_protocol};
use std::sync::Arc;

use crate::{AcmeConfigExt, AcmeManager};

pub struct AcmeTlsHandler {
    pub(crate) acme_manager: Arc<AcmeManager>,
    // Cached value to avoid repetitive lookups
    pub(crate) use_tls_alpn: bool,
}

impl AcmeTlsHandler {
    pub fn new(
        acme_manager: Arc<AcmeManager>,
        config: jokoway_core::config::models::JokowayConfig,
    ) -> Self {
        let use_tls_alpn = config
            .acme()
            .map(|a| matches!(a.challenge, crate::AcmeChallengeType::TlsAlpn01))
            .unwrap_or(false);

        Self {
            acme_manager,
            use_tls_alpn,
        }
    }
}

impl TlsCallbackHandler for AcmeTlsHandler {
    fn servername_callback(&self, ssl: &mut SslRef, _alert: &mut SslAlert) -> Result<(), SniError> {
        let name = ssl.servername(boring::ssl::NameType::HOST_NAME);
        if let Some(name) = name
            && let Some(cached) = self
                .acme_manager
                .get_certificate_cached(name, self.use_tls_alpn)
            && let Some(leaf) = cached.certificate_chain.first()
            && ssl.set_certificate(leaf).is_ok()
            && ssl.set_private_key(&cached.private_key).is_ok()
        {
            for intermediate in cached.certificate_chain.iter().skip(1) {
                let _ = ssl.add_chain_cert(intermediate);
            }
            return Ok(());
        }
        Ok(())
    }

    fn alpn_select_callback<'a>(
        &self,
        ssl: &mut SslRef,
        client_protos: &'a [u8],
    ) -> Result<&'a [u8], AlpnError> {
        // Only if ACME TLS-ALPN-01 is enabled
        if !self.use_tls_alpn {
            return Err(AlpnError::NOACK);
        }

        if contains_alpn_protocol(client_protos, AlpnProtocol::AcmeTls)
            && let Some(name) = ssl.servername(boring::ssl::NameType::HOST_NAME)
            && self
                .acme_manager
                .get_certificate_cached(name, true)
                .is_some()
        {
            log::debug!("ALPN: selected acme-tls/1 for domain {}", name);
            return Ok(AlpnProtocol::AcmeTls.as_bytes());
        }

        Err(AlpnError::NOACK)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{AcmeChallengeType, AcmeSettings};
    use jokoway_core::config::models::JokowayConfig;

    fn create_handler(challenge: AcmeChallengeType) -> AcmeTlsHandler {
        // Create temp storage path
        let mut path = std::env::temp_dir();
        path.push(format!("test_acme_store_{}", std::process::id()));
        let storage_path = path.to_str().unwrap().to_string();

        let settings = AcmeSettings {
            storage: storage_path,
            challenge: challenge.clone(),
            ..Default::default()
        };
        let manager = Arc::new(AcmeManager::new(&settings));

        // Create config with matching challenge
        let mut config = JokowayConfig::default();
        config
            .extra
            .insert("acme".to_string(), serde_yaml::to_value(settings).unwrap());

        AcmeTlsHandler::new(manager, config)
    }

    #[test]
    fn test_handler_init_use_tls_alpn() {
        let handler = create_handler(AcmeChallengeType::TlsAlpn01);
        assert!(handler.use_tls_alpn);

        let handler = create_handler(AcmeChallengeType::Http01);
        assert!(!handler.use_tls_alpn);
    }
}
