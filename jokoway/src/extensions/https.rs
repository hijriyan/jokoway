use crate::config::models::JokowayConfig;
use crate::error::JokowayError;
use crate::prelude::*;
use crate::server::context::AppCtx;
use crate::server::proxy::JokowayProxy;
use crate::server::router::{HTTPS_PROTOCOLS, Router};
use crate::server::service::ServiceManager;
use crate::server::upstream::UpstreamManager;
use boring::pkey::PKey;
use boring::ssl::{AlpnError, SslAcceptor, SslMethod, SslVerifyMode, SslVersion};
use boring::x509::X509;
use jokoway_core::tls::{AlpnProtocol, contains_alpn_protocol};
use pingora::listeners::tls::TlsSettings;
use pingora::proxy::http_proxy_service;
use std::fs;
use std::path::Path;
use std::sync::Arc;

pub struct HttpsExtension;

impl HttpsExtension {
    fn load_pem_pair_from_files(
        cert_path: &str,
        key_path: &str,
    ) -> Result<(X509, PKey<boring::pkey::Private>), Box<dyn std::error::Error>> {
        let cert_pem = fs::read(cert_path)?;
        let key_pem = fs::read(key_path)?;
        let cert = X509::from_pem(&cert_pem)?;
        let key = PKey::private_key_from_pem(&key_pem)?;
        Ok((cert, key))
    }

    fn self_signed_pair(
        ssl: &crate::config::models::SslSettings,
    ) -> Option<(X509, PKey<boring::pkey::Private>)> {
        let subject_alt_names = ssl
            .sans
            .clone()
            .filter(|sans| !sans.is_empty())
            .unwrap_or_else(|| vec!["localhost".to_string(), "127.0.0.1".to_string()]);

        // Custom cert parameters for self-signed
        let mut params = rcgen::CertificateParams::new(subject_alt_names).ok()?;
        params.distinguished_name.remove(rcgen::DnType::CommonName);
        params
            .distinguished_name
            .push(rcgen::DnType::CommonName, "Jokoway Gateway");

        let key_pair = rcgen::KeyPair::generate().ok()?;
        let cert = params.self_signed(&key_pair).ok()?;

        let priv_key_pem = key_pair.serialize_pem();
        let cert_pem = cert.pem();
        let key = PKey::private_key_from_pem(priv_key_pem.as_bytes()).ok()?;
        let cert = X509::from_pem(cert_pem.as_bytes()).ok()?;
        Some((cert, key))
    }
}

fn parse_ssl_version(version: &str) -> Option<SslVersion> {
    match version.to_uppercase().as_str() {
        "TLSV1" | "TLS1" | "TLS1.0" | "1.0" => Some(SslVersion::TLS1),
        "TLSV1.1" | "TLS1.1" | "1.1" => Some(SslVersion::TLS1_1),
        "TLSV1.2" | "TLS1.2" | "1.2" => Some(SslVersion::TLS1_2),
        "TLSV1.3" | "TLS1.3" | "1.3" => Some(SslVersion::TLS1_3),
        _ => None,
    }
}

impl JokowayExtension for HttpsExtension {
    fn init(
        &self,
        server: &mut pingora::server::Server,
        app_ctx: &mut AppCtx,
        http_middlewares: &mut Vec<std::sync::Arc<dyn HttpMiddlewareDyn>>,
        websocket_middlewares: &mut Vec<std::sync::Arc<dyn WebsocketMiddlewareDyn>>,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let config = app_ctx
            .get::<JokowayConfig>()
            .ok_or_else(|| JokowayError::Config("JokowayConfig not found in AppCtx".to_string()))?;

        // Check if HTTPS is configured to listen
        if config.https_listen.is_none() {
            return Ok(());
        }

        let upstream_manager = app_ctx.get::<UpstreamManager>().ok_or_else(|| {
            JokowayError::Config("UpstreamManager not found in AppCtx".to_string())
        })?;
        let service_manager = app_ctx.get::<ServiceManager>().ok_or_else(|| {
            JokowayError::Config("ServiceManager not found in AppCtx".to_string())
        })?;

        let router = Router::new(service_manager, upstream_manager.clone(), &HTTPS_PROTOCOLS);
        let proxy = JokowayProxy::new(
            router,
            Arc::new(app_ctx.clone()),
            http_middlewares.clone(),
            websocket_middlewares.clone(),
            true,
        )?;

        if let Some(ssl) = &config.ssl {
            let mut ssl_acceptor = match SslAcceptor::mozilla_intermediate(SslMethod::tls()) {
                Ok(acceptor) => acceptor,
                Err(e) => {
                    log::error!("Failed to create SSL acceptor: {}", e);
                    return Err(Box::new(JokowayError::Tls(format!(
                        "Failed to create SSL acceptor: {}",
                        e
                    ))));
                }
            };

            let cert_paths = match (&ssl.server_cert, &ssl.server_key) {
                (Some(cert), Some(key)) => {
                    if !Path::new(cert).exists() {
                        return Err(Box::new(JokowayError::Tls(format!(
                            "Certificate file not found: {}",
                            cert
                        ))));
                    }
                    if !Path::new(key).exists() {
                        return Err(Box::new(JokowayError::Tls(format!(
                            "Private key file not found: {}",
                            key
                        ))));
                    }
                    Some((cert, key))
                }
                (Some(_), None) | (None, Some(_)) => {
                    log::error!("Both server_cert and server_key must be specified together");
                    return Err(Box::new(JokowayError::Tls(
                        "Both server_cert and server_key must be specified together".to_string(),
                    )));
                }
                _ => None,
            };

            let base_pair = if let Some((cert_path, key_path)) = cert_paths {
                match Self::load_pem_pair_from_files(cert_path, key_path) {
                    Ok(pair) => Some(pair),
                    Err(e) => {
                        log::error!("Failed to load TLS certs from config: {}", e);
                        return Err(Box::new(JokowayError::Tls(format!(
                            "Failed to load TLS certs from config: {}",
                            e
                        ))));
                    }
                }
            } else {
                None
            };

            let fallback_pair = match base_pair.clone() {
                Some(pair) => Some(pair),
                None => {
                    let generated = Self::self_signed_pair(ssl);
                    if generated.is_some() {
                        log::debug!("Using self-signed certificate fallback");
                    }
                    generated
                }
            };

            // Set initial certificate on the acceptor
            if let Some((cert, key)) = fallback_pair.as_ref() {
                if let Err(e) = ssl_acceptor.set_private_key(key) {
                    log::error!("Failed to set fallback private key: {}", e);
                    return Err(Box::new(JokowayError::Tls(format!(
                        "Failed to set fallback private key: {}",
                        e
                    ))));
                }
                if let Err(e) = ssl_acceptor.set_certificate(cert) {
                    log::error!("Failed to set fallback certificate: {}", e);
                    return Err(Box::new(JokowayError::Tls(format!(
                        "Failed to set fallback certificate: {}",
                        e
                    ))));
                }
            }

            let tls_callback = app_ctx.get::<TlsCallback>();

            // --- 1. SNI Callback ---
            let fallback_pair_for_sni = fallback_pair.clone();
            let tls_cb_sni = tls_callback.clone();

            ssl_acceptor.set_servername_callback(move |ssl_ref, alert| {
                // 1. Dynamic Handler
                if let Some(c) = tls_cb_sni.as_ref() {
                    let h_arc = c.get_handler();
                    if let Some(handler) = h_arc.as_ref() {
                        match handler.servername_callback(ssl_ref, alert) {
                            Ok(()) => return Ok(()),
                            Err(_e) => {
                                // Delegate returned error/pass-through, but we can try fallback
                            }
                        }
                    }
                }

                // 2. Fallback Pair
                if let Some((cert, key)) = fallback_pair_for_sni.as_ref() {
                    let _ = ssl_ref.set_certificate(cert);
                    let _ = ssl_ref.set_private_key(key);
                }
                Ok(())
            });

            // --- 2. ALPN Callback (must be set AFTER enable_h2() which overwrites it) ---
            let tls_cb_alpn = tls_callback.clone();
            ssl_acceptor.set_alpn_select_callback(move |ssl_ref, client_protos| {
                // 1. Dynamic Handler (e.g. ACME TLS-ALPN-01)
                if let Some(c) = tls_cb_alpn.as_ref() {
                    let h_arc = c.get_handler();
                    if let Some(handler) = h_arc.as_ref() {
                        match handler.alpn_select_callback(ssl_ref, client_protos) {
                            Ok(idx) => return Ok(idx),
                            Err(AlpnError::NOACK) => { /* fallthrough */ }
                            Err(e) => return Err(e),
                        }
                    }
                }

                // 2. Standard Default: prefer H2, fallback to H1
                if contains_alpn_protocol(client_protos, AlpnProtocol::H2) {
                    Ok(AlpnProtocol::H2.as_bytes())
                } else {
                    Ok(AlpnProtocol::H1.as_bytes())
                }
            });

            // --- 3. Cert Selection Callback ---
            let tls_cb_cert = tls_callback.clone();
            ssl_acceptor.set_select_certificate_callback(move |client_hello| {
                if let Some(c) = tls_cb_cert.as_ref() {
                    let h_arc = c.get_handler();
                    if let Some(handler) = h_arc.as_ref() {
                        return handler.select_certificate_callback(client_hello);
                    }
                }
                Ok(())
            });

            // --- 4. Verify Callback ---
            let tls_cb_verify = tls_callback.clone();
            let verify_mode = if let Some(ca_path) = &ssl.cacert {
                if !Path::new(ca_path).exists() {
                    return Err(Box::new(JokowayError::Tls(format!(
                        "CA certificate file not found: {}",
                        ca_path
                    ))));
                }

                if let Err(e) = ssl_acceptor.set_ca_file(ca_path) {
                    return Err(Box::new(JokowayError::Tls(format!(
                        "Failed to set CA file for client auth: {}",
                        e
                    ))));
                }

                // Enforce client auth if CA is specified
                SslVerifyMode::PEER | SslVerifyMode::FAIL_IF_NO_PEER_CERT
            } else {
                SslVerifyMode::NONE
            };

            // Note: using set_verify_callback overrides default verification logic
            // We pass the determined verify_mode
            ssl_acceptor.set_verify_callback(verify_mode, move |preverify, x509_ctx| {
                if let Some(c) = tls_cb_verify.as_ref() {
                    let h_arc = c.get_handler();
                    if let Some(handler) = h_arc.as_ref() {
                        return handler.verify_callback(preverify, x509_ctx);
                    }
                }
                preverify
            });

            // --- 5. Session Callbacks ---
            let tls_cb_sess_new = tls_callback.clone();
            ssl_acceptor.set_new_session_callback(move |ssl, session| {
                if let Some(c) = tls_cb_sess_new.as_ref() {
                    let h_arc = c.get_handler();
                    if let Some(handler) = h_arc.as_ref() {
                        handler.new_session_callback(ssl, session);
                    }
                }
            });

            let tls_cb_sess_remove = tls_callback.clone();
            ssl_acceptor.set_remove_session_callback(move |ctx, session| {
                if let Some(c) = tls_cb_sess_remove.as_ref() {
                    let h_arc = c.get_handler();
                    if let Some(handler) = h_arc.as_ref() {
                        handler.remove_session_callback(ctx, session);
                    }
                }
            });

            unsafe {
                let tls_cb_sess_get = tls_callback.clone();
                ssl_acceptor.set_get_session_callback(move |ssl, id| {
                    if let Some(c) = tls_cb_sess_get.as_ref() {
                        let h_arc = c.get_handler();
                        if let Some(handler) = h_arc.as_ref() {
                            return handler.get_session_callback(ssl, id);
                        }
                    }
                    Ok(None)
                });
            }

            // --- 6. PSK Callback ---
            let tls_cb_psk = tls_callback.clone();
            ssl_acceptor.set_psk_server_callback(move |ssl, id, psk| {
                if let Some(c) = tls_cb_psk.as_ref() {
                    let h_arc = c.get_handler();
                    if let Some(handler) = h_arc.as_ref() {
                        return handler.psk_server_callback(ssl, id, psk);
                    }
                }
                Ok(0)
            });

            // --- 7. OCSP Status Callback ---
            let tls_cb_status = tls_callback.clone();
            ssl_acceptor
                .set_status_callback(move |ssl| {
                    if let Some(c) = tls_cb_status.as_ref() {
                        let h_arc = c.get_handler();
                        if let Some(handler) = h_arc.as_ref() {
                            return handler.status_callback(ssl);
                        }
                    }
                    Ok(true)
                })
                .map_err(|e| Box::new(e) as Box<dyn std::error::Error + Send + Sync>)?;

            // --- 8. Keylog Callback ---
            let tls_cb_keylog = tls_callback.clone();
            ssl_acceptor.set_keylog_callback(move |ssl, line| {
                if let Some(c) = tls_cb_keylog.as_ref() {
                    let h_arc = c.get_handler();
                    if let Some(handler) = h_arc.as_ref() {
                        handler.keylog_callback(ssl, line);
                    }
                }
            });

            if let Some(ver) = ssl.ssl_min_version.as_deref().and_then(parse_ssl_version)
                && let Err(e) = ssl_acceptor.set_min_proto_version(Some(ver))
            {
                log::error!("Failed to set min TLS version: {}", e);
                return Err(Box::new(JokowayError::Tls(format!(
                    "Failed to set min TLS version: {}",
                    e
                ))));
            }
            if let Some(ver) = ssl.ssl_max_version.as_deref().and_then(parse_ssl_version)
                && let Err(e) = ssl_acceptor.set_max_proto_version(Some(ver))
            {
                log::error!("Failed to set max TLS version: {}", e);
                return Err(Box::new(JokowayError::Tls(format!(
                    "Failed to set max TLS version: {}",
                    e
                ))));
            }
            if let Some(ciphers) = &ssl.cipher_suites {
                let ciphers_str = ciphers.join(":");
                if let Err(e) = ssl_acceptor.set_cipher_list(&ciphers_str) {
                    log::error!("Failed to set cipher suites: {}", e);
                    return Err(Box::new(JokowayError::Tls(format!(
                        "Failed to set cipher suites: {}",
                        e
                    ))));
                }
            }

            let tls_settings = TlsSettings::from(ssl_acceptor);
            let mut https_service = http_proxy_service(&server.configuration, proxy.clone());
            https_service.add_tls_with_settings(
                config.https_listen.as_ref().unwrap(),
                None,
                tls_settings,
            );
            server.add_service(https_service);
            log::info!(
                "HTTPS proxy listening on {}",
                config.https_listen.as_ref().unwrap()
            );
        }
        Ok(())
    }
}
