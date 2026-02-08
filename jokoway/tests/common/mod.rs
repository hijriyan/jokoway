#![allow(dead_code)]
use futures_util::{SinkExt, StreamExt};
use openssl::asn1::Asn1Time;
use openssl::bn::{BigNum, MsbOption};
use openssl::hash::MessageDigest;
use openssl::pkey::{PKey, Private};
use openssl::rsa::Rsa;
use openssl::ssl::{Ssl, SslAcceptor, SslMethod, SslVerifyMode};
use openssl::x509::extension::{
    BasicConstraints, ExtendedKeyUsage, KeyUsage, SubjectAlternativeName,
};
use openssl::x509::{X509, X509NameBuilder};
use std::pin::Pin;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio_tungstenite::accept_async;
use wiremock::MockServer;

pub struct Certs {
    pub ca_cert: String,
    pub server_cert: String,
    pub server_key: String,
    pub client_cert: String,
    pub client_key: String,
}

fn generate_key() -> PKey<Private> {
    let rsa = Rsa::generate(2048).unwrap();
    PKey::from_rsa(rsa).unwrap()
}

fn generate_ca() -> (X509, PKey<Private>) {
    let key = generate_key();
    let mut x509 = X509::builder().unwrap();
    x509.set_version(2).unwrap();
    let serial_number = {
        let mut serial = BigNum::new().unwrap();
        serial.rand(159, MsbOption::MAYBE_ZERO, false).unwrap();
        serial.to_asn1_integer().unwrap()
    };
    x509.set_serial_number(&serial_number).unwrap();

    let mut name = X509NameBuilder::new().unwrap();
    name.append_entry_by_text("CN", "Jokoway Test CA").unwrap();
    let name = name.build();
    x509.set_subject_name(&name).unwrap();
    x509.set_issuer_name(&name).unwrap();

    x509.set_not_before(&Asn1Time::days_from_now(0).unwrap())
        .unwrap();
    x509.set_not_after(&Asn1Time::days_from_now(365).unwrap())
        .unwrap();
    x509.set_pubkey(&key).unwrap();

    x509.append_extension(BasicConstraints::new().critical().ca().build().unwrap())
        .unwrap();
    x509.append_extension(
        KeyUsage::new()
            .critical()
            .key_cert_sign()
            .crl_sign()
            .build()
            .unwrap(),
    )
    .unwrap();

    x509.sign(&key, MessageDigest::sha256()).unwrap();
    (x509.build(), key)
}

fn generate_cert(cn: &str, ca_cert: &X509, ca_key: &PKey<Private>) -> (String, String) {
    let key = generate_key();
    let mut x509 = X509::builder().unwrap();
    x509.set_version(2).unwrap();
    let serial_number = {
        let mut serial = BigNum::new().unwrap();
        serial.rand(159, MsbOption::MAYBE_ZERO, false).unwrap();
        serial.to_asn1_integer().unwrap()
    };
    x509.set_serial_number(&serial_number).unwrap();

    let mut name = X509NameBuilder::new().unwrap();
    name.append_entry_by_text("CN", cn).unwrap();
    let name = name.build();
    x509.set_subject_name(&name).unwrap();
    x509.set_issuer_name(ca_cert.subject_name()).unwrap();

    x509.set_not_before(&Asn1Time::days_from_now(0).unwrap())
        .unwrap();
    x509.set_not_after(&Asn1Time::days_from_now(365).unwrap())
        .unwrap();
    x509.set_pubkey(&key).unwrap();

    let mut san = SubjectAlternativeName::new();
    san.dns(cn);
    san.ip("127.0.0.1");
    // Add localhost as IP too? No, "127.0.0.1" is IP.

    x509.append_extension(
        san.build(&x509.x509v3_context(Some(ca_cert), None))
            .unwrap(),
    )
    .unwrap();

    x509.append_extension(
        KeyUsage::new()
            .digital_signature()
            .key_encipherment()
            .build()
            .unwrap(),
    )
    .unwrap();
    x509.append_extension(
        ExtendedKeyUsage::new()
            .server_auth()
            .client_auth()
            .build()
            .unwrap(),
    )
    .unwrap();

    x509.sign(ca_key, MessageDigest::sha256()).unwrap();
    let cert_pem = String::from_utf8(x509.build().to_pem().unwrap()).unwrap();
    let key_pem = String::from_utf8(key.private_key_to_pem_pkcs8().unwrap()).unwrap();
    (cert_pem, key_pem)
}

pub fn generate_test_certs() -> Certs {
    let (ca_cert, ca_key) = generate_ca();
    let ca_pem = String::from_utf8(ca_cert.to_pem().unwrap()).unwrap();

    let (server_cert, server_key) = generate_cert("localhost", &ca_cert, &ca_key);
    let (client_cert, client_key) = generate_cert("client", &ca_cert, &ca_key);

    Certs {
        ca_cert: ca_pem,
        server_cert,
        server_key,
        client_cert,
        client_key,
    }
}

/// Starts a mock HTTP server using wiremock.
pub async fn start_http_mock() -> MockServer {
    MockServer::start().await
}

/// Starts a mock WebSocket echo server.
/// Returns the WebSocket URL (ws://...) and a JoinHandle for the server task.
pub async fn start_ws_mock() -> (String, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let url = format!("ws://{}", addr);

    let handle = tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            tokio::spawn(async move {
                let mut ws_stream = accept_async(stream).await.unwrap();
                while let Some(msg) = ws_stream.next().await {
                    if let Ok(msg) = msg {
                        if msg.is_text() || msg.is_binary() {
                            ws_stream.send(msg).await.unwrap();
                        }
                    } else {
                        break;
                    }
                }
            });
        }
    });

    (url, handle)
}

/// Starts a mock server that requires mTLS.
/// Returns the server address (host:port) and a JoinHandle.
pub async fn start_mtls_mock(certs: &Certs) -> (String, tokio::task::JoinHandle<()>) {
    let mut acceptor = SslAcceptor::mozilla_intermediate(SslMethod::tls()).unwrap();

    // Configure CA verification
    let mut store = openssl::x509::store::X509StoreBuilder::new().unwrap();
    let ca_cert = X509::from_pem(certs.ca_cert.as_bytes()).unwrap();
    store.add_cert(ca_cert).unwrap();
    acceptor.set_cert_store(store.build());

    acceptor.set_verify(SslVerifyMode::PEER | SslVerifyMode::FAIL_IF_NO_PEER_CERT);

    // Configure Server Identity
    let server_cert = X509::from_pem(certs.server_cert.as_bytes()).unwrap();
    let server_key = PKey::private_key_from_pem(certs.server_key.as_bytes()).unwrap();
    acceptor.set_certificate(&server_cert).unwrap();
    acceptor.set_private_key(&server_key).unwrap();

    let acceptor = std::sync::Arc::new(acceptor.build());
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let addr = format!("127.0.0.1:{}", port);

    let handle = tokio::spawn(async move {
        loop {
            let (stream, _) = listener.accept().await.unwrap();
            let acceptor = acceptor.clone();
            tokio::spawn(async move {
                let ssl = Ssl::new(acceptor.context()).unwrap();
                let mut stream = tokio_openssl::SslStream::new(ssl, stream).unwrap();

                // Wait for the handshake to complete
                if let Err(e) = Pin::new(&mut stream).accept().await {
                    eprintln!("Mock mTLS server handshake failed: {}", e);
                    return;
                }

                // Read HTTP request (optional, but good to consume)
                let mut buf = [0u8; 1024];
                if let Ok(_) = stream.read(&mut buf).await {
                    // Simple HTTP response
                    let _ = stream
                        .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 7\r\n\r\nmTLS OK")
                        .await;
                }
            });
        }
    });

    (addr, handle)
}
