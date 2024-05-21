//! limitedclient: This example demonstrates usage of ClientConfig building
//! so that unused cryptography in rustls can be discarded by the linker.  You can
//! observe using `nm` that the binary of this program does not contain any AES code.

extern crate alloc;

use std::io::{stdout, Read, Write};
use std::net::TcpStream;
use std::sync::Arc;

use rustls::crypto::{aws_lc_rs as provider, CryptoProvider};

mod danger {
    use std::fs::File;
    use std::io::Write;
    use std::path::Path;

    use base64::{engine::general_purpose::STANDARD, Engine as _};
    use pki_types::{CertificateDer, ServerName, UnixTime};
    use rustls::client::danger::HandshakeSignatureValid;
    use rustls::crypto::{verify_tls12_signature, verify_tls13_signature, CryptoProvider};
    // use rustls::webpki::verify::{
    //     verify_server_cert_signed_by_trust_anchor_impl, verify_tls12_signature,
    //     verify_tls13_signature, ParsedCertificate,
    // };
    use rustls::DigitallySignedStruct;

    #[derive(Debug)]
    pub struct MyCertificateVerification {
        pub provider: CryptoProvider,
        // pub stores: Mutex<Vec<Vec<u8>>>,
    }

    impl MyCertificateVerification {
        pub fn new(provider: CryptoProvider) -> Self {
            Self {
                provider,
                // stores: Vec::new(),
            }
        }
    }

    impl rustls::client::danger::ServerCertVerifier for MyCertificateVerification {
        fn verify_server_cert(
            &self,
            end_entity: &CertificateDer<'_>,
            intermediates: &[CertificateDer<'_>],
            server_name: &ServerName<'_>,
            ocsp: &[u8],
            now: UnixTime,
        ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
            println!("---- 22 verify_server_cert: 11{end_entity:?}, 22{intermediates:?}, {server_name:?}, {ocsp:?}, {now:?}");

            let b64 = STANDARD.encode(end_entity);
            let filename = "cert.pem".to_string();
            let path = Path::new(&filename);
            let mut file = File::create(path).unwrap();
            file.write_all(b"-----BEGIN CERTIFICATE-----\n")
                .unwrap();
            file.write_all(b64.as_bytes()).unwrap();
            file.write_all(b"\n-----END CERTIFICATE-----")
                .unwrap();
            println!("Certificate  written to {}", filename);

            Ok(rustls::client::danger::ServerCertVerified::assertion())

            /* let cert = ParsedCertificate::try_from(end_entity)?;

            let crl_refs = self.crls.iter().collect::<Vec<_>>();

            let revocation = if self.crls.is_empty() {
                None
            } else {
                // Note: unwrap here is safe because RevocationOptionsBuilder only errors when given
                //       empty CRLs.
                Some(
                    webpki::RevocationOptionsBuilder::new(crl_refs.as_slice())
                        // Note: safe to unwrap here - new is only fallible if no CRLs are provided
                        //       and we verify this above.
                        .unwrap()
                        .with_depth(self.revocation_check_depth)
                        .with_status_policy(self.unknown_revocation_policy)
                        .build(),
                )
            };

            // Note: we use the crate-internal `_impl` fn here in order to provide revocation
            // checking information, if applicable.
            verify_server_cert_signed_by_trust_anchor_impl(
                &cert,
                &self.roots,
                intermediates,
                revocation,
                now,
                self.supported.all,
            )?;

            if !ocsp_response.is_empty() {
                trace!("Unvalidated OCSP response: {:?}", ocsp_response.to_vec());
            }

            verify_server_name(&cert, server_name)?;
            Ok(ServerCertVerified::assertion()) */
        }

        fn verify_tls12_signature(
            &self,
            message: &[u8],
            cert: &CertificateDer<'_>,
            dss: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, rustls::Error> {
            println!("---- 22 verify_tls12_signature");
            verify_tls12_signature(
                message,
                cert,
                dss,
                &self
                    .provider
                    .signature_verification_algorithms,
            )
        }

        fn verify_tls13_signature(
            &self,
            message: &[u8],
            cert: &CertificateDer<'_>,
            dss: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, rustls::Error> {
            println!("---- 22 verify_tls13_signature: {message:?}, {cert:?}, {dss:?}");

            verify_tls13_signature(
                message,
                cert,
                dss,
                &self
                    .provider
                    .signature_verification_algorithms,
            )
        }

        fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
            println!("---- 22 supported_verify_schemes");
            self.provider
                .signature_verification_algorithms
                .supported_schemes()
        }
    }
}

mod hash {

    use alloc::boxed::Box;

    use rustls::crypto::hash;
    use sha2::Digest;

    pub struct Sha256;

    impl hash::Hash for Sha256 {
        fn start(&self) -> Box<dyn hash::Context> {
            Box::new(Sha256Context(sha2::Sha256::new()))
        }

        fn hash(&self, data: &[u8]) -> hash::Output {
            hash::Output::new(&sha2::Sha256::digest(data)[..])
        }

        fn algorithm(&self) -> hash::HashAlgorithm {
            hash::HashAlgorithm::SHA256
        }

        fn output_len(&self) -> usize {
            32
        }
    }

    struct Sha256Context(sha2::Sha256);

    impl hash::Context for Sha256Context {
        fn fork_finish(&self) -> hash::Output {
            hash::Output::new(&self.0.clone().finalize()[..])
        }

        fn fork(&self) -> Box<dyn hash::Context> {
            Box::new(Sha256Context(self.0.clone()))
        }

        fn finish(self: Box<Self>) -> hash::Output {
            hash::Output::new(&self.0.finalize()[..])
        }

        fn update(&mut self, data: &[u8]) {
            self.0.update(data);
        }
    }
}

mod hmac {
    use alloc::boxed::Box;

    use hmac::{Hmac, Mac};
    use rustls::crypto;
    use sha2::{Digest, Sha256};

    pub struct Sha256Hmac;

    impl crypto::hmac::Hmac for Sha256Hmac {
        fn with_key(&self, key: &[u8]) -> Box<dyn crypto::hmac::Key> {
            Box::new(Sha256HmacKey(Hmac::<Sha256>::new_from_slice(key).unwrap()))
        }

        fn hash_output_len(&self) -> usize {
            Sha256::output_size()
        }
    }

    struct Sha256HmacKey(Hmac<Sha256>);

    impl crypto::hmac::Key for Sha256HmacKey {
        fn sign_concat(&self, first: &[u8], middle: &[&[u8]], last: &[u8]) -> crypto::hmac::Tag {
            let mut ctx = self.0.clone();
            ctx.update(first);
            for m in middle {
                ctx.update(m);
            }
            ctx.update(last);
            crypto::hmac::Tag::new(&ctx.finalize().into_bytes()[..])
        }

        fn tag_len(&self) -> usize {
            Sha256::output_size()
        }
    }
}

mod aead {
    use std::println;

    use alloc::boxed::Box;

    use chacha20poly1305::aead::Buffer;
    use chacha20poly1305::{AeadInPlace, KeyInit, KeySizeUser};
    use rustls::crypto::cipher::{
        make_tls12_aad, make_tls13_aad, AeadKey, BorrowedPayload, InboundOpaqueMessage,
        InboundPlainMessage, Iv, KeyBlockShape, MessageDecrypter, MessageEncrypter, Nonce,
        OutboundOpaqueMessage, OutboundPlainMessage, PrefixedPayload, Tls12AeadAlgorithm,
        Tls13AeadAlgorithm, UnsupportedOperationError, NONCE_LEN,
    };
    use rustls::{ConnectionTrafficSecrets, ContentType, ProtocolVersion};

    pub struct Chacha20Poly1305;

    impl Tls13AeadAlgorithm for Chacha20Poly1305 {
        fn encrypter(&self, key: AeadKey, iv: Iv) -> Box<dyn MessageEncrypter> {
            Box::new(Tls13Cipher(
                chacha20poly1305::ChaCha20Poly1305::new_from_slice(key.as_ref()).unwrap(),
                iv,
            ))
        }

        fn decrypter(&self, key: AeadKey, iv: Iv) -> Box<dyn MessageDecrypter> {
            Box::new(Tls13Cipher(
                chacha20poly1305::ChaCha20Poly1305::new_from_slice(key.as_ref()).unwrap(),
                iv,
            ))
        }

        fn key_len(&self) -> usize {
            chacha20poly1305::ChaCha20Poly1305::key_size()
        }

        fn extract_keys(
            &self,
            key: AeadKey,
            iv: Iv,
        ) -> Result<ConnectionTrafficSecrets, UnsupportedOperationError> {
            Ok(ConnectionTrafficSecrets::Chacha20Poly1305 { key, iv })
        }
    }

    impl Tls12AeadAlgorithm for Chacha20Poly1305 {
        fn encrypter(&self, key: AeadKey, iv: &[u8], _: &[u8]) -> Box<dyn MessageEncrypter> {
            Box::new(Tls12Cipher(
                chacha20poly1305::ChaCha20Poly1305::new_from_slice(key.as_ref()).unwrap(),
                Iv::copy(iv),
            ))
        }

        fn decrypter(&self, key: AeadKey, iv: &[u8]) -> Box<dyn MessageDecrypter> {
            Box::new(Tls12Cipher(
                chacha20poly1305::ChaCha20Poly1305::new_from_slice(key.as_ref()).unwrap(),
                Iv::copy(iv),
            ))
        }

        fn key_block_shape(&self) -> KeyBlockShape {
            KeyBlockShape {
                enc_key_len: 32,
                fixed_iv_len: 12,
                explicit_nonce_len: 0,
            }
        }

        fn extract_keys(
            &self,
            key: AeadKey,
            iv: &[u8],
            _explicit: &[u8],
        ) -> Result<ConnectionTrafficSecrets, UnsupportedOperationError> {
            // This should always be true because KeyBlockShape and the Iv nonce len are in agreement.
            debug_assert_eq!(NONCE_LEN, iv.len());
            Ok(ConnectionTrafficSecrets::Chacha20Poly1305 {
                key,
                iv: Iv::new(iv[..].try_into().unwrap()),
            })
        }
    }

    struct Tls13Cipher(chacha20poly1305::ChaCha20Poly1305, Iv);

    impl MessageEncrypter for Tls13Cipher {
        fn encrypt(
            &mut self,
            m: OutboundPlainMessage,
            seq: u64,
        ) -> Result<OutboundOpaqueMessage, rustls::Error> {
            let total_len = self.encrypted_payload_len(m.payload.len());
            let mut payload = PrefixedPayload::with_capacity(total_len);

            payload.extend_from_chunks(&m.payload);
            payload.extend_from_slice(&m.typ.to_array());
            let nonce = chacha20poly1305::Nonce::from(Nonce::new(&self.1, seq).0);
            let aad = make_tls13_aad(total_len);

            self.0
                .encrypt_in_place(&nonce, &aad, &mut EncryptBufferAdapter(&mut payload))
                .map_err(|_| rustls::Error::EncryptError)
                .map(|_| {
                    OutboundOpaqueMessage::new(
                        ContentType::ApplicationData,
                        ProtocolVersion::TLSv1_2,
                        payload,
                    )
                })
        }

        fn encrypted_payload_len(&self, payload_len: usize) -> usize {
            payload_len + 1 + CHACHAPOLY1305_OVERHEAD
        }
    }

    impl MessageDecrypter for Tls13Cipher {
        fn decrypt<'a>(
            &mut self,
            mut m: InboundOpaqueMessage<'a>,
            seq: u64,
        ) -> Result<InboundPlainMessage<'a>, rustls::Error> {
            println!("---- tls decrypt message: {:?}", m);
            let payload = &mut m.payload;
            let nonce = chacha20poly1305::Nonce::from(Nonce::new(&self.1, seq).0);
            let aad = make_tls13_aad(payload.len());

            self.0
                .decrypt_in_place(&nonce, &aad, &mut DecryptBufferAdapter(payload))
                .map_err(|_| rustls::Error::DecryptError)?;

            m.into_tls13_unpadded_message()
        }
    }

    struct Tls12Cipher(chacha20poly1305::ChaCha20Poly1305, Iv);

    impl MessageEncrypter for Tls12Cipher {
        fn encrypt(
            &mut self,
            m: OutboundPlainMessage,
            seq: u64,
        ) -> Result<OutboundOpaqueMessage, rustls::Error> {
            let total_len = self.encrypted_payload_len(m.payload.len());
            let mut payload = PrefixedPayload::with_capacity(total_len);

            payload.extend_from_chunks(&m.payload);
            let nonce = chacha20poly1305::Nonce::from(Nonce::new(&self.1, seq).0);
            let aad = make_tls12_aad(seq, m.typ, m.version, m.payload.len());

            self.0
                .encrypt_in_place(&nonce, &aad, &mut EncryptBufferAdapter(&mut payload))
                .map_err(|_| rustls::Error::EncryptError)
                .map(|_| OutboundOpaqueMessage::new(m.typ, m.version, payload))
        }

        fn encrypted_payload_len(&self, payload_len: usize) -> usize {
            payload_len + CHACHAPOLY1305_OVERHEAD
        }
    }

    impl MessageDecrypter for Tls12Cipher {
        fn decrypt<'a>(
            &mut self,
            mut m: InboundOpaqueMessage<'a>,
            seq: u64,
        ) -> Result<InboundPlainMessage<'a>, rustls::Error> {
            println!("---- tls12 message: {:?}", m);
            let payload = &m.payload;
            let nonce = chacha20poly1305::Nonce::from(Nonce::new(&self.1, seq).0);
            let aad = make_tls12_aad(
                seq,
                m.typ,
                m.version,
                payload.len() - CHACHAPOLY1305_OVERHEAD,
            );

            let payload = &mut m.payload;
            self.0
                .decrypt_in_place(&nonce, &aad, &mut DecryptBufferAdapter(payload))
                .map_err(|_| rustls::Error::DecryptError)?;

            Ok(m.into_plain_message())
        }
    }

    const CHACHAPOLY1305_OVERHEAD: usize = 16;

    struct EncryptBufferAdapter<'a>(&'a mut PrefixedPayload);

    impl AsRef<[u8]> for EncryptBufferAdapter<'_> {
        fn as_ref(&self) -> &[u8] {
            self.0.as_ref()
        }
    }

    impl AsMut<[u8]> for EncryptBufferAdapter<'_> {
        fn as_mut(&mut self) -> &mut [u8] {
            self.0.as_mut()
        }
    }

    impl Buffer for EncryptBufferAdapter<'_> {
        fn extend_from_slice(&mut self, other: &[u8]) -> chacha20poly1305::aead::Result<()> {
            self.0.extend_from_slice(other);
            Ok(())
        }

        fn truncate(&mut self, len: usize) {
            self.0.truncate(len)
        }
    }

    struct DecryptBufferAdapter<'a, 'p>(&'a mut BorrowedPayload<'p>);

    impl AsRef<[u8]> for DecryptBufferAdapter<'_, '_> {
        fn as_ref(&self) -> &[u8] {
            self.0
        }
    }

    impl AsMut<[u8]> for DecryptBufferAdapter<'_, '_> {
        fn as_mut(&mut self) -> &mut [u8] {
            self.0
        }
    }

    impl Buffer for DecryptBufferAdapter<'_, '_> {
        fn extend_from_slice(&mut self, _: &[u8]) -> chacha20poly1305::aead::Result<()> {
            unreachable!("not used by `AeadInPlace::decrypt_in_place`")
        }

        fn truncate(&mut self, len: usize) {
            self.0.truncate(len)
        }
    }
}

static ALL_CIPHER_SUITES: &[rustls::SupportedCipherSuite] = &[
    TLS13_CHACHA20_POLY1305_SHA256,
    // TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
];

pub static TLS13_CHACHA20_POLY1305_SHA256: rustls::SupportedCipherSuite =
    rustls::SupportedCipherSuite::Tls13(&rustls::Tls13CipherSuite {
        common: rustls::crypto::CipherSuiteCommon {
            suite: rustls::CipherSuite::TLS13_CHACHA20_POLY1305_SHA256,
            hash_provider: &hash::Sha256,
            confidentiality_limit: u64::MAX,
        },
        hkdf_provider: &rustls::crypto::tls13::HkdfUsingHmac(&hmac::Sha256Hmac),
        aead_alg: &aead::Chacha20Poly1305,
        quic: None,
    });

// pub static TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256: rustls::SupportedCipherSuite =
//     rustls::SupportedCipherSuite::Tls12(&rustls::Tls12CipherSuite {
//         common: rustls::crypto::CipherSuiteCommon {
//             suite: rustls::CipherSuite::TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
//             hash_provider: &hash::Sha256,
//             confidentiality_limit: u64::MAX,
//         },
//         kx: rustls::crypto::KeyExchangeAlgorithm::ECDHE,
//         sign: &[
//             rustls::SignatureScheme::RSA_PSS_SHA256,
//             rustls::SignatureScheme::RSA_PKCS1_SHA256,
//         ],re
//         prf_provider: &rustls::crypto::tls12::PrfUsingHmac(&hmac::Sha256Hmac),
//         aead_alg: &aead::Chacha20Poly1305,
//     });

/// 1. normal http request based on tls connection
/// 2. extract session key
/// 3. extract certificate, signature, and verify
fn main() {
    let root_store = rustls::RootCertStore::from_iter(
        webpki_roots::TLS_SERVER_ROOTS
            .iter()
            .cloned(),
    );
    // let cipher_suites = provider::DEFAULT_CIPHER_SUITES.to_vec();
    let crypto_provider = CryptoProvider {
        cipher_suites: ALL_CIPHER_SUITES.to_vec(),
        ..provider::default_provider()
    };
    let protocol_versions = rustls::DEFAULT_VERSIONS.to_vec();

    let mut config = rustls::ClientConfig::builder_with_protocol_versions(&protocol_versions)
        .with_root_certificates(root_store)
        .with_no_client_auth();

    config
        .dangerous()
        .set_certificate_verifier(Arc::new(danger::MyCertificateVerification::new(
            crypto_provider,
        )));
    // To extract session key
    config.enable_secret_extraction = true;

    let host_name = "test.alux.fun";

    let server_name = host_name.try_into().unwrap();
    println!("--- server name {:?}", server_name);

    let mut conn = rustls::ClientConnection::new(Arc::new(config), server_name).unwrap();
    let mut sock = TcpStream::connect(format!("{host_name}:443")).unwrap();
    // let mut sock = TcpStream::connect("184.72.1.148:443").unwrap();
    let mut tls = rustls::Stream::new(&mut conn, &mut sock);
    tls.write_all(
        format!(
            "GET / HTTP/1.1\r\nHost: {}\r\nConnection: close\r\nAccept-Encoding: identity\r\n\r\n",
            host_name
        )
        .as_bytes(), //api/v3/avgPrice?symbol=BTCUSDT
    )
    .unwrap();

    let ciphersuite = tls
        .conn
        .negotiated_cipher_suite()
        .unwrap();
    println!(
        // &mut std::io::stderr(),
        "Current ciphersuite: {:?}",
        ciphersuite.suite()
    );
    // .unwrap();
    // println!("Connect {:?}", tls.conn.peer_certificates());
    println!("Connect {:?}", tls.conn.protocol_version());

    let mut plaintext = Vec::new();
    tls.read_to_end(&mut plaintext).unwrap();
    stdout().write_all(&plaintext).unwrap();

    let sk = conn
        .dangerous_extract_secrets()
        .unwrap();
    println!("--- session key {:?}", sk.tx);
    println!("--- session key {:?}", sk.rx);
}
