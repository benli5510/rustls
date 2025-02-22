use alloc::sync::Arc;
use alloc::vec::Vec;

// aws-lc-rs has a -- roughly -- ring-compatible API, so we just reuse all that
// glue here.  The shared files should always use `super::ring_like` to access a
// ring-compatible crate, and `super::ring_shim` to bridge the gaps where they are
// small.
pub(crate) use aws_lc_rs as ring_like;
use pki_types::PrivateKeyDer;
use webpki::aws_lc_rs as webpki_algs;

use crate::crypto::{CryptoProvider, KeyProvider, SecureRandom};
use crate::enums::SignatureScheme;
use crate::rand::GetRandomFailed;
use crate::sign::SigningKey;
use crate::suites::SupportedCipherSuite;
use crate::webpki::WebPkiSupportedAlgorithms;
use crate::Error;

/// Using software keys for authentication.
pub mod sign;

#[path = "../ring/hash.rs"]
pub(crate) mod hash;
#[path = "../ring/kx.rs"]
pub(crate) mod kx;
#[path = "../ring/quic.rs"]
pub(crate) mod quic;
#[cfg(any(feature = "std", feature = "hashbrown"))]
#[path = "../ring/ticketer.rs"]
pub(crate) mod ticketer;
#[cfg(feature = "tls12")]
pub(crate) mod tls12;
pub(crate) mod tls13;

/// A `CryptoProvider` backed by aws-lc-rs.
pub fn default_provider() -> CryptoProvider {
    CryptoProvider {
        cipher_suites: DEFAULT_CIPHER_SUITES.to_vec(),
        kx_groups: default_kx_groups(),
        signature_verification_algorithms: SUPPORTED_SIG_ALGS,
        secure_random: &AwsLcRs,
        key_provider: &AwsLcRs,
    }
}

fn default_kx_groups() -> Vec<&'static dyn SupportedKxGroup> {
    #[cfg(feature = "fips")]
    {
        ALL_KX_GROUPS
            .iter()
            .filter(|cs| cs.fips())
            .copied()
            .collect()
    }
    #[cfg(not(feature = "fips"))]
    {
        ALL_KX_GROUPS.to_vec()
    }
}

#[derive(Debug)]
struct AwsLcRs;

impl SecureRandom for AwsLcRs {
    fn fill(&self, buf: &mut [u8]) -> Result<(), GetRandomFailed> {
        use ring_like::rand::SecureRandom;

        ring_like::rand::SystemRandom::new()
            .fill(buf)
            .map_err(|_| GetRandomFailed)
    }

    fn fips(&self) -> bool {
        fips()
    }
}

impl KeyProvider for AwsLcRs {
    fn load_private_key(
        &self,
        key_der: PrivateKeyDer<'static>,
    ) -> Result<Arc<dyn SigningKey>, Error> {
        sign::any_supported_type(&key_der)
    }

    fn fips(&self) -> bool {
        fips()
    }
}

/// The cipher suite configuration that an application should use by default.
///
/// This will be [`ALL_CIPHER_SUITES`] sans any supported cipher suites that
/// shouldn't be enabled by most applications.
pub static DEFAULT_CIPHER_SUITES: &[SupportedCipherSuite] = &[
    // TLS1.3 suites
    tls13::TLS13_AES_256_GCM_SHA384,
    tls13::TLS13_AES_128_GCM_SHA256,
    #[cfg(not(feature = "fips"))]
    tls13::TLS13_CHACHA20_POLY1305_SHA256,
    // TLS1.2 suites
    #[cfg(feature = "tls12")]
    tls12::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
    #[cfg(feature = "tls12")]
    tls12::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
    #[cfg(all(feature = "tls12", not(feature = "fips")))]
    tls12::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
    #[cfg(feature = "tls12")]
    tls12::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
    #[cfg(feature = "tls12")]
    tls12::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
    #[cfg(all(feature = "tls12", not(feature = "fips")))]
    tls12::TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
];

/// A list of all the cipher suites supported by the rustls aws-lc-rs provider.
pub static ALL_CIPHER_SUITES: &[SupportedCipherSuite] = &[
    // TLS1.3 suites
    tls13::TLS13_AES_256_GCM_SHA384,
    tls13::TLS13_AES_128_GCM_SHA256,
    tls13::TLS13_CHACHA20_POLY1305_SHA256,
    // TLS1.2 suites
    #[cfg(feature = "tls12")]
    tls12::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
    #[cfg(feature = "tls12")]
    tls12::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
    #[cfg(feature = "tls12")]
    tls12::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
    #[cfg(feature = "tls12")]
    tls12::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
    #[cfg(feature = "tls12")]
    tls12::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
    #[cfg(feature = "tls12")]
    tls12::TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
];

/// All defined cipher suites supported by aws-lc-rs appear in this module.
pub mod cipher_suite {
    #[cfg(feature = "tls12")]
    pub use super::tls12::{
        TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
        TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256, TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
        TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384, TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
    };
    pub use super::tls13::{
        TLS13_AES_128_GCM_SHA256, TLS13_AES_256_GCM_SHA384, TLS13_CHACHA20_POLY1305_SHA256,
    };
}

/// A `WebPkiSupportedAlgorithms` value that reflects webpki's capabilities when
/// compiled against aws-lc-rs.
static SUPPORTED_SIG_ALGS: WebPkiSupportedAlgorithms = WebPkiSupportedAlgorithms {
    all: &[
        webpki_algs::ECDSA_P256_SHA256,
        webpki_algs::ECDSA_P256_SHA384,
        webpki_algs::ECDSA_P384_SHA256,
        webpki_algs::ECDSA_P384_SHA384,
        webpki_algs::ECDSA_P521_SHA512,
        webpki_algs::ED25519,
        webpki_algs::RSA_PSS_2048_8192_SHA256_LEGACY_KEY,
        webpki_algs::RSA_PSS_2048_8192_SHA384_LEGACY_KEY,
        webpki_algs::RSA_PSS_2048_8192_SHA512_LEGACY_KEY,
        webpki_algs::RSA_PKCS1_2048_8192_SHA256,
        webpki_algs::RSA_PKCS1_2048_8192_SHA384,
        webpki_algs::RSA_PKCS1_2048_8192_SHA512,
        webpki_algs::RSA_PKCS1_3072_8192_SHA384,
    ],
    mapping: &[
        // Note: for TLS1.2 the curve is not fixed by SignatureScheme. For TLS1.3 it is.
        (
            SignatureScheme::ECDSA_NISTP521_SHA512,
            &[webpki_algs::ECDSA_P521_SHA512],
        ),
        (
            SignatureScheme::ECDSA_NISTP384_SHA384,
            &[
                webpki_algs::ECDSA_P384_SHA384,
                webpki_algs::ECDSA_P256_SHA384,
            ],
        ),
        (
            SignatureScheme::ECDSA_NISTP256_SHA256,
            &[
                webpki_algs::ECDSA_P256_SHA256,
                webpki_algs::ECDSA_P384_SHA256,
            ],
        ),
        (SignatureScheme::ED25519, &[webpki_algs::ED25519]),
        (
            SignatureScheme::RSA_PSS_SHA512,
            &[webpki_algs::RSA_PSS_2048_8192_SHA512_LEGACY_KEY],
        ),
        (
            SignatureScheme::RSA_PSS_SHA384,
            &[webpki_algs::RSA_PSS_2048_8192_SHA384_LEGACY_KEY],
        ),
        (
            SignatureScheme::RSA_PSS_SHA256,
            &[webpki_algs::RSA_PSS_2048_8192_SHA256_LEGACY_KEY],
        ),
        (
            SignatureScheme::RSA_PKCS1_SHA512,
            &[webpki_algs::RSA_PKCS1_2048_8192_SHA512],
        ),
        (
            SignatureScheme::RSA_PKCS1_SHA384,
            &[webpki_algs::RSA_PKCS1_2048_8192_SHA384],
        ),
        (
            SignatureScheme::RSA_PKCS1_SHA256,
            &[webpki_algs::RSA_PKCS1_2048_8192_SHA256],
        ),
    ],
};

/// All defined key exchange groups supported by aws-lc-rs appear in this module.
///
/// [`ALL_KX_GROUPS`] is provided as an array of all of these values.
pub mod kx_group {
    pub use super::kx::{SECP256R1, SECP384R1, X25519};
}

pub use kx::ALL_KX_GROUPS;
#[cfg(any(feature = "std", feature = "hashbrown"))]
pub use ticketer::Ticketer;

use super::SupportedKxGroup;

/// Compatibility shims between ring 0.16.x and 0.17.x API
mod ring_shim {
    use super::ring_like;
    use crate::crypto::SharedSecret;

    pub(super) fn agree_ephemeral(
        priv_key: ring_like::agreement::EphemeralPrivateKey,
        peer_key: &ring_like::agreement::UnparsedPublicKey<&[u8]>,
    ) -> Result<SharedSecret, ()> {
        ring_like::agreement::agree_ephemeral(priv_key, peer_key, (), |secret| {
            Ok(SharedSecret::from(secret))
        })
    }
}

/// AEAD algorithm that is used by `mod ticketer`.
#[cfg(any(feature = "std", feature = "hashbrown"))]
pub(super) static TICKETER_AEAD: &ring_like::aead::Algorithm = &ring_like::aead::AES_256_GCM;

/// Are we in FIPS mode?
pub(super) fn fips() -> bool {
    aws_lc_rs::try_fips_mode().is_ok()
}

#[cfg(test)]
mod tests {
    #[cfg(feature = "fips")]
    #[test]
    fn default_suites_are_fips() {
        assert!(super::DEFAULT_CIPHER_SUITES
            .iter()
            .all(|scs| scs.fips()));
    }

    #[cfg(not(feature = "fips"))]
    #[test]
    fn default_suites() {
        assert_eq!(super::DEFAULT_CIPHER_SUITES, super::ALL_CIPHER_SUITES);
    }
}
