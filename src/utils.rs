use anyhow::Context;
use sha2::Digest;

pub const BASE32_ALPHABET: base32::Alphabet = base32::Alphabet::RFC4648 { padding: false };

pub fn hash_password(password: &str, salt: &[u8]) -> Vec<u8> {
    let mut digest = sha2::Sha512::new();
    digest.update(password);
    digest.update(salt);
    digest.finalize().to_vec()
}

pub fn generate_private_key_pem() -> anyhow::Result<String> {
    picky::key::PrivateKey::generate_rsa(2048)
        .with_context(|| "Failed to generate private key")?
        .to_pem()
        .with_context(|| "Failed to encode private key to PEM format")
}

pub fn load_private_key_from_pem(pem: &str) -> anyhow::Result<picky::key::PrivateKey> {
    pem.parse::<picky::pem::Pem>()
        .with_context(|| "Failed to parse private key PEM")
        .and_then(|pem| {
            picky::key::PrivateKey::from_pem(&pem)
                .with_context(|| "Failed to load private key from PEM")
        })
}
