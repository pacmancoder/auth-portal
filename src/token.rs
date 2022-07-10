use anyhow::{bail, Context};
use picky::jose::{
    jws::{JwsAlg, JwsHeader},
    jwt::{Jwt, JwtDate, JwtSig, JwtValidator},
};
use serde::{Deserialize, Serialize};

const TOKEN_ISSUER: &str = "auth-portal";
const TOKEN_LEEWAY: u16 = 60;

#[derive(Serialize, Deserialize)]
pub struct Token {
    #[serde(rename = "iss")]
    issuer: String,
    #[serde(rename = "aud")]
    service: String,
    #[serde(rename = "sub")]
    login: String,
    #[serde(rename = "iat")]
    issued_at: i64,
    #[serde(rename = "exp")]
    expires_at: i64,
    #[serde(rename = "nbf")]
    not_before: i64,
}

pub fn generate(
    login: &str,
    service: &str,
    key: &picky::key::PrivateKey,
    ttl_secs: i64,
) -> anyhow::Result<String> {
    let now = current_timestamp();

    JwtSig {
        header: JwsHeader::new(JwsAlg::RS512),
        claims: Token {
            issuer: TOKEN_ISSUER.to_owned(),
            service: service.to_owned(),
            login: login.to_owned(),
            issued_at: now,
            expires_at: now + ttl_secs,
            not_before: now,
        },
    }
    .encode(key)
    .with_context(|| "Failed to encode jwt token")
}

pub fn validate(token: &str, service: &str, key: &picky::key::PublicKey) -> anyhow::Result<Token> {
    let current_date = JwtDate::new_with_leeway(current_timestamp(), TOKEN_LEEWAY);
    let validator = JwtValidator::strict(&current_date);

    let jwt: Jwt<JwsHeader, Token> =
        JwtSig::decode(token, key, &validator).with_context(|| "Failed to validate token")?;

    if jwt.claims.issuer != TOKEN_ISSUER {
        bail!("Invalid token issuer {}", jwt.claims.issuer);
    }

    if jwt.claims.service != service {
        bail!(
            "Token issued for service {} but client tries to connect to {}",
            jwt.claims.service,
            service,
        );
    }

    Ok(jwt.claims)
}

fn current_timestamp() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("BUG: current time is always bigger than epoch start")
        .as_secs() as i64
}
