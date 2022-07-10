use anyhow::Context;
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, path::Path};

use crate::utils::{generate_private_key_pem, hash_password, BASE32_ALPHABET};

#[derive(Default, Serialize, Deserialize)]
pub struct Service {
    #[serde(alias = "user")]
    pub users: HashMap<String, User>,
}

#[derive(Deserialize, Serialize, Clone)]
pub struct User {
    pub password_hash: String,
    pub password_salt: String,
    pub totp_key: Option<String>,
}

#[derive(Deserialize, Serialize)]
pub struct Config {
    pub jwt_key: String,
    pub session_ttl: i64,
    #[serde(alias = "service")]
    pub services: HashMap<String, Service>,
}

pub struct SetCredentialsOutput {
    pub totp_key: Option<String>,
}

impl Config {
    pub fn new(session_ttl: i64) -> anyhow::Result<Self> {
        Ok(Self {
            services: Default::default(),
            jwt_key: generate_private_key_pem()?,
            session_ttl,
        })
    }

    pub fn load(path: &Path) -> anyhow::Result<Self> {
        let config_data =
            std::fs::read_to_string(path).with_context(|| "Failed to read config file")?;

        toml::from_str(&config_data).with_context(|| "Failed to parse config file")
    }

    pub fn save(&self, path: &Path) -> anyhow::Result<()> {
        let serialized =
            toml::to_string_pretty(self).with_context(|| "Failed to serialize config file")?;

        std::fs::write(path, serialized).with_context(|| "Failed to write config file")
    }

    pub fn set_credentials(
        &mut self,
        service: &str,
        login: &str,
        password: &str,
        enable_totp: bool,
    ) -> anyhow::Result<SetCredentialsOutput> {
        if !self.services.contains_key(service) {
            self.services.insert(service.to_owned(), Default::default());
        }

        let (password_hash, password_salt) = {
            let salt_data: [u8; 32] = rand::random();
            let hash_data = hash_password(password, &salt_data);
            let hash = base32::encode(BASE32_ALPHABET, &hash_data);
            let salt = base32::encode(BASE32_ALPHABET, &salt_data);

            (hash, salt)
        };

        let totp_key = enable_totp.then(|| {
            let data: [u8; 20] = rand::random();
            base32::encode(BASE32_ALPHABET, &data)
        });

        let service = self
            .services
            .get_mut(service)
            .expect("BUG: Code above should already ensure that service exist");

        match service.users.get_mut(login) {
            Some(existing) => {
                existing.password_hash = password_hash;
                existing.password_salt = password_salt;
                if totp_key.is_some() {
                    existing.totp_key = totp_key.clone();
                }
            }
            None => {
                service.users.insert(
                    login.to_owned(),
                    User {
                        password_hash,
                        password_salt,
                        totp_key: totp_key.clone(),
                    },
                );
            }
        };

        Ok(SetCredentialsOutput { totp_key })
    }
}
