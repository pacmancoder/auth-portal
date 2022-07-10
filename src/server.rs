use crate::{
    config::Config,
    token,
    utils::{hash_password, load_private_key_from_pem, BASE32_ALPHABET},
};
use anyhow::{anyhow, bail, Context};
use picky::key::PublicKey;
use serde::Deserialize;
use std::{collections::HashMap, net::ToSocketAddrs};

pub const LOGIN_PAGE: &str = include_str!("static/login.html");
pub const PICO_CSS: &str = include_str!("static/pico.min.css");

#[derive(Deserialize)]
struct Credentials {
    #[serde(rename = "l")]
    login: String,
    #[serde(rename = "p")]
    password: String,
    #[serde(rename = "k")]
    totp_key: Option<String>,
}

struct UserInfo {
    salt: Vec<u8>,
    hash: Vec<u8>,
    totp_key: Option<Vec<u8>>,
}

#[derive(Hash, PartialEq, Eq)]
struct UserId {
    service: String,
    login: String,
}

pub struct Server {
    prefix: String,
    public_key: picky::key::PublicKey,
    private_key: picky::key::PrivateKey,
    session_ttl: i64,
    users: HashMap<UserId, UserInfo>,
    handlebars: handlebars::Handlebars<'static>,
    secure: bool,
}

impl Server {
    pub fn run(
        config: &Config,
        host: impl ToSocketAddrs,
        mut prefix: String,
        secure: bool,
    ) -> anyhow::Result<()> {
        // Add trailing slash if missing
        if !prefix.ends_with('/') {
            prefix.push('/')
        }

        let socker_addr = host
            .to_socket_addrs()
            .with_context(|| "Invalid socker addr")?
            .next()
            .expect("BUG: At least single socker addr should be parsed");

        let private_key = load_private_key_from_pem(&config.jwt_key)?;
        let public_key = private_key.to_public_key();
        let session_ttl = config.session_ttl;

        let users = config
            .services
            .iter()
            .flat_map(|(service_name, service_data)| {
                service_data.users.iter().map(|(user_name, user_data)| {
                    let id = UserId {
                        service: service_name.clone(),
                        login: user_name.clone(),
                    };

                    let hash = base32::decode(BASE32_ALPHABET, &user_data.password_hash)
                        .ok_or_else(|| {
                            anyhow!("Failed to read password hash for user {}", user_name)
                        })?;

                    let totp_key = user_data
                        .totp_key
                        .as_ref()
                        .map(|key| {
                            base32::decode(BASE32_ALPHABET, key)
                                .ok_or_else(|| anyhow!("Failed to totp key for user {}", user_name))
                        })
                        .transpose()?;

                    let salt = base32::decode(BASE32_ALPHABET, &user_data.password_salt)
                        .ok_or_else(|| {
                            anyhow!("Failed to read password salt for user {}", user_name)
                        })?;

                    let info = UserInfo {
                        hash,
                        salt,
                        totp_key,
                    };

                    Ok((id, info))
                })
            })
            .collect::<Result<HashMap<_, _>, anyhow::Error>>()?;

        let mut handlebars = handlebars::Handlebars::new();
        handlebars
            .register_template_string("login", LOGIN_PAGE)
            .with_context(|| "Failed to parse login template")?;

        let context = Server {
            prefix,
            public_key,
            private_key,
            session_ttl,
            users,
            handlebars,
            secure,
        };

        let (stop_tx, stop_rx) = std::sync::mpsc::channel();

        ctrlc::set_handler(move || {
            let _ = stop_tx.send(());
        })
        .with_context(|| "Failed to set Ctrl+C handler")?;

        let server = tiny_http::Server::http(socker_addr)
            .map_err(|err| anyhow!("Failed to start server: {:#}", err))?;

        let server = std::sync::Arc::new(server);
        let server_handle = server.clone();

        let handle = std::thread::spawn(move || {
            for mut request in server.incoming_requests() {
                let url = request.url().to_owned();
                let host = request.remote_addr().to_owned();

                match handle_request(&mut request, &context) {
                    Ok(response) => {
                        let _ = request.respond(response);
                    }
                    Err(err) => {
                        log::error!("Request `{url}` from {host} has failed: {err}");
                        let _ = request.respond(tiny_http::Response::empty(500));
                    }
                }
            }
        });

        if stop_rx.recv().is_ok() {
            log::warn!("Received Ctrl+C signal, shutting down the server...");
        } else {
            log::error!("Stop signal channel was unexpectedly killed");
        }

        server_handle.unblock();
        if handle.join().is_err() {
            bail!("Server thread failed");
        }

        Ok(())
    }
}

fn handle_request(
    request: &mut tiny_http::Request,
    context: &Server,
) -> anyhow::Result<tiny_http::ResponseBox> {
    log::trace!("Processing request: {:?}", request);

    let uri: http::Uri = request
        .url()
        .parse()
        .with_context(|| "Failed to parse url")?;
    let mut path = uri.path().to_owned();
    if path.ends_with('/') {
        path.pop();
    }

    if !path.starts_with(&context.prefix) {
        return Ok(tiny_http::Response::empty(403).boxed());
    }

    // path with stripped prefix
    let path = path.split_off(context.prefix.len());
    let parts = path.split('/').collect::<Vec<_>>();
    if parts.len() != 2 {
        return Ok(tiny_http::Response::empty(403).boxed());
    }

    let (route, service) = (parts[0], parts[1]);

    match (route, request.method()) {
        ("auth", tiny_http::Method::Get) => {
            let response_code = if check_request_auth(request, service, &context.public_key) {
                log::trace!("Auth for service `{service}` successful");
                200 // OK
            } else {
                log::trace!("Auth for service `{service}` has failed");
                401 // Not authorized
            };

            Ok(tiny_http::Response::empty(response_code).boxed())
        }
        ("login", tiny_http::Method::Get) => {
            let data = match render_login_page(&context.handlebars, service, &context.prefix) {
                Ok(data) => data,
                Err(err) => {
                    log::error!("Failed to render login page: {err}");
                    return Ok(tiny_http::Response::empty(500).boxed());
                }
            };

            let header: tiny_http::Header = "Content-Type: text/html".parse().unwrap();
            Ok(tiny_http::Response::from_string(data)
                .with_header(header)
                .boxed())
        }
        ("login", tiny_http::Method::Post) => {
            log::trace!("Processing login request for service `{service}`");

            const BODY_SIZE_LIMIT: usize = 1024;
            let body_length = request.body_length().unwrap_or(0);
            if body_length == 0 || body_length > BODY_SIZE_LIMIT {
                log::trace!("Received request body have not acceptable size={body_length}");
                return Ok(tiny_http::Response::empty(400).boxed());
            }

            let mut body = String::new();
            match request.as_reader().read_to_string(&mut body) {
                Ok(_) => {}
                Err(err) => {
                    log::trace!("Failed to read request body: {err}");
                    return Ok(tiny_http::Response::empty(400).boxed());
                }
            }

            match serde_json::from_str(&body) {
                Ok(Credentials {
                    login,
                    password,
                    totp_key,
                }) => {
                    let user_id = UserId {
                        service: service.to_owned(),
                        login: login.clone(),
                    };

                    if let Some(user_info) = context.users.get(&user_id) {
                        let hashed_actual = hash_password(&password, &user_info.salt);
                        if hashed_actual != user_info.hash {
                            log::info!(
                                "Received invalid `{service}` service passord for user `{login}`"
                            );
                            return Ok(tiny_http::Response::empty(401).boxed());
                        }
                        if let Some(totp_secret) = &user_info.totp_key {
                            let totp_key = match totp_key {
                                Some(key) => key,
                                None => {
                                    log::info!(
                                        "Missing TOTP key for service `{service}` in login attempt for user `{login}`"
                                    );
                                    return Ok(tiny_http::Response::empty(401).boxed());
                                }
                            };

                            let now = (time::OffsetDateTime::now_utc()
                                - time::OffsetDateTime::UNIX_EPOCH)
                                .whole_seconds();
                            let expected_value = totp_lite::totp_custom::<totp_lite::Sha1>(
                                30,
                                6,
                                totp_secret,
                                now as u64,
                            );

                            if expected_value != totp_key {
                                log::trace!("Specified TOTP for service `{service}` in login attempt for user `{login}` is invalid");
                                return Ok(tiny_http::Response::empty(401).boxed());
                            }
                        }

                        let token = token::generate(
                            &login,
                            service,
                            &context.private_key,
                            context.session_ttl,
                        )
                        .with_context(|| "Failed to generate token")?;
                        let cookie =
                            make_token_cookie(service, &token, context.session_ttl, context.secure);
                        let header: tiny_http::Header =
                            format!("Set-Cookie: {cookie}").parse().unwrap();

                        log::info!(
                            "User `{login}` for service `{service}` authenticated successfully"
                        );

                        Ok(tiny_http::Response::empty(200).with_header(header).boxed())
                    } else {
                        log::trace!(
                            "Requested user `{login}` does not exist for `{service}` service"
                        );
                        Ok(tiny_http::Response::empty(401).boxed())
                    }
                }
                Err(_) => {
                    log::trace!("Failed to decode credentials for service `{service}`");
                    Ok(tiny_http::Response::empty(400).boxed())
                }
            }
        }
        ("logout", tiny_http::Method::Post) => {
            if check_request_auth(request, service, &context.public_key) {
                let cookie = make_killer_cookie(service, context.secure);
                let header: tiny_http::Header = format!("Set-Cookie: {cookie}").parse().unwrap();
                log::trace!("Logout for service `{service}` successful");
                Ok(tiny_http::Response::empty(200).with_header(header).boxed())
            } else {
                log::trace!("Logout for `{service}` has failed");
                Ok(tiny_http::Response::empty(401).boxed())
            }
        }
        ("static", tiny_http::Method::Get) => {
            let file = service;

            let (data, content_type) = match file {
                "pico.min.css" => (PICO_CSS, "text/css"),
                _ => {
                    log::trace!("Static file {file} not found");
                    return Ok(tiny_http::Response::empty(404).boxed());
                }
            };
            let header = format!("Content-Type: {content_type}")
                .parse::<tiny_http::Header>()
                .expect("BUG: Invalid header format");

            Ok(tiny_http::Response::from_string(data)
                .with_header(header)
                .boxed())
        }
        _ => {
            log::trace!("Route {path} not found");
            Ok(tiny_http::Response::empty(404).boxed())
        }
    }
}

fn cookie_name(service: &str) -> String {
    format!("ap-token-{service}")
}

fn check_request_auth(request: &tiny_http::Request, service: &str, jwt_key: &PublicKey) -> bool {
    request
        .headers()
        .iter()
        .filter_map(|header| {
            header
                .field
                .equiv("Cookie")
                .then(|| header.value.as_str())
                .and_then(|value| cookie_extract_service_token(value, service))
        })
        .any(|token| token::validate(&token, service, jwt_key).is_ok())
}

fn make_token_cookie(service: &str, token: &str, session_ttl: i64, secure: bool) -> String {
    use cookie::time::ext::NumericalDuration;

    cookie::CookieBuilder::new(cookie_name(service), token)
        .http_only(true)
        .same_site(cookie::SameSite::Strict)
        .secure(secure)
        .expires(cookie::time::OffsetDateTime::now_utc() + session_ttl.seconds())
        .path("/")
        .finish()
        .to_string()
}

fn make_killer_cookie(service: &str, secure: bool) -> String {
    cookie::CookieBuilder::new(cookie_name(service), "deleted")
        .http_only(true)
        .same_site(cookie::SameSite::Strict)
        .secure(secure)
        .expires(cookie::time::OffsetDateTime::UNIX_EPOCH)
        .path("/")
        .finish()
        .to_string()
}

fn cookie_extract_service_token(cookie: &str, service: &str) -> Option<String> {
    let cookie = cookie::Cookie::parse(cookie).ok()?;

    // Check for exact cookie name
    if cookie.name() != cookie_name(service) {
        return None;
    }

    // We don't interested in expiration date (already validated via jwt token), and other check
    // make no sense as cookie could be easily modified on the client side
    Some(cookie.value().to_owned())
}

fn render_login_page(
    handlebars: &handlebars::Handlebars,
    service: &str,
    prefix: &str,
) -> anyhow::Result<String> {
    handlebars
        .render(
            "login",
            &serde_json::json!({
                "AP_PREFIX": prefix,
                "AP_SERVICE": service,
            }),
        )
        .with_context(|| "Failed to render login template")
}
