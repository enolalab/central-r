//! `pgxPostgresSuperuserSyncer`'s transport — the smallest honest
//! PostgreSQL wire client the superuser credential store drives:
//! startup → SASL `SCRAM-SHA-256` → `ReadyForQuery` → one simple
//! query → terminate.
//!
//! Upstream reaches for pgx because Go already depends on it; the
//! Rust workspace deliberately keeps `sqlx` scoped to
//! `central-adapter-postgres` (boundary doc §1's dependency matrix),
//! so this module implements exactly the protocol surface the two
//! operations need — cleartext never crosses this socket, no driver
//! feature beyond `AuthenticationSASL`/`AuthenticationOk`/simple
//! query is honored, and every message is length-checked before it
//! is trusted.
//!
//! Fixed endpoint: the compose policy's pinned loopback published
//! port (`127.0.0.1:55432`, upstream `productionPostgresLoopbackHostPort`),
//! database `central`, role `central`.

use std::io::{Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::time::{Duration, Instant};

use central_foundation::failure::Failure;
use hmac::{Hmac, KeyInit, Mac};
use sha2::{Digest, Sha256};

use crate::broker::wire::{b64_decode, b64_encode, b64_raw_encode};

/// `productionPostgresLoopbackHostPort`.
const POSTGRES_LOOPBACK_HOST_PORT: &str = "127.0.0.1:55432";
/// The startup packet's user/database pair (fixed, not caller-chosen).
const POSTGRES_USER: &str = "central";
const POSTGRES_DATABASE: &str = "central";
/// pgx's `connect_timeout=5` dial bound.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
/// pgx's `context.WithTimeout(ctx, 10*time.Second)` whole-exchange bound.
const EXCHANGE_TIMEOUT: Duration = Duration::from_secs(10);
/// PostgreSQL rejects absurd message sizes; 1 MiB is far above the
/// largest frame this exchange can legitimately produce.
const MAX_MESSAGE_BYTES: usize = 1 << 20;

type HmacSha256 = Hmac<Sha256>;

fn unavailable(msg: &str) -> Failure {
    Failure::denied("pg_wire", msg.to_owned())
}

fn hmac_sha256(key: &[u8], data: &[u8]) -> [u8; 32] {
    // HMAC accepts keys of any length; construction cannot fail.
    let mut mac = <HmacSha256 as KeyInit>::new_from_slice(key)
        .unwrap_or_else(|_| unreachable!("hmac accepts any key length"));
    mac.update(data);
    let out = mac.finalize().into_bytes();
    let mut result = [0u8; 32];
    result.copy_from_slice(&out);
    result
}

/// `Hi(str, salt, i)` — RFC 5802's PBKDF2-HMAC-SHA256 with a single
/// block (the output is exactly one SHA-256 block).
fn salted_password(password: &str, salt: &[u8], iterations: u32) -> [u8; 32] {
    let mut block = salt.to_vec();
    block.extend_from_slice(&1u32.to_be_bytes());
    let mut u = hmac_sha256(password.as_bytes(), &block);
    let mut result = u;
    let mut count = 1u32;
    while count < iterations {
        u = hmac_sha256(password.as_bytes(), &u);
        for (r, x) in result.iter_mut().zip(u.iter()) {
            *r ^= x;
        }
        count += 1;
    }
    result
}

/// One received backend message: type byte + payload.
struct Message {
    kind: u8,
    payload: Vec<u8>,
}

/// `pgx.Conn` — the authenticated connection. `Drop` sends the `X`
/// terminate so the server reaps its backend promptly.
struct PgConn {
    stream: TcpStream,
    deadline: Instant,
}

impl PgConn {
    fn read_message(&mut self) -> Result<Message, Failure> {
        if Instant::now() >= self.deadline {
            return Err(unavailable("postgres wire: exchange deadline exceeded"));
        }
        let mut head = [0u8; 5];
        self.stream
            .read_exact(&mut head)
            .map_err(|_| unavailable("postgres wire: read failed"))?;
        let len = u32::from_be_bytes([head[1], head[2], head[3], head[4]]) as usize;
        // `len` counts its own 4 bytes but not the type byte.
        if !(4..=MAX_MESSAGE_BYTES + 4).contains(&len) {
            return Err(unavailable("postgres wire: malformed message"));
        }
        let mut payload = vec![0u8; len - 4];
        self.stream
            .read_exact(&mut payload)
            .map_err(|_| unavailable("postgres wire: read failed"))?;
        Ok(Message {
            kind: head[0],
            payload,
        })
    }

    fn write_message(&mut self, kind: u8, payload: &[u8]) -> Result<(), Failure> {
        let len = u32::try_from(payload.len() + 4)
            .map_err(|_| unavailable("postgres wire: oversized message"))?;
        let mut frame = Vec::with_capacity(payload.len() + 5);
        frame.push(kind);
        frame.extend_from_slice(&len.to_be_bytes());
        frame.extend_from_slice(payload);
        self.stream
            .write_all(&frame)
            .map_err(|_| unavailable("postgres wire: write failed"))
    }

    /// Reads until `ReadyForQuery`, refusing `ErrorResponse` and any
    /// unexpected message. Parameter/notice/row/complete frames are
    /// consumed and ignored — this client issues only `ALTER ROLE`
    /// and the empty ping query, whose outcomes are
    /// `CommandComplete`/`EmptyQueryResponse`.
    fn wait_ready(&mut self) -> Result<(), Failure> {
        loop {
            let msg = self.read_message()?;
            match msg.kind {
                b'Z' => return Ok(()),
                b'E' => return Err(unavailable("postgres wire: server refused")),
                b'S' | b'K' | b'N' | b'C' | b'T' | b'D' | b'I' => {}
                _ => return Err(unavailable("postgres wire: unexpected backend message")),
            }
        }
    }

    fn send_startup(&mut self) -> Result<(), Failure> {
        let mut body = Vec::with_capacity(64);
        body.extend_from_slice(&196608u32.to_be_bytes()); // protocol 3.0
        body.extend_from_slice(b"user\0");
        body.extend_from_slice(POSTGRES_USER.as_bytes());
        body.push(0);
        body.extend_from_slice(b"database\0");
        body.extend_from_slice(POSTGRES_DATABASE.as_bytes());
        body.push(0);
        body.push(0);
        let len = u32::try_from(body.len() + 4)
            .map_err(|_| unavailable("postgres wire: oversized message"))?;
        let mut frame = Vec::with_capacity(body.len() + 4);
        frame.extend_from_slice(&len.to_be_bytes());
        frame.extend_from_slice(&body);
        self.stream
            .write_all(&frame)
            .map_err(|_| unavailable("postgres wire: write failed"))
    }

    /// `p` message for password-family responses (cleartext, SASL
    /// initial, SASL response).
    fn send_password_frame(&mut self, payload: &[u8]) -> Result<(), Failure> {
        self.write_message(b'p', payload)
    }

    /// Drives the authentication exchange to `AuthenticationOk`, then
    /// to `ReadyForQuery`.
    fn authenticate(&mut self, password: &str) -> Result<(), Failure> {
        let mut scram: Option<ScramExchange> = None;
        loop {
            let msg = self.read_message()?;
            match msg.kind {
                b'E' => return Err(unavailable("postgres wire: server refused")),
                b'R' => {
                    if msg.payload.len() < 4 {
                        return Err(unavailable("postgres wire: malformed auth request"));
                    }
                    let code = u32::from_be_bytes(msg.payload[..4].try_into().unwrap_or([0; 4]));
                    match code {
                        0 => return self.wait_ready(), // AuthenticationOk
                        5 => {
                            // Cleartext — the protocol permits it and
                            // upstream's pgx accepts it too; the compose
                            // postgres only ever offers SCRAM-SHA-256,
                            // but the refusal set is the protocol's,
                            // not the deployment's.
                            let mut body = password.as_bytes().to_vec();
                            body.push(0);
                            self.send_password_frame(&body)?;
                        }
                        10 => {
                            // AuthenticationSASL — mechanism list after
                            // the code; must contain SCRAM-SHA-256.
                            let mechanisms = parse_cstring_list(&msg.payload[4..]);
                            if !mechanisms.iter().any(|m| m == "SCRAM-SHA-256") {
                                return Err(unavailable("postgres wire: no SASL mechanism"));
                            }
                            let exchange = ScramExchange::start(password)?;
                            let mut body = b"SCRAM-SHA-256\0".to_vec();
                            let initial = exchange.client_first.as_bytes();
                            body.extend_from_slice(
                                &i32::try_from(initial.len())
                                    .map_err(|_| unavailable("postgres wire: oversized"))?
                                    .to_be_bytes(),
                            );
                            body.extend_from_slice(initial);
                            self.send_password_frame(&body)?;
                            scram = Some(exchange);
                        }
                        11 => {
                            // AuthenticationSASLContinue — server-first.
                            let Some(exchange) = scram.as_mut() else {
                                return Err(unavailable("postgres wire: auth out of order"));
                            };
                            let response = exchange.respond_to(&msg.payload)?;
                            self.send_password_frame(response.as_bytes())?;
                        }
                        12 => {
                            // AuthenticationSASLFinal — verify the
                            // server signature before trusting the
                            // AuthenticationOk that follows.
                            let Some(exchange) = scram.take() else {
                                return Err(unavailable("postgres wire: auth out of order"));
                            };
                            exchange.verify_final(&msg.payload)?;
                        }
                        _ => return Err(unavailable("postgres wire: unsupported auth request")),
                    }
                }
                _ => return Err(unavailable("postgres wire: unexpected backend message")),
            }
        }
    }
}

impl Drop for PgConn {
    fn drop(&mut self) {
        // `X` Terminate — best-effort; a failed write still closes.
        let _ = self.write_message(b'X', &[]);
    }
}

fn parse_cstring_list(raw: &[u8]) -> Vec<String> {
    raw.split(|b| *b == 0)
        .filter(|s| !s.is_empty())
        .map(|s| String::from_utf8_lossy(s).into_owned())
        .collect()
}

/// One `key=value` attribute out of a SASL message's comma list.
fn sasl_attribute<'a>(message: &'a str, key: &str) -> Option<&'a str> {
    for part in message.split(',') {
        if let Some(value) = part.strip_prefix(key) {
            return Some(value);
        }
    }
    None
}

/// The in-flight SCRAM-SHA-256 exchange.
struct ScramExchange {
    password: String,
    client_first: String,
    client_nonce: String,
    client_first_bare: String,
    expected_server_signature: Option<[u8; 32]>,
}

impl ScramExchange {
    fn start(password: &str) -> Result<Self, Failure> {
        let mut raw = [0u8; 18];
        rustix::rand::getrandom(&mut raw, rustix::rand::GetRandomFlags::empty())
            .map_err(|_| unavailable("postgres wire: nonce unavailable"))?;
        let client_nonce = b64_raw_encode(&raw);
        let client_first_bare = format!("n=,r={client_nonce}");
        Ok(Self {
            password: password.to_owned(),
            client_first: format!("n,,{client_first_bare}"),
            client_nonce,
            client_first_bare,
            expected_server_signature: None,
        })
    }

    /// Replies to the `AuthenticationSASLContinue` server-first
    /// message and returns the `client-final-message`.
    fn respond_to(&mut self, server_first_raw: &[u8]) -> Result<String, Failure> {
        let server_first = String::from_utf8_lossy(server_first_raw).into_owned();
        let nonce = sasl_attribute(&server_first, "r=").unwrap_or("");
        let salt_b64 = sasl_attribute(&server_first, "s=").unwrap_or("");
        let iterations: u32 = sasl_attribute(&server_first, "i=")
            .and_then(|v| v.parse().ok())
            .unwrap_or(0);
        if nonce.is_empty()
            || !nonce.starts_with(self.client_nonce.as_str())
            || salt_b64.is_empty()
            || iterations == 0
        {
            return Err(unavailable("postgres wire: malformed server-first"));
        }
        let Some(salt) = b64_decode(salt_b64) else {
            return Err(unavailable("postgres wire: malformed server-first"));
        };
        let salted = salted_password(&self.password, &salt, iterations);
        let client_key = hmac_sha256(&salted, b"Client Key");
        let stored_key: [u8; 32] = Sha256::digest(client_key).into();
        let without_proof = format!("c=biws,r={nonce}");
        let auth_message = format!(
            "{},{},{}",
            self.client_first_bare, server_first, without_proof
        );
        let client_signature = hmac_sha256(&stored_key, auth_message.as_bytes());
        let mut proof = [0u8; 32];
        for (p, (k, s)) in proof
            .iter_mut()
            .zip(client_key.iter().zip(client_signature.iter()))
        {
            *p = k ^ s;
        }
        let server_key = hmac_sha256(&salted, b"Server Key");
        self.expected_server_signature = Some(hmac_sha256(&server_key, auth_message.as_bytes()));
        Ok(format!("{without_proof},p={}", b64_encode(&proof)))
    }

    /// Verifies `v=<b64 ServerSignature>` from `AuthenticationSASLFinal`.
    fn verify_final(&self, server_final_raw: &[u8]) -> Result<(), Failure> {
        let server_final = String::from_utf8_lossy(server_final_raw);
        let Some(value) = server_final.strip_prefix("v=") else {
            return Err(unavailable("postgres wire: malformed server-final"));
        };
        // The final message may carry channel-binding extensions the
        // server appends after `v=`; only the verifier field is read.
        let verifier = value.split(',').next().unwrap_or("");
        let Some(signature) = b64_decode(verifier) else {
            return Err(unavailable("postgres wire: malformed server-final"));
        };
        let Some(expected) = self.expected_server_signature else {
            return Err(unavailable("postgres wire: auth out of order"));
        };
        if signature.as_slice() != expected.as_slice() {
            return Err(unavailable("postgres wire: server signature mismatch"));
        }
        Ok(())
    }
}

/// `pgxPostgresSuperuserSyncer.connect` — dial, startup,
/// authenticate, ready.
fn connect(password: &str) -> Result<PgConn, Failure> {
    let addr = POSTGRES_LOOPBACK_HOST_PORT
        .to_socket_addrs()
        .ok()
        .and_then(|mut addrs| addrs.find(|a| a.is_ipv4()))
        .unwrap_or_else(|| {
            "127.0.0.1:55432"
                .parse()
                .unwrap_or_else(|_| std::net::SocketAddr::from(([127, 0, 0, 1], 55432)))
        });
    let stream = TcpStream::connect_timeout(&addr, CONNECT_TIMEOUT)
        .map_err(|_| unavailable("postgres wire: dial failed"))?;
    let deadline = Instant::now() + EXCHANGE_TIMEOUT;
    stream
        .set_read_timeout(Some(EXCHANGE_TIMEOUT))
        .and_then(|()| stream.set_write_timeout(Some(EXCHANGE_TIMEOUT)))
        .and_then(|()| stream.set_nodelay(true))
        .map_err(|_| unavailable("postgres wire: dial failed"))?;
    let mut conn = PgConn { stream, deadline };
    conn.send_startup()?;
    conn.authenticate(password)?;
    Ok(conn)
}

/// `pgxPostgresSuperuserSyncer` — the live-server seam
/// `RotateForOperation` drives: `verify` proves a password currently
/// authenticates the `central` role; `alter` authenticates with
/// `auth_password` and sets `new_password`.
pub(crate) struct PostgresSuperuserSyncer;

impl PostgresSuperuserSyncer {
    pub(crate) fn new() -> Self {
        Self
    }

    /// `Verify` — connect + the empty ping query upstream's
    /// `conn.Ping` sends (the server answers `EmptyQueryResponse`).
    pub(crate) fn verify(&self, password: &str) -> Result<(), Failure> {
        let mut conn = connect(password)?;
        conn.write_message(b'Q', b"\0")?;
        conn.wait_ready()
    }

    /// `Alter` — `ALTER ROLE` cannot take a bind parameter for the
    /// password; the caller's minted alphabet is closed
    /// (`valid_postgres_superuser_password`), so the single-quoted
    /// literal cannot escape — upstream's exact reasoning.
    pub(crate) fn alter(&self, auth_password: &str, new_password: &str) -> Result<(), Failure> {
        if !valid_postgres_superuser_password(new_password) {
            return Err(unavailable(
                "postgres superuser credential: refusing to set a malformed password",
            ));
        }
        let mut conn = connect(auth_password)?;
        let mut sql =
            format!("ALTER ROLE {POSTGRES_USER} WITH PASSWORD '{new_password}'").into_bytes();
        sql.push(0);
        conn.write_message(b'Q', &sql)?;
        conn.wait_ready()
    }
}

/// `validPostgresSuperuserPassword` — the exact shape this store
/// mints (`base64.RawURLEncoding` of 32 bytes): 43 characters of
/// `[A-Za-z0-9_-]`.
pub(crate) fn valid_postgres_superuser_password(value: &str) -> bool {
    value.len() == 43
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

#[cfg(test)]
mod tests {
    use super::*;

    /// RFC 7677's SCRAM-SHA-256 example exchange values (password
    /// `pencil`, the RFC's fixed nonces/salt/iterations).
    #[test]
    fn scram_rfc7677_vector() {
        let mut exchange = ScramExchange {
            password: "pencil".to_owned(),
            client_first: "n,,n=user,r=rOprNGfwEbeRWgbNEkqO".to_owned(),
            client_nonce: "rOprNGfwEbeRWgbNEkqO".to_owned(),
            client_first_bare: "n=user,r=rOprNGfwEbeRWgbNEkqO".to_owned(),
            expected_server_signature: None,
        };
        let server_first = "r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0,s=W22ZaJ0SNY7soEsUEjb6gQ==,i=4096";
        let client_final = exchange.respond_to(server_first.as_bytes()).unwrap();
        assert_eq!(
            client_final,
            "c=biws,r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0,p=dHzbZapWIk4jUhN+Ute9ytag9zjfMHgsqmmiz7AndVQ="
        );
        exchange
            .verify_final(b"v=6rriTRBi23WpRR/wtup+mMhUZUn/dB5nLTJRsjl95G4=")
            .unwrap();
    }

    #[test]
    fn password_shape_is_closed() {
        assert!(valid_postgres_superuser_password(
            "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQ"
        ));
        assert!(!valid_postgres_superuser_password("short"));
        assert!(!valid_postgres_superuser_password(
            "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOP+"
        ));
        assert!(!valid_postgres_superuser_password(
            "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOP'"
        ));
    }
}
