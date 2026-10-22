//! Fake S3 HTTP test harness (port of upstream `fakes3_test.go`).
//!
//! A deliberately small S3-compatible stub: just enough surface for the
//! single-PUT flow, the multipart flow, GetObject, HeadObject, and
//! DeleteObject that this adapter uses — so the required unit tests never
//! need a live MinIO instance. It is a raw TCP HTTP/1.1 server (one request
//! per connection, `Connection: close`) because this crate takes no web
//! framework dependency.

use std::collections::HashMap;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

pub(crate) const TEST_BUCKET: &str = "central-artifacts";

#[derive(Debug, Clone)]
pub(crate) struct FakeRequest {
    pub method: String,
    pub path: String,
    /// Raw query pairs, decoded as `name=value`.
    pub query: HashMap<String, String>,
    pub headers: Vec<(String, String)>,
}

impl FakeRequest {
    pub(crate) fn header(&self, name: &str) -> Option<&str> {
        let wanted = name.to_ascii_lowercase();
        self.headers
            .iter()
            .find(|(n, _)| n.to_ascii_lowercase() == wanted)
            .map(|(_, v)| v.as_str())
    }

    pub(crate) fn query_has(&self, name: &str) -> bool {
        self.query.contains_key(name)
    }

    pub(crate) fn query_get(&self, name: &str) -> Option<&str> {
        self.query.get(name).map(String::as_str)
    }
}

#[derive(Clone)]
pub(crate) struct FakeObject {
    pub body: Vec<u8>,
    /// When > 0, overrides `body.len()` in Content-Length (fixture test).
    pub declared_size: i64,
    pub etag: String,
    pub version: String,
}

struct State {
    requests: Vec<FakeRequest>,
    objects: HashMap<String, FakeObject>,
    uploads: HashMap<String, HashMap<i32, Vec<u8>>>,
    part_sizes: Vec<usize>,
    next_id: i32,
    /// Forced status/code for the next single-PUT or complete request.
    complete_status: u16,
    complete_code: String,
    /// When true, GET delivers one byte then stalls until the client goes
    /// away (idle-watchdog test).
    block_get: bool,
}

pub(crate) struct FakeS3 {
    state: Mutex<State>,
    endpoint: String,
}

impl FakeS3 {
    pub(crate) fn new() -> Arc<Self> {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind fake s3");
        let port = listener.local_addr().expect("local addr").port();
        let fake = Arc::new(Self {
            state: Mutex::new(State {
                requests: Vec::new(),
                objects: HashMap::new(),
                uploads: HashMap::new(),
                part_sizes: Vec::new(),
                next_id: 0,
                complete_status: 0,
                complete_code: String::new(),
                block_get: false,
            }),
            endpoint: format!("127.0.0.1:{port}"),
        });
        let worker = Arc::clone(&fake);
        std::thread::Builder::new()
            .name("fakes3-accept".to_owned())
            .spawn(move || {
                loop {
                    match listener.accept() {
                        Ok((stream, _)) => {
                            let worker = Arc::clone(&worker);
                            let _ = std::thread::Builder::new()
                                .name("fakes3-conn".to_owned())
                                .spawn(move || handle_conn(stream, worker));
                        }
                        Err(_) => return,
                    }
                }
            })
            .expect("spawn fakes3 accept loop");
        fake
    }

    pub(crate) fn endpoint(&self) -> &str {
        &self.endpoint
    }

    pub(crate) fn recorded(&self) -> Vec<FakeRequest> {
        self.state.lock().expect("fakes3 state").requests.clone()
    }

    pub(crate) fn count_requests(&self, f: impl Fn(&FakeRequest) -> bool) -> usize {
        self.state
            .lock()
            .expect("fakes3 state")
            .requests
            .iter()
            .filter(|r| f(r))
            .count()
    }

    pub(crate) fn part_sizes(&self) -> Vec<usize> {
        self.state.lock().expect("fakes3 state").part_sizes.clone()
    }

    pub(crate) fn put_object(&self, key: &str, body: Vec<u8>) {
        self.state.lock().expect("fakes3 state").objects.insert(
            key.to_owned(),
            FakeObject {
                body,
                declared_size: 0,
                etag: fake_etag(key),
                version: format!("ver-{}", fake_etag(key)),
            },
        );
    }

    pub(crate) fn put_fixture_object(&self, key: &str, body: Vec<u8>, declared_size: i64) {
        self.state.lock().expect("fakes3 state").objects.insert(
            key.to_owned(),
            FakeObject {
                body,
                declared_size,
                etag: fake_etag(key),
                version: "fixture-v1".to_owned(),
            },
        );
    }

    pub(crate) fn object(&self, key: &str) -> Option<FakeObject> {
        self.state
            .lock()
            .expect("fakes3 state")
            .objects
            .get(key)
            .cloned()
    }

    /// Upstream `f.completeStatus`/`completeCode`: force the next PUT or
    /// complete response.
    pub(crate) fn force_complete(&self, status: u16, code: &str) {
        let mut state = self.state.lock().expect("fakes3 state");
        state.complete_status = status;
        state.complete_code = code.to_owned();
    }

    /// Upstream `f.blockGet`.
    pub(crate) fn block_get(&self, blocked: bool) {
        self.state.lock().expect("fakes3 state").block_get = blocked;
    }
}

fn fake_etag(seed: &str) -> String {
    let mut sum: u32 = 0;
    for c in seed.chars() {
        sum = sum.wrapping_mul(31).wrapping_add(c as u32);
    }
    format!("{sum:032x}")
}

/// Upstream `keyOf`: strips the leading `/<bucket>/` from a path-style
/// request.
fn key_of(path: &str) -> &str {
    let trimmed = path.trim_start_matches('/');
    match trimmed.find('/') {
        Some(i) => &trimmed[i + 1..],
        None => "",
    }
}

fn parse_query(raw: &str) -> HashMap<String, String> {
    let mut out = HashMap::new();
    for pair in raw.split('&') {
        if pair.is_empty() {
            continue;
        }
        match pair.split_once('=') {
            Some((k, v)) => {
                out.insert(k.to_owned(), v.to_owned());
            }
            None => {
                out.insert(pair.to_owned(), String::new());
            }
        }
    }
    out
}

// ---------------------------------------------------------------------------
// Minimal HTTP/1.1 framing
// ---------------------------------------------------------------------------

struct Request {
    method: String,
    path: String,
    query: HashMap<String, String>,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

fn header<'a>(headers: &'a [(String, String)], name: &str) -> Option<&'a str> {
    let wanted = name.to_ascii_lowercase();
    headers
        .iter()
        .find(|(n, _)| n.to_ascii_lowercase() == wanted)
        .map(|(_, v)| v.as_str())
}

fn read_line(reader: &mut BufReader<TcpStream>) -> Option<String> {
    let mut line = Vec::new();
    match reader.read_until(b'\n', &mut line) {
        Ok(0) | Err(_) => None,
        Ok(_) => Some(
            String::from_utf8_lossy(&line)
                .trim_end_matches(['\r', '\n'])
                .to_owned(),
        ),
    }
}

/// Reads one request; returns None on a clean or broken start.
fn read_request(reader: &mut BufReader<TcpStream>) -> Option<Request> {
    let request_line = read_line(reader)?;
    if request_line.is_empty() {
        return None;
    }
    let mut parts = request_line.split_whitespace();
    let method = parts.next().unwrap_or_default().to_owned();
    let target = parts.next().unwrap_or_default().to_owned();
    let (path, raw_query) = match target.split_once('?') {
        Some((p, q)) => (p.to_owned(), q),
        None => (target, ""),
    };

    let mut headers = Vec::new();
    loop {
        let line = read_line(reader)?;
        if line.is_empty() {
            break;
        }
        if let Some((name, value)) = line.split_once(':') {
            headers.push((name.trim().to_owned(), value.trim().to_owned()));
        }
    }

    let body = read_body(reader, &headers);
    Some(Request {
        method,
        path,
        query: parse_query(raw_query),
        headers,
        body,
    })
}

/// Reads the raw HTTP body (Content-Length or chunked), then decodes the
/// aws-chunked streaming-signature framing when present — upstream
/// `readRequestBody`.
fn read_body(reader: &mut BufReader<TcpStream>, headers: &[(String, String)]) -> Vec<u8> {
    let raw = if header(headers, "transfer-encoding")
        .map(|v| v.to_ascii_lowercase().contains("chunked"))
        .unwrap_or(false)
    {
        let mut out = Vec::new();
        while let Some(line) = read_line(reader) {
            let size = match usize::from_str_radix(line.trim(), 16) {
                Ok(s) => s,
                Err(_) => break,
            };
            if size == 0 {
                // Consume trailer lines until the blank terminator.
                while let Some(t) = read_line(reader) {
                    if t.is_empty() {
                        break;
                    }
                }
                break;
            }
            let mut chunk = vec![0u8; size];
            if reader.read_exact(&mut chunk).is_err() {
                break;
            }
            out.extend_from_slice(&chunk);
            let mut crlf = [0u8; 2];
            let _ = reader.read_exact(&mut crlf);
        }
        out
    } else if let Some(len) = header(headers, "content-length").and_then(|v| v.parse().ok()) {
        let mut buf = vec![0u8; len];
        let _ = reader.read_exact(&mut buf);
        buf
    } else {
        Vec::new()
    };

    let streaming = header(headers, "x-amz-content-sha256")
        .map(|v| v.starts_with("STREAMING-"))
        .unwrap_or(false);
    if !streaming {
        return raw;
    }
    // aws-chunk framing inside the HTTP body: `<hex>;chunk-signature=...\r\n`
    // `<data>\r\n`, terminated by a zero-length chunk.
    let mut out = Vec::new();
    let mut pos = 0usize;
    while pos < raw.len() {
        let Some(line_end) = raw[pos..]
            .windows(2)
            .position(|w| w == b"\r\n")
            .map(|i| pos + i)
        else {
            break;
        };
        let header_text = String::from_utf8_lossy(&raw[pos..line_end]);
        let size_hex = header_text.split(';').next().unwrap_or_default().trim();
        let Ok(size) = usize::from_str_radix(size_hex, 16) else {
            break;
        };
        if size == 0 {
            break;
        }
        let data_start = line_end + 2;
        if data_start + size > raw.len() {
            break;
        }
        out.extend_from_slice(&raw[data_start..data_start + size]);
        pos = data_start + size + 2; // trailing CRLF
    }
    out
}

fn respond(
    stream: &mut TcpStream,
    status: u16,
    reason: &str,
    headers: &[(&str, String)],
    body: &[u8],
) {
    let mut out = format!("HTTP/1.1 {status} {reason}\r\nconnection: close\r\n");
    for (name, value) in headers {
        out.push_str(&format!("{name}: {value}\r\n"));
    }
    out.push_str(&format!("content-length: {}\r\n\r\n", body.len()));
    let _ = stream.write_all(out.as_bytes());
    let _ = stream.write_all(body);
    let _ = stream.flush();
}

fn write_s3_error(stream: &mut TcpStream, status: u16, reason: &str, code: &str, key: &str) {
    // Deliberately embeds the bucket and key in Resource — exactly the
    // locator material the adapter must never let escape into a returned
    // error.
    let body = format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\
         <Error><Code>{code}</Code><Message>denied for {TEST_BUCKET}/{key}</Message>\
         <Resource>/{TEST_BUCKET}/{key}</Resource>\
         <RequestId>req-1</RequestId><HostId>host-1</HostId></Error>"
    );
    respond(
        stream,
        status,
        reason,
        &[("content-type", "application/xml".to_owned())],
        body.as_bytes(),
    );
}

fn reason_of(status: u16) -> &'static str {
    match status {
        200 => "OK",
        204 => "No Content",
        400 => "Bad Request",
        401 => "Unauthorized",
        403 => "Forbidden",
        404 => "Not Found",
        405 => "Method Not Allowed",
        409 => "Conflict",
        411 => "Length Required",
        412 => "Precondition Failed",
        413 => "Payload Too Large",
        500 => "Internal Server Error",
        _ => "Status",
    }
}

fn handle_conn(mut stream: TcpStream, fake: Arc<FakeS3>) {
    let _ = stream.set_read_timeout(Some(Duration::from_secs(15)));
    let _ = stream.set_write_timeout(Some(Duration::from_secs(15)));
    let _ = stream.set_nodelay(true);
    let mut reader = BufReader::new(stream.try_clone().expect("clone stream"));
    let Some(req) = read_request(&mut reader) else {
        return;
    };

    {
        let mut state = fake.state.lock().expect("fakes3 state");
        state.requests.push(FakeRequest {
            method: req.method.clone(),
            path: req.path.clone(),
            query: req.query.clone(),
            headers: req.headers.clone(),
        });
    }

    let key = key_of(&req.path).to_owned();
    let has_upload_id = req.query.get("uploadId").is_some_and(|v| !v.is_empty());
    let is_initiate = req.method == "POST" && req.query.contains_key("uploads");
    let is_part = req.method == "PUT" && has_upload_id;
    let is_complete = req.method == "POST" && has_upload_id && !is_initiate;
    let is_abort = req.method == "DELETE" && has_upload_id;

    if is_initiate {
        let upload_id = {
            let mut state = fake.state.lock().expect("fakes3 state");
            state.next_id += 1;
            let id = format!("upload-{}", state.next_id);
            state.uploads.insert(id.clone(), HashMap::new());
            id
        };
        let body = format!(
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\
             <InitiateMultipartUploadResult><Bucket>{TEST_BUCKET}</Bucket>\
             <Key>{key}</Key><UploadId>{upload_id}</UploadId></InitiateMultipartUploadResult>"
        );
        respond(
            &mut stream,
            200,
            "OK",
            &[("content-type", "application/xml".to_owned())],
            body.as_bytes(),
        );
        return;
    }

    if is_part {
        let part: i32 = req
            .query
            .get("partNumber")
            .and_then(|v| v.parse().ok())
            .unwrap_or_default();
        let id = req.query.get("uploadId").expect("uploadId").clone();
        {
            let mut state = fake.state.lock().expect("fakes3 state");
            state
                .uploads
                .entry(id.clone())
                .or_default()
                .insert(part, req.body.clone());
            state.part_sizes.push(req.body.len());
        }
        let etag = fake_etag(&format!("{id}{part}"));
        respond(
            &mut stream,
            200,
            "OK",
            &[("etag", format!("\"{etag}\""))],
            &[],
        );
        return;
    }

    if is_complete {
        let (forced_status, forced_code) = {
            let state = fake.state.lock().expect("fakes3 state");
            (state.complete_status, state.complete_code.clone())
        };
        if forced_status != 0 {
            write_s3_error(
                &mut stream,
                forced_status,
                reason_of(forced_status),
                &forced_code,
                &key,
            );
            return;
        }
        let id = req.query.get("uploadId").expect("uploadId").clone();
        let mut state = fake.state.lock().expect("fakes3 state");
        let parts = state.uploads.remove(&id).unwrap_or_default();
        let mut nums: Vec<i32> = parts.keys().copied().collect();
        nums.sort_unstable();
        let mut body = Vec::new();
        for n in nums {
            if let Some(p) = parts.get(&n) {
                body.extend_from_slice(p);
            }
        }
        state.objects.insert(
            key.clone(),
            FakeObject {
                body,
                declared_size: 0,
                etag: fake_etag(&key),
                version: format!("ver-{}", fake_etag(&key)),
            },
        );
        let out = format!(
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\
             <CompleteMultipartUploadResult><Bucket>{TEST_BUCKET}</Bucket>\
             <Key>{key}</Key><ETag>&#34;{}&#34;</ETag></CompleteMultipartUploadResult>",
            fake_etag(&key)
        );
        respond(
            &mut stream,
            200,
            "OK",
            &[
                ("content-type", "application/xml".to_owned()),
                ("x-amz-version-id", format!("ver-{}", fake_etag(&key))),
            ],
            out.as_bytes(),
        );
        return;
    }

    if is_abort {
        let id = req.query.get("uploadId").expect("uploadId").clone();
        fake.state.lock().expect("fakes3 state").uploads.remove(&id);
        respond(&mut stream, 204, "No Content", &[], &[]);
        return;
    }

    match req.method.as_str() {
        "PUT" => {
            let (forced_status, forced_code, exists) = {
                let state = fake.state.lock().expect("fakes3 state");
                (
                    state.complete_status,
                    state.complete_code.clone(),
                    state.objects.contains_key(&key),
                )
            };
            if forced_status != 0 {
                write_s3_error(
                    &mut stream,
                    forced_status,
                    reason_of(forced_status),
                    &forced_code,
                    &key,
                );
                return;
            }
            if header(&req.headers, "if-none-match") == Some("*") && exists {
                write_s3_error(
                    &mut stream,
                    412,
                    "Precondition Failed",
                    "PreconditionFailed",
                    &key,
                );
                return;
            }
            fake.state.lock().expect("fakes3 state").objects.insert(
                key.clone(),
                FakeObject {
                    body: req.body.clone(),
                    declared_size: 0,
                    etag: fake_etag(&key),
                    version: format!("ver-{}", fake_etag(&key)),
                },
            );
            respond(
                &mut stream,
                200,
                "OK",
                &[
                    ("etag", format!("\"{}\"", fake_etag(&key))),
                    ("x-amz-version-id", format!("ver-{}", fake_etag(&key))),
                ],
                &[],
            );
        }
        "HEAD" => {
            let obj = fake.object(&key);
            match obj {
                None => respond(&mut stream, 404, "Not Found", &[], &[]),
                Some(obj) => {
                    let size = if obj.declared_size > 0 {
                        obj.declared_size
                    } else {
                        obj.body.len() as i64
                    };
                    // Written by hand, not via `respond`: a HEAD response
                    // carries Content-Length with no body, and `respond`
                    // would append a second `content-length: 0`.
                    let mut head = "HTTP/1.1 200 OK\r\nconnection: close\r\n".to_owned();
                    for (name, value) in [
                        ("content-type", "application/octet-stream".to_owned()),
                        ("content-length", size.to_string()),
                        ("etag", format!("\"{}\"", obj.etag)),
                        ("x-amz-version-id", obj.version.clone()),
                        ("accept-ranges", "bytes".to_owned()),
                    ] {
                        head.push_str(&format!("{name}: {value}\r\n"));
                    }
                    head.push_str("\r\n");
                    let _ = stream.write_all(head.as_bytes());
                    let _ = stream.flush();
                }
            }
        }
        "GET" => {
            let (obj, block) = {
                let state = fake.state.lock().expect("fakes3 state");
                (state.objects.get(&key).cloned(), state.block_get)
            };
            match obj {
                None => write_s3_error(&mut stream, 404, "Not Found", "NoSuchKey", &key),
                Some(obj) => {
                    let size = if obj.declared_size > 0 {
                        obj.declared_size
                    } else {
                        obj.body.len() as i64
                    };
                    let mut head = "HTTP/1.1 200 OK\r\nconnection: close\r\n".to_owned();
                    for (name, value) in [
                        ("content-type", "application/octet-stream".to_owned()),
                        ("content-length", size.to_string()),
                        ("etag", format!("\"{}\"", obj.etag)),
                        ("x-amz-version-id", obj.version.clone()),
                        ("accept-ranges", "bytes".to_owned()),
                    ] {
                        head.push_str(&format!("{name}: {value}\r\n"));
                    }
                    head.push_str("\r\n");
                    let _ = stream.write_all(head.as_bytes());
                    let _ = stream.flush();
                    if block && !obj.body.is_empty() {
                        let _ = stream.write_all(&obj.body[..1]);
                        let _ = stream.flush();
                        // Wait for the client-side watchdog to drop the
                        // connection (upstream waits on r.Context().Done()).
                        let wait_started = Instant::now();
                        let mut peek = [0u8; 1];
                        loop {
                            match stream.peek(&mut peek) {
                                Ok(0) => return, // client closed
                                Ok(_) => return, // unexpected data
                                Err(e)
                                    if e.kind() == std::io::ErrorKind::WouldBlock
                                        || e.kind() == std::io::ErrorKind::TimedOut => {}
                                Err(_) => return,
                            }
                            if wait_started.elapsed() > Duration::from_secs(10) {
                                return;
                            }
                            std::thread::sleep(Duration::from_millis(10));
                        }
                    }
                    let _ = stream.write_all(&obj.body);
                    let _ = stream.flush();
                }
            }
        }
        "DELETE" => {
            fake.state
                .lock()
                .expect("fakes3 state")
                .objects
                .remove(&key);
            respond(&mut stream, 204, "No Content", &[], &[]);
        }
        _ => {
            write_s3_error(&mut stream, 400, "Bad Request", "MethodNotAllowed", &key);
        }
    }
}
