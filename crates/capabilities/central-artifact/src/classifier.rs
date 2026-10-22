//! Bounded content classification for the required-report Artifact class —
//! the port of `central/internal/artifact/app/classifier.go`.
//!
//! [`ReportClassifier`] is the production implementation of
//! [`port::Classifier`]. Three properties matter and are all deliberate:
//!
//! - It is bounded. It reads at most [`CLASSIFY_PREFIX_BYTES`] of the
//!   already-staged body, because classification is a policy decision over
//!   representative content, not a second full-body scan. The size and
//!   checksum are already recomputed from the full body by the
//!   verification step.
//! - It treats the declared media type as a hint only. The decision is made
//!   from the bytes that landed.
//! - Its output is sanitized by construction. [`ClassifyResult`] carries a
//!   detected media type and a closed rejection code and nothing else: no
//!   matched substring, no offset, no excerpt. A secret that was detected is
//!   never echoed back in the evidence that says it was detected.

use std::io::Read;

use central_foundation::failure::Failure;

use crate::domain::{FAILURE_CODE_SECRET_DISCLOSURE, FAILURE_CODE_UNSUPPORTED_MEDIA_TYPE};
use crate::port::{Classifier, ClassifyRequest, ClassifyResult};

/// The bounded content classifier for the required-report Artifact class
/// (upstream `ReportClassifier`).
#[derive(Debug, Default, Clone, Copy)]
pub struct ReportClassifier;

impl ReportClassifier {
    /// Constructs the stateless classifier.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
}

/// The bounded classification window. A 1 MiB default report is fully
/// covered; a larger one is judged on a representative prefix.
pub const CLASSIFY_PREFIX_BYTES: usize = 1 << 20;

/// The detected media type for a body carrying structural Markdown markers.
pub const MEDIA_TYPE_MARKDOWN: &str = "text/markdown";
/// The detected media type for accepted plain text (upstream
/// `mediaTypePlain`).
pub const MEDIA_TYPE_PLAIN: &str = "text/plain";
/// The detected media type for a body that is not valid report text —
/// upstream's `mediaTypeBinary`; it is also the content-policy download
/// fallback.
pub const MEDIA_TYPE_OCTET_STREAM: &str = "application/octet-stream";

impl Classifier for ReportClassifier {
    /// Applies the content policy to a staged body (upstream
    /// `ReportClassifier.Classify`).
    ///
    /// The secret-disclosure decision comes first and is unconditional: it
    /// applies whatever the content turns out to be, so an unsupported
    /// media type can never mask a disclosed credential.
    async fn classify(&self, request: ClassifyRequest) -> Result<ClassifyResult, Failure> {
        // `io::Read::take` bounds the read exactly like upstream's
        // `io.LimitReader(req.Body, ClassifyPrefixBytes)`.
        let mut prefix = Vec::new();
        request
            .body
            .take(CLASSIFY_PREFIX_BYTES as u64)
            .read_to_end(&mut prefix)
            .map_err(|_| {
                Failure::unavailable(
                    "ARTIFACT_CLASSIFY_READ_FAILED",
                    "the staged body could not be read for classification",
                )
            })?;

        if contains_secret_disclosure(&prefix) {
            return Ok(ClassifyResult {
                detected_media_type: detect_media_type(&prefix).to_owned(),
                secret_disclosure: true,
                rejection_code: FAILURE_CODE_SECRET_DISCLOSURE.to_owned(),
            });
        }

        let detected = detect_media_type(&prefix);
        if detected == MEDIA_TYPE_OCTET_STREAM {
            return Ok(ClassifyResult {
                detected_media_type: detected.to_owned(),
                secret_disclosure: false,
                rejection_code: FAILURE_CODE_UNSUPPORTED_MEDIA_TYPE.to_owned(),
            });
        }
        Ok(ClassifyResult {
            detected_media_type: detected.to_owned(),
            secret_disclosure: false,
            rejection_code: String::new(),
        })
    }
}

/// Sniffs the bounded prefix (upstream `detectMediaType`). A body carrying a
/// NUL byte, or one that is not valid UTF-8, is not a Markdown report
/// whatever it declared.
fn detect_media_type(prefix: &[u8]) -> &'static str {
    if prefix.is_empty() {
        return MEDIA_TYPE_PLAIN;
    }
    if prefix.contains(&0x00) {
        return MEDIA_TYPE_OCTET_STREAM;
    }
    // A truncated final rune at the window boundary is expected and must not
    // be read as a binary body, so the check tolerates one incomplete rune.
    let scan = if prefix.len() == CLASSIFY_PREFIX_BYTES {
        trim_partial_rune(prefix)
    } else {
        prefix
    };
    if std::str::from_utf8(scan).is_err() {
        return MEDIA_TYPE_OCTET_STREAM;
    }
    if looks_markdown(scan) {
        return MEDIA_TYPE_MARKDOWN;
    }
    MEDIA_TYPE_PLAIN
}

/// Drops a trailing incomplete UTF-8 sequence (upstream
/// `trimPartialRune`). Upstream tries successively shorter candidates — at
/// most `utf8.UTFMax` (4) — and keeps the first whose *last* rune decodes
/// legally; a rune error anywhere earlier in the candidate does not count
/// because `utf8.Valid` re-checks the whole scan afterwards.
fn trim_partial_rune(b: &[u8]) -> &[u8] {
    for i in 0..4usize.min(b.len()) {
        let candidate = &b[..b.len() - i];
        if last_rune_decodes(candidate) {
            return candidate;
        }
    }
    b
}

/// Whether `candidate`'s final UTF-8 sequence decodes legally — the
/// `DecodeLastRune` half of upstream's `r != utf8.RuneError || size > 1`
/// test. An empty candidate reports `false`, matching
/// `DecodeLastRune`'s `RuneError` result on empty input.
fn last_rune_decodes(candidate: &[u8]) -> bool {
    let Some((&last, _)) = candidate.split_last() else {
        return false;
    };
    if last < 0x80 {
        // A terminal ASCII byte is always a complete rune.
        return true;
    }
    // Walk back over continuation bytes to the sequence's lead byte; a
    // rune is at most 4 bytes, so no more than 3 continuation bytes can
    // belong to it. A run of 4+ continuation bytes is itself invalid.
    let mut start = candidate.len() - 1;
    while start > 0 && (candidate[start] & 0xC0) == 0x80 {
        start -= 1;
        if candidate.len() - start > 4 {
            return false;
        }
    }
    std::str::from_utf8(&candidate[start..]).is_ok()
}

/// The structural markers that distinguish a Markdown report from arbitrary
/// plain text (upstream `markdownMarkers`). Their presence is a positive
/// signal only: plain text is accepted too, so a false negative costs
/// nothing.
const MARKDOWN_MARKERS: [&[u8]; 10] = [
    b"# ", b"## ", b"### ", b"\n- ", b"\n* ", b"\n1. ", b"```", b"](", b"**", b"\n> ",
];

/// Reports whether the body contains at least one Markdown structural
/// marker (upstream `looksMarkdown`).
fn looks_markdown(body: &[u8]) -> bool {
    MARKDOWN_MARKERS
        .iter()
        .any(|marker| contains_subslice(body, marker))
}

/// Normalizes a media-type token for comparison: trims ASCII whitespace
/// and folds ASCII case. Upstream has no named equivalent — the port
/// carries it because durable `detected_media_type` evidence is compared
/// against lowercase allowlist constants by the delivery path, and a
/// stored `Text/Markdown` must not silently fall out of the allowlist.
pub(crate) fn normalize_media_type(raw: &str) -> String {
    raw.trim().to_ascii_lowercase()
}

/// Reports whether `needle` occurs anywhere in `haystack` — the
/// `bytes.Contains` equivalent these byte-oriented heuristics use.
fn contains_subslice(haystack: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty()
        && haystack.len() >= needle.len()
        && haystack
            .windows(needle.len())
            .any(|window| window == needle)
}

/// Finds the first occurrence of `needle` in `haystack` at or after
/// `from`, returning its absolute index (`bytes.Index(haystack[from:], needle)`
/// folded back into absolute coordinates).
fn find_subslice(haystack: &[u8], needle: &[u8], from: usize) -> Option<usize> {
    if needle.is_empty() || from >= haystack.len() || haystack.len() - from < needle.len() {
        return None;
    }
    haystack[from..]
        .windows(needle.len())
        .position(|window| window == needle)
        .map(|position| position + from)
}

/// Unambiguous credential-bearing literals (upstream
/// `literalSecretMarkers`). Each one is a fixed string that has no
/// innocent meaning inside a report.
const LITERAL_SECRET_MARKERS: [&[u8]; 12] = [
    // PEM private key blocks of every common flavour.
    b"-----BEGIN PRIVATE KEY-----",
    b"-----BEGIN RSA PRIVATE KEY-----",
    b"-----BEGIN EC PRIVATE KEY-----",
    b"-----BEGIN DSA PRIVATE KEY-----",
    b"-----BEGIN OPENSSH PRIVATE KEY-----",
    b"-----BEGIN PGP PRIVATE KEY BLOCK-----",
    b"-----BEGIN ENCRYPTED PRIVATE KEY-----",
    // Credential-bearing environment names. Their presence in a report
    // body means a secret-carrying variable was rendered rather than
    // referenced.
    b"AWS_SECRET_ACCESS_KEY=",
    b"MINIO_ROOT_PASSWORD=",
    b"POSTGRES_PASSWORD=",
    b"OPENAI_API_KEY=",
    b"ANTHROPIC_API_KEY=",
];

/// Provider token prefixes (upstream `tokenSecretPrefixes`). A prefix alone
/// is not a finding: `"sk-"` appears in ordinary prose and package names. A
/// finding requires the prefix to be followed by a run of at least
/// [`MIN_TOKEN_BODY_BYTES`] token characters, which is what an actual key
/// looks like.
const TOKEN_SECRET_PREFIXES: [&[u8]; 10] = [
    b"sk-ant-",     // Anthropic-style secret key
    b"sk-",         // OpenAI-style secret key
    b"AKIA",        // AWS access key id
    b"ASIA",        // AWS temporary access key id
    b"xoxb-",       // Slack bot token
    b"xoxp-",       // Slack user token
    b"ghp_",        // GitHub personal access token
    b"gho_",        // GitHub OAuth token
    b"github_pat_", // GitHub fine-grained token
    b"glpat-",      // GitLab personal access token
];

/// The shortest *unbroken alphanumeric* key segment this classifier treats
/// as a credential (upstream `minTokenBodyBytes`). It is set at 16 because
/// every prefix above is followed by at least that much entropy in
/// practice, while ordinary prose is not.
///
/// Counting only alphanumeric characters is load-bearing. An earlier
/// version counted `-` and `_` toward the run, which made every long
/// hyphenated slug beginning with a provider prefix —
/// `"sk-nearest-neighbour-baseline-variant"`, a documentation URL segment
/// such as `"sk-provisioning-and-rotation-guide"` — satisfy the threshold
/// and produce a terminal `SECRET_DISCLOSURE` on a perfectly legitimate
/// report. Since that code is terminal and also drives revoke/rotate
/// operator guidance, a false positive destroyed a required report and
/// raised a false credential-compromise alert.
const MIN_TOKEN_BODY_BYTES: usize = 16;

/// Reports whether the bounded prefix carries a suspected credential
/// (upstream `containsSecretDisclosure`). It returns only the boolean: the
/// caller records a closed rejection code and safe revoke/rotate guidance,
/// never the match.
fn contains_secret_disclosure(prefix: &[u8]) -> bool {
    for marker in LITERAL_SECRET_MARKERS {
        if contains_subslice(prefix, marker) {
            return true;
        }
    }
    for token_prefix in TOKEN_SECRET_PREFIXES {
        if has_token_after_prefix(prefix, token_prefix) {
            return true;
        }
    }
    // A connection string is a finding only when it actually carries a
    // password, i.e. "scheme://user:secret@host". A bare "postgres://host"
    // discloses nothing and is common in legitimate documentation.
    contains_credentialed_url(prefix)
}

/// Reports whether any occurrence of `token_prefix` begins a word and is
/// followed by a key-shaped body (upstream `hasTokenAfterPrefix`).
///
/// Two conditions must both hold, and each one exists to kill a distinct
/// class of false positive:
///
/// - The prefix must start at a word boundary. `"AKIA"` appearing in the
///   middle of a base64 blob, or `"sk-"` inside `"risk-management"`, is
///   not a credential and must never be read as one.
/// - The body that follows must contain an unbroken alphanumeric segment
///   of at least [`MIN_TOKEN_BODY_BYTES`]. Separators (`-` and `_`) do not
///   terminate the scan — a Slack token such as
///   `"xoxb-<digits>-<digits>-<secret>"` carries its entropy in the last
///   segment — but they never count toward the length, so a hyphenated
///   English slug cannot reach the threshold.
fn has_token_after_prefix(body: &[u8], token_prefix: &[u8]) -> bool {
    let mut offset = 0usize;
    while offset < body.len() {
        let Some(index) = find_subslice(body, token_prefix, offset) else {
            return false;
        };
        let start = index;
        if at_word_boundary(body, start) && has_key_shaped_body(&body[start + token_prefix.len()..])
        {
            return true;
        }
        offset = start + token_prefix.len();
    }
    false
}

/// Reports whether `index` begins a new word: the start of the body, or a
/// position whose preceding byte is not alphanumeric (upstream
/// `atWordBoundary`).
fn at_word_boundary(body: &[u8], index: usize) -> bool {
    index == 0 || !is_alphanumeric(body[index - 1])
}

/// Reports whether the token run starting at `rest` contains an unbroken
/// alphanumeric segment long enough to be a real key body (upstream
/// `hasKeyShapedBody`).
fn has_key_shaped_body(rest: &[u8]) -> bool {
    let mut run = 0usize;
    for &b in rest {
        if is_alphanumeric(b) {
            run += 1;
            if run >= MIN_TOKEN_BODY_BYTES {
                return true;
            }
        } else if b == b'-' || b == b'_' {
            // A separator ends the segment but not the token: a real key
            // may carry its entropy after one.
            run = 0;
        } else {
            return false;
        }
    }
    false
}

/// ASCII alphanumeric — the token alphabet (upstream `isAlphanumeric`).
fn is_alphanumeric(b: u8) -> bool {
    b.is_ascii_alphanumeric()
}

/// The connection-string schemes whose userinfo component routinely
/// carries a password (upstream `credentialedURLSchemes`).
const CREDENTIALED_URL_SCHEMES: [&[u8]; 9] = [
    b"postgres://",
    b"postgresql://",
    b"mysql://",
    b"mongodb://",
    b"redis://",
    b"amqp://",
    b"s3://",
    b"https://",
    b"http://",
];

/// Reports whether a URL with a populated `"user:password@"` userinfo
/// component appears in the body (upstream `containsCredentialedURL`).
fn contains_credentialed_url(body: &[u8]) -> bool {
    for scheme in CREDENTIALED_URL_SCHEMES {
        let mut offset = 0usize;
        while let Some(index) = find_subslice(body, scheme, offset) {
            let start = index + scheme.len();
            if has_userinfo_password(&body[start..]) {
                return true;
            }
            offset = start;
            if offset >= body.len() {
                break;
            }
        }
    }
    false
}

/// Reports whether the authority component that begins at the start of
/// `rest` is of the form `"user:password@"` (upstream
/// `hasUserinfoPassword`). The scan stops at the first delimiter that ends
/// an authority, so a colon appearing later in a path or query is never
/// mistaken for a password separator.
fn has_userinfo_password(rest: &[u8]) -> bool {
    let mut colon: Option<usize> = None;
    for (i, &b) in rest.iter().enumerate() {
        match b {
            b':' => {
                if colon.is_none() {
                    colon = Some(i);
                }
            }
            b'@' => {
                // A password must be non-empty and must precede the '@'.
                return colon.is_some_and(|c| i > c + 1);
            }
            b'/' | b'?' | b'#' | b' ' | b'\t' | b'\n' | b'\r' | b'"' | b'\'' | b'<' | b'>'
            | b')' => return false,
            _ => {}
        }
    }
    false
}

#[cfg(test)]
mod tests {
    //! Port of `classifier_test.go`: markdown/plain acceptance, binary
    //! rejection, every secret-disclosure heuristic family, legitimate-prose
    //! acceptance, and the bounded-prefix read.

    use super::*;

    /// Drives the async port method on the test suite's minimal executor
    /// (the classifier never actually yields).
    fn classify(body: &[u8]) -> ClassifyResult {
        let request = ClassifyRequest {
            declared_media_type: "text/markdown".to_owned(),
            size: body.len() as i64,
            body: Box::new(std::io::Cursor::new(body.to_vec())),
        };
        crate::testkit::block_on(ReportClassifier::new().classify(request))
            .expect("classify must not fail on an in-memory body")
    }

    // Upstream `TestReportClassifierAcceptsMarkdownAndPlainText`.
    #[test]
    fn report_classifier_accepts_markdown_and_plain_text() {
        for (name, body, want) in [
            ("markdown", "# Report\n\n- finding\n", MEDIA_TYPE_MARKDOWN),
            (
                "plain",
                "a plain text report without markers\n",
                MEDIA_TYPE_PLAIN,
            ),
            ("empty", "", MEDIA_TYPE_PLAIN),
        ] {
            let result = classify(body.as_bytes());
            assert_eq!(result.detected_media_type, want, "{name}");
            assert!(result.rejection_code.is_empty(), "{name}: {result:?}");
            assert!(!result.secret_disclosure, "{name}");
        }
    }

    // Upstream `TestReportClassifierRejectsBinaryContent`.
    #[test]
    fn report_classifier_rejects_binary_content() {
        for (name, body) in [
            ("nul byte", b"report\x00tail".as_slice()),
            ("invalid utf-8", &[0xff, 0xfe, 0xfd][..]),
        ] {
            let result = classify(body);
            assert_eq!(
                result.detected_media_type, MEDIA_TYPE_OCTET_STREAM,
                "{name}"
            );
            assert_eq!(
                result.rejection_code, FAILURE_CODE_UNSUPPORTED_MEDIA_TYPE,
                "{name}"
            );
        }
    }

    // Upstream `TestReportClassifierRejectsSuspectedSecretDisclosure` —
    // every heuristic family must independently trigger the closed code.
    #[test]
    fn report_classifier_rejects_suspected_secret_disclosure() {
        let cases: &[(&str, &[u8])] = &[
            (
                "PEM private key",
                b"key material\n-----BEGIN RSA PRIVATE KEY-----\nMIIabc",
            ),
            (
                "openssh key",
                b"-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaA==",
            ),
            (
                "pgp key block",
                b"-----BEGIN PGP PRIVATE KEY BLOCK-----\nxg==",
            ),
            ("aws env", b"AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI"),
            ("pg password", b"POSTGRES_PASSWORD=hunter2"),
            ("openai key", b"OPENAI_API_KEY=sk-abc123"),
            ("anthropic env", b"ANTHROPIC_API_KEY=sk-ant-api03-x"),
            ("anthropic token", b"token: sk-ant-abcdef0123456789abcdef"),
            (
                "openai token",
                b"Authorization: Bearer sk-1234567890abcdefgh",
            ),
            (
                "aws access key id",
                b"aws_access_key_id = AKIAIOSFODNN7EXAMPLE",
            ),
            (
                "slack bot token",
                b"xoxb-123456789012-1234567890123-abcdefghijklmnop",
            ),
            ("github pat", b"ghp_abcdefghijklmnopqrstuvwxyz0123456789"),
            ("gitlab pat", b"glpat-abcdefghij0123456789"),
            (
                "credentialed postgres url",
                b"dsn = postgres://central:s3cret-password@localhost:5432/central",
            ),
            (
                "credentialed https url",
                b"endpoint https://user:hunter2pass@example.invalid/api",
            ),
        ];
        for (name, body) in cases {
            let result = classify(body);
            assert!(result.secret_disclosure, "{name}: {result:?}");
            assert_eq!(
                result.rejection_code, FAILURE_CODE_SECRET_DISCLOSURE,
                "{name}"
            );
        }
    }

    // Upstream `TestReportClassifierAcceptsLegitimateReportProse`: the
    // false-positive killers for each heuristic family.
    #[test]
    fn report_classifier_accepts_legitimate_report_prose() {
        for (name, body) in [
            (
                "sk- prose slug",
                "the sk-provisioning-and-rotation-guide section explains rotation\n",
            ),
            ("sk- inside a word", "risk-management notes for the desk\n"),
            (
                "akia inside base64",
                "checksum blob ZmFrZUFLSUFmb3Jub3Rha2V5MTIz\n",
            ),
            ("short key body", "token sk-abc-123-short\n"),
            (
                "bare connection string",
                "database: postgres://localhost:5432/central\n",
            ),
            (
                "userinfo without password",
                "endpoint postgres://central@localhost:5432/central\n",
            ),
            (
                "env name without assignment",
                "the AWS_SECRET_ACCESS_KEY variable is read from the environment\n",
            ),
        ] {
            let result = classify(body.as_bytes());
            assert!(
                !result.secret_disclosure,
                "{name}: false positive {result:?}"
            );
            assert_eq!(result.rejection_code, "", "{name}: {result:?}");
        }
    }

    // Upstream `TestReportClassifierReadsABoundedPrefixOnly`: a body larger
    // than the window classifies on the prefix alone — a secret just past
    // the window is not reached.
    #[test]
    fn report_classifier_reads_a_bounded_prefix_only() {
        use std::sync::Arc;
        use std::sync::atomic::{AtomicUsize, Ordering};

        // A reader that counts how many bytes were actually consumed. The
        // counter is shared because the boxed field requires 'static.
        struct CountingReader {
            inner: std::io::Cursor<Vec<u8>>,
            read: Arc<AtomicUsize>,
        }
        impl std::io::Read for CountingReader {
            fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
                let n = self.inner.read(buf)?;
                self.read.fetch_add(n, Ordering::SeqCst);
                Ok(n)
            }
        }
        let mut body = vec![b'x'; CLASSIFY_PREFIX_BYTES + 64];
        body.extend_from_slice(b"-----BEGIN PRIVATE KEY-----");
        let consumed = Arc::new(AtomicUsize::new(0));
        let reader = CountingReader {
            inner: std::io::Cursor::new(body),
            read: Arc::clone(&consumed),
        };
        let request = ClassifyRequest {
            declared_media_type: "text/plain".to_owned(),
            size: 0,
            body: Box::new(reader),
        };
        let result = crate::testkit::block_on(ReportClassifier::new().classify(request)).unwrap();
        assert!(
            !result.secret_disclosure,
            "the secret beyond the window must not be read"
        );
        assert_eq!(
            consumed.load(Ordering::SeqCst),
            CLASSIFY_PREFIX_BYTES,
            "the classifier must consume exactly the bounded prefix"
        );
    }

    /// A 1 MiB window ending mid-rune tolerates the truncated final
    /// sequence rather than declaring the body binary.
    #[test]
    fn truncated_final_rune_at_the_window_is_tolerated() {
        // '€' is a 3-byte UTF-8 sequence; split it across the boundary.
        let mut body = vec![b'a'; CLASSIFY_PREFIX_BYTES - 1];
        body.extend_from_slice("€".as_bytes()); // window now ends 2 bytes into the rune
        assert_eq!(body.len(), CLASSIFY_PREFIX_BYTES + 2);
        let window = &body[..CLASSIFY_PREFIX_BYTES];
        assert_eq!(detect_media_type(window), MEDIA_TYPE_PLAIN);
    }

    /// A genuinely invalid byte *inside* the window is still binary —
    /// the truncation tolerance reaches at most the last three bytes, so
    /// an invalid byte earlier than that fails `from_utf8` on the whole
    /// scan (upstream `utf8.Valid(scan)`).
    #[test]
    fn genuinely_invalid_byte_inside_the_window_is_binary() {
        let mut body = vec![b'a'; CLASSIFY_PREFIX_BYTES - 5];
        body.push(0xff);
        body.extend_from_slice(b"aaaa");
        assert_eq!(body.len(), CLASSIFY_PREFIX_BYTES);
        assert_eq!(detect_media_type(&body), MEDIA_TYPE_OCTET_STREAM);

        // And mid-body invalid bytes in a short body reject the same way.
        let mut short = b"# Title\n".to_vec();
        short.extend_from_slice(&[0xff, 0xfe, 0xfd]);
        assert_eq!(detect_media_type(&short), MEDIA_TYPE_OCTET_STREAM);
    }

    // Direct helper coverage: normalize_media_type folds case and space.
    #[test]
    fn normalize_media_type_folds_case_and_whitespace() {
        assert_eq!(normalize_media_type(" Text/Markdown \n"), "text/markdown");
        assert_eq!(normalize_media_type("text/plain"), "text/plain");
    }
}
