//! Raw-TCP TLS-passthrough handler for TLSRoute / GEP-2643.
//!
//! The proxy **never** terminates TLS on this path.  A bounded [`TcpStream::peek`]
//! reads the ClientHello without consuming it (bytes stay in the kernel queue),
//! [`tls_parser`] extracts the SNI, and the matched backend receives the
//! full original stream via [`tokio::io::copy_bidirectional_with_sizes`].
//!
//! All failure paths close the connection and return — nothing on this path
//! may panic or call `unwrap` (data-plane zero-crash bar).

use std::io;
use std::net::SocketAddr;
use std::time::Duration;

use thiserror::Error;
use tls_parser::{
    TlsExtension, TlsMessage, TlsMessageHandshake, TlsPlaintext, parse_tls_plaintext,
};
use tokio::io::copy_bidirectional_with_sizes;
use tokio::net::TcpStream;
use tokio::time::timeout;
use tracing::debug;

use coxswain_core::routing::{BackendGroup, Selected};

use crate::edge::peek::PeekBackoff;

/// Buffer size for each direction of the TCP splice (~16 KiB).
const SPLICE_BUF: usize = 16 * 1024;

/// Maximum bytes read when peeking the TLS ClientHello.
///
/// A standard ClientHello fits in ~300 bytes; this cap guards against
/// slowloris-style exhaustion of the peek buffer.
const MAX_PEEK: usize = 16 * 1024;

/// Timeout on the initial ClientHello peek.
const PEEK_TIMEOUT: Duration = Duration::from_secs(10);

// ── SNI extraction ────────────────────────────────────────────────────────────

/// Result of parsing bytes peeked from a TLS ClientHello.
#[derive(Debug)]
pub(crate) enum SniPeek {
    /// Need more bytes — caller should grow the peek buffer and retry.
    Incomplete,
    /// SNI extension found; `host` is borrowed from the peeked buffer so the
    /// caller converts it to owned.
    Found(String),
    /// A complete ClientHello was parsed but it carried no SNI extension.
    NoSni,
}

/// Error variants for [`client_hello_sni`].
#[non_exhaustive]
#[derive(Debug, Error)]
pub(crate) enum SniParseError {
    /// The record is not a TLS handshake / ClientHello.
    #[error("not a TLS ClientHello record")]
    NotClientHello,
    /// The SNI hostname is not valid UTF-8.
    #[error("SNI hostname contains invalid UTF-8")]
    InvalidUtf8,
}

/// Inspect a peeked byte slice and attempt to extract the SNI server_name.
///
/// Returns [`SniPeek::Incomplete`] when `buf` does not yet contain a full TLS
/// record — the caller should expand the peek buffer and retry.  Returns an
/// error only when the bytes are definitively *not* a TLS ClientHello;
/// a missing SNI extension is not an error (returns [`SniPeek::NoSni`]).
///
/// # Errors
///
/// Returns [`SniParseError::NotClientHello`] when the bytes are a complete TLS
/// record that is not a ClientHello handshake.
/// Returns [`SniParseError::InvalidUtf8`] when the SNI hostname bytes are not
/// valid UTF-8.
pub(crate) fn client_hello_sni(buf: &[u8]) -> Result<SniPeek, SniParseError> {
    use tls_parser::nom::Err as NomErr;

    // A TLS ClientHello is always carried in a Handshake record (content type 0x16).
    // Guard before calling tls-parser: garbage input (e.g. HTTP) may have a first
    // byte that makes nom interpret following bytes as a huge record length,
    // returning a spurious Incomplete instead of an error.
    match buf.first().copied() {
        None => return Ok(SniPeek::Incomplete),
        Some(b) if b != 0x16 => return Err(SniParseError::NotClientHello),
        Some(_) => {}
    }

    let record: TlsPlaintext = match parse_tls_plaintext(buf) {
        Ok((_, r)) => r,
        Err(NomErr::Incomplete(_)) => return Ok(SniPeek::Incomplete),
        Err(_) => return Err(SniParseError::NotClientHello),
    };

    // Walk the messages in the record looking for the ClientHello.
    let hello = record.msg.into_iter().find_map(|msg| {
        if let TlsMessage::Handshake(TlsMessageHandshake::ClientHello(ch)) = msg {
            Some(ch)
        } else {
            None
        }
    });
    let hello = match hello {
        Some(h) => h,
        None => return Err(SniParseError::NotClientHello),
    };

    // Walk the extensions looking for SNI.
    let ext_bytes = match hello.ext {
        Some(b) => b,
        None => return Ok(SniPeek::NoSni),
    };

    let mut remaining = ext_bytes;
    while !remaining.is_empty() {
        match tls_parser::parse_tls_extension(remaining) {
            Ok((rest, TlsExtension::SNI(names))) => {
                // Only the `host_name` (type 0) name type is defined by RFC 6066.
                if let Some((_, name)) = names.into_iter().next() {
                    // Lowercased here, at the one point that turns ClientHello
                    // bytes into an SNI, so every consumer downstream compares
                    // against the lowercase hostnames the routing and TLS tables
                    // are keyed by. RFC 6066 defers to DNS, which is
                    // case-insensitive; a peer is free to send `App.Example.Com`.
                    // Costs nothing over the `to_owned` it replaces.
                    let host = std::str::from_utf8(name)
                        .map_err(|_| SniParseError::InvalidUtf8)?
                        .to_ascii_lowercase();
                    return Ok(SniPeek::Found(host));
                }
                remaining = rest;
            }
            Ok((rest, _)) => {
                remaining = rest;
            }
            Err(_) => break,
        }
    }

    Ok(SniPeek::NoSni)
}

// ── Connection handler ────────────────────────────────────────────────────────

/// Splice one accepted TCP connection to `backend`, encrypted end-to-end.
///
/// `backend` is resolved by the caller ([`crate::edge::accept`]'s TLS-L4
/// dispatch), which has already peeked the ClientHello and matched `sni`
/// against the passthrough table. Taking the resolved group rather than the
/// table is what makes the routing decision and the connection it applies to
/// the same event: re-loading the snapshot here would both repeat the peek and
/// SNI match, and let a reconcile landing in between drop a connection that had
/// just tested as routable. `sni` is carried only for diagnostics.
///
/// All failure paths log at `debug` level and return — the connection is closed
/// when the `TcpStream` is dropped.
pub(crate) async fn handle_passthrough(
    tcp: TcpStream,
    peer_addr: SocketAddr,
    backend: &BackendGroup,
    sni: Option<&str>,
    dial_timeout: Duration,
) {
    let Selected {
        addr: backend_addr, ..
    } = match backend.select_upstream(None) {
        Some(s) => s,
        None => {
            debug!(
                peer = %peer_addr,
                sni = ?sni,
                "TLS passthrough: backend group is empty"
            );
            return;
        }
    };

    let mut upstream = match timeout(dial_timeout, TcpStream::connect(backend_addr)).await {
        Ok(Ok(s)) => s,
        Ok(Err(e)) => {
            debug!(
                peer = %peer_addr,
                backend = %backend_addr,
                error = %e,
                "TLS passthrough: failed to connect to backend"
            );
            return;
        }
        Err(_) => {
            debug!(
                peer = %peer_addr,
                backend = %backend_addr,
                timeout = ?dial_timeout,
                "TLS passthrough: backend connect timed out"
            );
            return;
        }
    };

    // The peeked bytes are still in the kernel queue — the backend connection
    // receives the intact ClientHello as the first bytes of the splice.
    let mut downstream = tcp;
    if let Err(e) =
        copy_bidirectional_with_sizes(&mut downstream, &mut upstream, SPLICE_BUF, SPLICE_BUF).await
    {
        // Connection-reset and EOF errors are normal on TLS connections.
        debug!(
            peer = %peer_addr,
            backend = %backend_addr,
            error = %e,
            "TLS passthrough: splice ended"
        );
    }
}

/// Peek the TLS ClientHello off `tcp` (MSG_PEEK — data stays in the kernel
/// queue) and return the SNI server_name if present.
///
/// Grows the peek buffer until [`client_hello_sni`] reports a complete parse,
/// or until [`MAX_PEEK`] bytes have been read, or until `PEEK_TIMEOUT` fires.
/// Retries wait on `PeekBackoff` — see `crate::edge::peek` for why a peek loop
/// must poll rather than await readiness.
///
/// # Errors
///
/// Returns an IO error on socket failure or when the ClientHello times out or
/// exceeds the size cap.
pub(crate) async fn peek_sni(tcp: &TcpStream) -> io::Result<Option<String>> {
    let mut buf = vec![0u8; 512];
    let deadline = timeout(PEEK_TIMEOUT, async {
        let mut backoff = PeekBackoff::new();
        loop {
            let n = tcp.peek(&mut buf).await?;
            if n == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "connection closed during peek",
                ));
            }
            match client_hello_sni(&buf[..n]) {
                Ok(SniPeek::Incomplete) => {
                    // Grow only when the buffer was full: a short read means the
                    // capacity is already sufficient and bytes are simply missing.
                    // Growing unconditionally is what made a fragmented ClientHello
                    // hit the cap and get rejected (#614).
                    if n == buf.len() {
                        if buf.len() >= MAX_PEEK {
                            return Err(io::Error::new(
                                io::ErrorKind::InvalidData,
                                "ClientHello exceeds peek cap",
                            ));
                        }
                        buf.resize((buf.len() * 2).min(MAX_PEEK), 0);
                        // A larger buffer may expose bytes already queued.
                        continue;
                    }
                    backoff.wait(n).await;
                }
                Ok(SniPeek::Found(host)) => return Ok(Some(host)),
                Ok(SniPeek::NoSni) => return Ok(None),
                Err(e) => {
                    return Err(io::Error::new(io::ErrorKind::InvalidData, e.to_string()));
                }
            }
        }
    });
    deadline
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "ClientHello peek timed out"))?
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncWriteExt;
    use tokio::net::TcpListener;

    #[test]
    fn parse_sni_from_client_hello() {
        // Verify that tls_parser can parse SNI extension bytes directly.
        // minimal known-good one from tls-parser's own test suite approach:
        // just verify that tls_parser can parse the SNI extension bytes directly.

        // Minimal ClientHello: ContentType=0x16, version=0x0301,
        // record length contains exactly the SNI extension.
        let sni_ext: &[u8] = &[
            // extension type SNI = 0x0000
            0x00, 0x00, // extension length = 13
            0x00, 0x0d, // ServerNameList length = 11
            0x00, 0x0b, // name_type = host_name (0)
            0x00, // name length = 8
            0x00, 0x08, // "app.test"
            b'a', b'p', b'p', b'.', b't', b'e', b's', b't',
        ];

        match tls_parser::parse_tls_extension(sni_ext) {
            Ok((_, TlsExtension::SNI(names))) => {
                let host = std::str::from_utf8(names[0].1).unwrap();
                assert_eq!(host, "app.test");
            }
            other => panic!("unexpected parse result: {other:?}"),
        }
    }

    #[test]
    fn incomplete_returns_incomplete() {
        // Just the first few bytes of a TLS record — definitely incomplete.
        let partial = &[0x16u8, 0x03, 0x01, 0x00, 0x50];
        match client_hello_sni(partial) {
            Ok(SniPeek::Incomplete) => {}
            other => panic!("expected Incomplete, got: {other:?}"),
        }
    }

    #[test]
    fn garbage_returns_not_client_hello() {
        let garbage = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";
        match client_hello_sni(garbage) {
            Err(SniParseError::NotClientHello) => {}
            other => panic!("expected NotClientHello, got: {other:?}"),
        }
    }

    /// Build a minimal but complete TLS ClientHello record carrying `sni_host`.
    ///
    /// Record: ContentType=22 (handshake), version=0x0301, then body.
    /// Handshake: type=1 (ClientHello), length (3 bytes), then:
    ///   version (2), random (32), session_id_len (1), cipher_suites_len (2),
    ///   cipher_suites (2), compression_len (1), compression (1),
    ///   extensions_len (2), extensions...
    pub(super) fn sample_client_hello(sni_host: &[u8]) -> Vec<u8> {
        let sni_host_len = sni_host.len() as u16;
        // SNI extension wire format
        let sni_ext_body: Vec<u8> = {
            let mut v = Vec::new();
            // ServerNameList length = 1 + 2 + sni_host_len
            let list_len = 3 + sni_host_len;
            v.extend_from_slice(&list_len.to_be_bytes());
            v.push(0x00); // name_type = host_name
            v.extend_from_slice(&sni_host_len.to_be_bytes());
            v.extend_from_slice(sni_host);
            v
        };
        let ext_body_len = sni_ext_body.len() as u16;

        let mut extensions: Vec<u8> = Vec::new();
        extensions.extend_from_slice(&0x0000u16.to_be_bytes()); // type = SNI
        extensions.extend_from_slice(&ext_body_len.to_be_bytes());
        extensions.extend_from_slice(&sni_ext_body);

        let extensions_len = extensions.len() as u16;

        // ClientHello body (fixed fields + extensions)
        let mut ch_body: Vec<u8> = Vec::new();
        ch_body.extend_from_slice(&[0x03, 0x03]); // version = TLS 1.2 compat
        ch_body.extend_from_slice(&[0u8; 32]); // random
        ch_body.push(0x00); // session_id_len = 0
        ch_body.extend_from_slice(&[0x00, 0x02]); // cipher_suites_len = 2
        ch_body.extend_from_slice(&[0x13, 0x01]); // TLS_AES_128_GCM_SHA256
        ch_body.push(0x01); // compression_methods_len = 1
        ch_body.push(0x00); // null compression
        ch_body.extend_from_slice(&extensions_len.to_be_bytes());
        ch_body.extend_from_slice(&extensions);

        let ch_len = ch_body.len() as u32;

        // Handshake record
        let mut hs: Vec<u8> = vec![
            0x01, // type = ClientHello
            ((ch_len >> 16) & 0xff) as u8,
            ((ch_len >> 8) & 0xff) as u8,
            (ch_len & 0xff) as u8,
        ];
        hs.extend_from_slice(&ch_body);

        let hs_len = hs.len() as u16;

        // TLS record
        let mut record: Vec<u8> = Vec::new();
        record.push(0x16); // ContentType = handshake
        record.extend_from_slice(&[0x03, 0x01]); // version
        record.extend_from_slice(&hs_len.to_be_bytes());
        record.extend_from_slice(&hs);
        record
    }

    #[test]
    fn full_client_hello_with_sni_extracted() {
        let record = sample_client_hello(b"sni.example.com");
        match client_hello_sni(&record) {
            Ok(SniPeek::Found(host)) => assert_eq!(host, "sni.example.com"),
            other => panic!("expected Found, got: {other:?}"),
        }
    }

    /// RFC 6066 defers to DNS, which is case-insensitive, so a peer may send any
    /// casing. Every table the SNI is matched against is keyed by the lowercase
    /// hostnames the reconciler wrote, so normalizing at this single extraction
    /// point is what keeps mixed-case connections routable.
    #[test]
    fn mixed_case_sni_is_normalized_at_extraction() {
        let record = sample_client_hello(b"SNI.Example.COM");
        match client_hello_sni(&record) {
            Ok(SniPeek::Found(host)) => assert_eq!(
                host, "sni.example.com",
                "a mixed-case SNI must be lowercased here; leaving it raw makes \
                 every downstream lookup (route, cert, mTLS config) miss"
            ),
            other => panic!("expected Found, got: {other:?}"),
        }
    }

    /// #614: a ClientHello split across TCP segments must still be peeked.
    ///
    /// Before the fix the grow loop doubled the buffer on every `Incomplete`
    /// regardless of how many bytes had actually arrived, so a short first read
    /// ran 512→`MAX_PEEK` in microseconds and returned "ClientHello exceeds peek
    /// cap" long before the second segment landed. A single-segment test passes
    /// even with that bug — the split and the delay between writes are what make
    /// this a regression test.
    #[tokio::test]
    async fn fragmented_client_hello_is_peeked_across_segments() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let hello = sample_client_hello(b"frag.example.com");
        // Split mid-record: 20 bytes is past the 5-byte record header but far
        // short of the SNI extension, so the first parse must report Incomplete.
        let (head, tail) = hello.split_at(20);
        let (head, tail) = (head.to_vec(), tail.to_vec());

        let writer = tokio::spawn(async move {
            let mut client = TcpStream::connect(addr).await.unwrap();
            client.write_all(&head).await.unwrap();
            client.flush().await.unwrap();
            // Force a genuine segment boundary: the peek loop must park here.
            tokio::time::sleep(Duration::from_millis(150)).await;
            client.write_all(&tail).await.unwrap();
            client.flush().await.unwrap();
            // Hold the connection open until the peek completes.
            tokio::time::sleep(Duration::from_secs(2)).await;
        });

        let (server, _) = listener.accept().await.unwrap();
        let sni = peek_sni(&server)
            .await
            .expect("fragmented hello must parse");
        assert_eq!(sni.as_deref(), Some("frag.example.com"));
        writer.abort();
    }

    /// The cap still rejects a hello that genuinely never completes — the #614
    /// fix must not turn "too large" into "hang until the timeout".
    #[tokio::test]
    async fn oversized_client_hello_still_rejected() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        // A record claiming the u16 maximum, followed by more filler than
        // MAX_PEEK, so the grow loop fills its cap and never completes a parse.
        let mut blob: Vec<u8> = vec![0x16, 0x03, 0x01, 0xff, 0xff];
        blob.resize(MAX_PEEK + 1024, 0);

        let writer = tokio::spawn(async move {
            let mut client = TcpStream::connect(addr).await.unwrap();
            let _ = client.write_all(&blob).await;
            tokio::time::sleep(Duration::from_secs(2)).await;
        });

        let (server, _) = listener.accept().await.unwrap();
        let err = peek_sni(&server)
            .await
            .expect_err("must reject over-cap hello");
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        writer.abort();
    }
}
