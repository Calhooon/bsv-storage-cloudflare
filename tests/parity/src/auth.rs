//! BRC-31 mutual auth client for the parity harness.
//!
//! Thin wrapper around `bsv_rs::auth::Peer<ProtoWallet, SimplifiedFetchTransport>`
//! that exposes a plain `request()` API so scenarios can stay oblivious to the
//! handshake/sign/session machinery.
//!
//! ## Design
//!
//! `bsv-rs`'s `Peer::to_peer(payload, ...)` is fire-and-forget — the HTTP
//! response comes back **through the transport's callback**, not through the
//! call's return value. That's fine for peer-to-peer messaging but awkward
//! for a request/response harness. We bridge it with a `request_id →
//! oneshot::Sender<HttpResponse>` map: before calling `to_peer`, we
//! pre-register the ID; inside the general-message callback we pop the ID
//! and send the parsed `HttpResponse` on the oneshot. The caller `await`s
//! the receiver.
//!
//! This works because `SimplifiedFetchTransport::send()` for a General
//! message is synchronous-with-respect-to-response: it makes the HTTP call,
//! parses the response, and invokes the callback before returning — so by
//! the time `to_peer` returns Ok, the oneshot has already been fulfilled.
//!
//! ## Why not re-use rust-bsv-worm's `AuthriteClient`?
//!
//! rust-bsv-worm ships a battle-tested BRC-31 client at
//! `~/bsv/rust-bsv-worm/src/auth/client.rs`, but it persists sessions to
//! `~/.local/share/brc31-sessions/` and is tightly coupled to a wallet
//! backend trait. For a test harness we want in-memory sessions (one fresh
//! handshake per base_url, no disk writes) and a bare private key. Wrapping
//! `bsv-rs::Peer` directly is simpler and has zero hidden state.
//!
//! ## What this doesn't cover
//!
//! * **BRC-29 payment**: separate concern, wired in `src/payment.rs` when
//!   `/upload` + `/renew` go live-fire (task #30).
//! * **Certificate exchange**: we pass `certificates_to_request: None` —
//!   neither nanostore nor our worker requires certificates for
//!   `/find`/`/list`/`/upload`/`/renew` (upload/renew need payment, not a
//!   cert). Revisit if a future scenario needs one.

use bsv_rs::auth::transports::{HttpRequest, HttpResponse, SimplifiedFetchTransport};
use bsv_rs::auth::{Peer, PeerOptions};
use bsv_rs::primitives::ec::PrivateKey;
use bsv_rs::wallet::ProtoWallet;
use rand::RngCore;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{oneshot, Mutex};

/// Max time we'll wait for the server to respond to a General message.
/// BRC-31 handshake + request fit in well under this on a healthy link.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

/// Map from request correlation ID to the oneshot that should receive the
/// decoded HTTP response. Shared between the general-message callback
/// (producer) and `request()` (consumer).
type PendingMap = Arc<Mutex<HashMap<[u8; 32], oneshot::Sender<HttpResponse>>>>;

/// Authenticated HTTP client scoped to a single `base_url`. Holds a
/// BRC-31 session for the life of the struct, so successive requests reuse
/// the same handshake. One instance per (identity, base_url) — typical
/// harness run creates two (one for reference, one for local).
pub struct AuthClient {
    peer: Arc<Peer<ProtoWallet, SimplifiedFetchTransport>>,
    pending: PendingMap,
}

/// A response borrowed back out of the BRC-31 wrapper. JSON bodies are
/// returned as raw bytes — the caller decodes (scenarios need full control
/// because volatile-aware diffing has to see the exact UTF-8 the server
/// sent).
#[derive(Debug, Clone)]
pub struct AuthResponse {
    pub status: u16,
    /// Authorization + `x-bsv-*` response headers filtered by the
    /// transport. Carries the BRC-29 402 signals
    /// (`x-bsv-payment-satoshis-required`, `x-bsv-payment-derivation-prefix`)
    /// that `Brc31Paid` scenarios parse to build their payment envelope.
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl AuthClient {
    /// Build a client that will authenticate to `base_url` with the given
    /// private key. The first request triggers the handshake; subsequent
    /// requests on the same instance reuse the session.
    ///
    /// This is synchronous — no network I/O happens here.
    pub fn new(base_url: &str, private_key: &PrivateKey) -> Result<Self, String> {
        let wallet = ProtoWallet::new(Some(private_key.clone()));
        let transport = SimplifiedFetchTransport::new(base_url);
        let pending: PendingMap = Arc::new(Mutex::new(HashMap::new()));

        let peer = Arc::new(Peer::new(PeerOptions {
            wallet,
            transport,
            certificates_to_request: None,
            session_manager: None,
            auto_persist_last_session: false,
            originator: None,
        }));
        peer.start();

        Ok(Self { peer, pending })
    }

    /// Install the general-message callback that routes responses back to
    /// `request()` callers. Must be called once after `new()`. Separate
    /// from `new()` because `listen_for_general_messages` is async.
    pub async fn prepare(&self) {
        let pending = self.pending.clone();
        self.peer
            .listen_for_general_messages(move |_sender, payload| {
                let pending = pending.clone();
                Box::pin(async move {
                    // Non-fatal: if the payload doesn't decode, just drop the
                    // message. The `to_peer()` caller will time out on its
                    // oneshot — which is the correct failure mode (garbled
                    // server response).
                    if let Ok(resp) = HttpResponse::from_payload(&payload) {
                        let mut map = pending.lock().await;
                        if let Some(tx) = map.remove(&resp.request_id) {
                            // Drop the send result — receiver gone just means
                            // the caller already bailed on timeout.
                            let _ = tx.send(resp);
                        }
                    }
                    Ok(())
                })
            })
            .await;
    }

    /// The server's identity public key (hex, 66-char compressed).
    /// Forces a handshake if none has happened yet. Needed for BRC-29
    /// payment derivation — the recipient-key counterparty is always
    /// the server's identity as revealed by the BRC-31 InitialResponse.
    pub async fn server_identity_hex(&self) -> Result<String, String> {
        // `to_peer` with an empty-ish payload triggers `get_authenticated_session`,
        // which performs the handshake on first call. But sending a
        // General message to just learn identity is wasteful — instead
        // call the same session-getter directly.
        let session = self
            .peer
            .get_authenticated_session(None, Some(REQUEST_TIMEOUT.as_millis() as u64))
            .await
            .map_err(|e| format!("get_authenticated_session: {e}"))?;
        let key = session
            .peer_identity_key
            .ok_or("session has no peer_identity_key after handshake")?;
        Ok(key.to_hex())
    }

    /// Send an authenticated HTTP request. Blocks until the server responds
    /// or `REQUEST_TIMEOUT` elapses. The first call on a fresh client also
    /// performs the BRC-31 handshake inline.
    pub async fn request(
        &self,
        method: &str,
        path: &str,
        search: &str,
        body: Vec<u8>,
        extra_headers: Vec<(String, String)>,
    ) -> Result<AuthResponse, String> {
        // 32-byte correlation ID — has to be unique per in-flight request
        // so the callback can demux. Cryptographic randomness is overkill
        // but keeps collisions impossible.
        let mut request_id = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut request_id);

        let http_req = HttpRequest {
            request_id,
            method: method.to_string(),
            path: path.to_string(),
            search: search.to_string(),
            headers: extra_headers,
            body,
        };
        let payload = http_req.to_payload();

        let (tx, rx) = oneshot::channel();
        {
            let mut map = self.pending.lock().await;
            map.insert(request_id, tx);
        }

        // `None` for identity_key → use any existing session, triggering
        // handshake if none exists yet. Our transport talks to exactly one
        // server, so ambiguity is impossible.
        let send_result = self
            .peer
            .to_peer(&payload, None, Some(REQUEST_TIMEOUT.as_millis() as u64))
            .await;

        if let Err(e) = send_result {
            // Drop the pending entry so subsequent requests with the same
            // (randomly-drawn) request_id don't collide with a ghost.
            self.pending.lock().await.remove(&request_id);
            return Err(format!("to_peer failed: {e}"));
        }

        // The transport has already fired our callback inside send() above,
        // so the oneshot is typically ready immediately. Timeout is a
        // safety net for transport misbehavior.
        let resp = tokio::time::timeout(REQUEST_TIMEOUT, rx)
            .await
            .map_err(|_| "response timeout — callback did not fire".to_string())?
            .map_err(|_| "response channel closed without value".to_string())?;

        Ok(AuthResponse {
            status: resp.status,
            headers: resp.headers,
            body: resp.body,
        })
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use bsv_rs::primitives::ec::PrivateKey;

    #[test]
    fn client_constructs_without_network_io() {
        // No network — just proves the type wires up.
        let key = PrivateKey::random();
        let client = AuthClient::new("https://example.invalid", &key);
        assert!(client.is_ok());
    }

    #[tokio::test]
    async fn prepare_can_be_called_before_request() {
        // Proves listen_for_general_messages registration doesn't block.
        let key = PrivateKey::random();
        let client = AuthClient::new("https://example.invalid", &key).unwrap();
        client.prepare().await;
        // If prepare returned, the callback is installed. We don't exercise
        // request() here because that needs a real server.
    }

    #[test]
    fn auth_response_preserves_status_and_body() {
        // Trivial shape check — catches accidental field reordering.
        let r = AuthResponse {
            status: 418,
            headers: vec![("x-kind".to_string(), "teapot".to_string())],
            body: b"short and stout".to_vec(),
        };
        assert_eq!(r.status, 418);
        assert_eq!(r.body, b"short and stout");
        assert_eq!(r.headers.len(), 1);
    }
}
