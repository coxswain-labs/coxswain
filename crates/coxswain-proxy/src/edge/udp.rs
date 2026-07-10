//! Session-tracked UDP datagram forwarder for UDPRoute / GEP-2645.
//!
//! UDP is connectionless: unlike TCP there is no accept loop, no per-client
//! socket, and no OS-level connection state to demux replies. A single bound
//! [`UdpSocket`] receives every client's datagrams multiplexed onto one fd, so
//! this module hand-rolls session tracking instead of reusing the
//! dial-once-then-splice idiom [`crate::edge::tcp`] uses.
//!
//! # Session model
//!
//! On the first datagram from a client `SocketAddr`, [`handle_datagram`] picks
//! a backend via [`BackendGroup::select_upstream`], binds a fresh ephemeral
//! [`UdpSocket`], and `connect()`s it to the backend. UDP "connect" performs no
//! handshake — it only pins the peer address so the kernel demuxes that
//! backend's replies back to this one socket, giving the flow a stable
//! "5-tuple" for the session's lifetime. A per-session reply-pump task then
//! loops `recv()` on that socket and `send_to()`s each reply back to the
//! client through the shared *listener* socket, so the client sees replies
//! from the stable port it originally contacted.
//!
//! The backend is selected once per session (not per datagram): this matches
//! the Gateway API conformance weighted-routing test, which opens a fresh
//! client socket (hence a fresh session) per probe and expects the
//! distribution to converge across sessions.
//!
//! # The recv loop never awaits per-datagram
//!
//! [`run_udp_listener`]'s loop is the only reader of the shared listener
//! socket, so anything it awaits before looping back to `recv_from` delays
//! *every other client's* next datagram too. [`handle_datagram`] is therefore
//! synchronous: a repeat datagram on an existing session uses
//! [`UdpSocket::try_send`] (non-blocking), and a brand-new session's
//! bind/connect/first-send/reply-pump all run in a freshly spawned task. This
//! matters under concurrent fresh-session bursts (again, exactly the weighted
//! conformance test's traffic shape) — serializing session setup inline once
//! queued enough new sessions past the client's own read timeout to fail the
//! test, even though no datagram was actually lost.
//!
//! Sessions age out after `idle_timeout` of inactivity — UDP has no FIN/RST,
//! so "connection end" is purely a timeout policy, matched by the reply-pump
//! task's own recv timeout.
//!
//! # Drain semantics differ from TCP
//!
//! TCP drain waits for in-flight connections to finish within a timeout
//! before force-closing. UDP has no notion of a graceful close — a dropped
//! datagram is normal, expected behaviour for the protocol, and the client's
//! own retry/timeout logic already tolerates it. So a UDP listener drain
//! immediately stops the recv loop and aborts every session's reply-pump task;
//! there is no drain window to wait out.
//!
//! # Zero-crash bar
//!
//! Every failure path (no route, empty backend group, bind/connect/send/recv
//! error) logs at `debug` and drops the datagram or tears down the session —
//! nothing on this path may panic or call `.unwrap()`.

use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use dashmap::DashMap;
use parking_lot::Mutex;
use tokio::net::UdpSocket;
use tokio::task::JoinSet;
use tokio::time::timeout;
use tokio_util::sync::CancellationToken;
use tracing::debug;

use coxswain_core::routing::{Selected, SharedUdpRouteTable};

use crate::metrics;

/// Max UDP datagram size (theoretical max payload for a UDP packet). Used for
/// the one shared per-listener recv buffer — costs nothing extra to keep at
/// the true max since there is exactly one of these per listener, not one per
/// session.
const MAX_DATAGRAM: usize = 65535;

/// Reply-pump buffer size, allocated once per session. Must stay at
/// [`MAX_DATAGRAM`]: this forwarder is protocol-agnostic (any UDPRoute
/// backend, not just small request/response protocols), and a `recv()` into
/// an undersized buffer silently truncates a larger datagram rather than
/// erroring — corrupting a delivered reply is worse than the UDP-normal
/// "drop and let the client retry" outcome, so there is no safe smaller size.
const SESSION_REPLY_BUF: usize = MAX_DATAGRAM;

/// Maximum concurrent sessions per listener. A client beyond this limit has its
/// datagram dropped (logged) rather than evicting an existing session — mirrors
/// `MAX_CONCURRENT_CONNECTIONS` in `edge::accept`, sized down from that
/// sibling's 4096 because each UDP session pins a full [`SESSION_REPLY_BUF`]
/// (64 KiB) for its lifetime, unlike a TCP connection's transient splice
/// buffer: 2048 × 64 KiB ≈ 128 MiB worst case, about half of the shared-proxy
/// chart's default 256Mi memory limit, leaving headroom for routing snapshots
/// and the rest of the proxy's normal working set.
const MAX_CONCURRENT_SESSIONS: usize = 2048;

/// One tracked client flow: the backend-bound socket and last-activity stamp.
///
/// `last_seen` is read by the reply-pump task on every idle-timeout tick to
/// distinguish "genuinely idle" from "a fresh datagram raced the timeout".
struct UdpSession {
    upstream: UdpSocket,
    last_seen: Mutex<Instant>,
}

type SessionMap = DashMap<SocketAddr, Arc<UdpSession>>;

/// Per-listener state [`handle_datagram`] needs, grouped so the function stays
/// under the workspace `clippy::too_many_arguments` limit.
struct ListenerState<'a> {
    socket: &'a Arc<UdpSocket>,
    table: &'a SharedUdpRouteTable,
    sessions: &'a Arc<SessionMap>,
    pump_tasks: &'a mut JoinSet<()>,
    listener_port: u16,
    idle_timeout: Duration,
}

/// Run the UDP forwarding loop for one `protocol: UDP` listener.
///
/// Unlike the TCP/HTTP paths there is no per-connection task: this single task
/// owns the listener socket for its lifetime, demuxing every client's
/// datagrams through the session table. Stops immediately when `drain_token`
/// is cancelled or the global shutdown fires — see the module-level doc for
/// why UDP drain has no graceful window.
pub(crate) async fn run_udp_listener(
    socket: UdpSocket,
    listener_port: u16,
    table: SharedUdpRouteTable,
    idle_timeout: Duration,
    drain_token: CancellationToken,
    mut global_shutdown: pingora_core::server::ShutdownWatch,
) {
    let socket = Arc::new(socket);
    let sessions: Arc<SessionMap> = Arc::new(DashMap::new());
    let mut pump_tasks: JoinSet<()> = JoinSet::new();
    let mut buf = vec![0u8; MAX_DATAGRAM];

    loop {
        tokio::select! {
            biased;

            _ = drain_token.cancelled() => break,
            Ok(()) = global_shutdown.changed() => break,

            result = socket.recv_from(&mut buf) => {
                match result {
                    Ok((n, client)) => {
                        handle_datagram(
                            ListenerState {
                                socket: &socket,
                                table: &table,
                                sessions: &sessions,
                                pump_tasks: &mut pump_tasks,
                                listener_port,
                                idle_timeout,
                            },
                            client,
                            &buf[..n],
                        );
                    }
                    Err(e) => {
                        debug!(port = listener_port, error = %e, "UDP proxy: recv error");
                    }
                }
            }

            // Reap completed reply-pump tasks.
            Some(_) = pump_tasks.join_next(), if !pump_tasks.is_empty() => {}
        }
    }

    // No graceful drain window for UDP (see module doc) — abort every
    // in-flight reply-pump task and let the shared socket drop with it.
    pump_tasks.abort_all();
}

/// Handle one inbound datagram: forward it on the client's existing session,
/// or spawn a new session (backend pick + upstream bind/connect) if this is
/// the first datagram from `client`.
///
/// Deliberately synchronous (no `.await`): this is called from the single
/// per-listener recv loop, so anything awaited here blocks that loop from
/// picking up the *next* client's datagram. Repeat traffic on an existing
/// session uses [`UdpSocket::try_send`] (non-blocking — UDP's kernel send
/// buffer accepts near-unconditionally). A brand-new session needs bind +
/// connect, which are real (if fast) async operations, so that work — and the
/// session's entire reply-pump lifetime — runs in its own spawned task
/// instead of inline here. Without this, N clients opening fresh sessions
/// concurrently (exactly the Gateway API weighted-routing conformance test's
/// traffic shape: one new UDP socket per probe) would have their session
/// setup serialized through this one loop, queuing later arrivals long enough
/// to blow past the client's own read timeout.
fn handle_datagram(state: ListenerState<'_>, client: SocketAddr, payload: &[u8]) {
    let ListenerState {
        socket: listener_socket,
        table,
        sessions,
        pump_tasks,
        listener_port,
        idle_timeout,
    } = state;

    // Fast path: existing session. Clone the Arc and drop the DashMap guard
    // before touching the session — holding a shard guard while the
    // reply-pump task also wants it (e.g. to evict on idle) would stall that
    // writer for no reason.
    if let Some(entry) = sessions.get(&client) {
        let session = Arc::clone(&entry);
        drop(entry);
        *session.last_seen.lock() = Instant::now();
        if let Err(e) = session.upstream.try_send(payload) {
            debug!(
                peer = %client,
                port = listener_port,
                error = %e,
                "UDP proxy: forwarding to existing session failed"
            );
        }
        return;
    }

    if sessions.len() >= MAX_CONCURRENT_SESSIONS {
        tracing::warn!(
            peer = %client,
            port = listener_port,
            limit = MAX_CONCURRENT_SESSIONS,
            "UDP proxy: session limit reached, dropping datagram"
        );
        return;
    }

    let snapshot = table.load();
    let backend = match snapshot.port(listener_port) {
        Some(bg) => bg,
        None => {
            debug!(
                peer = %client,
                port = listener_port,
                "UDP proxy: no route for listener port"
            );
            return;
        }
    };

    let Selected {
        addr: backend_addr, ..
    } = match backend.select_upstream(None) {
        Some(s) => s,
        None => {
            debug!(
                peer = %client,
                port = listener_port,
                "UDP proxy: backend group is empty"
            );
            return;
        }
    };

    let payload = payload.to_vec();
    let listener_socket = Arc::clone(listener_socket);
    let sessions = Arc::clone(sessions);
    pump_tasks.spawn(async move {
        establish_and_run_session(
            listener_socket,
            sessions,
            client,
            backend_addr,
            payload,
            idle_timeout,
            listener_port,
        )
        .await;
    });
}

/// Bind + connect a fresh upstream socket for a new session, forward its
/// first datagram, register the session, then run its reply pump for the
/// rest of the session's lifetime — all in one spawned task so the recv loop
/// in [`run_udp_listener`] never waits on it (see [`handle_datagram`]).
async fn establish_and_run_session(
    listener_socket: Arc<UdpSocket>,
    sessions: Arc<SessionMap>,
    client: SocketAddr,
    backend_addr: SocketAddr,
    payload: Vec<u8>,
    idle_timeout: Duration,
    listener_port: u16,
) {
    let bind_addr: SocketAddr = if backend_addr.is_ipv4() {
        (Ipv4Addr::UNSPECIFIED, 0).into()
    } else {
        (Ipv6Addr::UNSPECIFIED, 0).into()
    };
    let upstream = match UdpSocket::bind(bind_addr).await {
        Ok(s) => s,
        Err(e) => {
            debug!(
                peer = %client,
                backend = %backend_addr,
                error = %e,
                "UDP proxy: failed to bind upstream socket"
            );
            return;
        }
    };
    if let Err(e) = upstream.connect(backend_addr).await {
        debug!(
            peer = %client,
            backend = %backend_addr,
            error = %e,
            "UDP proxy: failed to connect upstream socket"
        );
        return;
    }

    let session = Arc::new(UdpSession {
        upstream,
        last_seen: Mutex::new(Instant::now()),
    });
    if let Err(e) = session.upstream.send(&payload).await {
        debug!(
            peer = %client,
            backend = %backend_addr,
            error = %e,
            "UDP proxy: failed to forward first datagram to backend"
        );
        return;
    }

    sessions.insert(client, Arc::clone(&session));
    let mut buf = itoa::Buffer::new();
    let listener = buf.format(listener_port);
    metrics::udp_sessions_total()
        .with_label_values(&[listener])
        .inc();
    metrics::udp_sessions_active()
        .with_label_values(&[listener])
        .inc();

    run_reply_pump(
        listener_socket,
        session,
        client,
        sessions,
        idle_timeout,
        listener_port,
    )
    .await;
}

/// Pump replies from one session's backend-bound socket back to the client via
/// the shared listener socket. Exits (and evicts the session) on a recv error
/// or once `idle_timeout` has genuinely elapsed since the last client datagram.
async fn run_reply_pump(
    listener_socket: Arc<UdpSocket>,
    session: Arc<UdpSession>,
    client: SocketAddr,
    sessions: Arc<SessionMap>,
    idle_timeout: Duration,
    listener_port: u16,
) {
    let mut buf = vec![0u8; SESSION_REPLY_BUF];
    loop {
        match timeout(idle_timeout, session.upstream.recv(&mut buf)).await {
            Ok(Ok(n)) => {
                if let Err(e) = listener_socket.send_to(&buf[..n], client).await {
                    debug!(
                        peer = %client,
                        port = listener_port,
                        error = %e,
                        "UDP proxy: failed to send reply to client"
                    );
                }
            }
            Ok(Err(e)) => {
                debug!(
                    peer = %client,
                    port = listener_port,
                    error = %e,
                    "UDP proxy: upstream recv error, tearing down session"
                );
                break;
            }
            Err(_) => {
                // Idle-timeout tick: a fresh client datagram may have bumped
                // `last_seen` after this recv() was already parked, so check
                // real elapsed idle time before tearing down.
                if session.last_seen.lock().elapsed() >= idle_timeout {
                    break;
                }
            }
        }
    }

    // Two datagrams racing on the same brand-new client (e.g. a client that
    // retries before its first send's session finished establishing) can spawn
    // two competing sessions for one key; the later insert wins the map entry.
    // Remove only if we still own it, so this task's teardown can never evict
    // a *different*, still-live session that happens to share our client key.
    sessions.remove_if(&client, |_, entry| Arc::ptr_eq(entry, &session));
    let mut buf = itoa::Buffer::new();
    let listener = buf.format(listener_port);
    metrics::udp_sessions_active()
        .with_label_values(&[listener])
        .dec();
}
