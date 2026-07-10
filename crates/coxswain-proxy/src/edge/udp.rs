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

/// Max UDP datagram size (theoretical max payload for a UDP packet).
const MAX_DATAGRAM: usize = 65535;

/// Maximum concurrent sessions per listener. A client beyond this limit has its
/// datagram dropped (logged) rather than evicting an existing session — mirrors
/// `MAX_CONCURRENT_CONNECTIONS` in `edge::accept`.
const MAX_CONCURRENT_SESSIONS: usize = 4096;

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
                        )
                        .await;
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
/// or create a new session (backend pick + upstream bind/connect) if this is
/// the first datagram from `client`.
async fn handle_datagram(state: ListenerState<'_>, client: SocketAddr, payload: &[u8]) {
    let ListenerState {
        socket: listener_socket,
        table,
        sessions,
        pump_tasks,
        listener_port,
        idle_timeout,
    } = state;

    // Fast path: existing session. Clone the Arc and drop the DashMap guard
    // before awaiting — holding a shard guard across `.await` would stall any
    // writer (e.g. the reply-pump's eviction) on the same shard for the
    // duration of the send.
    if let Some(entry) = sessions.get(&client) {
        let session = Arc::clone(&entry);
        drop(entry);
        *session.last_seen.lock() = Instant::now();
        if let Err(e) = session.upstream.send(payload).await {
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
    if let Err(e) = session.upstream.send(payload).await {
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

    let pump_socket = Arc::clone(listener_socket);
    let pump_sessions = Arc::clone(sessions);
    pump_tasks.spawn(async move {
        run_reply_pump(
            pump_socket,
            session,
            client,
            pump_sessions,
            idle_timeout,
            listener_port,
        )
        .await;
    });
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
    let mut buf = vec![0u8; MAX_DATAGRAM];
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

    sessions.remove(&client);
    let mut buf = itoa::Buffer::new();
    let listener = buf.format(listener_port);
    metrics::udp_sessions_active()
        .with_label_values(&[listener])
        .dec();
}
