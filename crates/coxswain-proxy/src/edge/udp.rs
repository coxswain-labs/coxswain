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
//! # Every session resource is owned by one guard
//!
//! An admitted session holds three coupled resources: a [`MAX_CONCURRENT_SESSIONS`]
//! permit, an entry in the session map, and a unit of
//! `coxswain_proxy_udp_sessions_active`. [`SessionGuard`] owns all three, so
//! they are acquired and released together on *every* teardown path — including
//! the drain abort that cancels a reply pump mid-`recv()`, where straight-line
//! cleanup code after the pump loop would simply never run.
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
//! The abort is followed by a *reap*, which is not a drain window: no
//! forwarding continues, and an aborted task cannot progress past the await it
//! is parked on. `JoinSet::abort_all` only *schedules* cancellation, so the
//! reap is what forces every [`SessionGuard`] to have run by the time the
//! listener decrements its own gauge — making the session gauge exact when the
//! listener exits rather than some time afterwards.
//!
//! # Zero-crash bar
//!
//! Every path that discards a datagram (no route, empty backend group, session
//! limit, bind/connect/send error, and a reply that could not be delivered)
//! drops it and increments
//! `coxswain_proxy_udp_datagrams_dropped_total{listener, reason}` — nothing on
//! this path may panic or call `.unwrap()`. Most log at `debug`: for UDP these
//! are ordinary, expected events and the counter is the alertable signal.
//! `session_limit` is the exception and logs at `warn`, because it means the
//! listener is saturated rather than that UDP is being UDP.
//!
//! A session *teardown* (an upstream recv error) is not a datagram drop and is
//! deliberately not counted there — it is visible instead as
//! `coxswain_proxy_udp_sessions_active` falling while `_total` keeps climbing,
//! i.e. re-establishment churn.

use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use dashmap::DashMap;
use parking_lot::Mutex;
use tokio::net::UdpSocket;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tokio::task::JoinSet;
use tokio::time::timeout;
use tokio_util::sync::CancellationToken;
use tracing::debug;

use coxswain_core::routing::{Selected, SharedUdpRouteTable};

use crate::edge::accept::release_listener_slot;
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

/// Maximum sessions *admitted* concurrently per listener. A client beyond this
/// limit has its datagram dropped (logged, counted) rather than evicting an
/// existing session.
///
/// Mirrors `MAX_CONCURRENT_CONNECTIONS` in [`crate::edge::accept`] — both the
/// constant and its `Semaphore` + `try_acquire_owned` admission mechanism —
/// sized down from that sibling's 4096 because each established UDP session
/// pins a full [`SESSION_REPLY_BUF`] (64 KiB) for its lifetime, unlike a TCP
/// connection's transient splice buffer: 2048 × 64 KiB ≈ 128 MiB per listener
/// worst case. Like its TCP sibling the bound is **per listener**, so a Gateway
/// serving several UDP ports scales that figure linearly — it is a per-listener
/// blast-radius cap, not a pod-wide memory budget, and sizing it against the
/// chart's 256Mi default only holds for a single-listener proxy.
///
/// The permit is taken in [`handle_datagram`] *before* the setup task is
/// spawned, so the bound also covers sessions still binding or connecting, which
/// have not yet allocated a reply buffer. It cannot be enforced by counting the
/// session map instead: the insert happens inside the spawned task, so a
/// fresh-session burst would read a stale-low count and spawn tasks and
/// ephemeral fds without limit.
///
/// Because admission precedes establishment, `coxswain_proxy_udp_sessions_active`
/// — which counts only *established* sessions — reads below the permit count by
/// design and cannot be used to detect saturation. The `session_limit` reason on
/// `coxswain_proxy_udp_datagrams_dropped_total` is the signal for that.
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
    session_limit: &'a Arc<Semaphore>,
    pump_tasks: &'a mut JoinSet<()>,
    listener_port: u16,
    idle_timeout: Duration,
}

/// One admitted-but-not-yet-established session: everything the spawned setup
/// task owns from the moment [`handle_datagram`] admits it.
///
/// Grouped because threading the admission permit past [`handle_datagram`] put
/// [`establish_and_run_session`] over the workspace `clippy::too_many_arguments`
/// limit — and because `permit` *must* travel with the rest: it is what makes
/// every early-return path in that function give the slot back.
/// [`ListenerState`] cannot serve here: it borrows, so it cannot cross a spawn.
struct PendingSession {
    listener_socket: Arc<UdpSocket>,
    sessions: Arc<SessionMap>,
    client: SocketAddr,
    backend_addr: SocketAddr,
    payload: Vec<u8>,
    idle_timeout: Duration,
    listener_port: u16,
    permit: OwnedSemaphorePermit,
}

/// Record one dropped datagram on
/// `coxswain_proxy_udp_datagrams_dropped_total{listener, reason}`.
///
/// `reason` is `&'static str` and the port renders through [`itoa::Buffer`], so
/// this allocates nothing — it sits only on drop paths, never on the forwarding
/// success path.
fn record_drop(listener_port: u16, reason: &'static str) {
    let mut buf = itoa::Buffer::new();
    metrics::udp_datagrams_dropped_total()
        .with_label_values(&[buf.format(listener_port), reason])
        .inc();
}

/// RAII guard owning one live session's three coupled resources: its
/// [`MAX_CONCURRENT_SESSIONS`] admission slot, its entry in the session map, and
/// its unit of `coxswain_proxy_udp_sessions_active{listener}`.
///
/// It exists because the reply-pump task is *aborted*, not asked to stop: drain
/// calls `JoinSet::abort_all` while the pump is parked in `recv()`, so cleanup
/// written as straight-line code after the pump loop never runs. The gauge is a
/// registry series keyed by port, so a re-added listener on the same port
/// inherits the leak and it compounds across reconciles instead of self-healing.
/// Binding cleanup to `Drop` makes it run on every termination path: idle
/// timeout, upstream recv error, drain abort, panic. Mirrors `ConnectionGuard`
/// in [`crate::edge::accept`], whose doc cites the same drain-abort reason.
///
/// Constructing the guard is what *establishes* the session — `new` performs the
/// map insert and both metric increments — so the entry and the gauge can never
/// drift apart.
#[must_use = "a SessionGuard that is dropped immediately establishes and instantly tears down the session"]
struct SessionGuard {
    sessions: Arc<SessionMap>,
    session: Arc<UdpSession>,
    client: SocketAddr,
    listener_port: u16,
    /// Held purely so the admission slot is returned when the guard drops.
    /// `Drop::drop`'s body runs before any field is dropped, so the slot is
    /// always released after the map removal and the gauge decrement below,
    /// wherever this field is declared.
    _permit: OwnedSemaphorePermit,
}

impl SessionGuard {
    /// Establish `session` for `client`: insert it into the map and count it.
    fn new(
        sessions: Arc<SessionMap>,
        session: Arc<UdpSession>,
        client: SocketAddr,
        listener_port: u16,
        permit: OwnedSemaphorePermit,
    ) -> Self {
        sessions.insert(client, Arc::clone(&session));
        let mut buf = itoa::Buffer::new();
        let listener = buf.format(listener_port);
        metrics::udp_sessions_total()
            .with_label_values(&[listener])
            .inc();
        metrics::udp_sessions_active()
            .with_label_values(&[listener])
            .inc();
        Self {
            sessions,
            session,
            client,
            listener_port,
            _permit: permit,
        }
    }
}

impl Drop for SessionGuard {
    fn drop(&mut self) {
        // Two datagrams racing on the same brand-new client (e.g. a client that
        // retries before its first send's session finished establishing) can spawn
        // two competing sessions for one key; the later insert wins the map entry.
        // Remove only if we still own it, so this teardown can never evict
        // a *different*, still-live session that happens to share our client key.
        self.sessions
            .remove_if(&self.client, |_, entry| Arc::ptr_eq(entry, &self.session));

        // Unconditional, even when the `remove_if` above matched nothing: `new`
        // incremented unconditionally, so a race loser that skipped this would
        // leak the unit. It is also what the gauge means — during such a race two
        // sockets and two reply buffers are genuinely live for one client key, so
        // the gauge counts resources, not map keys, and may briefly exceed
        // `sessions.len()`.
        let mut buf = itoa::Buffer::new();
        metrics::udp_sessions_active()
            .with_label_values(&[buf.format(self.listener_port)])
            .dec();
    }
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
    let session_limit = Arc::new(Semaphore::new(MAX_CONCURRENT_SESSIONS));
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
                                session_limit: &session_limit,
                                pump_tasks: &mut pump_tasks,
                                listener_port,
                                idle_timeout,
                            },
                            client,
                            &buf[..n],
                        );
                    }
                    Err(e) => {
                        // On an unconnected socket the realistic causes are
                        // ENOBUFS/ENOMEM: a datagram the kernel genuinely lost.
                        debug!(port = listener_port, error = %e, "UDP proxy: recv error");
                        record_drop(listener_port, "recv_error");
                    }
                }
            }

            // Reap completed reply-pump tasks.
            Some(_) = pump_tasks.join_next(), if !pump_tasks.is_empty() => {}
        }
    }

    // No graceful drain window for UDP (see module doc) — abort every in-flight
    // reply-pump task and let the shared socket drop with it.
    pump_tasks.abort_all();
    // Reap, not drain: an aborted task cannot progress past the await it is
    // parked on, so this costs one poll each. It is what forces every
    // `SessionGuard` to have run before this listener exits, so the session
    // gauge is exact at return rather than eventually.
    while pump_tasks.join_next().await.is_some() {}

    // Only a reconcile-driven removal moved this listener to `draining`; a global
    // shutdown left it `serving`. `release_listener_slot` decrements whichever it
    // actually holds. No `drain_duration` sample: UDP has no drain window to
    // measure (see above), so a ~0 observation would be noise, not signal.
    if drain_token.is_cancelled() {
        metrics::lifecycle()
            .with_label_values(&["drain_completed"])
            .inc();
    }
    release_listener_slot(&drain_token);
}

/// Handle one inbound datagram: forward it on the client's existing session,
/// or spawn a new session (backend pick + upstream bind/connect) if this is
/// the first datagram from `client`.
///
/// Deliberately synchronous (no `.await`): this is called from the single
/// per-listener recv loop, so anything awaited here blocks that loop from
/// picking up the *next* client's datagram. Repeat traffic on an existing
/// session uses [`UdpSocket::try_send`] (non-blocking — UDP's kernel send
/// buffer accepts near-unconditionally), and new-session admission uses
/// [`Semaphore::try_acquire_owned`], also non-blocking. A brand-new session
/// needs bind + connect, which are real (if fast) async operations, so that
/// work — and the session's entire reply-pump lifetime — runs in its own
/// spawned task instead of inline here. Without this, N clients opening fresh
/// sessions concurrently (exactly the Gateway API weighted-routing conformance
/// test's traffic shape: one new UDP socket per probe) would have their session
/// setup serialized through this one loop, queuing later arrivals long enough
/// to blow past the client's own read timeout.
fn handle_datagram(state: ListenerState<'_>, client: SocketAddr, payload: &[u8]) {
    let ListenerState {
        socket: listener_socket,
        table,
        sessions,
        session_limit,
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
            record_drop(listener_port, "session_send");
        }
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
            record_drop(listener_port, "no_route");
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
            record_drop(listener_port, "no_backend");
            return;
        }
    };

    // Admission, after the route rejects above so a permit's lifetime maps
    // exactly to "a setup task exists". `try_acquire_owned` is non-blocking, so
    // the recv loop stays await-free, and the permit travels with the task —
    // covering the bind/connect window a session-map count cannot see (see
    // `MAX_CONCURRENT_SESSIONS`).
    let permit = match Arc::clone(session_limit).try_acquire_owned() {
        Ok(p) => p,
        Err(_) => {
            tracing::warn!(
                peer = %client,
                port = listener_port,
                limit = MAX_CONCURRENT_SESSIONS,
                "UDP proxy: session limit reached, dropping datagram"
            );
            record_drop(listener_port, "session_limit");
            return;
        }
    };

    pump_tasks.spawn(establish_and_run_session(PendingSession {
        listener_socket: Arc::clone(listener_socket),
        sessions: Arc::clone(sessions),
        client,
        backend_addr,
        payload: payload.to_vec(),
        idle_timeout,
        listener_port,
        permit,
    }));
}

/// Bind + connect a fresh upstream socket for a new session, forward its
/// first datagram, establish the session, then run its reply pump for the
/// rest of the session's lifetime — all in one spawned task so the recv loop
/// in [`run_udp_listener`] never waits on it (see [`handle_datagram`]).
///
/// Every early return below drops this frame, and with it `pending`'s permit,
/// returning the admission slot: nothing was established yet, so there is
/// nothing else to undo. Once the first datagram is away, [`SessionGuard`]
/// takes custody of the permit, the map entry and the gauge together.
async fn establish_and_run_session(pending: PendingSession) {
    let PendingSession {
        listener_socket,
        sessions,
        client,
        backend_addr,
        payload,
        idle_timeout,
        listener_port,
        permit,
    } = pending;

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
            record_drop(listener_port, "upstream_bind");
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
        record_drop(listener_port, "upstream_connect");
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
        record_drop(listener_port, "upstream_send");
        return;
    }
    // The first datagram is away, but this `Vec` — up to `MAX_DATAGRAM` — is a
    // local in the same scope as the pump await below, and Rust drops locals at
    // scope end rather than last use. Left alone it would sit pinned beside the
    // session's reply buffer for the whole session, doubling the per-session
    // footprint `MAX_CONCURRENT_SESSIONS` is sized against.
    drop(payload);

    // Custody transfer. The guard lives in this frame, so it is alive across the
    // pump's await below — including when drain aborts the whole future tree.
    let _guard = SessionGuard::new(
        sessions,
        Arc::clone(&session),
        client,
        listener_port,
        permit,
    );
    run_reply_pump(
        listener_socket,
        session,
        client,
        idle_timeout,
        listener_port,
    )
    .await;
}

/// Pump replies from one session's backend-bound socket back to the client via
/// the shared listener socket. Exits on a recv error or once `idle_timeout` has
/// genuinely elapsed since the last client datagram.
///
/// Teardown is not this function's job: the [`SessionGuard`] its caller holds
/// releases the session on every exit path, including the abort that cancels
/// this pump mid-`recv()`.
async fn run_reply_pump(
    listener_socket: Arc<UdpSocket>,
    session: Arc<UdpSession>,
    client: SocketAddr,
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
                    record_drop(listener_port, "client_send");
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
}

#[cfg(test)]
mod tests {
    use super::*;
    use coxswain_core::routing::{BackendGroup, UdpRouteTableBuilder};

    /// Read the live `udp_sessions_active` value for one listener port. Tests use
    /// disjoint ports so this global registry gauge stays test-local.
    fn active_sessions(listener_port: u16) -> i64 {
        let mut buf = itoa::Buffer::new();
        metrics::udp_sessions_active()
            .with_label_values(&[buf.format(listener_port)])
            .get()
    }

    /// Bind a throwaway loopback socket to stand in for a session's upstream.
    async fn session() -> Arc<UdpSession> {
        let upstream = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("loopback bind succeeds in tests");
        Arc::new(UdpSession {
            upstream,
            last_seen: Mutex::new(Instant::now()),
        })
    }

    fn client(port: u16) -> SocketAddr {
        (Ipv4Addr::LOCALHOST, port).into()
    }

    /// The regression this pins: the session bound must be enforced where a
    /// session is *admitted*, not where it lands in the map.
    ///
    /// `handle_datagram` is synchronous, so between these two calls no spawned
    /// task has run and `sessions.len()` is still 0. The old `sessions.len() >=
    /// MAX_CONCURRENT_SESSIONS` check therefore read stale-low and admitted both
    /// — which is the whole TOCTOU: under a fresh-session burst the map count
    /// never catches up, and the listener spawns tasks and ephemeral fds without
    /// limit. Only a permit taken before the spawn can see the second datagram
    /// for what it is.
    #[tokio::test]
    async fn admission_bound_holds_before_any_session_reaches_the_map() {
        const PORT: u16 = 9004;

        let backend = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("loopback bind succeeds in tests");
        let backend_addr = backend.local_addr().expect("bound socket has an addr");
        let table: SharedUdpRouteTable = SharedUdpRouteTable::new();
        table.store(Arc::new(
            UdpRouteTableBuilder::new()
                .add_route(
                    PORT,
                    Arc::new(BackendGroup::new("test".into(), vec![backend_addr])),
                )
                .build(),
        ));

        let socket = Arc::new(
            UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
                .await
                .expect("loopback bind succeeds in tests"),
        );
        let sessions: Arc<SessionMap> = Arc::new(DashMap::new());
        // A bound of exactly 1 makes the second datagram the one that must fail.
        let session_limit = Arc::new(Semaphore::new(1));
        let mut pump_tasks: JoinSet<()> = JoinSet::new();

        let deliver = |client: SocketAddr, pump_tasks: &mut JoinSet<()>| {
            handle_datagram(
                ListenerState {
                    socket: &socket,
                    table: &table,
                    sessions: &sessions,
                    session_limit: &session_limit,
                    pump_tasks,
                    listener_port: PORT,
                    idle_timeout: Duration::from_secs(3600),
                },
                client,
                b"ping",
            );
        };

        deliver(client(4001), &mut pump_tasks);
        deliver(client(4002), &mut pump_tasks);

        assert_eq!(
            sessions.len(),
            0,
            "neither spawned task can have run yet — `handle_datagram` is \
             synchronous and this test has not awaited. This is precisely the \
             window in which the old `sessions.len()` check read stale-low."
        );
        assert_eq!(
            pump_tasks.len(),
            1,
            "the second datagram must be refused at admission against a bound of \
             1; spawning it anyway is the TOCTOU — under a burst the map count \
             stays low and the listener spawns tasks and fds without limit"
        );

        pump_tasks.abort_all();
        while pump_tasks.join_next().await.is_some() {}
    }

    #[tokio::test]
    async fn guard_drop_releases_permit_and_evicts_own_session() {
        let sessions: Arc<SessionMap> = Arc::new(DashMap::new());
        let sem = Arc::new(Semaphore::new(1));
        let s = session().await;
        let peer = client(1111);

        let guard = SessionGuard::new(
            Arc::clone(&sessions),
            Arc::clone(&s),
            peer,
            9001,
            Arc::clone(&sem)
                .try_acquire_owned()
                .expect("bound of 1 admits the first session"),
        );
        assert!(
            sessions.contains_key(&peer),
            "SessionGuard::new must establish the session by inserting it"
        );
        assert!(
            Arc::clone(&sem).try_acquire_owned().is_err(),
            "a live session must hold its admission slot"
        );

        drop(guard);

        assert!(
            !sessions.contains_key(&peer),
            "dropping the guard must evict the session it owns"
        );
        assert!(
            Arc::clone(&sem).try_acquire_owned().is_ok(),
            "dropping the guard must return its admission slot"
        );
    }

    #[tokio::test]
    async fn drain_abort_releases_a_session_parked_in_the_reply_pump() {
        // The regression this pins: drain aborts the pump while it is parked at
        // `timeout(idle_timeout, recv()).await`, so teardown written as
        // straight-line code after the pump loop never runs — leaking the
        // session's map entry, its admission slot, and its gauge unit. Drives the
        // real `establish_and_run_session` so the whole custody chain is covered.
        let sessions: Arc<SessionMap> = Arc::new(DashMap::new());
        let sem = Arc::new(Semaphore::new(1));
        let peer = client(3333);

        let listener_socket = Arc::new(
            UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
                .await
                .expect("loopback bind succeeds in tests"),
        );
        // Receives the first datagram but never replies, so the pump parks.
        let backend = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("loopback bind succeeds in tests");
        let backend_addr = backend.local_addr().expect("bound socket has an addr");

        let mut pump_tasks: JoinSet<()> = JoinSet::new();
        pump_tasks.spawn(establish_and_run_session(PendingSession {
            listener_socket,
            sessions: Arc::clone(&sessions),
            client: peer,
            backend_addr,
            payload: b"ping".to_vec(),
            // Long enough that only the abort can end this session.
            idle_timeout: Duration::from_secs(3600),
            listener_port: 9003,
            permit: Arc::clone(&sem)
                .try_acquire_owned()
                .expect("bound of 1 admits the first session"),
        }));

        timeout(Duration::from_secs(5), async {
            while !sessions.contains_key(&peer) {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("the session establishes and inserts itself");
        assert!(
            Arc::clone(&sem).try_acquire_owned().is_err(),
            "an established session must hold its admission slot"
        );
        assert_eq!(
            active_sessions(9003),
            1,
            "an established session must be counted on udp_sessions_active"
        );

        pump_tasks.abort_all();
        while pump_tasks.join_next().await.is_some() {}

        assert!(
            !sessions.contains_key(&peer),
            "drain abort must still evict the session; the pump was cancelled at \
             its recv() await, so only a Drop guard can do this"
        );
        assert!(
            Arc::clone(&sem).try_acquire_owned().is_ok(),
            "drain abort must still return the admission slot, or a listener that \
             is re-added on this port starts already saturated"
        );
        assert_eq!(
            active_sessions(9003),
            0,
            "drain abort must return udp_sessions_active to zero — this gauge is \
             the leak #618 is about: it is keyed by port, so a listener re-added \
             on this port inherits the drift and it compounds per reconcile"
        );
    }

    #[tokio::test]
    async fn guard_drop_never_evicts_a_competing_session_on_the_same_key() {
        // Two datagrams racing on one brand-new client key: the later insert
        // wins the map entry, and the loser's teardown must not evict it.
        let sessions: Arc<SessionMap> = Arc::new(DashMap::new());
        let sem = Arc::new(Semaphore::new(2));
        let peer = client(2222);

        let loser = session().await;
        let winner = session().await;

        let loser_guard = SessionGuard::new(
            Arc::clone(&sessions),
            Arc::clone(&loser),
            peer,
            9002,
            Arc::clone(&sem)
                .try_acquire_owned()
                .expect("slot available"),
        );
        let winner_guard = SessionGuard::new(
            Arc::clone(&sessions),
            Arc::clone(&winner),
            peer,
            9002,
            Arc::clone(&sem)
                .try_acquire_owned()
                .expect("slot available"),
        );
        assert_eq!(
            active_sessions(9002),
            2,
            "both racers are genuinely live — two sockets, two reply buffers — so \
             the gauge counts resources, not map keys, and may exceed sessions.len()"
        );

        drop(loser_guard);

        let held = sessions.get(&peer).expect(
            "the loser's teardown must leave the winner's entry in place — \
             evicting it would silently blackhole a live session",
        );
        assert!(
            Arc::ptr_eq(&held, &winner),
            "the surviving entry must be the winner's session, not the loser's"
        );
        drop(held);
        assert_eq!(
            active_sessions(9002),
            1,
            "the loser's gauge unit must be released even though its remove_if \
             matched nothing; making the dec conditional on that removal — the \
             natural-looking cleanup — leaks one unit per race, forever"
        );

        drop(winner_guard);
        assert!(
            !sessions.contains_key(&peer),
            "the winner's own teardown must evict its entry"
        );
        assert_eq!(
            active_sessions(9002),
            0,
            "every established session must return its gauge unit"
        );
    }
}
