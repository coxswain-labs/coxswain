#![allow(missing_docs)]
//! #603 relay fan-out capacity load-test harness: measures a relay replica's
//! real broadcast capacity — p99 change-to-delivery latency, relay process
//! CPU/mem, and egress bytes — as a function of subscriber count `N` and
//! routing-churn rate, to pick a measured default for
//! `--relay-target-proxies-per-replica` (superseding the provisional 50 from
//! #602).
//!
//! Not a `criterion` micro-bench (`harness = false`): a relay is a fan-out
//! cache whose cost is I/O + serialization on change, not a hot function to
//! call in a loop, so this drives real gRPC connections against a real OS
//! process instead.
//!
//! # Design
//!
//! This binary re-execs itself into two roles:
//!
//! - **Server** (`--server`, spawned internally — never invoke by hand): runs
//!   the actual [`coxswain_discovery::server::DiscoveryService`] fan-out
//!   engine (the exact broadcast/serialize/push code path a real relay runs
//!   downstream) plaintext on a loopback port, over a synthetic
//!   `--world-size`-route ingress world. `serve relay` itself can't run
//!   standalone — its downstream mTLS serving cert is a bootstrapped rotating
//!   SVID that requires a live controller — so this drives `DiscoveryService`
//!   directly, the same substrate `server.rs`'s own test harness uses,
//!   fronted by a real child OS process so CPU/mem are isolable from the
//!   driver. If `--churn-rate > 0`, it rewrites one probe host's route
//!   `route_id` to `probe-<push_wallclock_nanos>` on every tick — every other
//!   host is spliced from the previous compiled table
//!   ([`IngressRoutingTable::get_compiled`] / `insert_compiled_exact_host`,
//!   the #511 partitioned-rebuild reuse path) so churn-tick cost stays O(1)
//!   in world size and doesn't contaminate the CPU measurement.
//! - **Driver** (default role): for each (subscriber count, churn rate) cell,
//!   spawns a fresh server child, opens `N` independent gRPC channels (one
//!   real subscriber each, `Scope::SharedPool`, raw generated client — no
//!   apply pipeline needed, delivery is what's measured, apply cost is
//!   already covered by `benches/delta_apply.rs`), samples the child's
//!   CPU/mem via `sysinfo`, and on every delivered `Snapshot` decodes the
//!   probe marker for latency and sums `Message::encoded_len()` for egress.
//!
//! Run: `cargo bench -p coxswain-discovery --bench relay_fanout -- --help`.
//! See `DEVELOPMENT.md` "Relay fan-out load test" for the full recipe and the
//! "do not commit numbers" convention — post results as a #603 comment.

use std::env;
use std::io::Write as _;
use std::net::SocketAddr;
use std::process::Stdio;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use clap::Parser;
use prost::Message as _;
use sysinfo::{Pid, ProcessesToUpdate, System};
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::net::TcpListener;
use tokio::process::{Child, Command};
use tokio::sync::watch;
use tokio_stream::wrappers::{ReceiverStream, TcpListenerStream};
use tonic::transport::{Endpoint, Server};

use coxswain_core::dedicated_registry::DedicatedRoutingRegistry;
use coxswain_core::listener_status::SharedGatewayListenerStatus;
use coxswain_core::node_registry::SharedNodeRegistry;
use coxswain_core::publish_index::SharedGatewayPublishIndex;
use coxswain_core::routing::{
    BackendGroup, IngressRoutingTable, IngressRoutingTableBuilder, PortTableBuilder, RouteEntry,
    SharedGatewayRoutingTable, SharedIngressRoutingTable, SharedTcpRouteTable,
    SharedTlsPassthroughTable, SharedUdpRouteTable, WildcardKind,
};
use coxswain_core::tls::{SharedClientCertStore, SharedPortTlsStore};
use coxswain_discovery::proto::v1::{
    self as p, client_message::Kind as CKind, discovery_client::DiscoveryClient as TonicClient,
    discovery_server::DiscoveryServer, server_message::Kind as SKind,
};
use coxswain_discovery::{DiscoveryService, Scope, SnapshotSource, WIRE_VERSION, scope_to_wire};

/// Fixed hostname the churn loop rewrites every tick; every other host in the
/// synthetic world is a static, never-changing filler route.
const PROBE_HOST: &str = "probe.relay-fanout.example.com";
const LISTEN_PORT: u16 = 80;

#[derive(Parser, Debug)]
#[command(
    name = "relay_fanout",
    about = "Relay fan-out capacity load-test harness (#603): p99 delivery \
             latency, relay CPU/mem, and egress vs subscriber count and \
             churn rate."
)]
struct Cli {
    /// Internal: re-exec as the fan-out server under test. Never pass by hand
    /// — the driver sets this when it spawns its own child process.
    #[arg(long, hide = true)]
    server: bool,

    /// Synthetic ingress world size (route count) the relay serves.
    #[arg(long, default_value_t = 500)]
    world_size: usize,

    /// Server role only: full-snapshot churn rate in changes/sec (0 = idle).
    #[arg(long, default_value_t = 0.0)]
    churn_rate: f64,

    /// Driver role only: subscriber counts to sweep.
    #[arg(long, value_delimiter = ',', default_value = "10,50,100,250,500,1000")]
    subscribers: Vec<usize>,

    /// Driver role only: churn rates (changes/sec) to sweep; 0 = idle.
    #[arg(long, value_delimiter = ',', default_value = "0,1,10")]
    churn_rates: Vec<f64>,

    /// Driver role only: how long to hold each (N, rate) cell before the
    /// child server is torn down and the next cell starts.
    #[arg(long, default_value_t = 10)]
    duration_secs: u64,
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();
    if cli.server {
        run_server(cli.world_size, cli.churn_rate).await;
        return;
    }
    run_driver(&cli).await;
}

// ── driver role ─────────────────────────────────────────────────────────────

async fn run_driver(cli: &Cli) {
    let exe = env::current_exe().unwrap_or_else(|e| panic!("current_exe: {e}"));
    let duration = Duration::from_secs(cli.duration_secs);

    println!(
        "{:>6}  {:>8}  {:>9}  {:>9}  {:>8}  {:>10}  {:>13}  {:>10}",
        "N", "churn/s", "p50(ms)", "p99(ms)", "cpu(%)", "mem(MB)", "egress(KB/s)", "snapshots"
    );
    for &rate in &cli.churn_rates {
        for &n in &cli.subscribers {
            let cell = run_cell(&exe, cli.world_size, rate, n, duration).await;
            print_cell(n, rate, &cell);
        }
    }
}

/// One (subscriber count, churn rate) measurement: spawn a fresh relay
/// server, attach `n_subscribers` real gRPC subscribers, hold for
/// `duration`, sample CPU/mem, tear down.
async fn run_cell(
    server_bin: &std::path::Path,
    world_size: usize,
    churn_rate: f64,
    n_subscribers: usize,
    duration: Duration,
) -> CellResult {
    let mut child = spawn_server(server_bin, world_size, churn_rate).await;
    let (port, pid) = read_port_pid(&mut child).await;
    let addr: SocketAddr = format!("127.0.0.1:{port}")
        .parse()
        .unwrap_or_else(|e| panic!("loopback addr: {e}"));

    let (stop_tx, stop_rx) = watch::channel(false);
    let mut handles = Vec::with_capacity(n_subscribers);
    for i in 0..n_subscribers {
        let node_id = format!("loadtest-{i}");
        handles.push(tokio::spawn(run_subscriber(addr, node_id, stop_rx.clone())));
    }

    // Let every subscriber finish its initial connect + full-snapshot Ack
    // before sampling starts, so steady-state CPU/mem isn't skewed by the
    // connect stampede.
    tokio::time::sleep(Duration::from_millis(200)).await;

    let mut sys = System::new_all();
    let sys_pid = Pid::from_u32(pid);
    let mut cpu_samples = Vec::new();
    let mut mem_samples = Vec::new();
    let deadline = Instant::now() + duration;
    while Instant::now() < deadline {
        tokio::time::sleep(Duration::from_millis(500)).await;
        sys.refresh_processes(ProcessesToUpdate::Some(&[sys_pid]), true);
        if let Some(proc) = sys.process(sys_pid) {
            cpu_samples.push(proc.cpu_usage());
            mem_samples.push(proc.memory());
        }
    }

    stop_tx.send(true).ok();
    let mut stats = Vec::with_capacity(n_subscribers);
    for h in handles {
        if let Ok(s) = h.await {
            stats.push(s);
        }
    }

    let _ = child.start_kill();
    let _ = child.wait().await;

    aggregate(&stats, &cpu_samples, &mem_samples, duration)
}

async fn spawn_server(bin: &std::path::Path, world_size: usize, churn_rate: f64) -> Child {
    Command::new(bin)
        .arg("--server")
        .arg("--world-size")
        .arg(world_size.to_string())
        .arg("--churn-rate")
        .arg(churn_rate.to_string())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .kill_on_drop(true)
        .spawn()
        .unwrap_or_else(|e| panic!("spawn relay-under-test subprocess: {e}"))
}

/// Read the server's `PORT <n>` / `PID <n>` announcement lines off its
/// stdout (see [`run_server`]'s flushed startup banner).
async fn read_port_pid(child: &mut Child) -> (u16, u32) {
    let stdout = child.stdout.take().unwrap_or_else(|| {
        panic!("relay-under-test subprocess stdout was not piped");
    });
    let mut lines = BufReader::new(stdout).lines();
    let mut port = None;
    let mut pid = None;
    while port.is_none() || pid.is_none() {
        let Some(line) = lines.next_line().await.unwrap_or(None) else {
            break;
        };
        if let Some(v) = line.strip_prefix("PORT ") {
            port = v.trim().parse().ok();
        } else if let Some(v) = line.strip_prefix("PID ") {
            pid = v.trim().parse().ok();
        }
    }
    (
        port.unwrap_or_else(|| panic!("relay-under-test never reported PORT on stdout")),
        pid.unwrap_or_else(|| panic!("relay-under-test never reported PID on stdout")),
    )
}

/// Per-subscriber accumulated observations over one cell's run.
#[derive(Default)]
struct SubscriberStats {
    latencies_ms: Vec<f64>,
    egress_bytes: u64,
    snapshots: u64,
}

/// One synthetic subscriber: connects `Scope::SharedPool`, Acks every
/// received `Snapshot`, records fan-out latency off the probe marker and
/// cumulative wire bytes, until `stop_rx` flips.
async fn run_subscriber(
    addr: SocketAddr,
    node_id: String,
    mut stop_rx: watch::Receiver<bool>,
) -> SubscriberStats {
    let mut stats = SubscriberStats::default();

    let channel = Endpoint::from_shared(format!("http://{addr}"))
        .unwrap_or_else(|e| panic!("endpoint: {e}"))
        .connect_lazy();
    let mut client = TonicClient::new(channel);

    let (tx, rx) = tokio::sync::mpsc::channel::<p::ClientMessage>(16);
    tx.send(p::ClientMessage {
        kind: Some(CKind::Subscribe(p::Subscribe {
            node_id,
            wire_version: WIRE_VERSION,
            scope: Some(scope_to_wire(&Scope::SharedPool)),
        })),
    })
    .await
    .unwrap_or_else(|e| panic!("queue Subscribe: {e}"));

    let response = match client.stream(ReceiverStream::new(rx)).await {
        Ok(r) => r,
        Err(_) => return stats,
    };
    let mut inbound = response.into_inner();

    loop {
        tokio::select! {
            _ = stop_rx.changed() => break,
            result = inbound.message() => {
                let Ok(Some(msg)) = result else { break };
                let Some(SKind::Snapshot(snapshot)) = msg.kind else { continue };

                stats.snapshots += 1;
                stats.egress_bytes += u64::try_from(snapshot.encoded_len()).unwrap_or(u64::MAX);
                if let Some(pushed_nanos) = probe_marker(&snapshot) {
                    let now_nanos = SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_nanos();
                    let latency_ms = (now_nanos.saturating_sub(pushed_nanos)) as f64 / 1_000_000.0;
                    stats.latencies_ms.push(latency_ms);
                }

                if tx.send(p::ClientMessage {
                    kind: Some(CKind::Ack(p::Ack {
                        version: snapshot.version,
                        nonce: snapshot.nonce,
                    })),
                })
                .await
                .is_err()
                {
                    break;
                }
            }
        }
    }

    stats
}

/// Extract the push-time nanos the churn loop encoded into the probe host's
/// route `route_id` (`probe-<nanos>`), if this snapshot carries that host.
fn probe_marker(snapshot: &p::Snapshot) -> Option<u128> {
    snapshot.resources.iter().find_map(|r| {
        let p::resource::Payload::RouteHost(rh) = r.payload.as_ref()? else {
            return None;
        };
        let host = rh.host.as_ref()?;
        let p::host_entry::Pattern::Exact(name) = host.pattern.as_ref()? else {
            return None;
        };
        if name != PROBE_HOST {
            return None;
        }
        host.routes
            .first()?
            .route_id
            .strip_prefix("probe-")?
            .parse::<u128>()
            .ok()
    })
}

struct CellResult {
    p50_ms: Option<f64>,
    p99_ms: Option<f64>,
    avg_cpu_pct: f64,
    avg_mem_mb: f64,
    egress_kb_per_sec: f64,
    snapshots: u64,
}

fn aggregate(
    stats: &[SubscriberStats],
    cpu_samples: &[f32],
    mem_samples: &[u64],
    duration: Duration,
) -> CellResult {
    let mut latencies: Vec<f64> = stats
        .iter()
        .flat_map(|s| s.latencies_ms.iter().copied())
        .collect();
    latencies.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));

    let total_egress: u64 = stats.iter().map(|s| s.egress_bytes).sum();
    let snapshots: u64 = stats.iter().map(|s| s.snapshots).sum();

    let avg_cpu_pct = if cpu_samples.is_empty() {
        0.0
    } else {
        f64::from(cpu_samples.iter().sum::<f32>()) / cpu_samples.len() as f64
    };
    let avg_mem_mb = if mem_samples.is_empty() {
        0.0
    } else {
        let total: u64 = mem_samples.iter().sum();
        (total as f64 / mem_samples.len() as f64) / (1024.0 * 1024.0)
    };
    let egress_kb_per_sec = (total_egress as f64 / 1024.0) / duration.as_secs_f64().max(0.001);

    CellResult {
        p50_ms: percentile(&latencies, 0.50),
        p99_ms: percentile(&latencies, 0.99),
        avg_cpu_pct,
        avg_mem_mb,
        egress_kb_per_sec,
        snapshots,
    }
}

fn percentile(sorted: &[f64], q: f64) -> Option<f64> {
    if sorted.is_empty() {
        return None;
    }
    let idx = (((sorted.len() - 1) as f64) * q).round() as usize;
    sorted.get(idx).copied()
}

fn print_cell(n: usize, rate: f64, r: &CellResult) {
    println!(
        "{:>6}  {:>8.1}  {:>9}  {:>9}  {:>8.1}  {:>10.1}  {:>13.1}  {:>10}",
        n,
        rate,
        r.p50_ms
            .map_or_else(|| "-".to_string(), |v| format!("{v:.2}")),
        r.p99_ms
            .map_or_else(|| "-".to_string(), |v| format!("{v:.2}")),
        r.avg_cpu_pct,
        r.avg_mem_mb,
        r.egress_kb_per_sec,
        r.snapshots,
    );
}

// ── server role (the "relay under test") ───────────────────────────────────

/// Run the real `DiscoveryService` fan-out engine plaintext on a loopback
/// port, over a synthetic `world_size`-route ingress world. Prints
/// `PORT <n>` / `PID <n>` once bound (flushed — the driver reads these off a
/// piped, fully-buffered stdout), then serves until killed. If
/// `churn_rate > 0`, rewrites [`PROBE_HOST`]'s route every `1/churn_rate`
/// seconds.
async fn run_server(world_size: usize, churn_rate: f64) {
    let source = empty_source();
    let ingress = source.ingress.clone();
    let publish = source.publish.clone();
    let (rebuild_tx, rebuild_rx) = watch::channel(0u64);
    let registry = SharedNodeRegistry::new();

    // No probe host at startup: idle-mode subscribers must never see a probe
    // marker (there's no churn event to time), and a churning world adds the
    // probe host as a fresh resource on its first real tick instead of an
    // update to a meaningless sentinel.
    let initial = rebuild(&IngressRoutingTable::default(), world_size, None);
    let mut prev = Arc::new(initial);
    ingress.store(Arc::clone(&prev));

    let svc = DiscoveryService::new(source, registry, rebuild_rx);
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .unwrap_or_else(|e| panic!("bind loopback: {e}"));
    let addr = listener
        .local_addr()
        .unwrap_or_else(|e| panic!("local_addr: {e}"));

    println!("PORT {}", addr.port());
    println!("PID {}", std::process::id());
    std::io::stdout().flush().ok();

    tokio::spawn(
        Server::builder()
            .add_service(DiscoveryServer::new(svc))
            .serve_with_incoming(TcpListenerStream::new(listener)),
    );

    if churn_rate <= 0.0 {
        // Idle: serve the static world forever, measuring connection-hold
        // steady-state cost rather than change-delivery latency.
        std::future::pending::<()>().await;
        return;
    }

    let period = Duration::from_secs_f64((1.0 / churn_rate).max(0.001));
    let mut tick = tokio::time::interval(period);
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        tick.tick().await;
        let now_nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        let table = rebuild(&prev, world_size, Some(now_nanos));
        let next = Arc::new(table);
        ingress.store(Arc::clone(&next));
        prev = next;

        publish.stamp_rebuild(std::iter::empty());
        let next_gen = rebuild_tx.borrow().wrapping_add(1);
        rebuild_tx
            .send(next_gen)
            .unwrap_or_else(|e| panic!("rebuild watch send: {e}"));
    }
}

/// A `SnapshotSource` over freshly empty cells — every non-ingress cell stays
/// empty for the harness's whole run; only `ingress` and `publish` see
/// activity.
fn empty_source() -> SnapshotSource {
    SnapshotSource {
        ingress: SharedIngressRoutingTable::new(),
        gateway: SharedGatewayRoutingTable::new(),
        tls: SharedPortTlsStore::new(),
        client_certs: SharedClientCertStore::new(),
        listener_status: SharedGatewayListenerStatus::new(),
        dedicated: DedicatedRoutingRegistry::new(),
        passthrough_routes: SharedTlsPassthroughTable::new(),
        terminate_routes: SharedTlsPassthroughTable::new(),
        tcp_routes: SharedTcpRouteTable::new(),
        udp_routes: SharedUdpRouteTable::new(),
        publish: SharedGatewayPublishIndex::new(),
    }
}

/// Rebuild the `world_size`-host ingress world: every static host is spliced
/// in from `prev`'s already-compiled `HostRouter` (#511 reuse path, so churn
/// cost is O(1) in world size, not O(world_size)). `marker`, when present,
/// (re)writes [`PROBE_HOST`]'s route with a `route_id` carrying its nanos;
/// when absent, the probe host is omitted entirely — used for the startup
/// world so an idle relay's connect-time full snapshot never carries a
/// meaningless sentinel marker (see [`run_server`]).
fn rebuild(
    prev: &IngressRoutingTable,
    world_size: usize,
    marker: Option<u128>,
) -> IngressRoutingTable {
    let mut builder = IngressRoutingTableBuilder::new();
    let port_builder = builder.for_port(LISTEN_PORT);
    for i in 0..world_size {
        let host = format!("h{i}.relay-fanout.example.com");
        match prev.get_compiled(LISTEN_PORT, Some(&host), WildcardKind::MultiLabel) {
            Some(router) => port_builder.insert_compiled_exact_host(host, router),
            None => add_static_host(port_builder, &host, i),
        }
    }
    if let Some(now_nanos) = marker {
        add_probe_host(port_builder, now_nanos);
    }
    builder.build().unwrap_or_else(|e| panic!("rebuild: {e}"))
}

fn add_static_host(port_builder: &mut PortTableBuilder, host: &str, idx: usize) {
    let group = Arc::new(BackendGroup::new(
        format!("static-{idx}"),
        vec![
            "127.0.0.1:0"
                .parse()
                .unwrap_or_else(|e| panic!("placeholder addr: {e}")),
        ],
    ));
    let entry = Arc::new(RouteEntry::path_only(group, format!("static-{idx}"), None));
    port_builder.exact_host(host).add_prefix_route("/", entry);
}

fn add_probe_host(port_builder: &mut PortTableBuilder, now_nanos: u128) {
    let group = Arc::new(BackendGroup::new(
        "probe".to_string(),
        vec![
            "127.0.0.1:0"
                .parse()
                .unwrap_or_else(|e| panic!("placeholder addr: {e}")),
        ],
    ));
    let entry = Arc::new(RouteEntry::path_only(
        group,
        format!("probe-{now_nanos}"),
        None,
    ));
    port_builder
        .exact_host(PROBE_HOST)
        .add_prefix_route("/", entry);
}
