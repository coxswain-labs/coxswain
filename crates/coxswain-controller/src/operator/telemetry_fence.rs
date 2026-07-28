//! Telemetry-port fencing (#670): the **opt-in** `NetworkPolicy` a
//! controller-provisioned pod carries so an arbitrary in-cluster pod cannot
//! reach its `/metrics` and `/statusz`.
//!
//! Provisioned pods (shared pool, dedicated proxies, relays) serve no operator
//! surface at all — no manifests, no pod logs, no `/api/v1/*`. Their only
//! non-data-plane listeners are the kubelet port (`/healthz`, `/readyz`) and the
//! telemetry port, so the telemetry port is the only thing here worth fencing.
//! The controller's own operator port is fenced separately, by the chart.
//!
//! # Why this defaults OFF, unlike everything else security-shaped here
//!
//! What the telemetry port leaks is the **routing inventory**: the `route` label
//! is `metric_route_id` (`httproute/<ns>/<name>:<rule>`), and `upstream` carries
//! backend Service names, so `/metrics` enumerates every tenant namespace, route
//! object and backend. That is recon material — but not credentials, and already
//! visible to anyone holding `get httproutes`.
//!
//! Weighed against that: `PodMonitor` scrapes **pod IPs directly**, so a fenced
//! default silently drops every scrape from a Prometheus outside the pod's own
//! namespace and the install namespace — which is where essentially every
//! install puts it (`kube-prometheus-stack` defaults to `monitoring`). The
//! failure is invisible: targets sit at `context deadline exceeded` and a
//! dashboard is empty. A certain, silent, universal breakage outweighs an
//! exposure that only matters when untrusted workloads share a flat pod network,
//! so this fence is opt-in and the operator fence stays opt-out.
//!
//! # Why the open rule names a port *range*
//!
//! NetworkPolicy is allowlist-only: the moment any policy selects a pod for
//! `Ingress`, every port no rule names is denied. That makes "fence one port"
//! impossible to express directly — the policy has to enumerate everything it
//! leaves open, and coxswain's data planes bind ports that are **not knowable at
//! render time**:
//!
//! - the shared pool allocates one internal port per Gateway listener
//!   (`render_shared::…` VIP `targetPort`), none of which appear as a
//!   `containerPort`;
//! - a dedicated proxy binds whatever its Gateway's listeners declare, which
//!   changes as the Gateway is edited.
//!
//! Enumerating them would put this policy on the Gateway-reconcile hot path and
//! invent a new failure mode — routing converged, traffic blocked, because the
//! policy lagged a listener edit. Naming the *complement* of the single fenced
//! port instead is correct for every port set, forever, and never needs
//! re-rendering. [`open_tcp_ranges`] owns that inversion and is the one place the
//! "no data-plane port is ever accidentally denied" property is asserted.
//!
//! Only the telemetry port is fenced. The health port stays open (kubelet probes
//! are node-sourced, not pod-sourced, and most CNIs cannot select them at all —
//! and `/healthz`/`/readyz` carry no cluster data), and so does the discovery
//! port — it is already mutually authenticated by SVID mTLS, and its legitimate
//! callers are dedicated proxies in arbitrary tenant namespaces, which no static
//! selector can enumerate.

use std::collections::BTreeMap;

use k8s_openapi::api::networking::v1::{
    NetworkPolicy, NetworkPolicyIngressRule, NetworkPolicyPeer, NetworkPolicyPort,
    NetworkPolicySpec,
};
use k8s_openapi::apimachinery::pkg::apis::meta::v1::LabelSelector;
use k8s_openapi::apimachinery::pkg::util::intstr::IntOrString;
use kube::api::ObjectMeta;

/// Lowest legal TCP/UDP port. Port 0 is not addressable, so the complement never
/// includes it.
const MIN_PORT: i32 = 1;
/// Highest legal TCP/UDP port.
const MAX_PORT: i32 = 65535;

/// Install-wide telemetry-port fencing configuration (#670), threaded from the
/// chart's `networkPolicy.telemetry.*` values onto
/// [`super::reconciler::OperatorConfig`] and applied identically by all three
/// provisioning renderers.
#[derive(Clone, Debug)]
pub struct TelemetryFenceConfig {
    /// Whether to render the fence at all. `false` — the default, see
    /// [`Default`] — reclaims any previously applied policy (the renderers
    /// apply-or-delete on this).
    pub enabled: bool,
    /// Peers admitted to the telemetry port **in addition to** the built-in two.
    ///
    /// The case the built-ins get wrong is a Prometheus that scrapes from a
    /// third namespace — the chart's `PodMonitor` targets pod IPs directly, so
    /// the scrape is denied unless its namespace is named here. Only consulted
    /// when [`Self::enabled`]; with the fence off, every namespace already
    /// reaches the port. Passed through verbatim from the chart as
    /// `NetworkPolicyPeer` objects rather than a narrower coxswain-shaped type:
    /// the peer vocabulary (`podSelector` / `namespaceSelector` / `ipBlock`) is
    /// exactly what an operator needs to express this, and re-modelling it would
    /// only subset it.
    pub extra_ingress: Vec<NetworkPolicyPeer>,
    /// The install namespace, admitted alongside the target pod's own namespace.
    ///
    /// Without it the fence breaks the controller's own aggregator: a dedicated
    /// proxy runs in its **Gateway's** namespace, while the controller runs in
    /// the install namespace, so a same-namespace-only rule silently drops every
    /// `/statusz` probe the fleet view depends on and renders each dedicated
    /// proxy permanently `reachable: false`. This peer belongs to whichever port
    /// carries that probe — it moved here with the probe itself, and leaving it
    /// on the operator fence would break the fleet view for every install that
    /// turns fencing on.
    pub install_namespace: String,
}

impl Default for TelemetryFenceConfig {
    /// Fencing **off** with no extra peers, matching the chart's
    /// `networkPolicy.telemetry.fenced: false` default.
    ///
    /// This deliberately inverts the "a config built without an explicit opinion
    /// is the secure one" rule the operator fence follows. The module header
    /// argues the trade in full; in short, a fenced default breaks Prometheus
    /// silently on essentially every install, and what it would protect is a
    /// routing inventory rather than a credential.
    fn default() -> Self {
        Self {
            enabled: false,
            extra_ingress: Vec::new(),
            install_namespace: "coxswain-system".to_string(),
        }
    }
}

/// The TCP port ranges covering every port **except** `fenced`.
///
/// Splits `[1, 65535]` around `fenced`, dropping either side when the fenced
/// port sits on a boundary. The invariant every caller depends on — and that
/// this module's tests assert exhaustively — is that the returned ranges plus
/// `fenced` reconstitute `[1, 65535]` exactly: no data-plane port may be
/// silently denied by the fence, whatever telemetry port an install configures.
fn open_tcp_ranges(fenced: i32) -> Vec<NetworkPolicyPort> {
    let mut ranges = Vec::with_capacity(2);
    if fenced > MIN_PORT {
        ranges.push(tcp_range(MIN_PORT, fenced - 1));
    }
    if fenced < MAX_PORT {
        ranges.push(tcp_range(fenced + 1, MAX_PORT));
    }
    ranges
}

/// A TCP `[start, end]` port range. `end_port` is omitted for a single port so
/// the rendered object stays the plain form operators recognise.
fn tcp_range(start: i32, end: i32) -> NetworkPolicyPort {
    NetworkPolicyPort {
        protocol: Some("TCP".to_string()),
        port: Some(IntOrString::Int(start)),
        end_port: (end > start).then_some(end),
    }
}

/// The full UDP range, left open unconditionally.
///
/// The management servers are TCP-only, so UDP needs no carve-out — but it
/// does need naming: coxswain serves UDP Gateway listeners (the per-datagram
/// data plane), and an `Ingress` policy that never mentions UDP denies all of it.
fn open_udp_range() -> NetworkPolicyPort {
    NetworkPolicyPort {
        protocol: Some("UDP".to_string()),
        port: Some(IntOrString::Int(MIN_PORT)),
        end_port: Some(MAX_PORT),
    }
}

/// The peers allowed to reach the telemetry port: the policy's own namespace, the
/// install namespace, plus whatever the operator configured.
///
/// A `podSelector: {}` peer with no `namespaceSelector` means "any pod in this
/// policy's namespace" — that covers a co-located Prometheus and, for the shared
/// pool and relays, the controller too.
///
/// It does **not** cover a dedicated proxy, which runs in its Gateway's
/// namespace while the controller runs in the install namespace, so the install
/// namespace is admitted explicitly. `kubernetes.io/metadata.name` is the label
/// the apiserver stamps on every Namespace automatically, so this needs no
/// cooperation from whoever created it.
fn telemetry_peers(config: &TelemetryFenceConfig) -> Vec<NetworkPolicyPeer> {
    let mut peers = Vec::with_capacity(2 + config.extra_ingress.len());
    peers.push(NetworkPolicyPeer {
        pod_selector: Some(LabelSelector::default()),
        ..Default::default()
    });
    peers.push(NetworkPolicyPeer {
        namespace_selector: Some(LabelSelector {
            match_labels: Some(BTreeMap::from([(
                "kubernetes.io/metadata.name".to_string(),
                config.install_namespace.clone(),
            )])),
            ..Default::default()
        }),
        ..Default::default()
    });
    peers.extend(config.extra_ingress.iter().cloned());
    peers
}

/// Render the telemetry-port fence for a set of controller-provisioned pods.
///
/// `selector` must be the same label set the pods' Deployment stamps, and
/// `labels` the metadata set its siblings carry, so the policy is reclaimed by
/// the same ownership rules as the rest of the bundle.
pub(super) fn render_telemetry_fence(
    name: &str,
    namespace: &str,
    labels: BTreeMap<String, String>,
    selector: BTreeMap<String, String>,
    telemetry_port: u16,
    config: &TelemetryFenceConfig,
) -> NetworkPolicy {
    let fenced = i32::from(telemetry_port);
    let mut open_ports = open_tcp_ranges(fenced);
    open_ports.push(open_udp_range());

    NetworkPolicy {
        metadata: ObjectMeta {
            name: Some(name.to_string()),
            namespace: Some(namespace.to_string()),
            labels: Some(labels),
            ..Default::default()
        },
        spec: Some(NetworkPolicySpec {
            pod_selector: Some(LabelSelector {
                match_labels: Some(selector),
                ..Default::default()
            }),
            // Ingress only: the fence is about who may reach this pod. Naming
            // `Egress` here would additionally deny everything the pod dials —
            // the apiserver, upstream backends, the controller's discovery
            // stream — none of which this issue is about.
            policy_types: Some(vec!["Ingress".to_string()]),
            ingress: Some(vec![
                // Everything but the telemetry port, from anywhere. `from: None`
                // (not `Some(vec![])`, which would match no source at all) is
                // what makes this rule source-unrestricted.
                NetworkPolicyIngressRule {
                    from: None,
                    ports: Some(open_ports),
                },
                // The telemetry port, fenced to the own/install namespaces + extras.
                NetworkPolicyIngressRule {
                    from: Some(telemetry_peers(config)),
                    ports: Some(vec![tcp_range(fenced, fenced)]),
                },
            ]),
            egress: None,
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Expand the rendered ranges back into the concrete set of TCP ports they
    /// admit, so a test can compare against the ports coxswain actually binds.
    fn admitted_tcp(ports: &[NetworkPolicyPort]) -> Vec<(i32, i32)> {
        ports
            .iter()
            .filter(|p| p.protocol.as_deref() == Some("TCP"))
            .map(|p| {
                let start = match p.port {
                    Some(IntOrString::Int(n)) => n,
                    _ => panic!("invariant: rendered fence ports are always numeric"),
                };
                (start, p.end_port.unwrap_or(start))
            })
            .collect()
    }

    /// The property the whole design rests on: open ranges ∪ {fenced} covers
    /// every addressable port exactly once, for every telemetry port an install
    /// could configure. If this ever fails, some data-plane port is being
    /// silently denied by the fence.
    #[test]
    fn open_ranges_plus_fenced_port_cover_the_entire_port_space() {
        for fenced in [
            MIN_PORT,
            2,
            80,
            8080,
            8081,
            8082,
            9000,
            MAX_PORT - 1,
            MAX_PORT,
        ] {
            let mut covered: Vec<(i32, i32)> = admitted_tcp(&open_tcp_ranges(fenced));
            covered.push((fenced, fenced));
            covered.sort_unstable();

            let mut next = MIN_PORT;
            for (start, end) in covered {
                assert_eq!(
                    start, next,
                    "fenced={fenced}: gap or overlap before port {start} — a port is denied \
                     that should be open (or allowed twice)"
                );
                next = end + 1;
            }
            assert_eq!(
                next,
                MAX_PORT + 1,
                "fenced={fenced}: coverage stops short of {MAX_PORT}"
            );
        }
    }

    #[test]
    fn fencing_the_lowest_port_emits_only_the_upper_range() {
        let ranges = admitted_tcp(&open_tcp_ranges(MIN_PORT));
        assert_eq!(
            ranges,
            vec![(MIN_PORT + 1, MAX_PORT)],
            "nothing exists below port 1, so no lower range may be emitted"
        );
    }

    #[test]
    fn fencing_the_highest_port_emits_only_the_lower_range() {
        let ranges = admitted_tcp(&open_tcp_ranges(MAX_PORT));
        assert_eq!(
            ranges,
            vec![(MIN_PORT, MAX_PORT - 1)],
            "nothing exists above port 65535, so no upper range may be emitted"
        );
    }

    #[test]
    fn a_single_port_range_omits_end_port() {
        // `endPort` equal to `port` is legal but noisy; operators reading the
        // rendered policy should see the plain single-port form.
        assert_eq!(tcp_range(8082, 8082).end_port, None);
        assert_eq!(tcp_range(8082, 8083).end_port, Some(8083));
    }

    fn fence(telemetry_port: u16, config: &TelemetryFenceConfig) -> NetworkPolicy {
        render_telemetry_fence(
            "coxswain-shared-proxy-telemetry",
            "coxswain-system",
            BTreeMap::from([("app.kubernetes.io/name".to_string(), "coxswain".to_string())]),
            BTreeMap::from([(
                "app.kubernetes.io/component".to_string(),
                "shared-proxy".to_string(),
            )]),
            telemetry_port,
            config,
        )
    }

    fn rules(policy: &NetworkPolicy) -> Vec<NetworkPolicyIngressRule> {
        policy
            .spec
            .as_ref()
            .and_then(|s| s.ingress.clone())
            .expect("rendered fence always carries ingress rules")
    }

    #[test]
    fn the_open_rule_is_source_unrestricted() {
        // `from: Some(vec![])` would match NO source and black-hole the data
        // plane; only `from: None` means "any source". This distinction is the
        // single most dangerous way to get the fence wrong.
        let policy = fence(8082, &TelemetryFenceConfig::default());
        assert!(
            rules(&policy)[0].from.is_none(),
            "the open rule must leave `from` unset — an empty peer list denies every source"
        );
    }

    #[test]
    fn udp_stays_fully_open() {
        // A UDP Gateway listener binds an arbitrary port; an Ingress policy that
        // never names UDP denies the entire per-datagram data plane.
        let policy = fence(8082, &TelemetryFenceConfig::default());
        let ingress = rules(&policy);
        let udp: Vec<&NetworkPolicyPort> = ingress[0]
            .ports
            .as_ref()
            .expect("open rule carries ports")
            .iter()
            .filter(|p| p.protocol.as_deref() == Some("UDP"))
            .collect();
        assert_eq!(udp.len(), 1, "exactly one UDP range should be emitted");
        assert_eq!(udp[0].port, Some(IntOrString::Int(MIN_PORT)));
        assert_eq!(udp[0].end_port, Some(MAX_PORT));
    }

    #[test]
    fn the_telemetry_rule_fences_exactly_the_telemetry_port() {
        let policy = fence(8082, &TelemetryFenceConfig::default());
        let telemetry_rule = &rules(&policy)[1];
        assert_eq!(
            admitted_tcp(
                telemetry_rule
                    .ports
                    .as_ref()
                    .expect("telemetry rule carries ports")
            ),
            vec![(8082, 8082)]
        );
        // Own namespace + install namespace, by default.
        let peers = telemetry_rule
            .from
            .as_ref()
            .expect("telemetry rule carries peers");
        assert_eq!(peers.len(), 2);
        assert_eq!(peers[0].pod_selector, Some(LabelSelector::default()));
        assert!(
            peers[0].namespace_selector.is_none(),
            "omitting namespaceSelector is what scopes the peer to this policy's own namespace"
        );
    }

    #[test]
    fn the_install_namespace_is_always_admitted_to_the_telemetry_port() {
        // A dedicated proxy lives in its Gateway's namespace while the
        // controller lives in the install namespace, so a same-namespace-only
        // rule would drop the controller's `/statusz` probe and render
        // every dedicated proxy permanently `reachable: false` in the fleet view.
        let config = TelemetryFenceConfig {
            install_namespace: "coxswain-system".to_string(),
            ..TelemetryFenceConfig::default()
        };
        let policy = fence(8082, &config);
        let peers = rules(&policy)[1].from.clone().expect("peers");
        let admits_install_ns = peers.iter().any(|p| {
            p.namespace_selector.as_ref().is_some_and(|s| {
                s.match_labels.as_ref().is_some_and(|l| {
                    l.get("kubernetes.io/metadata.name").map(String::as_str)
                        == Some("coxswain-system")
                })
            })
        });
        assert!(
            admits_install_ns,
            "the telemetry rule must admit the install namespace so the controller can \
             aggregate proxies that live in tenant namespaces"
        );
    }

    #[test]
    fn a_non_default_telemetry_port_moves_the_fence() {
        // The complement is computed from the configured port, so an install
        // that relocates the telemetry surface stays both fenced and unbroken.
        let policy = fence(9000, &TelemetryFenceConfig::default());
        assert_eq!(
            admitted_tcp(rules(&policy)[1].ports.as_ref().expect("ports")),
            vec![(9000, 9000)]
        );
        assert_eq!(
            admitted_tcp(rules(&policy)[0].ports.as_ref().expect("ports")),
            vec![(1, 8999), (9001, 65535)]
        );
    }

    #[test]
    fn extra_peers_are_appended_after_the_same_namespace_default() {
        // The cross-namespace-Prometheus escape hatch: extra peers widen the
        // telemetry rule, they never replace the same-namespace default (which the
        // controller's own aggregator fan-out depends on).
        let scraper = NetworkPolicyPeer {
            namespace_selector: Some(LabelSelector {
                match_labels: Some(BTreeMap::from([(
                    "kubernetes.io/metadata.name".to_string(),
                    "monitoring".to_string(),
                )])),
                ..Default::default()
            }),
            ..Default::default()
        };
        let config = TelemetryFenceConfig {
            extra_ingress: vec![scraper.clone()],
            ..TelemetryFenceConfig::default()
        };
        let policy = fence(8082, &config);
        let peers = rules(&policy)[1].from.clone().expect("peers");
        assert_eq!(
            peers.len(),
            3,
            "own namespace + install namespace + the extra"
        );
        assert_eq!(peers[0].pod_selector, Some(LabelSelector::default()));
        assert_eq!(
            peers[2], scraper,
            "operator-supplied peers are appended, never substituted for the built-ins"
        );
    }

    #[test]
    fn the_fence_restricts_ingress_only() {
        // Naming Egress would additionally deny everything the pod dials — the
        // apiserver, upstream backends, the discovery stream.
        let policy = fence(8082, &TelemetryFenceConfig::default());
        let spec = policy.spec.as_ref().expect("spec");
        assert_eq!(spec.policy_types, Some(vec!["Ingress".to_string()]));
        assert!(spec.egress.is_none());
    }

    #[test]
    fn fencing_is_disabled_by_default() {
        // Deliberately the opposite of the operator fence's default. A fenced
        // telemetry port silently drops every scrape from a Prometheus outside
        // the pod's own namespace and the install namespace, and `PodMonitor`
        // dials pod IPs directly so there is no Service-level workaround. What
        // it would protect is a routing inventory, not a credential.
        assert!(
            !TelemetryFenceConfig::default().enabled,
            "telemetry fencing must be opt-in so unconfigured scraping works"
        );
    }
}
