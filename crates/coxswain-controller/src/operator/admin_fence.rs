//! Admin-port fencing (#670): the `NetworkPolicy` every controller-provisioned
//! pod carries so an arbitrary in-cluster pod cannot reach its admin surface.
//!
//! The management surface binds `0.0.0.0` by default so kubelet probes and
//! Prometheus scraping work out of the box, and the Kubernetes pod network is
//! flat — so without a policy, every pod in every namespace can reach every
//! coxswain pod's admin port. On the controller that port relays verbatim
//! Kubernetes manifests (including Pod `spec.containers[].env`) and pod logs;
//! on a proxy or relay it serves `/metrics`, whose `gateway_name` /
//! `gateway_namespace` labels map the install's whole routing topology. Both are
//! recon material, so every role is fenced rather than the controller alone.
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
//! Only the admin port is fenced. The health port stays open (kubelet probes are
//! node-sourced, not pod-sourced, and `/healthz`/`/readyz` carry no cluster
//! data), and so does the discovery port — it is already mutually authenticated
//! by SVID mTLS, and its legitimate callers are dedicated proxies in arbitrary
//! tenant namespaces, which no static selector can enumerate.

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

/// Install-wide admin-port fencing configuration (#670), threaded from the
/// chart's `networkPolicy.*` values onto [`super::reconciler::OperatorConfig`]
/// and applied identically by all three provisioning renderers.
#[derive(Clone, Debug)]
pub struct AdminFenceConfig {
    /// Whether to render the fence at all. `false` reclaims any previously
    /// applied policy (the renderers apply-or-delete on this), which is the
    /// escape hatch for clusters whose CNI does not enforce NetworkPolicy and
    /// for operators who fence the surface with their own policy instead.
    pub enabled: bool,
    /// Peers admitted to the admin port **in addition to** the built-in two.
    ///
    /// The case the defaults get wrong is a Prometheus that scrapes from a third
    /// namespace — the chart's `PodMonitor` targets pod IPs directly, so the
    /// scrape is denied unless its namespace is named here. Passed through
    /// verbatim from the chart as `NetworkPolicyPeer` objects rather than a
    /// narrower coxswain-shaped type: the peer vocabulary (`podSelector` /
    /// `namespaceSelector` / `ipBlock`) is exactly what an operator needs to
    /// express this, and re-modelling it would only subset it.
    pub extra_ingress: Vec<NetworkPolicyPeer>,
    /// The install namespace, admitted alongside the target pod's own namespace.
    ///
    /// Without it the fence breaks the controller's own aggregator: a dedicated
    /// proxy runs in its **Gateway's** namespace, while the controller runs in
    /// the install namespace, so a same-namespace-only rule silently drops every
    /// `/api/v1/health` probe the fleet view depends on and renders each
    /// dedicated proxy permanently `reachable: false`.
    pub install_namespace: String,
}

impl Default for AdminFenceConfig {
    /// Fencing **on** with no extra peers — the same posture as the chart's
    /// `networkPolicy.enabled: true` default, so a config built without an
    /// explicit opinion is the secure one rather than the open one.
    fn default() -> Self {
        Self {
            enabled: true,
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
/// silently denied by the fence, whatever admin port an install configures.
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
/// The admin and health servers are TCP-only, so UDP needs no carve-out — but it
/// does need naming: coxswain serves UDP Gateway listeners (the per-datagram
/// data plane), and an `Ingress` policy that never mentions UDP denies all of it.
fn open_udp_range() -> NetworkPolicyPort {
    NetworkPolicyPort {
        protocol: Some("UDP".to_string()),
        port: Some(IntOrString::Int(MIN_PORT)),
        end_port: Some(MAX_PORT),
    }
}

/// The peers allowed to reach the admin port: the policy's own namespace, the
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
fn admin_peers(config: &AdminFenceConfig) -> Vec<NetworkPolicyPeer> {
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

/// Render the admin-port fence for a set of controller-provisioned pods.
///
/// `selector` must be the same label set the pods' Deployment stamps, and
/// `labels` the metadata set its siblings carry, so the policy is reclaimed by
/// the same ownership rules as the rest of the bundle.
pub(super) fn render_admin_fence(
    name: &str,
    namespace: &str,
    labels: BTreeMap<String, String>,
    selector: BTreeMap<String, String>,
    admin_port: u16,
    config: &AdminFenceConfig,
) -> NetworkPolicy {
    let fenced = i32::from(admin_port);
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
                // Everything but the admin port, from anywhere. `from: None`
                // (not `Some(vec![])`, which would match no source at all) is
                // what makes this rule source-unrestricted.
                NetworkPolicyIngressRule {
                    from: None,
                    ports: Some(open_ports),
                },
                // The admin port, fenced to the own/install namespaces + extras.
                NetworkPolicyIngressRule {
                    from: Some(admin_peers(config)),
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
    /// every addressable port exactly once, for every admin port an install
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

    fn fence(admin_port: u16, config: &AdminFenceConfig) -> NetworkPolicy {
        render_admin_fence(
            "coxswain-shared-proxy-admin",
            "coxswain-system",
            BTreeMap::from([("app.kubernetes.io/name".to_string(), "coxswain".to_string())]),
            BTreeMap::from([(
                "app.kubernetes.io/component".to_string(),
                "shared-proxy".to_string(),
            )]),
            admin_port,
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
        let policy = fence(8082, &AdminFenceConfig::default());
        assert!(
            rules(&policy)[0].from.is_none(),
            "the open rule must leave `from` unset — an empty peer list denies every source"
        );
    }

    #[test]
    fn udp_stays_fully_open() {
        // A UDP Gateway listener binds an arbitrary port; an Ingress policy that
        // never names UDP denies the entire per-datagram data plane.
        let policy = fence(8082, &AdminFenceConfig::default());
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
    fn the_admin_rule_fences_exactly_the_admin_port() {
        let policy = fence(8082, &AdminFenceConfig::default());
        let admin_rule = &rules(&policy)[1];
        assert_eq!(
            admitted_tcp(admin_rule.ports.as_ref().expect("admin rule carries ports")),
            vec![(8082, 8082)]
        );
        // Own namespace + install namespace, by default.
        let peers = admin_rule.from.as_ref().expect("admin rule carries peers");
        assert_eq!(peers.len(), 2);
        assert_eq!(peers[0].pod_selector, Some(LabelSelector::default()));
        assert!(
            peers[0].namespace_selector.is_none(),
            "omitting namespaceSelector is what scopes the peer to this policy's own namespace"
        );
    }

    #[test]
    fn the_install_namespace_is_always_admitted_to_the_admin_port() {
        // A dedicated proxy lives in its Gateway's namespace while the
        // controller lives in the install namespace, so a same-namespace-only
        // rule would drop the controller's `/api/v1/health` fan-out and render
        // every dedicated proxy permanently `reachable: false` in the fleet view.
        let config = AdminFenceConfig {
            install_namespace: "coxswain-system".to_string(),
            ..AdminFenceConfig::default()
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
            "the admin rule must admit the install namespace so the controller can \
             aggregate proxies that live in tenant namespaces"
        );
    }

    #[test]
    fn a_non_default_admin_port_moves_the_fence() {
        // The complement is computed from the configured port, so an install
        // that relocates the admin surface stays both fenced and unbroken.
        let policy = fence(9000, &AdminFenceConfig::default());
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
        // admin rule, they never replace the same-namespace default (which the
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
        let config = AdminFenceConfig {
            extra_ingress: vec![scraper.clone()],
            ..AdminFenceConfig::default()
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
        let policy = fence(8082, &AdminFenceConfig::default());
        let spec = policy.spec.as_ref().expect("spec");
        assert_eq!(spec.policy_types, Some(vec!["Ingress".to_string()]));
        assert!(spec.egress.is_none());
    }

    #[test]
    fn fencing_is_enabled_by_default() {
        assert!(
            AdminFenceConfig::default().enabled,
            "a config built without an explicit opinion must be the fenced one"
        );
    }
}
