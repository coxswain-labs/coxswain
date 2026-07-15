//! `ClientTrafficPolicy` resolver: maps per-listener PROXY protocol config.
//!
//! Resolves CTP resources against owned Gateways and returns:
//! - A per-(gateway, optional-listener-name) `ProxyProtocolListenerConfig` map
//!   consumed by the listener rebuild to set `ListenerInfo.proxy_protocol`.
//! - A per-policy status map consumed by the controller to patch
//!   `status.ancestors[]`.
//!
//! Precedence follows GEP-713 direct-policy attachment:
//! - Section-scoped policies (with `sectionName`) take precedence over
//!   Gateway-scoped ones (without `sectionName`) for the targeted listener.
//! - Among two policies at the same scope targeting the same listener, the
//!   older `creationTimestamp` wins; the newer one receives `Conflicted=True`.

use crate::MergedStore;
use crate::k8s_utils::metadata_created_at;
use crate::status::{ClientTrafficPolicyStatus, ClientTrafficPolicyStatusMap};
use coxswain_core::crd::client_traffic_policy::ClientTrafficPolicy;
use coxswain_core::listener_status::ProxyProtocolListenerConfig;
use coxswain_core::ownership::ObjectKey;
use ipnet::IpNet;
use std::collections::{HashMap, HashSet};
use std::time::SystemTime;

/// Total ordering for `Option<SystemTime>`: `None` sorts last (treat as
/// "unknown" — penalise missing timestamps so they lose conflict resolution).
fn earlier(a: Option<SystemTime>, b: Option<SystemTime>) -> bool {
    match (a, b) {
        (Some(ta), Some(tb)) => ta < tb,
        (Some(_), None) => true, // known timestamp beats unknown
        (None, Some(_)) => false,
        (None, None) => false,
    }
}

/// Per-(gateway, optional-listener-name) PROXY protocol config resolved from
/// `ClientTrafficPolicy` resources.
///
/// A `None` listener name is a gateway-scoped policy (applies to all listeners
/// not targeted by a section-scoped entry). A `Some` listener name is a
/// section-scoped policy for exactly that named listener.
pub type ClientTrafficPolicyIndex =
    HashMap<(ObjectKey, Option<String>), ProxyProtocolListenerConfig>;

/// Resolve `ClientTrafficPolicy` resources against `owned_gateways`.
///
/// Returns a `(ClientTrafficPolicyIndex, ClientTrafficPolicyStatusMap)` pair.
/// Only policies whose `targetRefs` point at an owned Gateway are processed;
/// policies targeting unowned or non-existent Gateways are silently accepted
/// (no Coxswain annotation — a no-op from this controller's perspective).
///
/// # Errors
///
/// No errors are returned; malformed CIDR strings in `trustedSources` are
/// skipped with a `warn!` log and an empty `trusted_sources` list.
#[must_use = "caller must wire the index into ListenerInfo and publish the status map"]
pub fn resolve_client_traffic_policies(
    policies: &MergedStore<ClientTrafficPolicy>,
    owned_gateways: &HashSet<ObjectKey>,
) -> (ClientTrafficPolicyIndex, ClientTrafficPolicyStatusMap) {
    // Candidate map: (gw_key, section_name) → (timestamp, policy_key, config).
    // We collect all candidates first, then resolve conflicts.
    type Candidate = (Option<SystemTime>, ObjectKey, ProxyProtocolListenerConfig);
    let mut section_candidates: HashMap<(ObjectKey, String), Candidate> = HashMap::new();
    let mut gateway_candidates: HashMap<ObjectKey, Candidate> = HashMap::new();

    let mut status_map: ClientTrafficPolicyStatusMap = HashMap::new();

    for policy in policies.state() {
        let policy: &ClientTrafficPolicy = &policy;
        let policy_ns = policy.metadata.namespace.as_deref().unwrap_or("default");
        let Some(policy_name) = policy.metadata.name.as_deref() else {
            continue;
        };
        let policy_key = ObjectKey::new(policy_ns, policy_name);
        let created_at = metadata_created_at(&policy.metadata);

        // A policy with no proxyProtocol spec is a no-op: accepted, no effect.
        let Some(pp_spec) = policy.spec.proxy_protocol.as_ref() else {
            status_map.insert(policy_key, ClientTrafficPolicyStatus::default());
            continue;
        };

        if !pp_spec.enabled {
            // enabled=false: accepted but configures nothing.
            status_map.insert(policy_key, ClientTrafficPolicyStatus::default());
            continue;
        }

        let trusted_sources: Vec<IpNet> = pp_spec
            .trusted_sources
            .iter()
            .filter_map(|s| {
                s.parse()
                    .map_err(|e| {
                        tracing::warn!(
                            policy = %policy_key,
                            cidr = %s,
                            error = %e,
                            "ClientTrafficPolicy: ignoring unparseable trustedSources entry"
                        );
                    })
                    .ok()
            })
            .collect();

        let config = ProxyProtocolListenerConfig::new(true, trusted_sources);

        let mut matched_owned = false;
        for target_ref in &policy.spec.target_refs {
            if target_ref.group != "gateway.networking.k8s.io" || target_ref.kind != "Gateway" {
                continue;
            }
            let gw_key = ObjectKey::new(policy_ns, &target_ref.name);
            if !owned_gateways.contains(&gw_key) {
                continue;
            }
            matched_owned = true;

            match &target_ref.section_name {
                Some(section) => {
                    let entry = section_candidates.entry((gw_key, section.clone()));
                    match entry {
                        std::collections::hash_map::Entry::Vacant(v) => {
                            v.insert((created_at, policy_key.clone(), config.clone()));
                        }
                        std::collections::hash_map::Entry::Occupied(mut o) => {
                            let slot = o.get_mut();
                            if earlier(created_at, slot.0)
                                || (created_at == slot.0 && policy_key < slot.1)
                            {
                                let loser_key = slot.1.clone();
                                *slot = (created_at, policy_key.clone(), config.clone());
                                mark_conflicted(&mut status_map, loser_key);
                            } else {
                                mark_conflicted(&mut status_map, policy_key.clone());
                            }
                        }
                    }
                }
                None => {
                    let entry = gateway_candidates.entry(gw_key);
                    match entry {
                        std::collections::hash_map::Entry::Vacant(v) => {
                            v.insert((created_at, policy_key.clone(), config.clone()));
                        }
                        std::collections::hash_map::Entry::Occupied(mut o) => {
                            let slot = o.get_mut();
                            if earlier(created_at, slot.0)
                                || (created_at == slot.0 && policy_key < slot.1)
                            {
                                let loser_key = slot.1.clone();
                                *slot = (created_at, policy_key.clone(), config.clone());
                                mark_conflicted(&mut status_map, loser_key);
                            } else {
                                mark_conflicted(&mut status_map, policy_key.clone());
                            }
                        }
                    }
                }
            }
        }

        // Only insert a status entry when this policy targets at least one
        // owned Gateway — policies targeting foreign Gateways are not ours to report on.
        if matched_owned {
            status_map.entry(policy_key).or_default();
        }
    }

    // Flatten candidates into the output index.
    let mut index: ClientTrafficPolicyIndex = HashMap::new();
    for ((gw_key, section), (_, _, config)) in section_candidates {
        index.insert((gw_key, Some(section)), config);
    }
    for (gw_key, (_, _, config)) in gateway_candidates {
        index.insert((gw_key, None), config);
    }

    (index, status_map)
}

fn mark_conflicted(map: &mut ClientTrafficPolicyStatusMap, key: ObjectKey) {
    let entry = map.entry(key).or_default();
    entry.accepted = false;
    entry.accepted_reason = "Conflicted";
    entry.conflicted = true;
    entry.conflicted_reason = "SameListenerConflict";
}

/// Resolve the effective `ProxyProtocolListenerConfig` for a given Gateway listener.
///
/// Section-scoped policy for the named listener wins over a gateway-scoped policy.
/// Returns `None` when no applicable policy exists.
#[must_use]
pub fn effective_proxy_config<'a>(
    index: &'a ClientTrafficPolicyIndex,
    gw_key: &ObjectKey,
    listener_name: &str,
) -> Option<&'a ProxyProtocolListenerConfig> {
    index
        .get(&(gw_key.clone(), Some(listener_name.to_owned())))
        .or_else(|| index.get(&(gw_key.clone(), None)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use coxswain_core::crd::client_traffic_policy::ClientTrafficPolicy;
    use kube::runtime::reflector;

    fn make_ctp(
        ns: &str,
        name: &str,
        gw_name: &str,
        section_name: Option<&str>,
        enabled: bool,
    ) -> ClientTrafficPolicy {
        let section_field = match section_name {
            Some(s) => format!("    sectionName: {s}\n"),
            None => String::new(),
        };
        let yaml = format!(
            concat!(
                "apiVersion: gateway.coxswain-labs.dev/v1alpha1\n",
                "kind: ClientTrafficPolicy\n",
                "metadata:\n",
                "  namespace: {ns}\n",
                "  name: {name}\n",
                "spec:\n",
                "  targetRefs:\n",
                "  - group: gateway.networking.k8s.io\n",
                "    kind: Gateway\n",
                "    name: {gw_name}\n",
                "{section_field}",
                "  proxyProtocol:\n",
                "    enabled: {enabled}\n",
                "    trustedSources:\n",
                "    - 10.0.0.0/8\n",
            ),
            ns = ns,
            name = name,
            gw_name = gw_name,
            section_field = section_field,
            enabled = enabled,
        );
        serde_yaml::from_str(&yaml).unwrap_or_else(|e| panic!("bad yaml: {e}\n---\n{yaml}"))
    }

    fn owned(ns: &str, name: &str) -> HashSet<ObjectKey> {
        let mut s = HashSet::new();
        s.insert(ObjectKey::new(ns, name));
        s
    }

    fn store_from(policies: Vec<ClientTrafficPolicy>) -> MergedStore<ClientTrafficPolicy> {
        let (reader, mut writer) = reflector::store();
        writer.apply_watcher_event(&kube::runtime::watcher::Event::InitDone);
        for p in policies {
            writer.apply_watcher_event(&kube::runtime::watcher::Event::Apply(p));
        }
        MergedStore::single(reader)
    }

    #[test]
    fn no_policies_returns_empty() {
        let store = store_from(vec![]);
        let owned = owned("ns", "gw");
        let (index, status) = resolve_client_traffic_policies(&store, &owned);
        assert!(index.is_empty());
        assert!(status.is_empty());
    }

    #[test]
    fn gateway_scoped_policy_inserted() {
        let store = store_from(vec![make_ctp("ns", "p1", "gw", None, true)]);
        let owned = owned("ns", "gw");
        let (index, status) = resolve_client_traffic_policies(&store, &owned);
        let gw_key = ObjectKey::new("ns", "gw");
        assert!(index.contains_key(&(gw_key, None)));
        let s = status
            .get(&ObjectKey::new("ns", "p1"))
            .expect("status entry");
        assert!(s.accepted);
        assert!(!s.conflicted);
    }

    #[test]
    fn section_scoped_beats_gateway_scoped() {
        let store = store_from(vec![
            make_ctp("ns", "gw-policy", "gw", None, true),
            make_ctp("ns", "section-policy", "gw", Some("https"), true),
        ]);
        let owned = owned("ns", "gw");
        let (index, _) = resolve_client_traffic_policies(&store, &owned);
        let gw_key = ObjectKey::new("ns", "gw");
        assert!(index.contains_key(&(gw_key.clone(), None)));
        assert!(index.contains_key(&(gw_key, Some("https".to_owned()))));
    }

    #[test]
    fn unowned_gateway_is_ignored() {
        let store = store_from(vec![make_ctp("ns", "p1", "other-gw", None, true)]);
        let owned = owned("ns", "my-gw");
        let (index, status) = resolve_client_traffic_policies(&store, &owned);
        assert!(
            index.is_empty(),
            "unowned gateway must not produce an index entry"
        );
        // Policy itself has no targeted owned gateways — no status entry expected.
        assert!(status.is_empty());
    }

    #[test]
    fn effective_proxy_config_prefers_section_scoped() {
        let mut index = ClientTrafficPolicyIndex::new();
        let gw = ObjectKey::new("ns", "gw");
        let cfg_gw = ProxyProtocolListenerConfig::new(true, vec![]);
        let cfg_sec =
            ProxyProtocolListenerConfig::new(true, vec!["192.168.0.0/16".parse().unwrap()]);
        index.insert((gw.clone(), None), cfg_gw);
        index.insert((gw.clone(), Some("https".to_owned())), cfg_sec.clone());

        let result = effective_proxy_config(&index, &gw, "https");
        assert_eq!(
            result.map(|c| &c.trusted_sources),
            Some(&cfg_sec.trusted_sources)
        );

        // Listener without a section-scoped entry falls through to gateway-scoped.
        let result2 = effective_proxy_config(&index, &gw, "http");
        assert!(result2.is_some());
        assert!(result2.unwrap().trusted_sources.is_empty());
    }
}
