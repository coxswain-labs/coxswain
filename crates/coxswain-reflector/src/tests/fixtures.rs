use crate::MergedStore;
use coxswain_core::crd::{
    BasicAuth, Compression, IpAccessControl, PathRewriteRegex, RateLimit, RequestSizeLimit,
    RetryPolicy,
};
use k8s_openapi::api::core::v1::{Secret, Service};
use k8s_openapi::api::discovery::v1::{Endpoint, EndpointConditions, EndpointSlice};
use kube::api::ObjectMeta;
use kube::runtime::{reflector, watcher};
use std::collections::BTreeMap;

pub(crate) fn make_slice(ns: &str, svc: &str, ip: &str) -> EndpointSlice {
    make_slice_with_conditions(ns, svc, ip, None, Some(true))
}

pub(crate) fn make_slice_with_conditions(
    ns: &str,
    svc: &str,
    ip: &str,
    serving: Option<bool>,
    ready: Option<bool>,
) -> EndpointSlice {
    make_slice_with_all_conditions(ns, svc, ip, serving, ready, None)
}

/// Like [`make_slice_with_conditions`] but also sets `terminating`.
pub(crate) fn make_slice_with_all_conditions(
    ns: &str,
    svc: &str,
    ip: &str,
    serving: Option<bool>,
    ready: Option<bool>,
    terminating: Option<bool>,
) -> EndpointSlice {
    let mut labels = BTreeMap::new();
    labels.insert("kubernetes.io/service-name".to_string(), svc.to_string());
    EndpointSlice {
        metadata: ObjectMeta {
            name: Some(format!("{svc}-slice")),
            namespace: Some(ns.to_string()),
            labels: Some(labels),
            ..Default::default()
        },
        address_type: "IPv4".to_string(),
        endpoints: Some(vec![Endpoint {
            addresses: vec![ip.to_string()],
            conditions: Some(EndpointConditions {
                serving,
                ready,
                terminating,
            }),
            ..Default::default()
        }]),
        ports: None,
    }
}

pub(crate) fn slice_store(slices: Vec<EndpointSlice>) -> MergedStore<EndpointSlice> {
    let mut writer = reflector::store::Writer::<EndpointSlice>::default();
    for slice in slices {
        writer.apply_watcher_event(&watcher::Event::Apply(slice));
    }
    MergedStore::single(writer.as_reader())
}

/// Builds a ready-to-use [`crate::endpoints::pool::EndpointCache`] from a set of
/// `EndpointSlice`s — the test-fixture equivalent of the `refresh()` call the
/// rebuild loop performs once per cycle (#511). Callers that used to build a
/// raw [`slice_store`] to feed a `slices`-typed parameter now build one of
/// these instead, since route builders read through the cache rather than
/// scanning the `EndpointSlice` store directly.
pub(crate) fn endpoint_cache(slices: Vec<EndpointSlice>) -> crate::endpoints::pool::EndpointCache {
    let mut cache = crate::endpoints::pool::EndpointCache::default();
    cache.refresh(&slice_store(slices));
    cache
}

pub(crate) fn empty_svc_store() -> MergedStore<Service> {
    MergedStore::single(reflector::store::Writer::<Service>::default().as_reader())
}

pub(crate) fn empty_rate_limit_store() -> MergedStore<RateLimit> {
    MergedStore::single(reflector::store::Writer::<RateLimit>::default().as_reader())
}

pub(crate) fn empty_retry_policy_store() -> MergedStore<RetryPolicy> {
    MergedStore::single(reflector::store::Writer::<RetryPolicy>::default().as_reader())
}

pub(crate) fn make_retry_policy_store(crs: Vec<RetryPolicy>) -> MergedStore<RetryPolicy> {
    let mut writer = reflector::store::Writer::<RetryPolicy>::default();
    for cr in crs {
        writer.apply_watcher_event(&watcher::Event::Apply(cr));
    }
    MergedStore::single(writer.as_reader())
}

pub(crate) fn empty_path_rewrite_store() -> MergedStore<PathRewriteRegex> {
    MergedStore::single(reflector::store::Writer::<PathRewriteRegex>::default().as_reader())
}

pub(crate) fn empty_ip_access_store() -> MergedStore<IpAccessControl> {
    MergedStore::single(reflector::store::Writer::<IpAccessControl>::default().as_reader())
}

pub(crate) fn make_rate_limit_store(crs: Vec<RateLimit>) -> MergedStore<RateLimit> {
    let mut writer = reflector::store::Writer::<RateLimit>::default();
    for cr in crs {
        writer.apply_watcher_event(&watcher::Event::Apply(cr));
    }
    MergedStore::single(writer.as_reader())
}

pub(crate) fn make_ip_access_store(crs: Vec<IpAccessControl>) -> MergedStore<IpAccessControl> {
    let mut writer = reflector::store::Writer::<IpAccessControl>::default();
    for cr in crs {
        writer.apply_watcher_event(&watcher::Event::Apply(cr));
    }
    MergedStore::single(writer.as_reader())
}

pub(crate) fn empty_secret_store() -> MergedStore<Secret> {
    MergedStore::single(reflector::store::Writer::<Secret>::default().as_reader())
}

pub(crate) fn make_secret_store(secrets: Vec<Secret>) -> MergedStore<Secret> {
    let mut writer = reflector::store::Writer::<Secret>::default();
    for secret in secrets {
        writer.apply_watcher_event(&watcher::Event::Apply(secret));
    }
    MergedStore::single(writer.as_reader())
}

pub(crate) fn empty_basic_auth_store() -> MergedStore<BasicAuth> {
    MergedStore::single(reflector::store::Writer::<BasicAuth>::default().as_reader())
}

pub(crate) fn empty_external_auth_store() -> MergedStore<coxswain_core::crd::CoxswainExternalAuth> {
    MergedStore::single(
        reflector::store::Writer::<coxswain_core::crd::CoxswainExternalAuth>::default().as_reader(),
    )
}

pub(crate) fn make_basic_auth_store(crs: Vec<BasicAuth>) -> MergedStore<BasicAuth> {
    let mut writer = reflector::store::Writer::<BasicAuth>::default();
    for cr in crs {
        writer.apply_watcher_event(&watcher::Event::Apply(cr));
    }
    MergedStore::single(writer.as_reader())
}

pub(crate) fn empty_request_size_limit_store() -> MergedStore<RequestSizeLimit> {
    MergedStore::single(reflector::store::Writer::<RequestSizeLimit>::default().as_reader())
}

pub(crate) fn make_request_size_limit_store(
    crs: Vec<RequestSizeLimit>,
) -> MergedStore<RequestSizeLimit> {
    let mut writer = reflector::store::Writer::<RequestSizeLimit>::default();
    for cr in crs {
        writer.apply_watcher_event(&watcher::Event::Apply(cr));
    }
    MergedStore::single(writer.as_reader())
}

pub(crate) fn empty_compression_store() -> MergedStore<Compression> {
    MergedStore::single(reflector::store::Writer::<Compression>::default().as_reader())
}

pub(crate) fn make_compression_store(crs: Vec<Compression>) -> MergedStore<Compression> {
    let mut writer = reflector::store::Writer::<Compression>::default();
    for cr in crs {
        writer.apply_watcher_event(&watcher::Event::Apply(cr));
    }
    MergedStore::single(writer.as_reader())
}

pub(crate) fn make_svc_store(services: Vec<Service>) -> MergedStore<Service> {
    let mut writer = reflector::store::Writer::<Service>::default();
    for svc in services {
        writer.apply_watcher_event(&watcher::Event::Apply(svc));
    }
    MergedStore::single(writer.as_reader())
}

pub(crate) fn empty_jwt_auth_store() -> MergedStore<coxswain_core::crd::JwtAuth> {
    MergedStore::single(
        reflector::store::Writer::<coxswain_core::crd::JwtAuth>::default().as_reader(),
    )
}

pub(crate) fn make_jwt_auth_store(
    crs: Vec<coxswain_core::crd::JwtAuth>,
) -> MergedStore<coxswain_core::crd::JwtAuth> {
    let mut writer = reflector::store::Writer::<coxswain_core::crd::JwtAuth>::default();
    for cr in crs {
        writer.apply_watcher_event(&watcher::Event::Apply(cr));
    }
    MergedStore::single(writer.as_reader())
}

/// Empty JWKS cache — every `JwtAuth` resolving a remote JWKS fails closed
/// (`Unavailable`), matching production behaviour before the first fetch lands.
pub(crate) fn empty_jwks_cache() -> crate::jwks::JwksCacheHandle {
    crate::jwks::JwksCacheHandle::new()
}

/// Empty `CoxswainBackendPolicy` index — every backend Service resolves no
/// attached policy, leaving connection behaviour at its default.
pub(crate) fn empty_backend_policy_index() -> crate::gateway_api::BackendPolicyIndex {
    std::collections::HashMap::new()
}
