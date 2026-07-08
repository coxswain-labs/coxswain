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

pub(crate) fn slice_store(slices: Vec<EndpointSlice>) -> reflector::Store<EndpointSlice> {
    let mut writer = reflector::store::Writer::<EndpointSlice>::default();
    for slice in slices {
        writer.apply_watcher_event(&watcher::Event::Apply(slice));
    }
    writer.as_reader()
}

pub(crate) fn empty_svc_store() -> reflector::Store<Service> {
    reflector::store::Writer::<Service>::default().as_reader()
}

pub(crate) fn empty_rate_limit_store() -> reflector::Store<RateLimit> {
    reflector::store::Writer::<RateLimit>::default().as_reader()
}

pub(crate) fn empty_retry_policy_store() -> reflector::Store<RetryPolicy> {
    reflector::store::Writer::<RetryPolicy>::default().as_reader()
}

pub(crate) fn make_retry_policy_store(crs: Vec<RetryPolicy>) -> reflector::Store<RetryPolicy> {
    let mut writer = reflector::store::Writer::<RetryPolicy>::default();
    for cr in crs {
        writer.apply_watcher_event(&watcher::Event::Apply(cr));
    }
    writer.as_reader()
}

pub(crate) fn empty_path_rewrite_store() -> reflector::Store<PathRewriteRegex> {
    reflector::store::Writer::<PathRewriteRegex>::default().as_reader()
}

pub(crate) fn empty_ip_access_store() -> reflector::Store<IpAccessControl> {
    reflector::store::Writer::<IpAccessControl>::default().as_reader()
}

pub(crate) fn make_rate_limit_store(crs: Vec<RateLimit>) -> reflector::Store<RateLimit> {
    let mut writer = reflector::store::Writer::<RateLimit>::default();
    for cr in crs {
        writer.apply_watcher_event(&watcher::Event::Apply(cr));
    }
    writer.as_reader()
}

pub(crate) fn make_ip_access_store(crs: Vec<IpAccessControl>) -> reflector::Store<IpAccessControl> {
    let mut writer = reflector::store::Writer::<IpAccessControl>::default();
    for cr in crs {
        writer.apply_watcher_event(&watcher::Event::Apply(cr));
    }
    writer.as_reader()
}

pub(crate) fn empty_secret_store() -> reflector::Store<Secret> {
    reflector::store::Writer::<Secret>::default().as_reader()
}

pub(crate) fn make_secret_store(secrets: Vec<Secret>) -> reflector::Store<Secret> {
    let mut writer = reflector::store::Writer::<Secret>::default();
    for secret in secrets {
        writer.apply_watcher_event(&watcher::Event::Apply(secret));
    }
    writer.as_reader()
}

pub(crate) fn empty_basic_auth_store() -> reflector::Store<BasicAuth> {
    reflector::store::Writer::<BasicAuth>::default().as_reader()
}

pub(crate) fn empty_external_auth_store()
-> reflector::Store<coxswain_core::crd::CoxswainExternalAuth> {
    reflector::store::Writer::<coxswain_core::crd::CoxswainExternalAuth>::default().as_reader()
}

pub(crate) fn make_basic_auth_store(crs: Vec<BasicAuth>) -> reflector::Store<BasicAuth> {
    let mut writer = reflector::store::Writer::<BasicAuth>::default();
    for cr in crs {
        writer.apply_watcher_event(&watcher::Event::Apply(cr));
    }
    writer.as_reader()
}

pub(crate) fn empty_request_size_limit_store() -> reflector::Store<RequestSizeLimit> {
    reflector::store::Writer::<RequestSizeLimit>::default().as_reader()
}

pub(crate) fn make_request_size_limit_store(
    crs: Vec<RequestSizeLimit>,
) -> reflector::Store<RequestSizeLimit> {
    let mut writer = reflector::store::Writer::<RequestSizeLimit>::default();
    for cr in crs {
        writer.apply_watcher_event(&watcher::Event::Apply(cr));
    }
    writer.as_reader()
}

pub(crate) fn empty_compression_store() -> reflector::Store<Compression> {
    reflector::store::Writer::<Compression>::default().as_reader()
}

pub(crate) fn make_compression_store(crs: Vec<Compression>) -> reflector::Store<Compression> {
    let mut writer = reflector::store::Writer::<Compression>::default();
    for cr in crs {
        writer.apply_watcher_event(&watcher::Event::Apply(cr));
    }
    writer.as_reader()
}

pub(crate) fn make_svc_store(services: Vec<Service>) -> reflector::Store<Service> {
    let mut writer = reflector::store::Writer::<Service>::default();
    for svc in services {
        writer.apply_watcher_event(&watcher::Event::Apply(svc));
    }
    writer.as_reader()
}
