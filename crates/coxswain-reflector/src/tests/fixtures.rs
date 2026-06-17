use coxswain_core::crd::RateLimit;
use k8s_openapi::api::core::v1::Service;
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
        endpoints: vec![Endpoint {
            addresses: vec![ip.to_string()],
            conditions: Some(EndpointConditions {
                serving,
                ready,
                ..Default::default()
            }),
            ..Default::default()
        }],
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

pub(crate) fn make_svc_store(services: Vec<Service>) -> reflector::Store<Service> {
    let mut writer = reflector::store::Writer::<Service>::default();
    for svc in services {
        writer.apply_watcher_event(&watcher::Event::Apply(svc));
    }
    writer.as_reader()
}
