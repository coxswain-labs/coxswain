use coxswain_core::routing::RoutingTableBuilder;
use k8s_openapi::api::networking::v1::Ingress;
use kube::runtime::watcher;

pub struct IngressReconciler;

impl IngressReconciler {
    pub fn translate(event: watcher::Event<Ingress>, _builder: &mut RoutingTableBuilder) {
        match event {
            watcher::Event::Apply(ingress) | watcher::Event::InitApply(ingress) => {
                tracing::info!(name = ?ingress.metadata.name, "Reconciling Ingress");
            }
            watcher::Event::Delete(ingress) => {
                tracing::info!(name = ?ingress.metadata.name, "Deleting Ingress paths");
            }
            _ => {}
        }
    }
}
