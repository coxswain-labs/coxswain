use coxswain_core::routing::RoutingTable;
use k8s_openapi::api::networking::v1::Ingress;
use kube::runtime::watcher;

pub struct IngressTranslator;

impl IngressTranslator {
    pub fn translate(event: watcher::Event<Ingress>, _current_table: &mut RoutingTable) {
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
