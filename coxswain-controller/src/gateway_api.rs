use coxswain_core::routing::RoutingTable;
use gateway_api::apis::standard::httproutes::HTTPRoute;
use kube::runtime::watcher;

pub struct GatewayApiTranslator;

impl GatewayApiTranslator {
    pub fn apply(route: &HTTPRoute, _table: &mut RoutingTable) {
        tracing::info!(name = ?route.metadata.name, "Reconciling Gateway HTTPRoute");
    }

    pub fn translate(event: watcher::Event<HTTPRoute>, table: &mut RoutingTable) {
        match event {
            watcher::Event::Apply(route) | watcher::Event::InitApply(route) => {
                Self::apply(&route, table);
            }
            watcher::Event::Delete(route) => {
                tracing::info!(name = ?route.metadata.name, "Deleting Gateway HTTPRoute paths");
            }
            _ => {}
        }
    }
}
