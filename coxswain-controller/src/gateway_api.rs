use coxswain_core::routing::RoutingTableBuilder;
use gateway_api::apis::standard::httproutes::HTTPRoute;
use kube::runtime::watcher;

pub struct GatewayApiReconciler;

impl GatewayApiReconciler {
    pub fn apply(route: &HTTPRoute, _builder: &mut RoutingTableBuilder) {
        tracing::info!(name = ?route.metadata.name, "Reconciling Gateway HTTPRoute");
    }

    pub fn translate(event: watcher::Event<HTTPRoute>, builder: &mut RoutingTableBuilder) {
        match event {
            watcher::Event::Apply(route) | watcher::Event::InitApply(route) => {
                Self::apply(&route, builder);
            }
            watcher::Event::Delete(route) => {
                tracing::info!(name = ?route.metadata.name, "Deleting Gateway HTTPRoute paths");
            }
            _ => {}
        }
    }
}
