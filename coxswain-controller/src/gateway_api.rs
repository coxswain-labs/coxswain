use coxswain_core::routing::RoutingTable;
use gateway_api::apis::standard::httproutes::HTTPRoute;
use kube::runtime::watcher;

pub struct GatewayApiTranslator;

impl GatewayApiTranslator {
    pub fn translate(event: watcher::Event<HTTPRoute>, _current_table: &mut RoutingTable) {
        match event {
            watcher::Event::Apply(route) | watcher::Event::InitApply(route) => {
                println!("Reconciling Gateway HTTPRoute: {:?}", route.metadata.name);
            }
            watcher::Event::Delete(route) => {
                println!(
                    "Deleting Gateway HTTPRoute paths: {:?}",
                    route.metadata.name
                );
            }
            _ => {}
        }
    }
}
