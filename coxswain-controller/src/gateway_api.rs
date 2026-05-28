use kube::runtime::watcher;
use gateway_api::apis::standard::httproutes::HTTPRoute;
use coxswain_core::routing::RoutingTable;

pub struct GatewayApiTranslator;

impl GatewayApiTranslator {
    pub fn translate(event: watcher::Event<HTTPRoute>, _current_table: &mut RoutingTable) {
        match event {
            watcher::Event::Apply(route) => {
                println!("Reconciling Gateway HTTPRoute: {:?}", route.metadata.name);
            }
            watcher::Event::Delete(route) => {
                println!("Deleting Gateway HTTPRoute paths: {:?}", route.metadata.name);
            }
            _ => {}
        }
    }
}