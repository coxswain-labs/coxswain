use std::collections::HashMap;
use matchit::Router;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BackendPod {
    pub ip: String,
    pub port: u16,
    pub weight: u32,
}

#[derive(Clone, Default, Debug)]
pub struct RouteTarget {
    pub backends: Vec<BackendPod>,
}

#[derive(Clone, Default)]
pub struct RoutingTable {
    pub hosts: HashMap<String, Router<RouteTarget>>,
}

impl RoutingTable {
    pub fn new() -> Self {
        Self { hosts: HashMap::new() }
    }

    pub fn match_route(&self, host: &str, path: &str) -> Option<&RouteTarget> {
        let router = self.hosts.get(host)?;
        let matched = router.at(path).ok()?;
        Some(matched.value)
    }
}