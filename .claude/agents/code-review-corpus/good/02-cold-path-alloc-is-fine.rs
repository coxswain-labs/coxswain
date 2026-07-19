//! Upstream selection.
impl Proxy {
    async fn upstream_peer(&self, session: &mut Session, ctx: &mut Ctx) -> Result<Box<HttpPeer>> {
        // Hot path: no allocation, reads the ArcSwap snapshot.
        let snapshot = self.routes.load();
        match snapshot.find(ctx.host_captured, ctx.path_captured) {
            Some(peer) => Ok(Box::new(peer.clone_cheap())),
            None => {
                // Cold: this request is already failing; a format! here is
                // paid once per error, not per request.
                Err(Error::explain(
                    HTTPStatus(503),
                    format!("no upstream for {}", ctx.host_captured),
                ))
            }
        }
    }
}
