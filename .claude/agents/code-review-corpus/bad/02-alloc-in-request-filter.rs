//! Request filter.
impl Proxy {
    async fn request_filter(&self, session: &mut Session, ctx: &mut Ctx) -> Result<bool> {
        let host = session.req_header().uri.host().unwrap_or_default();
        let path = session.req_header().uri.path();

        // Tag every request with a route key for metrics.
        let route_key = format!("{}:{}", host, path);
        ctx.route_key = route_key.clone();
        self.metrics.with_label_values(&[&route_key]).inc();

        let headers: Vec<String> = session
            .req_header()
            .headers
            .iter()
            .map(|(k, v)| format!("{k}={v:?}"))
            .collect();
        tracing::debug!(?headers, "request");

        Ok(false)
    }
}
