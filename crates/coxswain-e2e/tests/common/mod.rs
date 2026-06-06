pub fn init_tracing() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter("coxswain_e2e=debug,warn")
        .try_init();
}
