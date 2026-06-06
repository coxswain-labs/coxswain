pub const ECHO: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/fixtures/backends/echo.yaml");

pub const WEBSOCKET_ECHO: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/fixtures/backends/websocket_echo.yaml"
);

pub const SLOW_ECHO: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/fixtures/backends/slow_echo.yaml"
);

pub const H2C_ECHO: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/fixtures/backends/h2c_echo.yaml"
);
