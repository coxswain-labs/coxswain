//! Tests for [`super`] (`crates/coxswain-bin/src/args.rs`). Hosted in a
//! sibling file because the clap-derive validation suite is large enough that
//! mixing it into `args.rs` made the file hard to scan; per CLAUDE.md's
//! test-layout rule, large per-source-file unit-test bodies live in a sibling
//! `<module>_tests.rs` file attached via `#[path = …] mod tests;`.

use super::*;
use clap::CommandFactory;

/// Sanity-check clap's derive output for inconsistencies.
#[test]
fn clap_definition_is_valid() {
    Cli::command().debug_assert();
}

/// Bare `coxswain serve` parses with `role = None`; the implicit-dev
/// fallback is handled in `main.rs`.
#[test]
fn bare_serve_omits_role() {
    let cli = Cli::try_parse_from(["coxswain", "serve"]).expect("parses");
    let Commands::Serve(serve) = cli.command;
    assert!(serve.role.is_none());
}

/// Explicit `coxswain serve dev` parses to `Role::Dev`.
#[test]
fn serve_dev_parses() {
    let cli = Cli::try_parse_from(["coxswain", "serve", "dev"]).expect("parses");
    let Commands::Serve(serve) = cli.command;
    assert!(matches!(serve.role, Some(Role::Dev(_))));
}

/// `coxswain serve controller` parses to `Role::Controller`.
#[test]
fn serve_controller_parses() {
    let cli = Cli::try_parse_from(["coxswain", "serve", "controller"]).expect("parses");
    let Commands::Serve(serve) = cli.command;
    assert!(matches!(serve.role, Some(Role::Controller(_))));
}

/// `coxswain serve proxy --shared` resolves to `ProxyScope::Shared`.
#[test]
fn serve_proxy_shared_parses() {
    let cli = Cli::try_parse_from(["coxswain", "serve", "proxy", "--shared"]).expect("parses");
    let Commands::Serve(serve) = cli.command;
    let Some(Role::Proxy(args)) = serve.role else {
        panic!("expected Role::Proxy");
    };
    assert_eq!(args.scope(), ProxyScope::Shared);
}

/// `coxswain serve proxy --dedicated --gateway-name=NAME
/// --gateway-namespace=NS` resolves to `ProxyScope::Gateway`.
#[test]
fn serve_proxy_gateway_parses() {
    let cli = Cli::try_parse_from([
        "coxswain",
        "serve",
        "proxy",
        "--dedicated",
        "--gateway-name=my-gw",
        "--gateway-namespace=tenant-a",
        "--proxy-watch-namespaces=tenant-a",
    ])
    .expect("parses");
    let Commands::Serve(serve) = cli.command;
    let Some(Role::Proxy(args)) = serve.role else {
        panic!("expected Role::Proxy");
    };
    assert_eq!(
        args.scope(),
        ProxyScope::Gateway {
            name: "my-gw".to_string(),
            namespace: "tenant-a".to_string(),
            allow_cluster_wide_route_read: false,
            allow_cluster_wide_namespace_read: false,
            watch_namespaces: vec!["tenant-a".to_string()],
        }
    );
}

/// Both opt-in flags parse and propagate through to the resolved scope.
#[test]
fn serve_proxy_gateway_opt_in_flags_parse() {
    let cli = Cli::try_parse_from([
        "coxswain",
        "serve",
        "proxy",
        "--dedicated",
        "--gateway-name=my-gw",
        "--gateway-namespace=tenant-a",
        "--proxy-watch-namespaces=tenant-a,shared",
        "--allow-cluster-wide-route-read",
        "--allow-cluster-wide-namespace-read",
    ])
    .expect("parses");
    let Commands::Serve(serve) = cli.command;
    let Some(Role::Proxy(args)) = serve.role else {
        panic!("expected Role::Proxy");
    };
    assert_eq!(
        args.scope(),
        ProxyScope::Gateway {
            name: "my-gw".to_string(),
            namespace: "tenant-a".to_string(),
            allow_cluster_wide_route_read: true,
            allow_cluster_wide_namespace_read: true,
            watch_namespaces: vec!["tenant-a".to_string(), "shared".to_string()],
        }
    );
}

/// `--dedicated` without `--proxy-watch-namespaces` fails the
/// `required_if_eq` rule — the proxy needs to know which namespaces it can
/// watch, derived by the controller from the desired-namespace set.
#[test]
fn serve_proxy_dedicated_requires_watch_namespaces() {
    let err = Cli::try_parse_from([
        "coxswain",
        "serve",
        "proxy",
        "--dedicated",
        "--gateway-name=my-gw",
        "--gateway-namespace=tenant-a",
    ])
    .unwrap_err();
    assert_eq!(err.kind(), clap::error::ErrorKind::MissingRequiredArgument);
}

/// `--proxy-watch-namespaces` conflicts with `--shared`.
#[test]
fn shared_rejects_proxy_watch_namespaces() {
    let err = Cli::try_parse_from([
        "coxswain",
        "serve",
        "proxy",
        "--shared",
        "--proxy-watch-namespaces=tenant-a",
    ])
    .unwrap_err();
    assert_eq!(err.kind(), clap::error::ErrorKind::ArgumentConflict);
}

/// The opt-in flags conflict with `--shared`.
#[test]
fn shared_rejects_opt_in_flags() {
    let err = Cli::try_parse_from([
        "coxswain",
        "serve",
        "proxy",
        "--shared",
        "--allow-cluster-wide-route-read",
    ])
    .unwrap_err();
    assert_eq!(err.kind(), clap::error::ErrorKind::ArgumentConflict);
}

/// `serve proxy` with no scope flag fails the ArgGroup `required` rule.
#[test]
fn serve_proxy_requires_a_scope() {
    let err = Cli::try_parse_from(["coxswain", "serve", "proxy"]).unwrap_err();
    // clap's MissingRequiredArgument kind when an ArgGroup is unsatisfied.
    assert_eq!(err.kind(), clap::error::ErrorKind::MissingRequiredArgument);
}

/// `serve proxy --shared --dedicated` fails the ArgGroup `multiple = false`
/// rule.
#[test]
fn serve_proxy_rejects_both_scopes() {
    let err =
        Cli::try_parse_from(["coxswain", "serve", "proxy", "--shared", "--dedicated"]).unwrap_err();
    assert_eq!(err.kind(), clap::error::ErrorKind::ArgumentConflict);
}

/// `serve proxy --dedicated` without identifiers fails the `required_if_eq`
/// rule.
#[test]
fn serve_proxy_gateway_requires_identifiers() {
    let err = Cli::try_parse_from(["coxswain", "serve", "proxy", "--dedicated"]).unwrap_err();
    assert_eq!(err.kind(), clap::error::ErrorKind::MissingRequiredArgument);

    let err = Cli::try_parse_from([
        "coxswain",
        "serve",
        "proxy",
        "--dedicated",
        "--gateway-name=my-gw",
    ])
    .unwrap_err();
    assert_eq!(err.kind(), clap::error::ErrorKind::MissingRequiredArgument);
}

/// `serve proxy --shared --gateway-name=…` fails the `conflicts_with`
/// rule (gateway identifiers don't belong on the shared pool).
#[test]
fn serve_proxy_shared_rejects_gateway_identifiers() {
    let err = Cli::try_parse_from([
        "coxswain",
        "serve",
        "proxy",
        "--shared",
        "--gateway-name=my-gw",
    ])
    .unwrap_err();
    assert_eq!(err.kind(), clap::error::ErrorKind::ArgumentConflict);
}

/// `--proxy-bind-address` does not exist on the `controller` role.
#[test]
fn controller_rejects_proxy_bind_address() {
    let err = Cli::try_parse_from([
        "coxswain",
        "serve",
        "controller",
        "--proxy-bind-address=10.0.0.1",
    ])
    .unwrap_err();
    assert_eq!(err.kind(), clap::error::ErrorKind::UnknownArgument);
}

/// `--status-address` does not exist on the `proxy` role.
#[test]
fn proxy_rejects_status_address() {
    let err = Cli::try_parse_from([
        "coxswain",
        "serve",
        "proxy",
        "--shared",
        "--status-address=example.com",
    ])
    .unwrap_err();
    assert_eq!(err.kind(), clap::error::ErrorKind::UnknownArgument);
}

/// `serve --help` lists controller and proxy but not the hidden dev role.
#[test]
fn serve_help_hides_dev() {
    let mut cmd = Cli::command();
    let serve = cmd.find_subcommand_mut("serve").expect("serve exists");
    let help = serve.render_help().to_string();
    assert!(help.contains("controller"), "help should list controller");
    assert!(help.contains("proxy"), "help should list proxy");
    // `dev` may still appear in unrelated copy (e.g. "for local
    // development"). Tighten by matching the subcommand listing line.
    assert!(
        !help
            .lines()
            .any(|line| line.trim_start().starts_with("dev ")),
        "dev should be hidden from `serve --help`:\n{help}"
    );
}

/// `serve dev --help` renders successfully and exposes the full flag set.
#[test]
fn serve_dev_help_round_trip() {
    let mut cmd = Cli::command();
    let dev = cmd
        .find_subcommand_mut("serve")
        .and_then(|s| s.find_subcommand_mut("dev"))
        .expect("dev subcommand exists even though hidden");
    let help = dev.render_help().to_string();
    // A flag from each group must appear.
    assert!(help.contains("--log"), "common log flag in dev help");
    assert!(
        help.contains("--proxy-bind-address"),
        "proxy bind address in dev help"
    );
    assert!(
        help.contains("--controller-lease-ttl"),
        "controller lease TTL in dev help"
    );
    assert!(
        help.contains("--management-bind-address"),
        "management bind address in dev help"
    );
}

/// `serve proxy --help` lists both scope flags.
#[test]
fn serve_proxy_help_lists_scope_flags() {
    let mut cmd = Cli::command();
    let proxy = cmd
        .find_subcommand_mut("serve")
        .and_then(|s| s.find_subcommand_mut("proxy"))
        .expect("proxy subcommand exists");
    let help = proxy.render_help().to_string();
    assert!(help.contains("--shared"), "proxy help lists --shared");
    assert!(help.contains("--dedicated"), "proxy help lists --dedicated");
    assert!(
        help.contains("--gateway-name"),
        "proxy help lists --gateway-name"
    );
}

/// `--management-bind-address` defaults to `0.0.0.0` when neither the CLI
/// flag nor the env var are set.
#[test]
fn management_bind_address_defaults_to_unspecified_v4() {
    // Set env vars to empty to avoid bleed-through from the test runner.
    let cli = Cli::try_parse_from(["coxswain", "serve", "controller"]).expect("controller parses");
    let Commands::Serve(serve) = cli.command;
    let Some(Role::Controller(controller)) = serve.role else {
        panic!("expected controller role");
    };
    assert_eq!(
        controller.common.management_bind_address,
        "0.0.0.0".parse::<IpAddr>().unwrap()
    );
}

/// `--access-log` defaults to `true` and `--access-log-path-mode` to `full`.
#[test]
fn access_log_defaults() {
    let cli = Cli::try_parse_from(["coxswain", "serve", "dev"]).expect("dev parses");
    let Commands::Serve(serve) = cli.command;
    let Some(Role::Dev(args)) = serve.role else {
        panic!("expected dev role");
    };
    assert!(args.proxy.access_log, "access_log defaults to true");
    assert_eq!(
        args.proxy.access_log_path_mode,
        AccessLogPathMode::Full,
        "access_log_path_mode defaults to Full"
    );
}

/// `--access-log false` and all three path mode values parse correctly.
#[test]
fn access_log_flags_parse() {
    let parse = |extra: &[&str]| {
        let mut args = vec!["coxswain", "serve", "dev"];
        args.extend_from_slice(extra);
        Cli::try_parse_from(args).expect("parses")
    };

    // Disabled access log
    let cli = parse(&["--access-log=false"]);
    let Commands::Serve(serve) = cli.command;
    let Some(Role::Dev(args)) = serve.role else {
        panic!("expected dev role");
    };
    assert!(!args.proxy.access_log);

    // Pattern mode
    let cli = parse(&["--access-log-path-mode=pattern"]);
    let Commands::Serve(serve) = cli.command;
    let Some(Role::Dev(args)) = serve.role else {
        panic!("expected dev role");
    };
    assert_eq!(args.proxy.access_log_path_mode, AccessLogPathMode::Pattern);

    // None mode
    let cli = parse(&["--access-log-path-mode=none"]);
    let Commands::Serve(serve) = cli.command;
    let Some(Role::Dev(args)) = serve.role else {
        panic!("expected dev role");
    };
    assert_eq!(args.proxy.access_log_path_mode, AccessLogPathMode::None);
}

/// `--access-log` and `--access-log-path-mode` appear in `dev --help`.
#[test]
fn access_log_flags_in_dev_help() {
    let mut cmd = Cli::command();
    let dev = cmd
        .find_subcommand_mut("serve")
        .and_then(|s| s.find_subcommand_mut("dev"))
        .expect("dev subcommand exists");
    let help = dev.render_help().to_string();
    assert!(help.contains("--access-log"), "dev help lists --access-log");
    assert!(
        help.contains("--access-log-path-mode"),
        "dev help lists --access-log-path-mode"
    );
}
