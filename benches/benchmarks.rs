use anyhow::Context;
use criterion::{criterion_group, criterion_main, Criterion};
use std::io::Write;
use std::net::Ipv4Addr;
use std::net::Ipv6Addr;
use testcontainers::{
    core::{ImageExt, IntoContainerPort, Mount, WaitFor},
    runners::AsyncRunner,
    ContainerAsync, GenericImage,
};
use tokio::net::TcpListener;
use tokio::task::JoinSet;
use tokio::time::sleep;
use tokio::try_join;
use url::Url;

use nkeys::KeyPair;
use std::time::Duration;
use wasmcloud_core::tls::NativeRootsExt as _;
use wasmcloud_test_util::lattice::config::assert_config_put;
use wasmcloud_test_util::provider::{assert_start_provider, StartProviderArgs};
use wasmcloud_test_util::{
    component::assert_scale_component, host::WasmCloudTestHost,
    lattice::link::assert_advertise_link,
};

use test_components::RUST_HTTP_HELLO_WORLD;

const LATTICE: &str = "default";
const COMPONENT_ID: &str = "http_hello_world";

/// Retrieve a free port to use from the OS
pub async fn free_port() -> anyhow::Result<u16> {
    TcpListener::bind((Ipv6Addr::LOCALHOST, 0))
        .await
        .context("failed to start TCP listener")?
        .local_addr()
        .context("failed to query listener local address")
        .map(|v| v.port())
}

pub async fn setup() -> anyhow::Result<(u16, ContainerAsync<GenericImage>)> {
    let nats_cfg = r#"
max_connections: 1M
jetstream {
    enabled: true
}
"#;

    let mut cfg = tempfile::NamedTempFile::new().unwrap();
    cfg.write(nats_cfg.as_bytes())
        .map_err(|e| anyhow::anyhow!("Failed to write config: {}", e))
        .unwrap();

    let mount = Mount::bind_mount(cfg.path().to_str().unwrap(), "/nats.cfg");
    let container = GenericImage::new("nats", "2.10")
        .with_exposed_port(4222.tcp())
        .with_wait_for(WaitFor::message_on_stderr("Server is ready"))
        .with_cmd(vec!["-js", "-c", "/nats.cfg", "-DV"])
        .with_mount(mount)
        .start()
        .await
        .expect("Started NATS");

    let url = format!(
        "nats://localhost:{}",
        container.get_host_port_ipv4(4222).await.unwrap()
    );

    let nats_client = async_nats::connect(&url).await.expect("Connected to NATS");

    let ctl_client = wasmcloud_control_interface::ClientBuilder::new(nats_client)
        .lattice(LATTICE.to_string())
        .build();
    // Build the host
    let host = WasmCloudTestHost::start(&url, LATTICE).await.unwrap();
    let http_port = free_port().await?;

    let http_server_config_name = "http-server".to_string();

    try_join!(
        async {
            assert_config_put(
                &ctl_client,
                &http_server_config_name,
                [(
                    "ADDRESS".to_string(),
                    format!("{}:{http_port}", Ipv4Addr::LOCALHOST),
                )],
            )
            .await
            .context("failed to put configuration")
        },
        async {
            let host_key = host.host_key();
            assert_start_provider(StartProviderArgs {
                client: &ctl_client,
                lattice: LATTICE,
                host_key: &host_key,
                provider_key: &KeyPair::from_public_key(
                    "VAG3QITQQ2ODAOWB5TTQSDJ53XK3SHBEIFNK4AYJ5RKAX2UNSCAPHA5M",
                )
                .unwrap(),
                provider_id: "VAG3QITQQ2ODAOWB5TTQSDJ53XK3SHBEIFNK4AYJ5RKAX2UNSCAPHA5M",
                url: &Url::parse("https://ghcr.io/wasmcloud/http-server:0.23.1").unwrap(),
                config: vec![],
            })
            .await
            .context("failed to start providers")
        },
        async {
            assert_scale_component(
                &ctl_client,
                &host.host_key(),
                format!("file://{RUST_HTTP_HELLO_WORLD}"),
                COMPONENT_ID,
                None,
                5000,
                Vec::new(),
            )
            .await
            .context("failed to scale `rust-http-hello-world` component")
        }
    )?;

    assert_advertise_link(
        &ctl_client,
        "VAG3QITQQ2ODAOWB5TTQSDJ53XK3SHBEIFNK4AYJ5RKAX2UNSCAPHA5M",
        COMPONENT_ID,
        "default",
        "wasi",
        "http",
        vec!["incoming-handler".to_string()],
        vec![http_server_config_name],
        vec![],
    )
    .await
    .context("failed to advertise link")?;

    // Wait for data to be propagated across lattice
    sleep(Duration::from_secs(1)).await;

    Ok((http_port, container))
}

pub async fn run_benchmark(http_port: u16) {
    reqwest::get(format!("http://localhost:{}", http_port))
        .await
        .unwrap();
}

pub fn host_benchmark(c: &mut Criterion) {
    let runtime = tokio::runtime::Runtime::new().unwrap();
    let (port, container) = runtime.block_on(setup()).unwrap();

    let mut group = c.benchmark_group("host");
    group.throughput(criterion::Throughput::Elements(1));
    group.bench_function("benchmark", |b| {
        b.to_async(&runtime).iter(|| run_benchmark(port));
    });
    group.finish();
    container.stop();
}

criterion_group!(benches, host_benchmark);
criterion_main!(benches);
