use clap::Parser;
use nkeys::XKey;
use secrets_nats_kv::Api;

#[derive(Parser, Debug)]
struct Args {
    #[arg(short, long)]
    xkey_seed: String,
    #[arg(short, long)]
    subject_base: String,
    #[arg(short = 'n', long)]
    name: Option<String>,
    #[arg(short = 'b', long)]
    secrets_bucket: String,
    #[arg(long, default_value = "64")]
    max_secret_history: usize,
    #[arg(long)]
    nats_creds_path: Option<String>,
    #[arg(long, default_value = "wasmcloud_secrets")]
    nats_queue_base: String,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();

    let args = Args::parse();

    let server_xkey = nkeys::XKey::new();
    let encryption_key = args.xkey_seed;

    let ec = XKey::from_seed(&encryption_key)?;
    let client = async_nats::connect("127.0.0.1:4222").await?;

    let name = args.name.unwrap_or_else(|| "nats-kv".to_string());

    let api = Api::new(
        server_xkey,
        ec,
        client,
        args.subject_base,
        name,
        args.secrets_bucket,
        args.max_secret_history,
        args.nats_queue_base,
    );
    api.run().await
}
