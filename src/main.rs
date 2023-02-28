use clap::Parser;
use tracing::{info, Level};
use tracing_subscriber::FmtSubscriber;

mod attestation;
mod backup;
mod chain;
mod pgp;
mod servers;
use crate::servers::http_server;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
	/// Server Port
	#[arg(short, long)]
	domain: String,

	/// Server Port
	#[arg(short, long)]
	port: u16,

	/// Path to the location for storing sealed NFT key-shares
	#[arg(short, long, default_value_t = String::from("/nft/"))]
	sealpath: String,

	/// Enclave unique name
	#[arg(short, long, default_value_t = String::from("DEV-C1N1E1"))]
	identity: String,
}

/* MAIN */

#[tokio::main(worker_threads = 4)]
async fn main() {
	info!("1-1 Main function started.");
	let subscriber = FmtSubscriber::builder().with_max_level(Level::TRACE).finish();
	tracing::subscriber::set_global_default(subscriber).expect("setting default subscriber failed"); // TODO: manage expect()

	info!("1-2 Tracing started");

	let _guard = sentry::init((
		"https://089e5c79239442bfb6af6e5d7676644c@error.ternoa.dev/22",
		sentry::ClientOptions {
			release: sentry::release_name!(),
			traces_sample_rate: 5.0,
			debug: true,
			..Default::default()
		},
	));

	info!("1-3 Sentry started.");

	let args = Args::parse();

	info!("1-4 Staring http-server");

	http_server::http_server(&args.domain, &args.port, &args.identity, &args.sealpath).await;

	info!("1-5 http-server exited");
}
