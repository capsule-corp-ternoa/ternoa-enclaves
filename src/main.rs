use clap::Parser;
use tracing::Level;
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
	let subscriber = FmtSubscriber::builder().with_max_level(Level::INFO).finish();
	tracing::subscriber::set_global_default(subscriber).expect("setting default subscriber failed");

	let args = Args::parse();

	http_server::http_server(&args.domain, &args.port, &args.identity, &args.sealpath).await;
}
