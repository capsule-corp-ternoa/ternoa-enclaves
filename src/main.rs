use clap::Parser;
use tracing::Level;
use tracing_subscriber::FmtSubscriber;

mod attestation;
mod backup;
mod chain;
mod servers;
use crate::servers::http_server;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
	/// Server Port
	#[arg(short, long)]
	port: u16,

	/// Path to the file, containing private key for Ternoa account of enclave owner
	#[arg(short, long, default_value_t = String::from("5Cf8PBw7QiRFNPBTnUoks9Hvkzn8av1qfcgMtSppJvjYcxp6"))]
	account: String,

	/// Path to the file, containing certificate for TLS connection
	#[arg(short, long, default_value_t = String::from("/opt/sgx_server/cert.pem"))]
	certfile: String,

	/// Path to the file, containing private-key for TLS connection
	#[arg(short, long, default_value_t = String::from("/opt/sgx_server/key.pem"))]
	keyfile: String,

	/// Path to the location for storing sealed NFT secret shares
	#[arg(short, long, default_value_t = String::from("/opt/sgx_server_nft/"))]
	sealpath: String,

	/// Enclave unique name
	#[arg(short, long, default_value_t = String::from("C1N1E1"))]
	identity: String,
}

/* MAIN */

#[tokio::main(worker_threads = 4)]
async fn main() {
	let subscriber = FmtSubscriber::builder().with_max_level(Level::INFO).finish();
	tracing::subscriber::set_global_default(subscriber).expect("setting default subscriber failed");

	let args = Args::parse();

	http_server::http_server(
		&args.port,
		&args.account,
		&args.certfile,
		&args.keyfile,
		&args.sealpath,
	)
	.await;
}
