use clap::Parser;
use tracing::{info, Level};
use tracing_subscriber::FmtSubscriber;

mod attestation;
mod backup;
mod chain;
mod servers;
mod sign;
use servers::http_server;

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

	/// Server Port
	#[arg(short, long, default_value_t = 2)]
	verbose: u8,
}

/* MAIN */

#[tokio::main]
async fn main() {
	info!("1-1 Main function started self-check.");

	match http_server::self_checksig() {
		Ok(str) =>
			if str == "Successful" {
				info!("Binary verification successful.");
			} else {
				tracing::error!("ERROR: Binary verfification Failed :  {}", str);
				return
			},
		Err(str) => {
			tracing::error!("ERROR: Binary verfification Failed :  {}", str);
			return
		},
	}

	let args = Args::parse();

	let verbosity_level = match args.verbose {
		0 => Level::ERROR,
		1 => Level::WARN,
		2 => Level::INFO,
		3 => Level::DEBUG,
		4 => Level::TRACE,
		_ => Level::INFO,
	};

	info!("1-2 Starting Tracing");

	let subscriber = FmtSubscriber::builder().with_max_level(verbosity_level).finish();
	tracing::subscriber::set_global_default(subscriber)
		.expect("main: setting default subscriber failed");

	info!("1-3 Starting Sentry");
	let _guard = sentry::init((
		"https://089e5c79239442bfb6af6e5d7676644c@error.ternoa.dev/22",
		sentry::ClientOptions {
			release: sentry::release_name!(),
			traces_sample_rate: 5.0,
			debug: true,
			..Default::default()
		},
	));

	info!("1-4 Staring http-server");

	http_server::http_server(&args.domain, &args.port, &args.identity, &args.sealpath).await;

	info!("1-5 http-server exited");
}
