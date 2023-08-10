use clap::Parser;
use tracing::{error, info, Level};
use tracing_subscriber::FmtSubscriber;

mod attestation;
mod backup;
mod chain;
mod servers;
mod sign;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
	/// Server Port
	#[arg(short, long)]
	domain: String,

	/// Server Port
	#[arg(short, long)]
	port: u16,

	/// Server Port
	#[arg(short, long, default_value_t = 2)]
	verbose: u8,
}

/* MAIN */

#[tokio::main]
async fn main() {
	info!("\n\n\t***********\n \tMain function started\n\t***********\n\n");

	match servers::binary_check::self_checksig() {
		Ok(str) => {
			if str == "Successful" {
				info!("Binary verification successful.");
			} else {
				tracing::error!("ERROR: Binary verfification Failed :  {}", str);
				return;
			}
		},
		Err(str) => {
			tracing::error!("ERROR: Binary verfification Failed :  {}", str);
			return;
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

	info!("Start Tracing");

	let subscriber = FmtSubscriber::builder().with_max_level(verbosity_level).finish();
	tracing::subscriber::set_global_default(subscriber)
		.expect("main: setting default subscriber failed");

	info!("Start Sentry");
	let _guard = sentry::init((
		"https://089e5c79239442bfb6af6e5d7676644c@error.ternoa.dev/22",
		sentry::ClientOptions {
			release: sentry::release_name!(),
			traces_sample_rate: 5.0,
			debug: true,
			..Default::default()
		},
	));

	info!("Define http-server");

	let http_app = match servers::http_server::http_server().await {
		Ok(app) => app,
		Err(_e) => {
			error!("Error creating http application, exiting.");
			return;
		},
	};

	info!("Start Server with routes");
	match servers::server_common::serve(http_app, &args.domain, &args.port).await {
		Ok(_) => info!("Server exited successfully"),
		Err(e) => error!("Server exited with error : {:?}", e),
	}
}
