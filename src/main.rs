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

#[tokio::main(worker_threads = 4)]
async fn main() {
	info!("\n\n\t***********\n \tMAIN function started\n\t***********\n\n");

	match servers::binary_check::self_checksig() {
		Ok(str) => {
			if str == "Successful" {
				info!("MAIN : Binary verification successful.");
			} else {
				tracing::error!("MAIN : ERROR : Binary verfification Failed : {}", str);
				sentry::capture_message("Binary verfification Failed", sentry::Level::Error);
				return;
			}
		},

		Err(estr) => {
			let message = format!("MAIN : ERROR: Binary verfification Failed : {}", estr);
			tracing::error!(message);
			sentry::capture_message(&message, sentry::Level::Error);
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

	info!("MAIN : Start Tracing");
	let subscriber = FmtSubscriber::builder().with_max_level(verbosity_level).finish();
	tracing::subscriber::set_global_default(subscriber)
		.expect("MAIN : setting default subscriber failed");

	info!("MAIN : Start Sentry");
	let env = if cfg!(feature = "mainnet") {
		"mainnet"
	} else if cfg!(feature = "alphanet") {
		"alphanet"
	} else if cfg!(feature = "dev-0") {
		"dev-0"
	} else if cfg!(feature = "dev-1") {
		"dev-1"
	} else {
		"unknown"
	};

	let _guard = sentry::init((
		"https://089e5c79239442bfb6af6e5d7676644c@error.ternoa.dev/22",
		sentry::ClientOptions {
			release: Some(format!("Ternoa Enclave Version v{}", chain::constants::VERSION).into()),
			traces_sample_rate: 1.0,
			debug: true,
			environment: Some(env.into()),
			before_send: Some(std::sync::Arc::new(|mut event| {
				// Modify event here
				event.server_name = Some("TERNOA SGX ENCLAVE SERVER".into());
				Some(event)
			})),
			..Default::default()
		},
	));

	sentry::configure_scope(|scope| {
		scope.set_level(Some(sentry::Level::Warning));

		let now = chrono::prelude::Utc::now().to_string();
		let mut map = std::collections::BTreeMap::new();
		map.insert(String::from("domain"), args.domain.clone().into());
		map.insert(String::from("port"), args.port.into());
		map.insert(String::from("start-date"), now.into());
		scope.set_context("ENCLAVE", sentry::protocol::Context::Other(map));

		scope.set_user(Some(sentry::User {
			id: Some("Ternoa Operator".into()),
			email: Some("john.doe@example.com".into()),
			..Default::default()
		}));
	});

	info!("MAIN : Define http-server");
	let http_app = match servers::http_server::http_server().await {
		Ok(app) => app,
		Err(err) => {
			error!("MAIN : Error creating http application, exiting : {err:?}");
			sentry::integrations::anyhow::capture_anyhow(&err);
			return;
		},
	};

	info!("MAIN : Start Server with routes");
	match servers::server_common::serve(http_app, &args.domain, &args.port).await {
		Ok(_) => info!("MAIN : Server exited successfully"),
		Err(err) => {
			error!("MAIN : Server exited with error : {err:?}");
			sentry::integrations::anyhow::capture_anyhow(&err);
		},
	}
}
