use crate::chain::constants::{SENTRY_URL, VERSION};
use clap::Parser;
use tracing::{error, info};
use tracing_subscriber::{fmt, prelude::*, EnvFilter};

mod attestation;
mod backup;
mod chain;
mod servers;

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
	println!(
		"\n\n\t**********************\n\n
	MAIN function started
	 	\n\n\t**********************\n\n"
	);

	let args = Args::parse();

	let verbosity_level = match args.verbose {
		0 => "Error",
		1 => "Warn",
		2 => "Info",
		3 => "Debug",
		4 => "Trace",
		_ => "Info",
	};

	let fmt_layer = fmt::layer()
		.with_target(false)
		.with_level(false)
		.with_thread_ids(false)
		.with_thread_names(false);
		

	let filter_layer = EnvFilter::try_from_default_env()
		.or_else(|_| EnvFilter::try_new::<String>(verbosity_level.into()))
		.expect("Error tracing subscriber filter layer");

	tracing_subscriber::registry().with(filter_layer).with(fmt_layer).init();

	info!("MAIN : Start Sentry");
	let env = if cfg!(feature = "mainnet") {
		"mainnet"
	} else if cfg!(feature = "alphanet") {
		"alphanet"
	} else if cfg!(feature = "dev0") {
		"dev0"
	} else if cfg!(feature = "dev1") {
		"dev1"
	} else {
		"localchain"
	};

	let _guard = sentry::init((
		SENTRY_URL,
		sentry::ClientOptions {
			release: Some(format!("Ternoa Enclave Version v{}", VERSION).into()),
			traces_sample_rate: 1.0,
			debug: false,
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
		scope.set_level(Some(sentry::Level::Error));

		let now = chrono::prelude::Utc::now().to_string();
		let mut map = std::collections::BTreeMap::new();
		map.insert(String::from("domain"), args.domain.clone().into());
		map.insert(String::from("port"), args.port.into());
		map.insert(String::from("start-date"), now.into());
		scope.set_context("ENCLAVE", sentry::protocol::Context::Other(map));

		scope.set_user(Some(sentry::User {
			id: Some("Ternoa Operator".into()),
			email: Some("john.doe@ternoa.com".into()),
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
