use std::{fs::File, io::prelude::*};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

mod backup;
mod chain;
mod keys;
mod servers;
use crate::servers::http_server;
use std::env;

use chrono::Local;
use env_logger::Builder;
use log::LevelFilter;

/* MAIN */

#[tokio::main(worker_threads = 4)]
async fn main() {
	Builder::new()
		.format(|buf, record| {
			writeln!(
				buf,
				"{} [{}] - {}",
				Local::now().format("%Y-%m-%dT%H:%M:%S"),
				record.level(),
				record.args()
			)
		})
		.filter(None, LevelFilter::Info)
		.init();

	let quote = generate_quote();

	tracing_subscriber::registry()
		.with(tracing_subscriber::EnvFilter::new(
			std::env::var("RUST_LOG")
				.unwrap_or_else(|_| "example_websockets=debug,tower_http=debug".into()),
		))
		.with(tracing_subscriber::fmt::layer())
		.init();

	let args: Vec<String> = env::args().collect();
	if args.len() < 1 {
		panic!("Please provide proper input arguments: <port> \n");
	}

	let port = &args[1].parse::<u16>().unwrap();

	http_server::http_server(port).await;
}

fn generate_quote() -> Vec<u8> {
	if !std::path::Path::new("/dev/attestation/user_report_data").exists() {
		log::warn!("This is NOT inside an Enclave!");
		return Vec::new()
	}

	let mut f1 = File::open("/dev/attestation/user_report_data").unwrap();
	log::info!("This is inside Enclave!");

	let mut f2 = File::open("/dev/attestation/attestation_type").unwrap();
	let mut attest_type = String::new();
	f2.read_to_string(&mut attest_type);
	log::info!("attestation type is : {}", attest_type);

	let write_zero = [0; 640];
	f1.write_all(&write_zero);

	log::info!("Reading The Quote ...");
	let mut f3 = File::open("/dev/attestation/quote").unwrap();
	let mut contents = vec![];
	f3.read_to_end(&mut contents).unwrap();
	//println!("{:-#?}",contents);

	log::info!("Writing the Quote");
	let mut f4 = File::create("/quote/enclave.quote").unwrap();
	f4.write_all(&contents);

	return contents
}
