use std::{fs::File, io::prelude::*};
use tracing::{info, Level};
use tracing_subscriber::{fmt, layer::SubscriberExt, Registry};

mod backup;
mod chain;
mod keys;
mod servers;
use crate::servers::http_server;
use std::env;

/* MAIN */

#[tokio::main(worker_threads = 4)]
async fn main() {
	let quote = generate_quote();

	let logger = Registry::default().with(fmt::Layer::default());
	tracing::subscriber::set_global_default(logger).unwrap();

	let args: Vec<String> = env::args().collect();
	if args.len() < 1 {
		panic!("Please provide proper input arguments: <port> \n");
	}

	let port = &args[1].parse::<u16>().unwrap();

	http_server::http_server(port).await;
}

fn generate_quote() -> Vec<u8> {
	if !std::path::Path::new("/dev/attestation/user_report_data").exists() {
		info!("This is NOT inside an Enclave!");
		return Vec::new()
	}

	let mut f1 = File::open("/dev/attestation/user_report_data").unwrap();
	info!("This is inside Enclave!");

	let mut f2 = File::open("/dev/attestation/attestation_type").unwrap();
	let mut attest_type = String::new();
	f2.read_to_string(&mut attest_type);
	info!("attestation type is : {}", attest_type);

	let write_zero = [0; 640];
	f1.write_all(&write_zero);

	info!("Reading The Quote ...");
	let mut f3 = File::open("/dev/attestation/quote").unwrap();
	let mut contents = vec![];
	f3.read_to_end(&mut contents).unwrap();
	//println!("{:-#?}",contents);

	info!("Writing the Quote");
	let mut f4 = File::create("/quote/enclave.quote").unwrap();
	f4.write_all(&contents);

	return contents
}
