use std::env;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

mod servers;
use crate::servers::{http_server, server_common};
mod chain;
mod keys;
use crate::keys::ipfs;

use std::fs::File;
use std::io::prelude::*;

/* MAIN */

#[tokio::main(worker_threads = 4)]
async fn main() {
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
		println!("This is NOT inside an Enclave!");
		return Vec::new();
	}

	let mut f1 = File::open("/dev/attestation/user_report_data").unwrap();
	println!("This is inside Enclave!");

	let mut f2 = File::open("/dev/attestation/attestation_type").unwrap();
	let mut attest_type = String::new();
	f2.read_to_string(&mut attest_type);
	println!("attestation type is : {}", attest_type);

	let write_zero = [0; 640];
	f1.write_all(&write_zero);

	println!("Reading The Quote ...");
	let mut f3 = File::open("/dev/attestation/quote").unwrap();
	let mut contents = vec![];
	f3.read_to_end(&mut contents).unwrap();
	//println!("{:-#?}",contents);

	println!("Writing the Quote");
	let mut f4 = File::create("/quote/enclave.quote").unwrap();
	f4.write_all(&contents);

	return contents;
}
