use std::env;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

mod servers;
use crate::servers::{http_server, server_common};
mod chain;
mod keys;
use crate::{
	keys::{ipfs, zipdir},
};

/* MAIN */

#[tokio::main]
async fn main() {
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
