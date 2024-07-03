#![allow(dead_code)]

use clap::Parser;

mod admin;
mod attestation;
mod helper;
mod metric;
mod retrieve_secret;
mod store_secret;

use tracing_subscriber::{fmt, prelude::*, EnvFilter};

/* *************************************
				MAIN
**************************************** */
#[tokio::main]
async fn main() {
	let fmt_layer = fmt::layer()
		.with_target(true)
		.with_level(true)
		.with_thread_ids(false)
		.with_thread_names(true);

	let filter_layer = EnvFilter::try_from_default_env()
		.or_else(|_| EnvFilter::try_new::<String>("Info".into()))
		.expect("Error tracing subscriber filter layer");

	tracing_subscriber::registry().with(filter_layer).with(fmt_layer).init();

	let args = helper::Args::parse();

	if args.seed.is_empty() {
		println!("\n Seed-phrase can not be empty! \n");
		return;
	}

	if args.nftid > 0 || !args.custom_data.is_empty() {
		match args.request.to_lowercase().as_str() {
			"retrieve" => retrieve_secret::generate_retrieve_request(args.clone()).await,
			"store" => store_secret::generate_store_request(args).await,
			_ => println!("\n Please provide a valid request type \n"),
		}
		return;
	} else if std::path::Path::new(&args.file).exists() {
		match args.request.to_lowercase().as_str() {
			"admin-push-bulk" => admin::generate_push_bulk(args.seed.clone(), args.file).await,
			"admin-fetch-bulk" => admin::generate_fetch_bulk(args.seed.clone()).await,
			_ => println!("\n Please provide a valid request type \n"),
		}
		return;
	} else if !args.id_vec.is_empty() {
		match args.request.to_lowercase().as_str() {
			"admin-push-id" => admin::generate_push_id(args.seed.clone(), args.id_vec).await,
			"admin-fetch-id" => admin::generate_fetch_id(args.seed.clone(), args.id_vec).await,
			_ => println!("\n Please provide a valid request type \n"),
		}
		return;
	} else if !args.block_interval.is_empty() {
		match args.request.to_lowercase().as_str() {
			"reconcilliation" =>
				metric::generate_reconcilliation(args.seed.clone(), args.block_interval).await,
			_ => println!("\n Please provide a valid request type \n"),
		}
		return;
	} else if !args.enclave_url.is_empty() {
		match args.request.to_lowercase().as_str() {
			"attest" => attestation::attest(args.seed.clone(), args.enclave_url).await.unwrap(),
			_ => println!("\n Please provide a valid request type \n"),
		}
		return;
	} else {
		println!("\n Please provide either a valid NFTID, ID_VEC, ENCLAVE_URL or Custom Data \n");
		return;
	}
}
