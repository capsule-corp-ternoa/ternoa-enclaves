#![allow(dead_code)]
use std::{
	fs::{File, OpenOptions},
	io::{Error, Read, Write},
	path::Path,
};

use axum::{extract::State, http::StatusCode, response::IntoResponse, Json};
use serde::{Deserialize, Serialize};
//use cached::proc_macro::once;
use sp_core::Pair;
use tracing::{debug, error, info};

use crate::servers::state::{get_accountid, get_blocknumber, get_keypair, SharedState};
use anyhow::{anyhow, Result};

#[derive(Serialize, Deserialize, Debug)]
pub struct QuoteResponse {
	pub block_number: u32,
	pub data: String,
}

// TODO [performace] : Rate Limit or Cache the Quote API
//#[once(time = 60, sync_writes = false)]
pub async fn ra_get_quote(State(state): State<SharedState>) -> impl IntoResponse {
	// Make a dynamic user data
	let enclave_id = get_accountid(&state).await;
	let block_number = get_blocknumber(&state).await;
	let sign_data = enclave_id + "_" + &block_number.to_string();

	debug!("QUOTE : report_data token  = {}", sign_data);

	// Signer
	let enclave_account = get_keypair(&state).await;

	let signature = enclave_account.sign(sign_data.as_bytes());

	write_user_report_data(None, &signature.0).unwrap();

	match generate_quote(None, None) {
		Ok(quote) => {
			(StatusCode::OK, Json(QuoteResponse { block_number, data: hex::encode(quote) }))
		},

		Err(e) => (
			StatusCode::INTERNAL_SERVER_ERROR,
			Json(QuoteResponse { block_number, data: e.to_string() }),
		),
	}
}

/// get the attestation type
/// # Arguments
/// * `attestation_type_path` - The path to the attestation type
/// # Returns
/// * `Result<String, Error>` - The result of the attestation type
pub fn generate_quote(
	attestation_quote_path: Option<String>,
	enclave_file_path: Option<String>,
) -> Result<Vec<u8>, Error> {
	info!("Dumping the Quote");

	let default_enclave_path = "/quote/enclave.quote";

	get_quote_content(attestation_quote_path).and_then(|result| {
		File::create(enclave_file_path.unwrap_or(String::from(default_enclave_path)))
			.and_then(|mut file| {
				file.write_all(&result).map_err(|err| {
					error!("Error writing to quote file {:?}", err);
					err
				})
			})
			.map_err(|err| {
				error!("Error Writing content");
				err
			})
			.map(|_| {
				debug!("content  {:?}", result);
				result
			})
	})
}

/// Reads the quote or else returns an error
/// # Arguments
/// * `file_path` - The path to the quote
/// # Returns
/// * `Result<Vec<u8>, Error>` - The result of the quote
fn get_quote_content(file_path: Option<String>) -> Result<Vec<u8>, Error> {
	info!("Reading The Quote ...");
	let default_path = "/dev/attestation/quote";
	let mut content = vec![];

	File::open(file_path.unwrap_or(String::from(default_path)))
		.and_then(|mut file| {
			file.read_to_end(&mut content).map_err(|err| {
				error!("Error opening file /dev/attestation/quote {:?}", err);
				err
			})
		})
		.map(|_| {
			debug!("content  {:?}", content);
			content
		})
}

/// Reads the attestation type or else returns an error
/// # Arguments
/// * `file_path` - The path to the attestation type
/// # Returns
/// * `Result<String, Error>` - The result of the attestation type
fn read_attestation_type(file_path: Option<String>) -> Result<String, Error> {
	let default_path = "/dev/attestation/attestation.attestation_type";
	let mut attest_type = String::new();

	File::open(file_path.unwrap_or(String::from(default_path)))
		.and_then(|mut file| {
			file.read_to_string(&mut attest_type).map_err(|err| {
				error!("Error reading file: {:?}", err);
				err
			})
		})
		.map(|_| {
			debug!("attestation type is : {}", attest_type);
			attest_type
		})
}

///  Writes user report data or else throws an Error
/// # Arguments
/// * `file_path` - The path to the user report data
/// # Returns
/// * `Result<(), Error>` - The result of the user report data
fn write_user_report_data(
	file_path: Option<String>,
	user_data: &[u8; 64],
) -> Result<(), anyhow::Error> {
	let default_path = "/dev/attestation/user_report_data";
	if !is_user_report_data_exist(None) {
		return Err(anyhow!("user_report_data does not exist!"));
	}

	Ok(OpenOptions::new()
		.write(true)
		.open(file_path.unwrap_or(String::from(default_path)))
		.and_then(|mut file| {
			info!("This is inside Enclave!");
			file.write_all(user_data.as_slice()).map_err(|err| {
				error!("Error writing to {} {:?}", default_path, err);
				err
			})
		})
		.map_err(|err| {
			error!("Error writing file: {:?}", err);
			err
		})
		.map(|_| ())?)
}

/// Check if file exists with correct permissions or else returns false
/// # Arguments
/// * `file_path` - The path to the user report data
/// # Returns
/// * `bool` - The result of the user report data
fn is_user_report_data_exist(file_path: Option<String>) -> bool {
	return match file_path {
		None => Path::new("/dev/attestation/user_report_data").exists(),
		Some(_) => Path::new(file_path.unwrap().as_str()).exists(),
	}

	let mut f1 = OpenOptions::new()
		.write(true)
		.open("/dev/attestation/user_report_data")
		.unwrap(); // TODO: manage unwrap()
	info!("This is inside Enclave!");

	let mut f2 = File::open("/dev/attestation/attestation_type").unwrap(); // TODO: manage unwrap()
	let mut attest_type = String::new();
	f2.read_to_string(&mut attest_type).unwrap(); // TODO: manage unwrap()
	info!("attestation type is : {}", attest_type);

	let write_zero = [0u8; 64];
	f1.write_all(&write_zero)
		.expect("Error writing to /dev/attestation/user_report_data"); // TODO: manage expect()

	info!("Reading The Quote ...");
	let mut f3 = File::open("/dev/attestation/quote").unwrap(); // TODO: manage unwrap()
	let mut contents = vec![];
	f3.read_to_end(&mut contents).unwrap(); // TODO: manage unwrap()
										//println!("{:-#?}",contents);

	info!("Dumping the Quote");
	let mut f4 = File::create("/quote/enclave.quote").unwrap(); // TODO: manage unwrap()
	f4.write_all(&contents).unwrap(); // TODO: manage unwrap()

	contents
}
