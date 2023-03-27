#![allow(dead_code)]
#![allow(unused_imports)]
#![allow(unused_variables)]

use axum::{
	body::{StreamBody, Bytes},
	extract::{Multipart, State, FromRequest},
	http::header,
	response::IntoResponse,
	Json,
};
use tokio_util::io::ReaderStream;

use hex::{FromHex, FromHexError};
use serde_json::{json, Value};
use sp_core::{crypto::Ss58Codec, sr25519, Pair};
use std::io::{Read, Write};

use tracing::{debug, info};

use std::fs::{remove_file, File};
use tracing::{debug, error, info};

use serde::{Deserialize, Serialize};
use sp_core::{crypto::PublicError, sr25519::Signature};

use crate::{chain::core::get_current_block_number, servers::http_server::StateConfig};

use super::zipdir::{add_dir_zip, zip_extract};

const BACKUP_WHITELIST: [&str; 3] = [
	"5FsD8XDoCWPkpwKCnqj9SuP3E7GhkQWQwUSVoZJPoMcvKqWZ", // Mohsin
	"5CfFQLwchs3ujcysbFgVMhSVqC1NdXbGHfRvnRrToWthW5PW", // Prabhu
	"5CcqaTBwWvbB2MvmeteSDLVujL3oaFHtdf24pPVT3Xf8v7tC", // Amin
];

/* *************************************
		FETCH  BULK DATA STRUCTURES
**************************************** */

// Validity time of Keyshare Data
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct FetchAuthenticationToken {
	pub block_number: u32,
	pub block_validation: u32,
}

/// Fetch Bulk Data
#[derive(Serialize, Deserialize)]
pub struct FetchBulkPacket {
	admin_address: String,
	auth_token: String, //FetchAuthenticationToken,
	signature: String,
}

/// Fetch Bulk Response
#[derive(Serialize)]
pub struct FetchBulkResponse {
	data: String,
	signature: String,
}

/* *************************************
		STORE  BULK DATA STRUCTURES
**************************************** */

// Validity time of Keyshare Data
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct StoreAuthenticationToken {
	pub block_number: u32,
	pub block_validation: u32,
	pub data_hash: String,
}

/// Store Bulk Packet
#[derive(Serialize, Deserialize)]
pub struct StoreBulkPacket {
	admin_address: String,
	restore_file: Vec<u8>,
	auth_token: StoreAuthenticationToken,
	signature: String,
}

/* ----------------------------------
AUTHENTICATION TOKEN IMPLEMENTATION
----------------------------------*/

/// Retrieving the stored Keyshare
impl FetchAuthenticationToken {
	pub async fn is_valid(&self) -> bool {
		let last_block_number = get_current_block_number().await;

		(last_block_number > self.block_number - 3) // for finalization delay
			&& (last_block_number < self.block_number + self.block_validation + 3) // validity period
				&&  (self.block_validation < 20) // A finite validity period
	}
}

impl StoreAuthenticationToken {
	pub async fn is_valid(&self) -> bool {
		let last_block_number = get_current_block_number().await;

		(last_block_number > self.block_number - 3) // for finalization delay
			&& (last_block_number < self.block_number + self.block_validation + 3) // validity period
				&&  (self.block_validation < 20) // A finite validity period
	}
}

/* *************************************
		 VERIFICATION FUNCTIONS
**************************************** */

/// Verifies the signature of the backup data
/// # Arguments
/// * `account_id` - Account ID
/// * `signature` - Signature
/// * `data` - Data
/// # Returns
/// * `Result<bool, PublicError>` - Result
/// # Example
/// ```
/// verify_signature(account_id, signature, data)
/// ```
/// # Errors
/// * `PublicError` - If the account ID is not a valid SS58 string
fn verify_account_id(account_id: &str) -> bool {
	BACKUP_WHITELIST.contains(&account_id)
}

/// Verifies the signature of the backup data
/// # Arguments
/// * `account_id` - Account ID
/// * `signature` - Signature
/// * `data` - Data
/// # Returns
/// * `Result<bool, PublicError>` - Result
/// # Example
/// ```
/// verify_signature(account_id, signature, data)
/// ```
/// # Errors
/// * `PublicError` - If the account ID is not a valid SS58 string
/// * `FromHexError` - If the signature is not a valid hex string
/// * `PublicError` - If the signature is not a valid signature
fn get_public_key(account_id: &str) -> Result<sr25519::Public, PublicError> {
	let pk: Result<sr25519::Public, PublicError> = sr25519::Public::from_ss58check(account_id)
		.map_err(|err: PublicError| {
			debug!("Error constructing public key {:?}", err);
			err
		});

	pk
}

/// Converts the signature to a Signature type
/// # Arguments
/// * `signature` - Signature
/// # Returns
/// * `Result<Signature, FromHexError>` - Signature
/// # Example
/// ```
/// get_signature(signature)
/// ```
/// # Errors
/// * `FromHexError` - If the signature is not a valid hex string
fn get_signature(signature: String) -> Result<Signature, FromHexError> {
	let stripped = match signature.strip_prefix("0x") {
		Some(sig) => sig,
		None => signature.as_str(),
	};

	match <[u8; 64]>::from_hex(stripped) {
		Ok(s) => {
			let sig = sr25519::Signature::from_raw(s);
			debug!("Signature :- {:?}", sig);
			Ok(sig)
		},
		Err(err) => Err(err),
	}
}

/// Verifies the signature of the message
/// # Arguments
/// * `account_id` - Account ID
/// * `signature` - Signature
/// * `message` - Message
/// # Returns
/// * `bool` - True if the signature is valid
/// # Example
/// ```
/// verify_signature(account_id, signature, message)
/// ```
fn verify_signature(account_id: &str, signature: String, message: &[u8]) -> bool {
	let account_pubkey = get_public_key(account_id);

	sr25519::Pair::verify(&get_signature(signature), message, &account_pubkey)
}

/// Backup Key Shares
/// This function is used to backup the key shares of the validators
/// # Arguments
/// * `state` - StateConfig
/// * `backup_request` - BackupRequest
/// # Returns
/// * `Json` - BackupResponse
/// # Example
/// ```
/// backup_key_shares(state, backup_request)
/// ```

pub async fn admin_backup_fetch_bulk(
	State(state): State<StateConfig>,
	Json(backup_request): Json<FetchBulkPacket>,
) -> impl IntoResponse {
	debug!("3-15 API : backup fetch bulk");

	if !verify_account_id(&backup_request.admin_address) {
		info!("Error backup key shares : Invalid admin : {}", backup_request.admin_address);

		return "Error backup keyshares : Invalid admin".into_response()
	}
	
	let mut auth = backup_request.auth_token.clone();

	if auth.starts_with("<Bytes>") && auth.ends_with("</Bytes>") {
		auth = auth
			.strip_prefix("<Bytes>")
			.unwrap()
			.strip_suffix("</Bytes>")
			.unwrap()
			.to_string();
	}

	let auth_token: FetchAuthenticationToken = serde_json::from_str(&auth).unwrap();
	
	if !verify_signature(
		&backup_request.admin_address,
		backup_request.signature.clone(),
		backup_request.auth_token.clone().as_bytes(),
	) {
		return "Invalid Signature".to_string().into_response();
	} 
	

	if !auth_token.is_valid().await {
		return "Authentication Token Expired".to_string().into_response();
	}

	let backup_file = "/temporary/backup.zip";
	// remove previously generated backup
	if std::path::Path::new(&backup_file).exists() {
		std::fs::remove_file(backup_file).unwrap();
	}
	// create new backup
	add_dir_zip(&state.seal_path.clone(), backup_file);

	// `File` implements `AsyncRead`
	let file = match tokio::fs::File::open(backup_file).await {
		Ok(file) => file,
		Err(err) => return format!("Backup File not found: {}", err).into_response(),
	};
	// convert the `AsyncRead` into a `Stream`
	let stream = ReaderStream::new(file);
	// convert the `Stream` into an `axum::body::HttpBody`
	let body = StreamBody::new(stream);

	let headers = [
		(header::CONTENT_TYPE, "text/toml; charset=utf-8"),
		(header::CONTENT_DISPOSITION, "attachment; filename=\"Backup.zip\""),
	];

	(headers, body).into_response()
	
}

/// Returns Json Response
/// # Arguments
/// * `status` - Status of the request
/// * `data` - Data to be returned
/// # Returns
/// * `Json<Value>` - Json response
/// # Example
/// ```
/// get_json_response("Successfull request".to_string(), data)
/// ```
fn get_json_response(status: String, data: Vec<u8>) -> Json<Value> {
	Json(json!({
		"status": status,
		"data": data,
	}))
}

/* ******************************
 BULK PUSH KEY_SHARES TO THIS ENCLAVE
********************************* */
/// Backup Key Shares
/// This function is used to backup the key shares of the validators
/// # Arguments
/// * `state` - StateConfig
/// * `store_request` - StoreBulkPacket
/// # Returns
/// * `Json` - BackupResponse
/// # Example
/// ```
/// backup_key_shares(state, backup_request)
/// ```

pub async fn admin_backup_push_bulk(
	State(state): State<StateConfig>,
	mut store_request: Multipart,
) -> Json<Value> {
	debug!("3-16 API : backup push bulk");
	debug!("received request = {:?}", store_request);

	let mut admin_address = String::new();
	let mut restore_file = Vec::<u8>::new();
	let mut auth_token = String::new();
	let mut signature = String::new();

	while let Some(field) = store_request.next_field().await.unwrap() {
		let name = match field.name() {
			Some(name) => name.to_string(),
			_ => {
				info!("Error restore backup keyshares : field name : {:?}", field);

		println!("Length of `{}` is {:?}", name, data);
	}
	/*
		if !verify_account_id(&store_request.admin_address.clone()) {
			info!("Error restore backup keyshares : Invalid admin : {}", store_request.admin_address);

	let data = store_request.data.clone();

	let data_bytes = match serde_json::to_vec(&data) {
		Ok(bytes) => bytes,
		Err(e) => {
			debug!("Failed to serialize data: {:?}", e);
			Vec::new()
		},
	};

	if verify_signature(&store_request.admin_address, store_request.signature.clone(), &data_bytes)
	{
		if store_request.data.auth_token.is_valid().await {
			let backup_file = state.seal_path.to_owned() + "backup.zip";

			let mut zipfile = std::fs::File::open(backup_file.clone()).unwrap();
			zipfile.write_all(&data_bytes).unwrap();

			zip_extract(&backup_file, &state.seal_path);

			remove_file(backup_file).unwrap();

			// TODO : manage big packet transfer
			Json(json! ({
				"status": "Successfully request",
			}))
		}

		let data = store_request.data.clone();

		let data_bytes = match serde_json::to_vec(&data) {
			Ok(bytes) => bytes,
			Err(e) => {
				debug!("Failed to serialize data: {:?}", e);
				Vec::new()
			},
		};

		match name.as_str() {
			"admin_address" =>
				admin_address = match field.text().await {
					Ok(bytes) => bytes,
					Err(e) => {
						info!(
							"Error restore backup keyshares : Error request admin_address {:?}",
							e
						);

						return Json(json!({
								"error": format!("Error request admin_address {:?}", e),
						}))
					},
				},

			"restore_file" =>
				restore_file = match field.bytes().await {
					Ok(bytes) => bytes.to_vec(),
					Err(e) => {
						info!(
							"Error restore backup keyshares : Error request restore_file {:?}",
							e
						);

						return Json(json!({
								"error": format!("Error request restore_file {:?}", e),
						}))
					},
				},

			"auth_token" =>
				auth_token = match field.text().await {
					Ok(bytes) => bytes,
					Err(e) => {
						info!("Error restore backup keyshares : Error request auth_token {:?}", e);

						return Json(json!({
							"error": format!("Error request auth_token {:?}", e),
						}))
					},
				},

			"signature" =>
				signature = match field.text().await {
					Ok(sig) => match sig.strip_prefix("0x") {
						Some(hexsig) => hexsig.to_owned(),
						_ => {
							info!("Error restore backup keyshares : Error request signature format, expectex 0x prefix, {sig}");

							return Json(json!({
									"error": format!("Error request signature format, expectex 0x prefix"),
							}))
						},
					},

					Err(e) => {
						info!("Error restore backup keyshares : Error request signature {:?}", e);

						return Json(json!({
								"error": format!("Error request signature {:?}", e),
						}))
					},
				},

			_ => {
				info!("Error restore backup keyshares : Error request field name {:?}", field);
				return Json(json!({
						"error": format!("Error request field name {:?}", field),
				}))
			},
		}
	}

	if !verify_account_id(&admin_address.clone()) {
		info!("Error restore backup keyshares : Invalid admin : {}", admin_address);

		return Json(json! ({
			"status": "Error restore backup keyshares : Invalid admin",
		}))
	}

	if !verify_signature(&admin_address, signature.clone(), auth_token.clone().as_bytes()) {
		info!("Error restore backup keyshares : Invalid signature : admin = {}", admin_address);

		return Json(json! ({
			"status": "Invalid signature",
		}))
	}

	if auth_token.starts_with("<Bytes>") && auth_token.ends_with("</Bytes>") {
		auth_token = auth_token
			.strip_prefix("<Bytes>")
			.unwrap()
			.strip_suffix("</Bytes>")
			.unwrap()
			.to_string();
	}

	let token: StoreAuthenticationToken = serde_json::from_str(auth_token.as_str()).unwrap();

	if !token.is_valid().await {
		info!("Error restore backup keyshares : token expired : admin = {}", admin_address);

		return Json(json! ({
			"status": "Authentication Token Expired",
		}))
	}

	let hash = sha256::digest(restore_file.as_slice());

	if token.data_hash != hash {
		info!("Error restore backup keyshares : mismatch data hash : admin = {}", admin_address);

		return Json(json! ({
			"status": " Mismatch Data Hash",
		}))
	}

	let backup_file = state.seal_path.to_owned() + "backup.zip";

	let mut zipfile = std::fs::File::create(backup_file.clone()).unwrap();
	zipfile.write_all(&restore_file).unwrap();

	match zip_extract(&backup_file, &state.seal_path) {
		Ok(_) => debug!("successful zip_extract"),
		Err(e) => {
			return Json(json!({
				"status": format!("Error restoring backups,{:?}",e),
			}))
		}
	}

	remove_file(backup_file).unwrap();

	// TODO : self-check extracted data
	Json(json!({
		"status": format!("Success restoring backups"),
	}))
}

/* **********************
		 TEST
********************** */

#[cfg(test)]
mod test {
	use super::*;

	#[tokio::test]
	async fn bulk_fetch_test() {
		let admin_keypair = sr25519::Pair::from_phrase(
			"hockey fine lawn number explain bench twenty blue range cover egg sibling",
			None,
		)
		.unwrap()
		.0;
		let last_block_number = get_current_block_number().await;

		let auth =
			FetchAuthenticationToken { block_number: last_block_number, block_validation: 10 };
		let auth_bytes = serde_json::to_vec(&auth).unwrap();
		let sig = admin_keypair.sign(&auth_bytes);
		let sig_str = serde_json::to_string(&sig).unwrap();

		let _request = FetchBulkPacket {
			admin_address: admin_keypair.public().to_string(),
			auth_token: serde_json::to_string(&auth).unwrap(),
			signature: sig_str,
		};
	}

	#[tokio::test]
	async fn bulk_restore_test() {
		let admin_keypair = sr25519::Pair::from_phrase(
			"hockey fine lawn number explain bench twenty blue range cover egg sibling",
			None,
		)
		.unwrap()
		.0;

		let mut zipdata = Vec::new();
		let mut zipfile = std::fs::File::open("./test.zip").unwrap();
		let _ = zipfile.read_to_end(&mut zipdata).unwrap();

		let last_block_number = get_current_block_number().await;

		let hash = sha256::digest(zipdata.as_slice());

		let auth = StoreAuthenticationToken {
			block_number: last_block_number,
			block_validation: 10,
			data_hash: hash,
		};

		let auth_str = serde_json::to_string(&auth).unwrap();
		let sig = admin_keypair.sign(auth_str.as_bytes());
		let sig_str = format!("{}{:?}", "0x", sig);

		println!(
			" Admin:\t\t {} \n Auth_Token:\t {} \n Signature:\t {} \n ",
			admin_keypair.public(),
			auth_str,
			sig_str
		);
	}

	#[tokio::test]
	async fn generate_fetch_bulk_test() {
		let admin = sr25519::Pair::from_phrase(
			"hockey fine lawn number explain bench twenty blue range cover egg sibling",
			None,
		)
		.unwrap()
		.0;

		let last_block_number = get_current_block_number().await;

		let admin_address = admin.public().to_ss58check();
		let auth =
			FetchAuthenticationToken { block_number: last_block_number, block_validation: 10 };
		let auth_str = serde_json::to_string(&auth).unwrap();
		let signature = admin.sign(auth_str.as_bytes());

		let packet = FetchBulkPacket {
			admin_address,
			auth_token: auth_str, 
			signature: format!("{}{:?}", "0x", signature),
		};

		println!("FetchBulkPacket = {}\n", serde_json::to_string_pretty(&packet).unwrap());
	}

	#[test]
	fn test_get_signature_valid() {
		let input  = "0xb7255023814e304b72bc880cc993d5c654ce060db0c3f0772b453714c760521962943747af605a90d0503812c6a62c5c1080cbf377095551af0c168a8c724da8".to_string();
		let expected = Signature(<[u8; 64]>::from_hex(input.strip_prefix("0x").unwrap()).unwrap());
		let results = get_signature(input).unwrap();
		assert_eq!(results, expected);
	}

	#[test]
	fn test_get_public_key_valid() {
		let account = "5DAENKLsmj9FbfxgKuWn81smhKz9dZg75fveUFSUtqrr4CPn";
		let results = get_public_key(account).unwrap();
		assert_eq!(results, sr25519::Public::from_ss58check(account).unwrap());
	}
}
