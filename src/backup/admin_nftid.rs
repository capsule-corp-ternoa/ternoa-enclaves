#![allow(dead_code)]
#![allow(unused_imports)]
#![allow(unused_variables)]

use axum::{
	body::{Bytes, StreamBody},
	extract::{FromRequest, Multipart, State},
	http::{header, StatusCode},
	response::IntoResponse,
	Json,
};

use tokio_util::io::ReaderStream;

use hex::{FromHex, FromHexError};
use serde_json::{json, Value};
use sp_core::{crypto::Ss58Codec, sr25519, Pair};
use std::{
	collections::BTreeMap,
	io::{Read, Write},
};

use std::fs::{remove_file, File};
use tracing::{debug, error, info, warn};

use serde::{Deserialize, Serialize};
use sp_core::{crypto::PublicError, sr25519::Signature};

use crate::{
	chain::core::get_current_block_number,
	servers::http_server::{SharedState, StateConfig},
};

use super::zipdir::{add_dir_zip, zip_extract};

#[cfg(any(feature = "alphanet", feature = "mainnet"))]
const BACKUP_WHITELIST: [&str; 3] = [
	"5FsD8XDoCWPkpwKCnqj9SuP3E7GhkQWQwUSVoZJPoMcvKqWZ",
	"5CfFQLwchs3ujcysbFgVMhSVqC1NdXbGHfRvnRrToWthW5PW",
	"5HmNNUGDRNJgKScvDu1yUKFeqKkXeGjsK5SMGW744Uo2YgFj",
];

#[cfg(any(feature = "dev-0", feature = "dev-1"))]
const BACKUP_WHITELIST: [&str; 3] = [
	"5FsD8XDoCWPkpwKCnqj9SuP3E7GhkQWQwUSVoZJPoMcvKqWZ",
	"5CfFQLwchs3ujcysbFgVMhSVqC1NdXbGHfRvnRrToWthW5PW",
	"5CcqaTBwWvbB2MvmeteSDLVujL3oaFHtdf24pPVT3Xf8v7tC", // Tests
];

const MAX_VALIDATION_PERIOD: u8 = 20;
const MAX_BLOCK_VARIATION: u8 = 5;

/* *************************************
		FETCH  BULK DATA STRUCTURES
**************************************** */

// Validity time of Keyshare Data
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct AuthenticationToken {
	pub block_number: u32,
	pub block_validation: u8,
	pub data_hash: String,
}

/// Fetch Bulk Data
#[derive(Serialize, Deserialize, Debug)]
pub struct FetchIdPacket {
	admin_address: String,
	nftid_vec: String,
	auth_token: String,
	signature: String,
}

/// Fetch Bulk Response
#[derive(Serialize)]
pub struct FetchIdResponse {
	data: String,
	signature: String,
}

/* *************************************
		STORE  BULK DATA STRUCTURES
**************************************** */

/// Store Bulk Packet
#[derive(Serialize, Deserialize, Debug)]
pub struct StoreIdPacket {
	admin_address: String,
	restore_map: String,
	auth_token: AuthenticationToken,
	signature: String,
}

/* ----------------------------------
AUTHENTICATION TOKEN IMPLEMENTATION
----------------------------------*/
#[derive(Debug)]
pub enum ValidationResult {
	Success,
	ErrorRpcCall,
	ExpiredBlockNumber,
	FutureBlockNumber,
	InvalidPeriod,
}

/// Retrieving the stored Keyshare
impl AuthenticationToken {
	pub async fn is_valid(&self) -> ValidationResult {
		let last_block_number = match get_current_block_number().await {
			Ok(number) => number,
			Err(err) => {
				error!("Failed to get current block number: {}", err);
				return ValidationResult::ErrorRpcCall;
			},
		};

		if last_block_number < self.block_number - (MAX_BLOCK_VARIATION as u32) {
			// for finalization delay
			return ValidationResult::ExpiredBlockNumber;
		}

		if self.block_validation > MAX_VALIDATION_PERIOD {
			// A finite validity period
			return ValidationResult::InvalidPeriod;
		}

		if last_block_number
			> self.block_number + ((self.block_validation + MAX_BLOCK_VARIATION) as u32)
		{
			// validity period
			return ValidationResult::FutureBlockNumber;
		}

		ValidationResult::Success
	}
}

/* *************************************
		 VERIFICATION FUNCTIONS
**************************************** */

/// Verify Account Id if it is Whitelisted
/// # Arguments
/// * `account_id` - Account ID
/// # Returns
/// * `bool` - Result
/// # Example
/// ```
/// verify_account_id(account_id)
/// ```
/// # Errors
/// * `PublicError` - If the account ID is not a valid SS58 string
fn verify_account_id(account_id: &str) -> bool {
	BACKUP_WHITELIST.contains(&account_id)
}

/// Get the public key of an Account ID
/// # Arguments
/// * `account_id` - Account ID
/// # Returns
/// * `Result<sr25519::Public, PublicError>` - Result
/// # Example
/// ```
/// get_public_key(account_id, signature, data)
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
	match get_public_key(account_id) {
		Ok(pk) => match get_signature(signature) {
			Ok(val) => sr25519::Pair::verify(&val, message, &pk),
			Err(err) => {
				debug!("Error generating pair {:?}", err);
				false
			},
		},
		Err(_) => false,
	}
}

async fn update_health_status(state: &SharedState, message: String) {
	let shared_state_write = &mut state.write().await;
	debug!("got shared state to write.");

	shared_state_write.set_maintenance(message);
	debug!("Maintenance state is set.");
}

pub async fn error_handler(message: String, state: &SharedState) -> impl IntoResponse {
	error!(message);
	update_health_status(state, String::new()).await;
	(StatusCode::BAD_REQUEST, Json(json!({ "error": message })))
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
#[axum::debug_handler]
pub async fn admin_backup_fetch_id(
	State(state): State<SharedState>,
	Json(backup_request): Json<FetchIdPacket>,
) -> impl IntoResponse {
	debug!("3-15 API : backup fetch bulk");

	update_health_status(&state, "Encalve is doing backup, please wait...".to_string()).await;

	if !verify_account_id(&backup_request.admin_address) {
		let message = format!(
			"Error backup key shares : Requester is not whitelisted : {}",
			backup_request.admin_address
		);

		return error_handler(message, &state).await.into_response();
	}

	let mut auth = backup_request.auth_token.clone();

	if auth.starts_with("<Bytes>") && auth.ends_with("</Bytes>") {
		auth = match auth.strip_prefix("<Bytes>") {
			Some(stripped) => stripped.to_owned(),
			_ => {
				return error_handler("Strip Token prefix error".to_string(), &state)
					.await
					.into_response();
			},
		};

		auth = match auth.strip_suffix("</Bytes>") {
			Some(stripped) => stripped.to_owned(),
			_ => {
				return error_handler("Strip Token suffix error".to_string(), &state)
					.await
					.into_response();
			},
		}
	}

	let auth_token: AuthenticationToken = match serde_json::from_str(&auth) {
		Ok(token) => token,
		Err(e) => {
			let message =
				format!("Error backup key shares : Authentication token is not parsable : {}", e);
			return error_handler(message, &state).await.into_response();
		},
	};

	if !verify_signature(
		&backup_request.admin_address,
		backup_request.signature.clone(),
		backup_request.auth_token.clone().as_bytes(),
	) {
		return error_handler("Invalid Signature".to_string(), &state).await.into_response();
	}

	debug!("Validating the authentication token");
	let validity = auth_token.is_valid().await;
	match validity {
		ValidationResult::Success => debug!("AUthentication token is valid."),
		_ => {
			let message = format!("Authentication Token is not valid, or expired : {:?}", validity);
			return error_handler(message, &state).await.into_response();
		},
	}

	let hash = sha256::digest(backup_request.nftid_vec.as_bytes());

	if auth_token.data_hash != hash {
		return error_handler("Admin backup : Mismatch Data Hash".to_string(), &state)
			.await
			.into_response();
	}

	let nft_slice: Vec<u8> = match serde_json::from_str(&backup_request.nftid_vec) {
		Ok(nfts) => nfts,
		Err(e) => {
			let message = format!("unable to deserialize nftid vector : {:?}", e);
			return error_handler(message, &state).await.into_response();
		},
	};

	let (_, nftids, _) = unsafe { nft_slice.align_to::<Vec<u32>>() };

	//let nftids =
	let mut backup_file = "/temporary/backup.zip".to_string();
	let counter = 1;
	// remove previously generated backup
	while std::path::Path::new(&backup_file.clone()).exists() {
		match std::fs::remove_file(backup_file.clone()) {
			Ok(_) => {
				debug!("Successfully removed previous zip file")
			},
			Err(e) => {
				let message = format!(
					"Error backup key shares : Can not remove previous backup file : {}",
					e
				);
				warn!(message);
				//return Json(json!({ "error": message })).into_response()
				backup_file = format!("/temporary/backup-{counter}.zip");
			},
		}
	}

	let shared_state_read = state.read().await;
	let seal_path = shared_state_read.get_seal_path();
	drop(shared_state_read);

	debug!("Start zippping file");
	add_dir_zip(&seal_path, &backup_file);

	// `File` implements `AsyncRead`
	debug!("Opening backup file");
	let file = match tokio::fs::File::open(backup_file).await {
		Ok(file) => file,
		Err(err) => {
			return Json(json!({ "error": format!("Backup File not found: {}", err) }))
				.into_response()
		},
	};

	// convert the `AsyncRead` into a `Stream`
	debug!("Create reader-stream");
	let stream = ReaderStream::new(file);

	// convert the `Stream` into an `axum::body::HttpBody`
	debug!("Create body-stream");
	let body = StreamBody::new(stream);

	let headers = [
		(header::CONTENT_TYPE, "text/toml; charset=utf-8"),
		(header::CONTENT_DISPOSITION, "attachment; filename=\"Backup.zip\""),
	];

	update_health_status(&state, String::new()).await;

	debug!("Sending the backup data to the client ...");
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
#[axum::debug_handler]
pub async fn admin_backup_push_id(
	State(state): State<SharedState>,
	mut store_request: Multipart,
) -> impl IntoResponse {
	debug!("3-16 API : backup push bulk");
	debug!("received request = {:?}", store_request);

	//update_health_status(&state, "Restoring the backups".to_string()).await;

	let mut admin_address = String::new();
	let mut restore_file = Vec::<u8>::new();
	let mut auth_token = String::new();
	let mut signature = String::new();

	while let Some(field) = match store_request.next_field().await {
		Ok(field) => field,
		Err(e) => {
			let message =
				format!("Error backup key shares : Can not parse request form-data : {}", e);
			warn!(message);
			update_health_status(&state, String::new()).await;
			return (StatusCode::BAD_REQUEST, Json(json!({ "error": message }))).into_response();
		},
	} {
		let name = match field.name() {
			Some(name) => name.to_string(),
			_ => {
				warn!("Admin restore :  field name : {:?}", field);

				let message = format!("Admin restore : Error request field name {:?}", field);
				update_health_status(&state, String::new()).await;
				return (StatusCode::BAD_REQUEST, Json(json!({ "error": message })))
					.into_response();
			},
		};

		match name.as_str() {
			"admin_address" => {
				admin_address = match field.text().await {
					Ok(bytes) => bytes,
					Err(e) => {
						warn!("Admin restore :  Error request admin_address {:?}", e);

						let message =
							format!("Admin restore : Error request admin_address {:?}", e);
						update_health_status(&state, String::new()).await;
						return (StatusCode::BAD_REQUEST, Json(json!({ "error": message })))
							.into_response();
					},
				}
			},

			"restore_file" => {
				restore_file = match field.bytes().await {
					Ok(bytes) => bytes.to_vec(),
					Err(e) => {
						warn!("Admin restore :  Error request restore_file {:?}", e);

						let message = format!("Admin restore : Error request restore_file {:?}", e);
						update_health_status(&state, String::new()).await;
						return (StatusCode::BAD_REQUEST, Json(json!({ "error": message })))
							.into_response();
					},
				}
			},

			"auth_token" => {
				auth_token = match field.text().await {
					Ok(bytes) => bytes,
					Err(e) => {
						warn!("Admin restore :  Error request auth_token {:?}", e);

						let message = format!("Admin restore : Error request auth_token {:?}", e);
						update_health_status(&state, String::new()).await;
						return (StatusCode::BAD_REQUEST, Json(json!({ "error": message })))
							.into_response();
					},
				}
			},

			"signature" => {
				signature = match field.text().await {
					Ok(sig) => match sig.strip_prefix("0x") {
						Some(hexsig) => hexsig.to_owned(),
						_ => {
							warn!("Admin restore :  Error request signature format, expectex 0x prefix, {sig}");
							let message = "Admin restore : Error request signature format, expectex 0x prefix".to_string();
							update_health_status(&state, String::new()).await;
							return (StatusCode::BAD_REQUEST, Json(json!({ "error": message })))
								.into_response();
						},
					},

					Err(e) => {
						warn!("Admin restore :  Error request signature {:?}", e);
						let message = format!("Admin restore : Error request signature {:?}", e);
						update_health_status(&state, String::new()).await;
						return (StatusCode::BAD_REQUEST, Json(json!({ "error": message })))
							.into_response();
					},
				}
			},

			_ => {
				warn!("Error restore backup keyshares : Error request field name {:?}", field);
				let message = format!("Admin restore : Error request field name {:?}", field);
				update_health_status(&state, String::new()).await;
				return (StatusCode::BAD_REQUEST, Json(json!({ "error": message })))
					.into_response();
			},
		}
	}

	if !verify_account_id(&admin_address.clone()) {
		let message = format!("Admin restore :  Requester is not whitelisted : {}", admin_address);

		warn!(message);

		update_health_status(&state, String::new()).await;
		return (StatusCode::BAD_REQUEST, Json(json!({ "error": message }))).into_response();
	}

	if !verify_signature(&admin_address, signature.clone(), auth_token.clone().as_bytes()) {
		warn!("Error restore backup keyshares : Invalid signature : admin = {}", admin_address);

		let message = "Invalid token signature".to_string();
		update_health_status(&state, String::new()).await;
		return (StatusCode::BAD_REQUEST, Json(json!({ "error": message }))).into_response();
	}

	if auth_token.starts_with("<Bytes>") && auth_token.ends_with("</Bytes>") {
		auth_token = match auth_token.strip_prefix("<Bytes>") {
			Some(stripped) => stripped.to_owned(),
			_ => {
				let message = "Strip Token prefix error".to_string();
				update_health_status(&state, String::new()).await;
				return (StatusCode::BAD_REQUEST, Json(json!({ "error": message })))
					.into_response();
			},
		};

		auth_token = match auth_token.strip_suffix("</Bytes>") {
			Some(stripped) => stripped.to_owned(),
			_ => {
				let message = "Strip Token suffix error".to_string();
				update_health_status(&state, String::new()).await;
				return (StatusCode::BAD_REQUEST, Json(json!({ "error": message })))
					.into_response();
			},
		}
	}

	let token: AuthenticationToken = match serde_json::from_str(auth_token.as_str()) {
		Ok(token) => token,
		Err(e) => {
			let message = format!("Admin restore : Can not parse the authentication token : {}", e);
			warn!(message);
			update_health_status(&state, String::new()).await;
			return (StatusCode::BAD_REQUEST, Json(json!({ "error": message }))).into_response();
		},
	};

	let validity = token.is_valid().await;
	match validity {
		ValidationResult::Success => debug!("AUthentication token is valid."),
		_ => {
			let message = format!("Authentication Token is not valid, or expired : {:?}", validity);
			update_health_status(&state, String::new()).await;
			return (StatusCode::BAD_REQUEST, Json(json!({ "error": message }))).into_response();
		},
	}

	let hash = sha256::digest(restore_file.as_slice());

	if token.data_hash != hash {
		warn!("Admin restore :  mismatch data hash : admin = {}", admin_address);
		let message = "Admin restore : Mismatch Data Hash".to_string();
		update_health_status(&state, String::new()).await;
		return (StatusCode::BAD_REQUEST, Json(json!({ "error": message }))).into_response();
	}

	let shared_state = state.read().await;
	let seal_path = shared_state.get_seal_path();
	let backup_file = seal_path.clone() + "backup.zip";
	drop(shared_state);

	let mut zipfile = match std::fs::File::create(backup_file.clone()) {
		Ok(file) => file,
		Err(e) => {
			let message = format!("Admin restore :  Can not create file on disk : {}", e);
			warn!(message);
			update_health_status(&state, String::new()).await;
			return (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({ "error": message })))
				.into_response();
		},
	};

	match zipfile.write_all(&restore_file) {
		Ok(_) => debug!("zip file is stored on disk."),
		Err(e) => {
			let message = format!("Admin restore :  writing zip file to disk{:?}", e);
			warn!(message);
			update_health_status(&state, String::new()).await;
			return (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({ "error": message })))
				.into_response();
		},
	}
	// TODO: Verify backup data befor writing them on the disk
	// Check if the enclave_account or keyshares are invalid
	match zip_extract(&backup_file, &seal_path) {
		Ok(_) => debug!("zip_extract success"),
		Err(e) => {
			let message = format!("Admin restore :  extracting zip file {:?}", e);
			warn!(message);
			update_health_status(&state, String::new()).await;
			return (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({ "error": message })))
				.into_response();
		},
	}

	match remove_file(backup_file) {
		Ok(_) => debug!("remove zip file successful"),
		Err(e) => {
			let message = format!("Backup success with Error in removing zip file, {:?}", e);
			warn!(message);
			update_health_status(&state, String::new()).await;
			return (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({ "error": message })))
				.into_response();
		},
	};

	// Update Enclave Account, if it is updated.
	let enclave_account_file = "/nft/enclave_account.key";
	if !std::path::Path::new(&enclave_account_file).exists() {
		let message = "Admin restore : Encalve Account file not found".to_string();
		warn!(message);
		update_health_status(&state, String::new()).await;
		return (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({ "error": message })))
			.into_response();
	};

	debug!("Admin restore : Found Enclave Account, Importing it! : path: {}", enclave_account_file);

	let phrase = match std::fs::read_to_string(enclave_account_file) {
		Ok(phrase) => phrase,
		Err(err) => {
			let message = format!("Admin restore : Error reading enclave account file: {:?}", err);
			warn!(message);
			update_health_status(&state, String::new()).await;
			return (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({ "error": message })))
				.into_response();
		},
	};

	debug!("Admin restore : Phrase read, converting it to keypair.");

	let enclave_keypair = match sp_core::sr25519::Pair::from_phrase(&phrase, None) {
		Ok((keypair, _seed)) => keypair,
		Err(err) => {
			let message = format!("Admin restore : Error creating keypair from phrase: {:?}", err);
			warn!(message);
			update_health_status(&state, String::new()).await;
			return (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({ "error": message })))
				.into_response();
		},
	};

	debug!("Admin restore : Keypair success");

	let mut shared_state_write = state.write().await;
	debug!("Admin restore : share-state is taken");
	shared_state_write.set_key(enclave_keypair);
	debug!("share-state Enclave Account updated");
	drop(shared_state_write);

	//update_health_status(&state, String::new()).await;

	// TODO : self-check extracted data
	(
		StatusCode::OK,
		Json(json!({
			"success": format!("Success restoring backups"),
		})),
	)
		.into_response()
}

/* **********************
		 TEST
********************** */

#[cfg(test)]
mod test {
	use super::*;

	#[tokio::test]
	async fn id_fetch_test() {
		let seed_phrase: &str =
			"hockey fine lawn number explain bench twenty blue range cover egg sibling";

		let admin_keypair = sr25519::Pair::from_phrase(seed_phrase, None).unwrap().0;
		let last_block_number = get_current_block_number().await.unwrap();
		let nfts: Vec<u32> = vec![10, 200, 3000, 40000, 500000, 6000000];
		let (_, aligned_nfts, _) = unsafe { nfts.align_to::<u8>() };
		let hash = sha256::digest(aligned_nfts);

		let auth = AuthenticationToken {
			block_number: last_block_number,
			block_validation: 10,
			data_hash: hash,
		};

		let auth_bytes = serde_json::to_vec(&auth).unwrap();
		let sig = admin_keypair.sign(&auth_bytes);
		let sig_str = serde_json::to_string(&sig).unwrap();

		let request = FetchIdPacket {
			admin_address: admin_keypair.public().to_string(),
			nftid_vec: serde_json::to_string(aligned_nfts).unwrap(),
			auth_token: serde_json::to_string(&auth).unwrap(),
			signature: sig_str,
		};

		println!("{:#?}", request);
	}

	#[tokio::test]
	async fn id_restore_test() {
		let seed_phrase: &str =
			"hockey fine lawn number explain bench twenty blue range cover egg sibling";

		let admin_keypair = sr25519::Pair::from_phrase(seed_phrase, None).unwrap().0;

		let mut zipdata = Vec::new();
		let mut zipfile = std::fs::File::open("./test/test.zip").unwrap();
		let _ = zipfile.read_to_end(&mut zipdata).unwrap();

		let last_block_number = get_current_block_number().await.unwrap();

		let hash = sha256::digest(zipdata.as_slice());

		let auth = AuthenticationToken {
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
