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

use subxt::{
	ext::sp_core::{
		crypto::{PublicError, Ss58Codec},
		sr25519,
		sr25519::Signature,
		Pair,
	},
	utils::AccountId32,
};

use tokio_util::io::ReaderStream;

use hex::{FromHex, FromHexError};
use serde_json::{json, Value};

use std::{
	collections::BTreeMap,
	fs::{remove_file, File},
	io::{Read, Write},
};

use tracing::{debug, error, info, warn};

use serde::{Deserialize, Serialize};

use crate::{
	backup::sync::cluster_discovery,
	chain::{
		constants::{ENCLAVE_ACCOUNT_FILE, MAX_BLOCK_VARIATION, MAX_VALIDATION_PERIOD, SEALPATH},
		core::get_current_block_number,
		helper,
	},
	servers::state::{
		get_blocknumber, get_clusters, reset_nft_availability, set_keypair, SharedState,
		StateConfig,
	},
};

use super::{
	sync::{set_sync_state, ClusterType},
	zipdir::{add_dir_zip, zip_extract},
};

/* *************************************
		FETCH BULK DATA STRUCTURES
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
		STORE BULK DATA STRUCTURES
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
#[derive(Debug)]
pub enum ValidationResult {
	Success,
	ErrorRpcCall,
	ExpiredBlockNumber,
	FutureBlockNumber,
	InvalidPeriod,
}

/// Retrieving the stored Keyshare
impl FetchAuthenticationToken {
	pub fn is_valid(&self, current_block_number: u32) -> ValidationResult {
		if self.block_number > current_block_number + MAX_BLOCK_VARIATION {
			// for finalization delay
			debug!(
				"current block number = {} < request block number = {}",
				current_block_number, self.block_number
			);
			return ValidationResult::FutureBlockNumber;
		}

		if self.block_validation > MAX_VALIDATION_PERIOD {
			// A finite validity period
			debug!(
				"MAX VALIDATION = {} < block_validation = {}",
				MAX_VALIDATION_PERIOD, self.block_validation
			);
			return ValidationResult::InvalidPeriod;
		}

		if self.block_number + self.block_validation < current_block_number {
			// validity period
			debug!(
				"current block number = {} >> request block number = {}",
				current_block_number, self.block_number
			);

			return ValidationResult::ExpiredBlockNumber;
		}

		ValidationResult::Success
	}
}

impl StoreAuthenticationToken {
	pub fn is_valid(&self, current_block_number: u32) -> ValidationResult {
		if self.block_number > current_block_number + MAX_BLOCK_VARIATION {
			// for finalization delay
			debug!(
				"current block number = {} < request block number = {}",
				current_block_number, self.block_number
			);
			return ValidationResult::FutureBlockNumber;
		}

		if self.block_validation > MAX_VALIDATION_PERIOD {
			// A finite validity period
			debug!(
				"MAX VALIDATION = {} < block_validation = {}",
				MAX_VALIDATION_PERIOD, self.block_validation
			);
			return ValidationResult::InvalidPeriod;
		}

		if self.block_number + self.block_validation < current_block_number {
			// validity period
			debug!(
				"current block number = {} >> request block number = {}",
				current_block_number, self.block_number
			);

			return ValidationResult::ExpiredBlockNumber;
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
async fn verify_account_id(state: &SharedState, account_id: &String) -> bool {
	let clusters = get_clusters(state).await;
	let allowed_id: Vec<String> = clusters
		.into_iter()
		.filter_map(|c| {
			if c.cluster_type == ClusterType::Admin {
				Some(
					c.enclaves
						.iter()
						.map(|e| e.enclave_account.to_string())
						.collect::<Vec<String>>(),
				)
			} else {
				None
			}
		})
		.flat_map(|x| x.into_iter())
		.collect();

	allowed_id.contains(&account_id.to_string())
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
			debug!("Error constructing public key {err:?}");
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
				debug!("Error generating pair {err:?}");
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
pub async fn admin_backup_fetch_bulk(
	State(state): State<SharedState>,
	Json(backup_request): Json<FetchBulkPacket>,
) -> impl IntoResponse {
	debug!("ADMIN FETCH BULK : backup fetch bulk");
	//update_health_status(&state, "Enclave is doing backup, please wait...".to_string()).await;

	if !verify_account_id(&state, &backup_request.admin_address).await {
		let message = format!(
			"Error backup key shares : Requester is not whitelisted : {}",
			backup_request.admin_address
		);
		warn!(message);

		return (StatusCode::FORBIDDEN, Json(json!({ "error": message }))).into_response();
	}

	let mut auth = backup_request.auth_token.clone();

	if auth.starts_with("<Bytes>") && auth.ends_with("</Bytes>") {
		auth = match auth.strip_prefix("<Bytes>") {
			Some(stripped) => stripped.to_owned(),
			_ =>
				return (
					StatusCode::BAD_REQUEST,
					Json(json!({"error": "Strip Token prefix error".to_string()})),
				)
					.into_response(),
		};

		auth = match auth.strip_suffix("</Bytes>") {
			Some(stripped) => stripped.to_owned(),
			_ =>
				return (
					StatusCode::BAD_REQUEST,
					Json(json!({"error": "Strip Token suffix error".to_string()})),
				)
					.into_response(),
		}
	}

	let auth_token: FetchAuthenticationToken = match serde_json::from_str(&auth) {
		Ok(token) => token,
		Err(err) => {
			let message =
				format!("Error backup key shares : Authentication token is not parsable : {}", err);
			warn!(message);
			return (StatusCode::BAD_REQUEST, Json(json!({ "error": message }))).into_response();
		},
	};

	if !verify_signature(
		&backup_request.admin_address,
		backup_request.signature.clone(),
		backup_request.auth_token.clone().as_bytes(),
	) {
		return (StatusCode::FORBIDDEN, Json(json!({"error": "Invalid Signature".to_string()})))
			.into_response();
	}

	let current_block_number = get_blocknumber(&state).await;

	debug!("ADMIN FETCH BULK : Validating the authentication token");
	let validation = auth_token.is_valid(current_block_number);
	match validation {
		ValidationResult::Success => debug!("ADMIN FETCH BULK : Authentication token is valid."),
		_ => {
			let message =
				format!("Authentication Token is not valid, or expired : {:?}", validation);
			error!("ADMIN FETCH BULK : {}", message);
			return (StatusCode::NOT_ACCEPTABLE, Json(json!({ "error": message }))).into_response();
		},
	}

	let mut backup_file = "/temporary/backup.zip".to_string();
	let counter = 1;
	// remove previously generated backup
	while std::path::Path::new(&backup_file.clone()).exists() {
		match std::fs::remove_file(backup_file.clone()) {
			Ok(_) => {
				debug!("ADMIN FETCH BULK : Successfully removed previous zip file")
			},
			Err(err) => {
				let message = format!(
					"ADMIN FETCH BULK : Error backup key shares : Can not remove previous backup file : {}",
					err
				);
				warn!(message);
				//return Json(json!({ "error": message })).into_response()
				backup_file = format!("/temporary/backup-{counter}.zip");
			},
		}
	}

	debug!("ADMIN FETCH BULK : Start zippping file");
	add_dir_zip(SEALPATH, &backup_file);

	// `File` implements `AsyncRead`
	debug!("ADMIN FETCH BULK : Opening backup file");
	let file = match tokio::fs::File::open(backup_file).await {
		Ok(file) => file,
		Err(err) =>
			return (
				StatusCode::INTERNAL_SERVER_ERROR,
				Json(json!({ "error": format!("Backup File not found: {}", err) })),
			)
				.into_response(),
	};

	// convert the `AsyncRead` into a `Stream`
	debug!("ADMIN FETCH BULK : Create reader-stream");
	let stream = ReaderStream::new(file);

	// convert the `Stream` into an `axum::body::HttpBody`
	debug!("ADMIN FETCH BULK : Create body-stream");
	let body = StreamBody::new(stream);

	let headers = [
		(header::CONTENT_TYPE, "text/toml; charset=utf-8"),
		(header::CONTENT_DISPOSITION, "attachment; filename=\"Backup.zip\""),
	];

	//update_health_status(&state, String::new()).await;

	debug!("ADMIN FETCH BULK : Sending the backup data to the client ...");
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
pub async fn admin_backup_push_bulk(
	State(state): State<SharedState>,
	mut store_request: Multipart,
) -> impl IntoResponse {
	debug!("ADMIN PUSH BULK : backup push bulk");
	debug!("ADMIN PUSH BULK : received request = {:?}", store_request);
	//update_health_status(&state, "Restoring the backups".to_string()).await;

	let mut admin_address = String::new();
	let mut restore_file = Vec::<u8>::new();
	let mut auth_token = String::new();
	let mut signature = String::new();

	while let Some(field) = match store_request.next_field().await {
		Ok(field) => field,
		Err(err) => {
			let message = format!(
				"ADMIN PUSH BULK : Error backup key shares : Can not parse request form-data : {}",
				err
			);
			warn!(message);
			return (StatusCode::BAD_REQUEST, Json(json!({ "error": message }))).into_response();
		},
	} {
		let name = match field.name() {
			Some(name) => name.to_string(),
			_ => {
				info!("ADMIN PUSH BULK : field name : {:?}", field);

				return (
					StatusCode::BAD_REQUEST,
					Json(json!({
							"error": format!("ADMIN PUSH BULK : Error request field name {:?}", field),
					})),
				)
					.into_response();
			},
		};

		match name.as_str() {
			"admin_address" =>
				admin_address = match field.text().await {
					Ok(bytes) => bytes,
					Err(err) => {
						info!("ADMIN PUSH BULK : Error request admin_address {err:?}");

						return (
							StatusCode::BAD_REQUEST,
							Json(json!({
									"error": format!("ADMIN PUSH BULK : Error request admin_address {err:?}"),
							})),
						)
							.into_response();
					},
				},

			"restore_file" =>
				restore_file = match field.bytes().await {
					Ok(bytes) => bytes.to_vec(),
					Err(err) => {
						info!("ADMIN PUSH BULK : Error request restore_file {err:?}");

						return (
							StatusCode::BAD_REQUEST,
							Json(json!({
									"error": format!("ADMIN PUSH BULK : Error request restore_file {err:?}"),
							})),
						)
							.into_response();
					},
				},

			"auth_token" =>
				auth_token = match field.text().await {
					Ok(bytes) => bytes,
					Err(err) => {
						info!("ADMIN PUSH BULK : Error request auth_token {err:?}");

						return (
							StatusCode::BAD_REQUEST,
							Json(json!({
								"error": format!("ADMIN PUSH BULK : Error request auth_token {err:?}"),
							})),
						)
							.into_response();
					},
				},

			"signature" =>
				signature = match field.text().await {
					Ok(sig) => match sig.strip_prefix("0x") {
						Some(hexsig) => hexsig.to_owned(),
						_ => {
							info!("ADMIN PUSH BULK : Error request signature format, expectex 0x prefix, {sig}");

							return (
								StatusCode::BAD_REQUEST,
								Json(json!({
										"error": format!("ADMIN PUSH BULK : Error request signature format, expectex 0x prefix"),
								})),
							)
								.into_response();
						},
					},

					Err(err) => {
						info!("ADMIN PUSH BULK : Error request signature {err:?}");

						return (
							StatusCode::BAD_REQUEST,
							Json(json!({
									"error": format!("ADMIN PUSH BULK : Error request signature {err:?}"),
							})),
						)
							.into_response();
					},
				},

			_ => {
				info!("Error restore backup keyshares : Error request field name {:?}", field);
				return (
					StatusCode::BAD_REQUEST,
					Json(json!({
							"error": format!("ADMIN PUSH BULK : Error request field name {:?}", field),
					})),
				)
					.into_response();
			},
		}
	}

	if !verify_account_id(&state, &admin_address.clone()).await {
		let message = format!("ADMIN PUSH BULK : Requester is not whitelisted : {}", admin_address);

		warn!(message);

		return (
			StatusCode::FORBIDDEN,
			Json(json! ({
				"error": message,
			})),
		)
			.into_response();
	}

	if !verify_signature(&admin_address, signature.clone(), auth_token.clone().as_bytes()) {
		warn!("Error restore backup keyshares : Invalid signature : admin = {}", admin_address);

		return (
			StatusCode::FORBIDDEN,
			Json(json! ({
				"error": "Invalid token signature",
			})),
		)
			.into_response();
	}

	if auth_token.starts_with("<Bytes>") && auth_token.ends_with("</Bytes>") {
		auth_token = match auth_token.strip_prefix("<Bytes>") {
			Some(stripped) => stripped.to_owned(),
			_ =>
				return (
					StatusCode::BAD_REQUEST,
					Json(json! ({"error": "ADMIN PUSH BULK : Strip Token prefix error"})),
				)
					.into_response(),
		};

		auth_token = match auth_token.strip_suffix("</Bytes>") {
			Some(stripped) => stripped.to_owned(),
			_ =>
				return (
					StatusCode::BAD_REQUEST,
					Json(json! ({"error": "Strip Token suffix error"})),
				)
					.into_response(),
		}
	}

	let token: StoreAuthenticationToken = match serde_json::from_str(auth_token.as_str()) {
		Ok(token) => token,
		Err(err) => {
			let message =
				format!("ADMIN PUSH BULK : Can not parse the authentication token : {}", err);
			warn!(message);
			return (StatusCode::BAD_REQUEST, Json(json!({ "error": message }))).into_response();
		},
	};

	let current_block_number = get_blocknumber(&state).await;

	let validation = token.is_valid(current_block_number);
	match validation {
		ValidationResult::Success => debug!("Authentication token is valid."),
		_ => {
			let message =
				format!("Authentication Token is not valid, or expired : {:?}", validation);
			error!("ADMIN PUSH BULK : token expired : {}", message);
			return (StatusCode::NOT_ACCEPTABLE, Json(json!({ "error": message }))).into_response();
		},
	}

	let hash = sha256::digest(restore_file.as_slice());

	if token.data_hash != hash {
		warn!("ADMIN PUSH BULK : mismatch data hash : admin = {}", admin_address);

		return (
			StatusCode::BAD_REQUEST,
			Json(json! ({
				"error": "ADMIN PUSH BULK : Mismatch Data Hash",
			})),
		)
			.into_response();
	}

	let backup_file = SEALPATH.to_string() + "/" + "backup.zip";

	let mut zipfile = match std::fs::File::create(backup_file.clone()) {
		Ok(file) => file,
		Err(err) => {
			let message = format!("ADMIN PUSH BULK : Can not create file on disk : {}", err);
			warn!(message);
			return (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({ "error": message })))
				.into_response();
		},
	};

	match zipfile.write_all(&restore_file) {
		Ok(_) => debug!("zip file is stored on disk."),
		Err(err) => {
			let message = format!("ADMIN PUSH BULK : writing zip file to disk{err:?}");
			error!(message);
			return (
				StatusCode::INTERNAL_SERVER_ERROR,
				Json(json!({
					"error": message,
				})),
			)
				.into_response();
		},
	}

	// Check if the enclave_account or keyshares are invalid
	match zip_extract(&backup_file, SEALPATH) {
		Ok(_) => debug!("zip_extract success"),
		Err(err) => {
			let message = format!("ADMIN PUSH BULK : extracting zip file {err:?}");
			error!(message);
			return (
				StatusCode::INTERNAL_SERVER_ERROR,
				Json(json!({
					"error": message,
				})),
			)
				.into_response();
		},
	}

	match remove_file(backup_file) {
		Ok(_) => debug!("ADMIN PUSH BULK : remove zip file successful"),
		Err(err) =>
			return (
				StatusCode::OK,
				Json(json!({
					"warning": format!("Backup success with Error in removing zip file, {:?}",err),
				})),
			)
				.into_response(),
	};

	// Update Enclave Account, if it is updated.;
	if !std::path::Path::new(&ENCLAVE_ACCOUNT_FILE).exists() {
		return (
			StatusCode::NO_CONTENT,
			Json(json!({
				"error": format!("ADMIN PUSH BULK : Enclave Account file not found"),
			})),
		)
			.into_response();
	};

	debug!(
		"ADMIN PUSH BULK : Found Enclave Account, Importing it! : path: {}",
		ENCLAVE_ACCOUNT_FILE
	);

	let phrase = match std::fs::read_to_string(ENCLAVE_ACCOUNT_FILE) {
		Ok(phrase) => phrase,
		Err(err) => {
			let message = format!("ADMIN PUSH BULK : Error reading enclave account file: {err:?}");
			error!(message);
			return (
				StatusCode::NO_CONTENT,
				Json(json!({
					"error": message,
				})),
			)
				.into_response();
		},
	};

	debug!("ADMIN PUSH BULK : Phrase read, converting it to keypair.");

	let enclave_keypair = match sr25519::Pair::from_phrase(&phrase, None) {
		Ok((keypair, _seed)) => keypair,
		Err(err) => {
			let message = format!("ADMIN PUSH BULK : Error creating keypair from phrase: {err:?}");
			error!(message);
			return (
				StatusCode::INTERNAL_SERVER_ERROR,
				Json(json!({
					"error": message,
				})),
			)
				.into_response();
		},
	};

	debug!("ADMIN PUSH BULK : Keypair success");

	set_keypair(&state, enclave_keypair).await;
	debug!("ADMIN PUSH BULK : share-state Enclave Account updated");

	match cluster_discovery(&state).await {
		Ok(res) => debug!("ADMIN PUSH BULK : CLUSTER DISCOVERY FOR NEW IDENTITY : {res}"),
		Err(err) => error!("ADMIN PUSH BULK : CLUSTER DISCOVERY FAILED : {err}"),
	}

	//update_health_status(&state, String::new()).await;
	let keyshare_list: BTreeMap<u32, helper::Availability> =
		match helper::query_keyshare_file(SEALPATH.to_string()) {
			Ok(list) => list,
			Err(err) =>
				return (
					StatusCode::INTERNAL_SERVER_ERROR,
					Json(json!({
						"error": format!("Unable to update keyshare availability, {err:?}"),
					})),
				)
					.into_response(),
		};

	let last_synced = keyshare_list.values().map(|av| av.block_number).max().unwrap();
	reset_nft_availability(&state, keyshare_list).await;
	let _ = set_sync_state(last_synced.to_string());

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
	use crate::chain::core::get_current_block_number_new_api;

	use super::*;

	#[tokio::test]
	async fn bulk_fetch_test() {
		let seed_phrase: &str =
			"hockey fine lawn number explain bench twenty blue range cover egg sibling";

		let admin_keypair = sr25519::Pair::from_phrase(seed_phrase, None).unwrap().0;
		let current_block_number = get_current_block_number_new_api().await.unwrap();

		let auth =
			FetchAuthenticationToken { block_number: current_block_number, block_validation: 10 };
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
		let seed_phrase: &str =
			"hockey fine lawn number explain bench twenty blue range cover egg sibling";

		let admin_keypair = sr25519::Pair::from_phrase(seed_phrase, None).unwrap().0;

		let mut zipdata = Vec::new();
		let mut zipfile = std::fs::File::open("./test/test.zip").unwrap();
		let _ = zipfile.read_to_end(&mut zipdata).unwrap();

		let current_block_number = get_current_block_number_new_api().await.unwrap();

		let hash = sha256::digest(zipdata.as_slice());

		let auth = StoreAuthenticationToken {
			block_number: current_block_number,
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
		let input = "0xb7255023814e304b72bc880cc993d5c654ce060db0c3f0772b453714c760521962943747af605a90d0503812c6a62c5c1080cbf377095551af0c168a8c724da8".to_string();
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
