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
use std::{
	collections::BTreeMap,
	io::{Read, Write},
};
use subxt::ext::sp_core::{crypto::Ss58Codec, sr25519, Pair};

use std::fs::{remove_file, File};
use tracing::{debug, error, info, warn};

use serde::{Deserialize, Serialize};
use subxt::ext::sp_core::{crypto::PublicError, sr25519::Signature};

use crate::{
	backup::zipdir::add_list_zip,
	chain::{
		constants::{MAX_BLOCK_VARIATION, MAX_VALIDATION_PERIOD, SEALPATH},
		core::get_current_block_number,
		helper,
	},
	servers::state::{
		get_blocknumber, get_clusters, get_nft_availability, set_nft_availability, SharedState,
		StateConfig,
	},
};

use super::{
	sync::ClusterType,
	zipdir::{add_dir_zip, zip_extract},
};

/* *************************************
	FETCH NFTID DATA STRUCTURES
**************************************** */

// Validity time of Keyshare Data
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct AuthenticationToken {
	pub block_number: u32,
	pub block_validation: u32,
	pub data_hash: String,
}

/// Fetch NFTID Data
#[derive(Serialize, Deserialize, Debug)]
pub struct IdPacket {
	admin_account: String,
	id_vec: String,
	auth_token: String,
	signature: String,
}

/// Fetch NFTID Response
#[derive(Serialize)]
pub struct IdResponse {
	data: String,
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
				debug!("Error get signature {err:?}");
				false
			},
		},
		Err(_) => {
			debug!("Error get public key from account-id");
			false
		},
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
	//update_health_status(state, String::new()).await;
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
	Json(backup_request): Json<IdPacket>,
) -> impl IntoResponse {
	debug!("ADMIN FETCH ID : backup fetch NFTID");

	update_health_status(
		&state,
		"ADMIN FETCH ID : Enclave is doing backup, please wait...".to_string(),
	)
	.await;

	if !verify_account_id(&state, &backup_request.admin_account).await {
		let message = format!(
			"ADMIN FETCH ID : Error backup key shares : Requester is not whitelisted : {}",
			backup_request.admin_account
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
				return error_handler(
					"ADMIN FETCH ID : Strip Token suffix error".to_string(),
					&state,
				)
				.await
				.into_response();
			},
		}
	}

	let auth_token: AuthenticationToken = match serde_json::from_str(&auth) {
		Ok(token) => token,
		Err(err) => {
			let message =
				format!("ADMIN FETCH ID :Error backup key shares : Authentication token is not parsable : {}", err);
			return error_handler(message, &state).await.into_response();
		},
	};

	if !verify_signature(
		&backup_request.admin_account,
		backup_request.signature.clone(),
		backup_request.auth_token.as_bytes(),
	) {
		return error_handler("ADMIN FETCH ID : Invalid Signature".to_string(), &state)
			.await
			.into_response();
	}

	let current_block_number = get_blocknumber(&state).await;

	debug!("ADMIN FETCH ID :Validating the authentication token");
	let validity = auth_token.is_valid(current_block_number);
	match validity {
		ValidationResult::Success => debug!("ADMIN FETCH ID : Authentication token is valid."),
		_ => {
			let message = format!(
				"ADMIN FETCH ID : Authentication Token is not valid, or expired : {:?}",
				validity
			);
			return error_handler(message, &state).await.into_response();
		},
	}

	let hash = sha256::digest(backup_request.id_vec.as_bytes());

	if auth_token.data_hash != hash {
		return error_handler("ADMIN FETCH ID : Mismatch Data Hash".to_string(), &state)
			.await
			.into_response();
	}

	let nftidv: Vec<u32> = match serde_json::from_str(&backup_request.id_vec) {
		Ok(v) => v,
		Err(err) => {
			let message = format!("ADMIN FETCH ID : unable to deserialize nftid vector : {err:?}");
			return error_handler(message, &state).await.into_response();
		},
	};

	let nftids: Vec<String> = nftidv.iter().map(|x| x.to_string()).collect::<Vec<String>>();

	let mut backup_file = "/temporary/backup.zip".to_string();
	let counter = 1;
	// remove previously generated backup
	while std::path::Path::new(&backup_file.clone()).exists() {
		match std::fs::remove_file(backup_file.clone()) {
			Ok(_) => {
				debug!("ADMIN FETCH ID : Successfully removed previous zip file")
			},
			Err(err) => {
				let message = format!(
					"ADMIN FETCH ID : Error backup key shares : Can not remove previous backup file : {}",
					err
				);
				warn!(message);
				//return Json(json!({ "error": message })).into_response()
				backup_file = format!("/temporary/backup-{counter}.zip");
			},
		}
	}

	debug!("ADMIN FETCH ID :Start zippping file");
	add_list_zip(SEALPATH, nftids, &backup_file);

	// `File` implements `AsyncRead`
	debug!("ADMIN FETCH ID : Opening backup file");
	let file = match tokio::fs::File::open(backup_file).await {
		Ok(file) => file,
		Err(err) => {
			return Json(json!({ "error": format!("Backup File not found: {}", err) }))
				.into_response()
		},
	};

	// convert the `AsyncRead` into a `Stream`
	debug!("ADMIN FETCH ID : Create reader-stream");
	let stream = ReaderStream::new(file);

	// convert the `Stream` into an `axum::body::HttpBody`
	debug!("ADMIN FETCH ID : Create body-stream");
	let body = StreamBody::new(stream);

	let headers = [
		(header::CONTENT_TYPE, "text/toml; charset=utf-8"),
		(header::CONTENT_DISPOSITION, "attachment; filename=\"Backup.zip\""),
	];

	update_health_status(&state, String::new()).await;

	debug!("ADMIN FETCH ID : Sending the backup data to the client ...");
	(headers, body).into_response()
}

/*
   Admin Restore Keyshares By NFTID
*/
#[axum::debug_handler]
pub async fn admin_backup_push_id(
	State(state): State<SharedState>,
	Json(backup_request): Json<IdPacket>,
) -> impl IntoResponse {
	debug!("ADMIN PUSH ID : backup fetch NFTID");

	update_health_status(
		&state,
		"ADMIN PUSH ID : Enclave is doing backup, please wait...".to_string(),
	)
	.await;

	if !verify_account_id(&state, &backup_request.admin_account).await {
		let message = format!(
			"ADMIN PUSH ID : Error backup key shares : Requester is not whitelisted : {}",
			backup_request.admin_account
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
				return error_handler(
					"ADMIN PUSH ID : Strip Token suffix error".to_string(),
					&state,
				)
				.await
				.into_response();
			},
		}
	}

	let auth_token: AuthenticationToken = match serde_json::from_str(&auth) {
		Ok(token) => token,
		Err(err) => {
			let message =
				format!("ADMIN PUSH ID : Error backup key shares : Authentication token is not parsable : {}", err);
			return error_handler(message, &state).await.into_response();
		},
	};

	if !verify_signature(
		&backup_request.admin_account,
		backup_request.signature.clone(),
		backup_request.auth_token.as_bytes(),
	) {
		return error_handler("ADMIN PUSH ID : Invalid Signature".to_string(), &state)
			.await
			.into_response();
	}

	let current_block_number = get_blocknumber(&state).await;

	debug!("ADMIN PUSH ID :Validating the authentication token");
	let validity = auth_token.is_valid(current_block_number);
	match validity {
		ValidationResult::Success => debug!("ADMIN PUSH ID : Authentication token is valid."),
		_ => {
			let message = format!(
				"ADMIN PUSH ID : Authentication Token is not valid, or expired : {:?}",
				validity
			);
			return error_handler(message, &state).await.into_response();
		},
	}

	let hash = sha256::digest(backup_request.id_vec.as_bytes());

	if auth_token.data_hash != hash {
		return error_handler("ADMIN PUSH ID : Mismatch Data Hash".to_string(), &state)
			.await
			.into_response();
	}

	let nftidv: Vec<String> = match serde_json::from_str(&backup_request.id_vec) {
		Ok(v) => v,
		Err(err) => {
			let message = format!("ADMIN PUSH ID : unable to deserialize nftid vector : {err:?}");
			return error_handler(message, &state).await.into_response();
		},
	};

	let id_keyshare: Vec<Option<(&str, &str)>> =
		nftidv.iter().map(|x| x.rsplit_once('_')).collect();
	for id_key in id_keyshare {
		if let Some((filename, keyshare)) = id_key {
			let nft_details: Vec<&str> = filename.split('_').collect();

			let nft_id = match nft_details[1].parse::<u32>() {
				Ok(num) => num,
				Err(err) => {
					let message =
						format!("ADMIN PUSH ID : error parse nftid: {}. {:?}", filename, err);
					error!(message);
					sentry::with_scope(
						|scope| {
							scope.set_tag("admin-push-id", filename);
						},
						|| sentry::capture_message(&message, sentry::Level::Error),
					);
					continue;
				},
			};

			let block_number = match nft_details[2].parse::<u32>() {
				Ok(num) => num,
				Err(err) => {
					let message = format!(
						"ADMIN PUSH ID : error parse block-number: {}. {:?}",
						filename, err
					);
					error!(message);
					sentry::with_scope(
						|scope| {
							scope.set_tag("admin-push-id", filename);
						},
						|| sentry::capture_message(&message, sentry::Level::Error),
					);
					continue;
				},
			};

			let mut nft_type = match nft_details[0] {
				"nft" => helper::NftType::Secret,
				"capsule" => helper::NftType::Capsule,
				_ => {
					let message = format!(
						"ADMIN PUSH ID : invalid nft type: {} {}",
						nft_details[0], filename
					);
					error!(message);
					sentry::with_scope(
						|scope| {
							scope.set_tag("admin-push-id", filename);
						},
						|| sentry::capture_message(&message, sentry::Level::Error),
					);
					continue;
				},
			};

			// REMOVE PREVIOUS NFTID IF AVAILABLE
			if let Some(av) = get_nft_availability(&state, nft_id).await {
				if nft_type == av.nft_type {
					let file_path = format!(
						"{SEALPATH}/{}_{}_{}.keyshare",
						nft_details[0], nft_id, av.block_number
					);

					match std::fs::remove_file(file_path.clone()) {
						Ok(_) => {
							debug!(
							"ADMIN PUSH ID : Remove the old keyshare of the nft_id.{} from enclave disk. {}", nft_id, file_path)
						},
						Err(err) => {
							let message = format!(
							"ADMIN PUSH ID : Error Removing the old keyshare of the nft_id.{nft_id} from enclave disk, path : {file_path} ,err: {err:?}.");

							error!(message);

							sentry::with_scope(
								|scope| {
									scope.set_tag("admin-push-id", nft_id.to_string());
								},
								|| sentry::capture_message(&message, sentry::Level::Error),
							);
						},
					}
				} else {
					nft_type = helper::NftType::Hybrid;
				}
			}

			// STORE NEW KEYSHARE ON DISK
			let filepath = format!("{SEALPATH}/{filename}.keyshare");

			match std::fs::write(filepath.clone(), keyshare) {
				Ok(_) => {
					debug!("ADMIN PUSH ID : Success writing keyshare to file: {filepath}");
					set_nft_availability(
						&state,
						(nft_id, helper::Availability { block_number, nft_type }),
					)
					.await;
				},
				Err(err) => {
					let message = format!(
						"ADMIN PUSH ID : error writing keyshare to file: {:?}. {:?}",
						filepath, err
					);
					error!(message);

					sentry::with_scope(
						|scope| {
							scope.set_tag("admin-push-id", filename);
						},
						|| sentry::capture_message(&message, sentry::Level::Error),
					);
				},
			}
		} else {
			let message = "ADMIN PUSH ID : unable to destructure one of id_keyshares".to_string();
			return error_handler(message, &state).await.into_response();
		}
	}

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
	use crate::chain::{
		core::{create_chain_api, get_current_block_number_new_api},
		helper,
	};

	use super::*;

	use axum::{
		body::Body,
		extract::connect_info::MockConnectInfo,
		http::{self, Request, StatusCode},
		response::Html,
		routing::post,
		Router,
	};

	use serde_json::{json, Value};
	use std::net::SocketAddr;
	use std::sync::Arc;
	use tokio::net::TcpListener;
	use tokio::sync::RwLock;
	use tower::Service; // for `call`
	use tower::ServiceExt;
	use tracing::Level;
	use tracing_subscriber::FmtSubscriber; // for `oneshot` and `ready`

	#[tokio::test]
	async fn id_fetch_test() {
		let _ = tracing::subscriber::set_default(
			FmtSubscriber::builder().with_max_level(Level::ERROR).finish(),
		);

		let seed_phrase: &str =
			"hockey fine lawn number explain bench twenty blue range cover egg sibling";

		let admin_keypair = sr25519::Pair::from_phrase(seed_phrase, None).unwrap().0;
		let current_block_number = get_current_block_number_new_api().await.unwrap();
		let nftids: &[u32] = &[10, 200, 3000, 40000, 500000, 6000000];

		let nftids_str = serde_json::to_string(nftids).unwrap();
		let hash = sha256::digest(nftids_str.as_bytes());

		let auth = AuthenticationToken {
			block_number: current_block_number,
			block_validation: 15,
			data_hash: hash,
		};

		let auth_str = serde_json::to_string(&auth).unwrap();
		let sig = admin_keypair.sign(auth_str.as_bytes());
		let sig_str = format!("{}{:?}", "0x", sig);

		let request = IdPacket {
			admin_account: admin_keypair.public().to_string(),
			id_vec: nftids_str,
			auth_token: auth_str,
			signature: sig_str,
		};

		let request_body = serde_json::to_string(&request).unwrap();
		println!("Request Body : {:#?}\n", request_body);

		// Test environment

		let (enclave_keypair, _, _) = sp_core::sr25519::Pair::generate_with_phrase(None);

		let state_config: SharedState = Arc::new(RwLock::new(StateConfig::new(
			enclave_keypair,
			String::new(),
			create_chain_api().await.unwrap(),
			"0.4.0".to_string(),
			0,
			BTreeMap::<u32, helper::Availability>::new(),
		)));

		//let app = Router::new().route("/admin_backup_fetch_id", post(admin_backup_fetch_id)).with_state(state_config);
		let mut app = match crate::servers::http_server::http_server().await {
			Ok(r) => r,
			Err(err) => {
				error!("Error creating http server {}", err);
				return;
			},
		};

		let request1 = Request::builder()
			.method(http::Method::GET)
			.uri("/api/health")
			.header(http::header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
			.body(Body::empty())
			.unwrap();

		let response = ServiceExt::<Request<Body>>::ready(&mut app)
			.await
			.unwrap()
			.call(request1)
			.await
			.unwrap();

		assert_eq!(response.status(), StatusCode::OK);
		let body = hyper::body::to_bytes(response.into_body()).await.unwrap();
		let body: Value = serde_json::from_slice(&body).unwrap();
		println!("Health Check Result: {:#?}", body);

		//info!("Wait for 5 seconds to update the block number between requests");
		//tokio::time::sleep(tokio::time::Duration::from_secs(15)).await;

		let request = Request::builder()
			.method(http::Method::POST)
			.uri("/api/backup/fetch-id")
			.header(http::header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
			.body(Body::from(request_body))
			.unwrap();

		let response = ServiceExt::<Request<Body>>::ready(&mut app)
			.await
			.unwrap()
			.call(request)
			.await
			.unwrap();

		assert_eq!(response.status(), StatusCode::OK);

		let (parts, body) = response.into_parts();
		let body_bytes = hyper::body::to_bytes(body).await.unwrap();

		println!("parts header len {}", parts.headers.len());
		println!("body len {}", body_bytes.len());

		let mut file = File::create("/tmp/ReceivedBackup.zip").unwrap();
		file.write_all(&body_bytes).unwrap();
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
