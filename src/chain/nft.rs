use crate::servers::http_server::SharedState;

use axum::{extract::State, http::StatusCode, response::IntoResponse, Json};

use std::{
	fs::OpenOptions,
	io::{Read, Write},
};

use tracing::{debug, error, info, warn};

use axum::extract::Path as PathExtract;

use crate::chain::chain::nft_secret_share_oracle;

/* **********************
	 DATA STRUCTURES
********************** */

/* **********************
	 DATA STRUCTURES
********************** */

use serde::{Deserialize, Serialize};

/* **********************
   KEYSHARE AVAILABLE API
********************** */
#[derive(Serialize)]
pub struct NFTExistsResponse {
	enclave_id: String,
	nft_id: u32,
	exists: bool,
}

/// if nft is available, return true
/// # Arguments
/// * `state` - StateConfig
/// * `nft_id` - u32
/// # Returns
/// * `Json(NFTExistsResponse)` - NFTExistsResponse
#[axum::debug_handler]
pub async fn is_nft_available(
	State(state): State<SharedState>,
	PathExtract(nft_id): PathExtract<u32>,
) -> Json<NFTExistsResponse> {
	debug!("3-6 API : is nft available");

	let shared_state = &state.read().await;
	let enclave_identity = shared_state.get_identity();
	let enclave_sealpath = shared_state.get_seal_path();

	let file_path = enclave_sealpath + "nft_" + &nft_id.to_string() + ".keyshare";

	if std::path::Path::new(&file_path).exists() {
		info!("Availability check : path checked, path: {}", file_path);
		Json(NFTExistsResponse { enclave_id: enclave_identity, nft_id, exists: true })
	} else {
		info!(
			"Availability check : NFT key-share does not exist, nft_id : {}, path : {}",
			nft_id, file_path
		);

		(
			StatusCode::OK,
			Json(NFTExistsResponse { enclave_id: enclave_identity, nft_id, exists: false }),
		)
	};

	owner
}

#[derive(Clone)]
pub struct SecretData {
	nft_id: u32,
	data: Vec<u8>,
}

impl SecretData {
	fn serialize(self) -> String {
		self.nft_id.to_string() + "_" + &String::from_utf8(self.data).unwrap()
	}
}

impl SecretPacket {
	fn parse_secret(&self) -> SecretData {
		let mut secret_data = self.secret_data.clone();
		if secret_data.starts_with("<Bytes>") && secret_data.ends_with("</Bytes>") {
			secret_data = secret_data
				.strip_prefix("<Bytes>")
				.unwrap()
				.strip_suffix("</Bytes>")
				.unwrap()
				.to_string();
		}

		let nftid_data: Vec<&str> = if secret_data.contains("_") {
			secret_data.split("_").collect()
		} else {
			vec![&secret_data]
		};

		SecretData {
			nft_id: nftid_data[0].parse::<u32>().unwrap(),
			data: if !nftid_data[1].is_empty() {
				nftid_data[1].as_bytes().to_vec()
			} else {
				Vec::new()
			},
		}
	}
}

#[async_trait]
pub trait VerifyNFT {
	fn get_public_key(&self) -> Result<sr25519::Public, ()>;
	fn parse_signature(&self) -> Result<sr25519::Signature, SignatureError>;
	fn verify_signature(&self) -> bool;
	async fn check_nft_ownership(&self) -> bool;
	async fn verify_receive_data(&self) -> Result<SecretData, SecretError>;
}

#[derive(Debug, PartialEq)]
pub enum SignatureError {
	PREFIXERROR,
	LENGHTERROR,
}

#[async_trait]
impl VerifyNFT for SecretPacket {
	fn get_public_key(&self) -> Result<sr25519::Public, ()> {
		sr25519::Public::from_slice(self.account_address.clone().as_slice())
	}

	fn parse_signature(&self) -> Result<sr25519::Signature, SignatureError> {
		let strip_sig = match self.signature.strip_prefix("0x") {
			Some(ssig) => ssig,
			_ => return Err(SignatureError::PREFIXERROR),
		};

		let sig_bytes = match <[u8; 64]>::from_hex(strip_sig) {
			Ok(bsig) => bsig,
			Err(_) => return Err(SignatureError::LENGHTERROR),
		};

		Ok(sr25519::Signature::from_raw(sig_bytes))
	}

	fn parse_signature(&self) -> Result<sr25519::Signature, SignatureError> {
		let strip_sig = match self.signature.strip_prefix("0x") {
			Some(ssig) => ssig,
			_ => return Err(SignatureError::PREFIXERROR),
		};

		let sig_bytes = match <[u8; 64]>::from_hex(strip_sig) {
			Ok(bsig) => bsig,
			Err(_) => return Err(SignatureError::LENGHTERROR),
		};
		
		Ok(sr25519::Signature::from_raw(sig_bytes))
	}

	fn verify_signature(&self) -> bool {
		let account_pubkey = match self.get_public_key() {
			Ok(pk) => pk,
			Err(_) => return false,
		};

		let signature = match self.parse_signature() {
			Ok(sig) => sig,
			Err(_) => return false,
		};

		sr25519::Pair::verify(&signature, self.secret_data.clone(), &account_pubkey)
	}

	async fn check_nft_ownership(&self) -> bool {
		let nft_owner = get_nft_owner(self.parse_secret().nft_id).await;
		match nft_owner {
			NFTOwner::Owner(owner) => owner == self.account_address.into(),
			NFTOwner::NotFound => false,
		}
	}

	async fn verify_receive_data(&self) -> Result<SecretData, SecretError> {
		if self.verify_signature() {
			if self.check_nft_ownership().await {
				Ok(self.parse_secret())
			} else {
				Err(SecretError::InvalidOwner)
			}
		} else {
			Err(SecretError::InvalidSignature)
		}
	}
}

/* **********************
	 KEYSHARE VIEW API
********************** */
#[derive(Serialize)]
pub struct NFTViewResponse {
	enclave_id: String,
	nft_id: u32,
	log: LogFile,
	description: String,
}

// TODO: check the request for signed data and prevent flooding requests.
/// get views per nft
/// # Arguments
/// * `state` - StateConfig
/// * `nft_id` - u32
/// # Returns
/// * `Json(NFTViewResponse)` - NFTViewResponse
#[axum::debug_handler]
pub async fn nft_get_views(
	State(state): State<SharedState>,
	PathExtract(nft_id): PathExtract<u32>,
) -> impl IntoResponse {
	debug!("3-7 API : nft get views");
	let shared_state = &state.read().await;
	let enclave_identity = shared_state.get_identity();
	let enclave_sealpath = shared_state.get_seal_path();

	let nft_state = match get_onchain_nft_data(state.clone(), nft_id).await {
		Some(data) => data.state,
		_ => {
			error!(
				"Error retrieving secret-nft shares access-log : nft_id.{} does not exist",
				nft_id
			);
			return (
				StatusCode::NOT_FOUND,
				Json(NFTViewResponse {
					enclave_id: enclave_identity,
					nft_id,
					log: LogFile::new(),
					description: "nft_id does not exist.".to_string(),
				}),
			);
		},
	};

	if !nft_state.is_secret {
		error!(
			"Error retrieving secret-nft shares access-log : nft_id.{} is not a secret-nft",
			nft_id
		);
		return (
			StatusCode::NOT_ACCEPTABLE,
			Json(NFTViewResponse {
				enclave_id: enclave_identity,
				nft_id,
				log: LogFile::new(),
				description: "nft_id is not a secret-nft".to_string(),
			}),
		);
	}

	let file_path = enclave_sealpath + &nft_id.to_string() + ".log";

	if std::path::Path::new(&file_path).exists() {
		info!("Log path checked, path: {}", file_path);
	} else {
		error!(
			"Error retrieving NFT key-share access-log : log path doe not exist, nft_id : {}, path : {}",
			nft_id, file_path
		);

		return (
			StatusCode::NOT_FOUND,
			Json(NFTViewResponse {
				enclave_id: enclave_identity,
				nft_id,
				log: LogFile::new(),
				description: "nft_id does not exist on this enclave".to_string(),
			}),
		);
	};

	let mut log_file = match OpenOptions::new().read(true).open(file_path.clone()) {
		Ok(f) => f,
		Err(_) => {
			error!(
				"Error retrieving NFT key-share access-log : can not open the log file, nft_id : {}, path : {}",
				nft_id, file_path
			);

			return (
				StatusCode::INTERNAL_SERVER_ERROR,
				Json(NFTViewResponse {
					enclave_id: enclave_identity,
					nft_id,
					log: LogFile::new(),
					description: "can not retrieve the log of secret-nft views".to_string(),
				}),
			);
		},
	};

	let mut log_data = String::new();
	match log_file.read_to_string(&mut log_data) {
		Ok(_) => {
			let log_data_json = match serde_json::from_str(&log_data) {
				Ok(deser) => deser,
				Err(e) => {
					error!(
						"Error retrieving NFT key-share access-log : can not deserialize log file : {:?}, nft_id : {}, path : {}",
						e, nft_id, file_path
					);

					return (StatusCode::UNPROCESSABLE_ENTITY, Json(NFTViewResponse {
						enclave_id: enclave_identity,
						nft_id,
						log: LogFile::new(),
						description:
							"deserialization error : can not retrieve the log of secret-nft views"
								.to_string(),
					}));
				},
			};

			info!("successfully retrieved log file for nft_id : {}", nft_id);
			(
				StatusCode::OK,
				Json(NFTViewResponse {
					enclave_id: enclave_identity,
					nft_id,
					log: log_data_json,
					description: "Successful".to_string(),
				}),
			)
		},

		Err(_) => {
			error!(
				"Error retrieving NFT key-share access-log : can not read the log file, nft_id : {}, path : {}",
				nft_id, file_path
			);

			(
				StatusCode::INTERNAL_SERVER_ERROR,
				Json(NFTViewResponse {
					enclave_id: enclave_identity,
					nft_id,
					log: LogFile::new(),
					description: "can not retrieve the log of nft views".to_string(),
				}),
			)
		},
	}
}

/* **********************
	 STORE KEY-SHARE
********************** */
#[derive(Serialize)]
pub struct StoreKeyshareResponse {
	status: ReturnStatus,
	nft_id: u32,
	enclave_id: String,
	description: String,
}

/// store keyshare
/// # Arguments
/// * `state` - StateConfig
/// * `request` - StoreKeysharePacket
/// # Returns
/// * `Json(StoreKeyshareResponse)` - StoreKeyshareResponse
#[axum::debug_handler]
pub async fn nft_store_keyshare(
	State(state): State<SharedState>,
	Json(request): Json<StoreKeysharePacket>,
) -> impl IntoResponse {
	debug!("3-8 API nft store keyshare");
	let shared_state = &state.read().await;
	let enclave_identity = shared_state.get_identity();
	let enclave_sealpath = shared_state.get_seal_path();
	let enclave_keypair = shared_state.get_key();

	match request.verify_store_request(state.clone(), "secret-nft").await {
		Ok(verified_data) => {
			if !std::path::Path::new(&enclave_sealpath).exists() {
				let status = ReturnStatus::DATABASEFAILURE;
				let description = format!(
					"TEE Key-share {:?}: seal path doe not exist, nft_id : {} Seal-Path : {}",
					APICALL::NFTSTORE,
					verified_data.nft_id,
					enclave_sealpath
				);

				info!("{}, requester : {}", description, request.owner_address);

				return (
					StatusCode::INTERNAL_SERVER_ERROR,
					Json(json!({
						"status": status,
						"nft_id": verified_data.nft_id,
						"enclave_id": enclave_identity,
						"description": "Error storing NFT key-share to TEE, use another enclave please."
						.to_string(),
					})),
				);
			};

			let file_path =
				enclave_sealpath.clone() + "nft_" + &verified_data.nft_id.to_string() + ".keyshare";
			let exist = std::path::Path::new(file_path.as_str()).exists();

			if exist {
				let status = ReturnStatus::NFTIDEXISTS;
				let description = format!(
					"TEE Key-share {:?}: nft_id.{} already exists",
					APICALL::NFTSTORE,
					verified_data.nft_id,
				);

				info!("{}, requester : {}", description, request.owner_address);

				return (
					StatusCode::CONFLICT,
					Json(json!({
						"status": status,
						"nft_id": verified_data.nft_id,
						"enclave_id": enclave_identity,
						"description": "Error storing NFT key-share to TEE : nft_id already exists"
						.to_string(),
					})),
				);
			}

			let mut f = match std::fs::File::create(file_path.clone()) {
				Ok(file) => file,
				Err(err) => {
					let status = ReturnStatus::DATABASEFAILURE;
					let description = format!(
						"TEE Key-share {:?}: error in creating file on disk, nft_id : {} path : {}, error: {}",
						APICALL::NFTSTORE,
						verified_data.nft_id,
						file_path,
						err
					);

					info!("{}, requester : {}", description, request.owner_address);

					return (
						StatusCode::INTERNAL_SERVER_ERROR,
						Json(json!({
							"status": status,
							"nft_id": verified_data.nft_id,
							"enclave_id": enclave_identity,
							"description": "Error storing NFT key-share to TEE, use another enclave please."
							.to_string(),
						})),
					);
				},
			};

			match f.write_all(&verified_data.keyshare) {
				Ok(_) => info!(
					"Keyshare is stored to TEE, nft_id = {}  Owner = {}",
					verified_data.nft_id, request.owner_address
				),

				Err(err) => {
					let status = ReturnStatus::DATABASEFAILURE;
					let description = format!(
						"TEE Key-share {:?}: error in writing data to file, nft_id : {} path : {}, error: {}",
						APICALL::NFTSTORE,
						verified_data.nft_id,
						file_path,
						err
					);

					info!("{}, requester : {}", description, request.owner_address);

					return (
						StatusCode::INTERNAL_SERVER_ERROR,
						Json(json!({
							"status": status,
							"nft_id": verified_data.nft_id,
							"enclave_id": enclave_identity,
							"description": "Error storing NFT key-share to TEE, use another enclave please."
							.to_string(),
						})),
					);
				},
			};

			// Send extrinsic to Secret-NFT Pallet as Storage-Oracle
			match nft_keyshare_oracle(state.clone(), enclave_keypair, verified_data.nft_id).await {
				Ok(txh) => {
					let result = nft_keyshare_oracle_results(
						enclave_sealpath,
						&request,
						&verified_data,
						txh,
					);

					// Log file for tracing the NFT key-share VIEW history in Marketplace.
					let file_path = state.seal_path + &verified_data.nft_id.to_string() + ".log";

					//if !std::path::Path::new(&file_path).exists() {
					let mut file = std::fs::File::create(file_path).unwrap(); // TODO: manage unwrap()

					let mut log_file_struct = LogFile::new();
					let log_account =
						LogAccount::new(request.owner_address.to_string(), RequesterType::OWNER);
					let new_log = LogStruct::new(log_account, LogType::STORE);
					log_file_struct.insert_new_nft_log(new_log);

					let log_buf = serde_json::to_vec(&log_file_struct).unwrap(); // TODO: manage unwrap()

					file.write_all(&log_buf).unwrap(); // TODO: manage unwrap()

					Json(json!({
						"status": ReturnStatus::STORESUCCESS,
						"nft_id": verified_data.nft_id,
						"enclave_id": state.identity,
						"description": "Keyshare is successfully stored to TEE".to_string(),
					}))
				},

				Err(err) => {
					let err_str = err.to_string();
					let message = format!(
						"Error sending proof of storage to chain, nft_id : {}, Error : {}",
						verified_data.nft_id, err_str
					);

					info!(message);

					warn!(
						"Removing the NFT key-share from TEE due to previous error, nft_id : {}",
						verified_data.nft_id
					);

					match std::fs::remove_file(file_path.clone()) {
						Ok(_) => debug!("nft-keyshare is successfully removed from TEE"),
						Err(e) => error!("Error removing nft-keyshare from TEE : {:?}", e),
					}

					(
						StatusCode::GATEWAY_TIMEOUT,
						Json(json!({
							"status": ReturnStatus::ORACLEFAILURE,
							"nft_id": verified_data.nft_id,
							"enclave_id": enclave_identity,
							"description": message,
						})),
					)
				},
			}
		},

		Err(err) => {
			let parsed_data = match request.parse_store_data() {
				Ok(parsed_data) => parsed_data,
				Err(e) => {
					return e.express_verification_error(
						APICALL::NFTRETRIEVE,
						request.owner_address.to_string(),
						0,
						enclave_identity,
					)
				},
			};

			err.express_verification_error(
				APICALL::NFTSTORE,
				request.owner_address.to_string(),
				parsed_data.nft_id,
				enclave_identity,
			)
		},
	}
}

/// Send extrinsic to Secret-NFT Pallet as Storage-Oracle
fn nft_keyshare_oracle_results(
	enclave_sealpath: String,
	request: &StoreKeysharePacket,
	verified_data: &StoreKeyshareData,
	txh: H256,
) -> bool {
	info!(
        "Proof of storage has been sent to blockchain nft-pallet, nft_id = {}  Owner = {}  tx-hash = {}",
        verified_data.nft_id, request.owner_address, txh
    );

	// Log file for tracing the NFT key-share VIEW history in Marketplace.
	let file_path = enclave_sealpath + &verified_data.nft_id.to_string() + ".log";

	let mut file = match File::create(file_path) {
		Ok(file) => file,
		Err(e) => {
			error!("Failed to create log file: {}", e);
			return false;
		},
	};

	let mut log_file_struct = LogFile::new();
	let log_account = LogAccount::new(request.owner_address.to_string(), RequesterType::OWNER);
	let new_log = LogStruct::new(log_account, LogType::STORE);
	log_file_struct.insert_new_nft_log(new_log);

	let log_buf = match serde_json::to_vec(&log_file_struct) {
		Ok(buf) => buf,
		Err(e) => {
			error!("Failed to serialize log file: {}", e);
			return false;
		},
	};

	if let Err(e) = file.write_all(&log_buf) {
		error!("Failed to write to log file: {}", e);
		return false;
	}

	true
}

/* **********************
	 RETRIEVE KEYSHARE
********************** */
#[derive(Serialize)]
pub struct RetrieveKeyshareResponse {
	status: ReturnStatus,
	enclave_id: String,
	secret_data: String,
	description: String,
}

/// Retrieve Key share from TEE
/// # Arguments
/// * `state` - StateConfig
/// * `request` - Retrieve Key share Packet
/// # Returns
/// * `Retrieve Key share Response`
#[axum::debug_handler]
pub async fn nft_retrieve_keyshare(
	State(state): State<SharedState>,
	Json(request): Json<RetrieveKeysharePacket>,
) -> impl IntoResponse {
	debug!("3-9 API : nft retrieve keyshare");
	let shared_state = &state.read().await;
	let enclave_identity = shared_state.get_identity();
	let enclave_sealpath = shared_state.get_seal_path();

	match request.verify_retrieve_request(state.clone(), "secret-nft").await {
		Ok(verified_data) => {
			let file_path =
				enclave_sealpath.clone() + "nft_" + &verified_data.nft_id.to_string() + ".keyshare";

			if !std::path::Path::new(&file_path).is_file() {
				let status = ReturnStatus::KEYNOTEXIST;
				let description =
					format!("TEE Key-share {:?}: file path does not exist", APICALL::NFTRETRIEVE);

				error!(
					"{}, file path : {}, requester : {}",
					description, file_path, request.requester_address
				);

				return (
					StatusCode::NOT_FOUND,
					Json(json!({
						"status": status,
						"nft_id": verified_data.nft_id,
						"enclave_id": enclave_identity,
						"description": description,
					})),
				);
			}

			let mut file = match std::fs::File::open(file_path) {
				Ok(file) => file,
				Err(err) => {
					let status = ReturnStatus::KEYNOTACCESSIBLE;
					let description = format!(
						"TEE Key-share {:?}: can not open keyshare file, nft_id : {} Error : {}",
						APICALL::NFTRETRIEVE,
						verified_data.nft_id,
						err
					);

					error!("{}, requester : {}", description, request.requester_address);

					return (
						StatusCode::INTERNAL_SERVER_ERROR,
						Json(json!({
							"status": status,
							"nft_id": verified_data.nft_id,
							"enclave_id": enclave_identity,
							"description": description,
						})),
					);
				},
			};

			let mut nft_keyshare = Vec::<u8>::new();

			match file.read_to_end(&mut nft_keyshare) {
				Ok(_) => {
					info!(
						"Keyshare of {} retrieved by {}",
						verified_data.nft_id, request.requester_address
					)
				},

				Err(err) => {
					let status = ReturnStatus::KEYNOTREADABLE;
					let description = format!(
						"TEE Key-share {:?}: can not read keyshare file, nft_id : {} Error : {}",
						APICALL::NFTRETRIEVE,
						verified_data.nft_id,
						err
					);

					info!("{}, requester : {}", description, request.requester_address);

					return (
						StatusCode::INTERNAL_SERVER_ERROR,
						Json(json!({
							"status": status,
							"nft_id": verified_data.nft_id,
							"enclave_id": enclave_identity,
							"description": description,
						})),
					);
				},
			};

			// TODO: handle the errors for log file : Reject the request

			// Put a VIEWING history log
			let file_path = enclave_sealpath + &verified_data.nft_id.to_string() + ".log";
			update_log_file_view(
				file_path,
				request.requester_address.to_string(),
				request.requester_type,
				LogType::VIEW,
				"secret-nft",
			);

			match get_current_block_number(state.clone()).await {
				Ok(block_number) => {
					let serialized_keyshare = StoreKeyshareData {
						nft_id: verified_data.nft_id,
						keyshare: nft_keyshare,
						auth_token: AuthenticationToken { block_number, block_validation: 15 },
					}
					.serialize();
					let status = ReturnStatus::RETRIEVESUCCESS;
					let description = format!(
						"TEE Key-share {:?}: Success retrieving nft_id key-share.",
						APICALL::NFTRETRIEVE
					);

					info!("{}, requester : {}", description, request.requester_address);

					(
						StatusCode::OK,
						Json(json!({
							"status": status,
							"nft_id": verified_data.nft_id,
							"enclave_id": enclave_identity,
							"keyshare_data": serialized_keyshare,
							"description": description,
						})),
					)
				},

				Err(e) => (
					StatusCode::GATEWAY_TIMEOUT,
					Json(json!({
						"status": ReturnStatus::InvalidBlockNumber,
						"nft_id": verified_data.nft_id,
						"enclave_id": enclave_identity,
						"keyshare_data": "Error in data",
						"description": format!("Error getting current block number: {}", e)
					})),
				),
			}
		},

		Err(err) => {
			let parsed_data = match request.parse_retrieve_data() {
				Ok(parsed_data) => parsed_data,
				Err(e) => {
					return e.express_verification_error(
						APICALL::NFTRETRIEVE,
						request.requester_address.to_string(),
						0,
						enclave_identity,
					)
				},
			};

			err.express_verification_error(
				APICALL::NFTRETRIEVE,
				request.requester_address.to_string(),
				parsed_data.nft_id,
				enclave_identity,
			)
		},
	}
}

/* **********************
	 REMOVE KEYSHARE
********************** */
#[derive(Serialize)]
pub struct RemoveKeyshareResponse {
	status: ReturnStatus,
	nft_id: u32,
	enclave_id: String,
	description: String,
}

/// Remove keyshare from the enclave
/// # Arguments
/// * `request` - RemoveKeysharePacket
/// # Returns
/// * `RemoveKeyshareResponse` - Response of the remove keyshare request
#[axum::debug_handler]
pub async fn nft_remove_keyshare(
	State(state): State<SharedState>,
	Json(request): Json<RemoveKeysharePacket>,
) -> impl IntoResponse {
	debug!("3-10 API : nft remove keyshare");
	let shared_state = &state.read().await;
	let enclave_identity = shared_state.get_identity();
	let enclave_sealpath = shared_state.get_seal_path();

	let nft_status = match get_onchain_nft_data(state.clone(), request.nft_id).await {
		Some(_) => true, // not burnt
		_ => false,      // burntd
	};

	// BAD-REQUEST
	if nft_status {
		error!("Error removing NFT key-share from TEE : nft is not in burnt state, nft-id.{}, requester : {}", request.nft_id, request.requester_address);
		return Json(RemoveKeyshareResponse {
			status: ReturnStatus::NOTBURNT,
			nft_id: request.nft_id,
			enclave_id: enclave_identity,
			description: "Error removing NFT key-share from TEE, NFT is not in burnt state."
				.to_string(),
		});
	}

	// BAD-REQUEST
	if !std::path::Path::new(&enclave_sealpath).exists() {
		error!("Error removing NFT key-share from TEE : seal path does not exist, nft_id : {}, path : {}", request.nft_id, enclave_sealpath);
		return Json(RemoveKeyshareResponse {
			status: ReturnStatus::DATABASEFAILURE,
			nft_id: request.nft_id,
			enclave_id: enclave_identity,
			description: "Error removing NFT key-share from TEE, use another enclave please."
				.to_string(),
		});
	};

	let file_path = enclave_sealpath.clone() + "nft_" + &request.nft_id.to_string() + ".keyshare";

	let exist = std::path::Path::new(file_path.as_str()).exists();

	if !exist {
		info!(
			"Error removing NFT key-share from TEE : nft_id does not exist, nft_id = {}",
			request.nft_id
		);

		return Json(RemoveKeyshareResponse {
			status: ReturnStatus::DATABASEFAILURE,
			nft_id: request.nft_id,
			enclave_id: enclave_identity,
			description: "Error removing NFT key-share from TEE : nft_id does not exist"
				.to_string(),
		});
	}

	match std::fs::remove_file(file_path.clone()) {
		Ok(_) => {
			let file_path = enclave_sealpath.clone() + &request.nft_id.to_string() + ".log";
			match std::fs::remove_file(file_path) {
				Ok(_) => info!(
					"Keyshare is successfully removed from enclave. nft_id = {}",
					request.nft_id
				),
				Err(e) => {
					error!(
						"Error removing Keyshare from Enclave {:?}, nft_id = {}",
						e, request.nft_id
					);
					return Json(RemoveKeyshareResponse {
						status: ReturnStatus::DATABASEFAILURE,
						nft_id: request.nft_id,
						enclave_id: enclave_identity,
						description: "Error removing Keyshare from Enclave.".to_string(),
					});
				},
			}

			Json(RemoveKeyshareResponse {
				status: ReturnStatus::REMOVESUCCESS,
				nft_id: request.nft_id,
				enclave_id: enclave_identity,
				description: "Keyshare is successfully removed from enclave.".to_string(),
			})
		},

		Err(err) => {
			info!("Error removing NFT key-share from TEE : error in removing file on disk, nft_id : {}, path : {}, Error : {}", request.nft_id, file_path, err);
			Json(RemoveKeyshareResponse {
					status: ReturnStatus::DATABASEFAILURE,
					nft_id: request.nft_id,
					enclave_id: enclave_identity,
					description:
						"Error removing NFT key-share from TEE, try again or contact cluster admin please."
							.to_string(),
				})
		},
	}
}
