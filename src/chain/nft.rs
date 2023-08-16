use crate::{
	chain::helper,
	servers::state::{
		get_accountid, get_blocknumber, get_nft_availability, remove_nft_availability,
		set_nft_availability, SharedState,
	},
};

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
	enclave_account: String,
	block_number: u32,
	nft_id: u32,
	exists: bool,
}

/// if nft is available, return true
/// # Arguments
/// * `state` - StateConfig
/// * `nft_id` - u32
/// # Returns
/// If successfull, block_number is last blocknumber where keyshare is updated
/// I Error happens, block_number is 0
/// If nftid is not available, block_number is the current block_number
#[axum::debug_handler]
pub async fn is_nft_available(
	State(state): State<SharedState>,
	PathExtract(nft_id): PathExtract<u32>,
) -> impl IntoResponse {
	info!("NFT AVAILABILITY CHECK for {}", nft_id);

	let enclave_account = get_accountid(&state).await;
	let current_block_number = get_blocknumber(&state).await;

	let file_path = enclave_sealpath + "nft_" + &nft_id.to_string() + ".keyshare";

	if std::path::Path::new(&file_path).exists() {
		info!("Availability check : path checked, path: {}", file_path);
		Json(NFTExistsResponse { enclave_account, block_number, nft_id, exists: true })
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

	(
		StatusCode::NOT_FOUND,
		Json(NFTExistsResponse {
			enclave_account,
			block_number: current_block_number,
			nft_id,
			exists: false,
		}),
	)
		.into_response()
}

/* **********************
	 KEYSHARE VIEW API
********************** */
#[derive(Serialize)]
pub struct NFTViewResponse {
	enclave_account: String,
	nft_id: u32,
	log: LogFile,
	description: String,
}

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
	debug!("\n\t**\nNFT GET VIEWS\n\t**\n");
	let enclave_account = get_accountid(&state).await;
	let enclave_sealpath = SEALPATH.to_string();

	let nft_state = match get_onchain_nft_data(&state, nft_id).await {
		Some(data) => data.state,
		_ => {
			info!(
				"NFT GET VIEWS : retrieving secret-nft shares access-log : nft_id.{} does not exist",
				nft_id
			);
			return (
				StatusCode::NOT_FOUND,
				Json(NFTViewResponse {
					enclave_account,
					nft_id,
					log: LogFile::new(),
					description: "nft_id does not exist.".to_string(),
				}),
			);
		},
	};

	if !nft_state.is_secret {
		info!(
			"NFT GET VIEWS : retrieving secret-nft shares access-log : nft_id.{} is not a secret-nft",
			nft_id
		);
		return (
			StatusCode::NOT_ACCEPTABLE,
			Json(NFTViewResponse {
				enclave_account,
				nft_id,
				log: LogFile::new(),
				description: "nft_id is not a secret-nft".to_string(),
			}),
		);
	}

	let file_path = format!("{enclave_sealpath}{nft_id}.log");

	if std::path::Path::new(&file_path).exists() {
		debug!("NFT GET VIEWS : Log path checked, path: {}", file_path);
	} else {
		let message = format!(
			"NFT GET VIEWS : Error retrieving NFT key-share access-log : log path doe not exist, nft_id : {}, path : {}",
			nft_id, file_path
		);

		error!(message);

		sentry::with_scope(
			|scope| {
				scope.set_tag("nft-view-log", nft_id.to_string());
			},
			|| sentry::capture_message(&message, sentry::Level::Error),
		);

		return (
			StatusCode::NOT_FOUND,
			Json(NFTViewResponse {
				enclave_account,
				nft_id,
				log: LogFile::new(),
				description: "log for this nft_id does not exist on this enclave".to_string(),
			}),
		);
	};

	let mut log_file = match OpenOptions::new().read(true).open(file_path.clone()) {
		Ok(f) => f,
		Err(_) => {
			let message = format!(
				"NFT GET VIEWS : Error retrieving NFT key-share access-log : can not open the log file, nft_id : {}, path : {}",
				nft_id, file_path
			);

			error!(message);

			sentry::with_scope(
				|scope| {
					scope.set_tag("nft-view-log", nft_id.to_string());
				},
				|| sentry::capture_message(&message, sentry::Level::Error),
			);

			return (
				StatusCode::INTERNAL_SERVER_ERROR,
				Json(NFTViewResponse {
					enclave_account,
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
				Err(err) => {
					let message = format!(
						"NFT GET VIEWS : Error retrieving NFT key-share access-log : can not deserialize log file : {:?}, nft_id : {}, path : {}",
						err, nft_id, file_path
					);

					error!(message);

					sentry::with_scope(
						|scope| {
							scope.set_tag("nft-view-log", nft_id.to_string());
						},
						|| sentry::capture_message(&message, sentry::Level::Error),
					);

					return (StatusCode::UNPROCESSABLE_ENTITY, Json(NFTViewResponse {
						enclave_account,
						nft_id,
						log: LogFile::new(),
						description:
							"deserialization error : can not retrieve the log of secret-nft views"
								.to_string(),
					}));
				},
			};

			info!("NFT GET VIEWS : successfully retrieved log file for nft_id : {}", nft_id);
			(
				StatusCode::OK,
				Json(NFTViewResponse {
					enclave_account,
					nft_id,
					log: log_data_json,
					description: "Successful".to_string(),
				}),
			)
		},

		Err(_) => {
			let message = format!(
				"NFT GET VIEWS : Error retrieving NFT key-share access-log : can not read the log file, nft_id : {}, path : {}",
				nft_id, file_path
			);

			error!(message);

			sentry::with_scope(
				|scope| {
					scope.set_tag("nft-view-log", nft_id.to_string());
				},
				|| sentry::capture_message(&message, sentry::Level::Error),
			);

			(
				StatusCode::INTERNAL_SERVER_ERROR,
				Json(NFTViewResponse {
					enclave_account,
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
	enclave_account: String,
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
	debug!("\n\t*****\nNFT STORE KEYSHARE API\n\t*****\n");
	let enclave_account = get_accountid(&state).await;
	let enclave_sealpath = SEALPATH.to_string();
	let block_number = get_blocknumber(&state).await;

	match request.verify_store_request(&state, "secret-nft").await {
		Ok(verified_data) => {
			if !std::path::Path::new(&enclave_sealpath).exists() {
				let status = ReturnStatus::DATABASEFAILURE;
				let message = format!(
					"TEE Key-share {:?}: seal path doe not exist, nft_id : {}, requester: {}, Seal-Path : {}",
					APICALL::NFTSTORE,
					verified_data.nft_id,
					request.owner_address,
					enclave_sealpath
				);

				error!(message);

				sentry::with_scope(
					|scope| {
						scope.set_tag("nft-store-keyshare", verified_data.nft_id.to_string());
					},
					|| sentry::capture_message(&message, sentry::Level::Error),
				);

				let description =
					"Error storing NFT key-share to TEE, use another enclave please.".to_string();

				return (
					StatusCode::INTERNAL_SERVER_ERROR,
					Json(
						to_value(ApiErrorResponse {
							status,
							nft_id: verified_data.nft_id,
							enclave_account,
							description,
						})
						.unwrap(),
					),
				);
			};

			// Does NFTID exist?
			if get_nft_availability(&state, verified_data.nft_id).await.is_some() {
				let status = ReturnStatus::NFTIDEXISTS;
				let description = format!(
					"TEE Key-share {:?}: nft_id.{} already exists",
					APICALL::NFTSTORE,
					verified_data.nft_id,
				);

				info!("{}, requester : {}", description, request.owner_address);
				let description =
					"Error storing NFT key-share to TEE : nft_id already exists".to_string();

				return (
					StatusCode::CONFLICT,
					Json(
						to_value(ApiErrorResponse {
							status,
							nft_id: verified_data.nft_id,
							enclave_account,
							description,
						})
						.unwrap(),
					),
				);
			}

			let mut f = match std::fs::File::create(file_path.clone()) {
				Ok(file) => file,
				Err(err) => {
					let status = ReturnStatus::DATABASEFAILURE;
					let message = format!(
						"TEE Key-share {:?}: error in creating file on disk, nft_id : {}, requester : {}, path : {}, error: {}",
						APICALL::NFTSTORE,
						verified_data.nft_id,
						request.owner_address,
						new_file_path,
						err
					);

					error!(message);
					sentry::with_scope(
						|scope| {
							scope.set_tag("nft-store-keyshare", verified_data.nft_id.to_string());
						},
						|| sentry::capture_message(&message, sentry::Level::Error),
					);

					let description =
						"Error storing NFT key-share to TEE, use another enclave please."
							.to_string();

					return (
						StatusCode::INTERNAL_SERVER_ERROR,
						Json(
							to_value(ApiErrorResponse {
								status,
								nft_id: verified_data.nft_id,
								enclave_account,
								description,
							})
							.unwrap(),
						),
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
					let message = format!(
						"TEE Key-share {:?}: error in writing data to file, nft_id : {}, requester: {}, path : {}, error: {}",
						APICALL::NFTSTORE,
						verified_data.nft_id,
						request.owner_address,
						new_file_path,
						err
					);

					error!(message);

					sentry::with_scope(
						|scope| {
							scope.set_tag("nft-store-keyshare", verified_data.nft_id.to_string());
						},
						|| sentry::capture_message(&message, sentry::Level::Error),
					);

					let description =
						"Error storing NFT key-share to TEE, use another enclave please."
							.to_string();

					return (
						StatusCode::INTERNAL_SERVER_ERROR,
						Json(
							to_value(ApiErrorResponse {
								status,
								nft_id: verified_data.nft_id,
								enclave_account,
								description,
							})
							.unwrap(),
						),
					);
				},
			};

			// Send extrinsic to Secret-NFT Pallet as Storage-Oracle
			match nft_keyshare_oracle(&state, verified_data.nft_id).await {
				Ok(txh) => {
					// TODO : Getting of TXH is not sufficient, It must wait untin next block to see if it is submitted.
					let result =
						nft_keyshare_oracle_results(block_number, &request, &verified_data, txh);

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

					error!(message);

					sentry::with_scope(
						|scope| {
							scope.set_tag("nft-store-keyshare", verified_data.nft_id.to_string());
						},
						|| sentry::capture_message(&message, sentry::Level::Error),
					);

					warn!(
						"Removing the NFT key-share from TEE due to previous error, nft_id : {}",
						verified_data.nft_id
					);

					match std::fs::remove_file(new_file_path.clone()) {
						Ok(_) => debug!("nft-keyshare is successfully removed from TEE"),
						Err(err) => {
							let message = format!("Error removing nft-keyshare from TEE : {err:?}");

							error!(message);

							sentry::with_scope(
								|scope| {
									scope.set_tag(
										"nft-store-keyshare",
										verified_data.nft_id.to_string(),
									);
								},
								|| sentry::capture_message(&message, sentry::Level::Error),
							);
						},
					}
					let status = ReturnStatus::ORACLEFAILURE;

					(
						StatusCode::GATEWAY_TIMEOUT,
						Json(
							to_value(ApiErrorResponse {
								status,
								nft_id: verified_data.nft_id,
								enclave_account,
								description: message,
							})
							.unwrap(),
						),
					)
				},
			}
		},

		Err(err) => {
			let parsed_data = match request.parse_store_data() {
				Ok(parsed_data) => parsed_data,
				Err(err) => {
					return err.express_verification_error(
						APICALL::NFTRETRIEVE,
						request.owner_address.to_string(),
						0,
						enclave_account,
					)
				},
			};

			err.express_verification_error(
				APICALL::NFTSTORE,
				request.owner_address.to_string(),
				parsed_data.nft_id,
				enclave_account,
			)
		},
	}
}

/// Send extrinsic to Secret-NFT Pallet as Storage-Oracle
fn nft_keyshare_oracle_results(
	block_number: u32,
	request: &StoreKeysharePacket,
	verified_data: &StoreKeyshareData,
	txh: H256,
) -> bool {
	info!(
        "Proof of storage has been sent to blockchain nft-pallet, nft_id = {}  Owner = {}  tx-hash = {}",
        verified_data.nft_id, request.owner_address, txh
    );

	// Log file for tracing the NFT key-share VIEW history in Marketplace.
	let file_path = format!("{SEALPATH}{}.log", verified_data.nft_id);

	let mut file = match File::create(file_path) {
		Ok(file) => file,
		Err(err) => {
			error!("Failed to create log file: {}", err);
			return false;
		},
	};

	let mut log_file_struct = LogFile::new();
	let log_account = LogAccount::new(request.owner_address.to_string(), RequesterType::OWNER);
	let new_log = LogStruct::new(block_number, log_account, LogType::STORE);
	log_file_struct.insert_new_nft_log(new_log);

	let log_buf = match serde_json::to_vec(&log_file_struct) {
		Ok(buf) => buf,
		Err(err) => {
			error!("Failed to serialize log file: {}", err);
			return false;
		},
	};

	if let Err(err) = file.write_all(&log_buf) {
		error!("Failed to write to log file: {}", err);
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
	enclave_account: String,
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
	debug!("\n\t*****\nNFT RETRIEVE KEYSHARE API\n\t*****\n");
	let enclave_account = get_accountid(&state).await;
	let enclave_sealpath = SEALPATH.to_string();
	let block_number = get_blocknumber(&state).await;

	match request.verify_retrieve_request(&state, "secret-nft").await {
		Ok(verified_data) => {
			let av = match get_nft_availability(&state, verified_data.nft_id).await {
				Some(av) => {
					if av.nft_type == helper::NftType::Secret {
						av
					} else {
						let status = ReturnStatus::KEYNOTEXIST;
						let description = "NFTID is for a capsule.".to_string();

						return (
							StatusCode::NOT_FOUND,
							Json(
								to_value(ApiErrorResponse {
									status,
									nft_id: verified_data.nft_id,
									enclave_account,
									description,
								})
								.unwrap(),
							),
						);
					}
				},
				None => {
					let status = ReturnStatus::KEYNOTEXIST;
					let description = "NFT Keyshare is not available.".to_string();

					return (
						StatusCode::NOT_FOUND,
						Json(
							to_value(ApiErrorResponse {
								status,
								nft_id: verified_data.nft_id,
								enclave_account,
								description,
							})
							.unwrap(),
						),
					);
				},
			};

			let file_path = format!(
				"{enclave_sealpath}nft_{}_{}.keyshare",
				verified_data.nft_id, av.block_number
			);

			if !std::path::Path::new(&file_path).is_file() {
				let status = ReturnStatus::KEYNOTEXIST;
				let description =
					format!("TEE Key-share {:?}: file path does not exist", APICALL::NFTRETRIEVE);

				let message = format!(
					"{}, file path : {}, requester : {}",
					description, file_path, request.requester_address
				);

				error!(message);

				sentry::with_scope(
					|scope| {
						scope.set_tag("nft-retrieve-keyshare", verified_data.nft_id.to_string());
					},
					|| sentry::capture_message(&message, sentry::Level::Error),
				);

				return (
					StatusCode::NOT_FOUND,
					Json(
						to_value(ApiErrorResponse {
							status,
							nft_id: verified_data.nft_id,
							enclave_account,
							description,
						})
						.unwrap(),
					),
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

					let message =
						format!("{}, requester : {}", description, request.requester_address);
					error!(message);
					sentry::with_scope(
						|scope| {
							scope
								.set_tag("nft-retrieve-keyshare", verified_data.nft_id.to_string());
						},
						|| sentry::capture_message(&message, sentry::Level::Error),
					);

					return (
						StatusCode::INTERNAL_SERVER_ERROR,
						Json(
							to_value(ApiErrorResponse {
								status,
								nft_id: verified_data.nft_id,
								enclave_account,
								description,
							})
							.unwrap(),
						),
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

					let message =
						format!("{}, requester : {}", description, request.requester_address);
					error!(message);

					sentry::with_scope(
						|scope| {
							scope
								.set_tag("nft-retrieve-keyshare", verified_data.nft_id.to_string());
						},
						|| sentry::capture_message(&message, sentry::Level::Error),
					);

					return (
						StatusCode::INTERNAL_SERVER_ERROR,
						Json(
							to_value(ApiErrorResponse {
								status,
								nft_id: verified_data.nft_id,
								enclave_account,
								description,
							})
							.unwrap(),
						),
					);
				},
			};

			// Put a VIEWING history log
			let file_path = format!("{enclave_sealpath}{}.log", verified_data.nft_id);

			update_log_file_view(
				block_number,
				file_path,
				request.requester_address.to_string(),
				request.requester_type,
				LogType::VIEW,
				"secret-nft",
			);

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
					"enclave_account": enclave_account,
					"keyshare_data": serialized_keyshare,
					"description": description,
				})),
			)
		},

		Err(err) => {
			let parsed_data = match request.parse_retrieve_data() {
				Ok(parsed_data) => parsed_data,
				Err(err) => {
					return err.express_verification_error(
						APICALL::NFTRETRIEVE,
						request.requester_address.to_string(),
						0,
						enclave_account,
					)
				},
			};

			err.express_verification_error(
				APICALL::NFTRETRIEVE,
				request.requester_address.to_string(),
				parsed_data.nft_id,
				enclave_account,
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
	enclave_account: String,
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
	debug!("\n\t*****\nNFT REMOVE KEYSHARE API\n\t*****\n");
	let enclave_account = get_accountid(&state).await;
	let enclave_sealpath = SEALPATH.to_string();

	// TODO : Verify requester_address with Registered Metric Server

	// Is nft burnt?
	if get_onchain_nft_data(&state, request.nft_id).await.is_some() {
		error!("Error removing NFT key-share from TEE : nft is not in burnt state, nft-id.{}, requester : {}", request.nft_id, request.requester_address);
		return (
			StatusCode::BAD_REQUEST,
			Json(RemoveKeyshareResponse {
				status: ReturnStatus::NOTBURNT,
				nft_id: request.nft_id,
				enclave_account,
				description: "Error removing NFT key-share from TEE, NFT is not in burnt state."
					.to_string(),
			}),
		);
	}

	// BAD-REQUEST
	if !std::path::Path::new(&enclave_sealpath).exists() {
		error!("Error removing NFT key-share from TEE : seal path does not exist, nft_id : {}, path : {}", request.nft_id, enclave_sealpath);
		return (
			StatusCode::INTERNAL_SERVER_ERROR,
			Json(RemoveKeyshareResponse {
				status: ReturnStatus::DATABASEFAILURE,
				nft_id: request.nft_id,
				enclave_account,
				description: "Error removing NFT key-share from TEE, use another enclave please."
					.to_string(),
			}),
		);
	};

	let av = match get_nft_availability(&state, request.nft_id).await {
		Some(av) => {
			if av.nft_type == helper::NftType::Secret {
				av
			} else {
				return (
					StatusCode::BAD_REQUEST,
					Json(RemoveKeyshareResponse {
						status: ReturnStatus::REMOVESUCCESS,
						nft_id: request.nft_id,
						enclave_account,
						description: "NFTID is not a secret-nft".to_string(),
					}),
				);
			}
		},

		None => {
			return (
				StatusCode::OK,
				Json(RemoveKeyshareResponse {
					status: ReturnStatus::REMOVESUCCESS,
					nft_id: request.nft_id,
					enclave_account,
					description: "NFT Keyshare was not available already".to_string(),
				}),
			)
		},
	};

	let file_path =
		format!("{}nft_{}_{}.keyshare", enclave_sealpath, request.nft_id, av.block_number);

	let exist = std::path::Path::new(file_path.as_str()).exists();

	if !exist {
		info!(
			"Error removing NFT key-share from TEE : nft_id does not exist, nft_id = {}",
			request.nft_id
		);

		return (
			StatusCode::INTERNAL_SERVER_ERROR,
			Json(RemoveKeyshareResponse {
				status: ReturnStatus::DATABASEFAILURE,
				nft_id: request.nft_id,
				enclave_account,
				description: "Error removing NFT key-share from TEE : nft_id does not exist"
					.to_string(),
			}),
		);
	}

	match std::fs::remove_file(file_path.clone()) {
		Ok(_) => {
			let file_path = format!("{enclave_sealpath}{}.log", request.nft_id);
			match std::fs::remove_file(file_path) {
				Ok(_) => info!(
					"Keyshare is successfully removed from enclave. nft_id = {}",
					request.nft_id
				),
				Err(err) => {
					error!(
						"Error removing Keyshare from Enclave {:?}, nft_id = {}",
						err, request.nft_id
					);

					return (
						StatusCode::INTERNAL_SERVER_ERROR,
						Json(RemoveKeyshareResponse {
							status: ReturnStatus::DATABASEFAILURE,
							nft_id: request.nft_id,
							enclave_account,
							description: "Error removing Keyshare from Enclave.".to_string(),
						}),
					);
				},
			}

			remove_nft_availability(&state, request.nft_id).await;

			(
				StatusCode::OK,
				Json(RemoveKeyshareResponse {
					status: ReturnStatus::REMOVESUCCESS,
					nft_id: request.nft_id,
					enclave_account,
					description: "Keyshare is successfully removed from enclave.".to_string(),
				}),
			)
		},

		Err(err) => {
			info!("Error removing NFT key-share from TEE : error in removing file on disk, nft_id : {}, path : {}, Error : {}", request.nft_id, file_path, err);
			(StatusCode::INTERNAL_SERVER_ERROR, Json(RemoveKeyshareResponse {
					status: ReturnStatus::DATABASEFAILURE,
					nft_id: request.nft_id,
					enclave_account,
					description:
						"Error removing NFT key-share from TEE, try again or contact cluster admin please."
							.to_string(),
				}))
		},
	}
}
