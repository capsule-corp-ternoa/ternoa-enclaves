use crate::servers::state::SharedState;

use axum::{extract::State, http::StatusCode, response::IntoResponse, Json};
use serde_json::json;

use std::{
	fs::OpenOptions,
	io::{Read, Write},
};

use tracing::{debug, error, info, warn};

use axum::extract::Path as PathExtract;

use crate::chain::{
	core::{capsule_keyshare_oracle, get_current_block_number, get_onchain_nft_data},
	log::*,
	verify::*,
};
use serde::Serialize;

const SEALPATH: String = String::from("/nft/");

/* **********************
   KEY-SHARE AVAILABLE API
********************** */

#[derive(Serialize)]
pub struct CapsuleExistsResponse {
	enclave_account: String,
	nft_id: u32,
	exists: bool,
}

/// check if the capsule key-share is available
/// # Arguments
/// * `state` - The state of the enclave
/// * `nft_id` - The nft_id of the capsule
/// # Returns
/// * `impl IntoResponse` - The result of the capsule key-share availability
pub async fn is_capsule_available(
	State(state): State<SharedState>,
	PathExtract(nft_id): PathExtract<u32>,
) -> impl IntoResponse {
	debug!("3-11 API : is capsule available");

	let shared_state = &state.read().await;
	let enclave_account = shared_state.get_accountid();
	let enclave_sealpath = SEALPATH;
	let block_number = shared_state.get_current_block();

	let file_path = enclave_sealpath + "capsule_" + &nft_id.to_string() + ".keyshare";

	if std::path::Path::new(&file_path).exists() {
		info!("Availability check : path checked, path: {}", file_path);

		(
			StatusCode::OK,
			Json(
				json!({"enclave_account": enclave_account, "block_number": block_number, "nft_id": nft_id, "exists": true}),
			),
		)
	} else {
		info!(
			"Availability check : capsule key-share does not exist, Capsule nft_id : {}, path : {}",
			nft_id, file_path
		);

		(
			StatusCode::OK,
			Json(
				json!({"enclave_account": enclave_account, "block_number": block_number, "nft_id": nft_id, "exists": false}),
			),
		)
	}
}

/* **********************
	 KEY-SHARE VIEW API
********************** */

#[derive(Serialize)]
pub struct CapsuleViewResponse {
	enclave_account: String,
	nft_id: u32,
	log: LogFile,
	description: String,
}

// TODO: check the request for signed data and prevent flooding requests.

/// get the capsule key-share
/// # Arguments
/// * `state` - The state of the enclave
/// * `nft_id` - The nft_id of the capsule
/// # Returns
/// * `impl IntoResponse` - The result of the capsule key-share
/// # Errors
/// * `Json(CapsuleViewResponse)` - The capsule key-share is not available
#[axum::debug_handler]
pub async fn capsule_get_views(
	State(state): State<SharedState>,
	PathExtract(nft_id): PathExtract<u32>,
) -> impl IntoResponse {
	debug!("3-12 API : get capsule views");

	let shared_state = &state.read().await;
	let enclave_account = shared_state.get_accountid();
	let enclave_sealpath = SEALPATH;

	let capsule_state = match get_onchain_nft_data(state.clone(), nft_id).await {
		Some(data) => data.state,
		_ => {
			error!(
				"Error retrieving capsule-nft shares access-log : nft_id.{} does not exist",
				nft_id
			);
			return (
				StatusCode::NOT_FOUND,
				Json(CapsuleViewResponse {
					enclave_account,
					nft_id,
					log: LogFile::new(),
					description: "nft_id does not exist.".to_string(),
				}),
			);
		},
	};

	if !capsule_state.is_capsule {
		error!(
			"Error retrieving capsule-nft shares access-log : nft_id.{} is not a capsule-nft",
			nft_id
		);

		return (
			StatusCode::NOT_ACCEPTABLE,
			Json(CapsuleViewResponse {
				enclave_account,
				nft_id,
				log: LogFile::new(),
				description: "nft_id is not a capsule-nft".to_string(),
			}),
		);
	}

	let file_path = enclave_sealpath + &nft_id.to_string() + ".log";

	// CHECK LOG-FILE PATH
	if !std::path::Path::new(&file_path).exists() {
		error!(
			"Error retrieving Capsule key-share access-log : log path does not exist, Capsule nft_id : {}, path : {}",
			nft_id, file_path
		);

		return (
			StatusCode::NOT_FOUND,
			Json(CapsuleViewResponse {
				enclave_account,
				nft_id,
				log: LogFile::new(),
				description: "Capsule nft_id does not exist on this enclave".to_string(),
			}),
		);
	};

	// OPEN LOG-FILE
	let mut log_file = match OpenOptions::new().read(true).open(file_path.clone()) {
		Ok(f) => f,
		Err(_) => {
			error!(
				"Error retrieving Capsule key-share access-log : can not open the log file, Capsule nft_id : {}, path : {}",
				nft_id, file_path
			);

			return (
				StatusCode::INTERNAL_SERVER_ERROR,
				Json(CapsuleViewResponse {
					enclave_account,
					nft_id,
					log: LogFile::new(),
					description: "can not retrieve the log of capsule views".to_string(),
				}),
			);
		},
	};

	// READ LOG-FILE
	let mut log_data = String::new();
	match log_file.read_to_string(&mut log_data) {
		Ok(_) => {
			info!("successfully retrieved log file for nft_id : {}", nft_id);

			match serde_json::from_str(&log_data) {
				Ok(log) => {
					error!("successfully deserialized log file for nft_id : {}", nft_id);

					(
						StatusCode::OK,
						Json(CapsuleViewResponse {
							enclave_account,
							nft_id,
							log,
							description: "successful".to_string(),
						}),
					)
				},
				Err(_) => {
					error!(
						"Error retrieving Capsule key-share access-log : can not deserialize the log file, Capsule nft_id : {}, path : {}",
						nft_id, file_path
					);

					(
						StatusCode::UNPROCESSABLE_ENTITY,
						Json(CapsuleViewResponse {
							enclave_account,
							nft_id,
							log: LogFile::new(),
							description: "can not deserialize the log of capsule views".to_string(),
						}),
					)
				},
			}
		},

		Err(_) => {
			error!(
				"Error retrieving Capsule key-share access-log : can not read the log file, Capsule nft_id : {}, path : {}",
				nft_id, file_path
			);

			(
				StatusCode::INTERNAL_SERVER_ERROR,
				Json(CapsuleViewResponse {
					enclave_account,
					nft_id,
					log: LogFile::new(),
					description: "Error reading the log of capsule views".to_string(),
				}),
			)
		},
	}
}

/* **********************
	 STORE KEY-SHARE
********************** */

/// store the capsule key-share
/// # Arguments
/// * `state` - The state of the enclave
/// * `request` - The request to store the capsule key-share
/// # Returns
/// * `impl IntoResponse` - The result of the capsule key-share

#[axum::debug_handler]
pub async fn capsule_set_keyshare(
	State(state): State<SharedState>,
	Json(request): Json<StoreKeysharePacket>,
) -> impl IntoResponse {
	debug!("3-13 API : capsule set keyshare");

	let shared_state = &state.read().await;
	let enclave_account = shared_state.get_accountid();
	let enclave_sealpath = SEALPATH;
	let enclave_keypair = shared_state.get_key();
	let block_number = shared_state.get_current_block();

	match request.verify_store_request(state.clone(), "capsule").await {
		// DATA-FILED IS VALID
		Ok(verified_data) => {
			// IS ENCLAVE SEAL-PATH READY?
			if !std::path::Path::new(&enclave_sealpath).exists() {
				let status = ReturnStatus::DATABASEFAILURE;
				let description = format!(
					"TEE Key-share {:?}: seal path doe not exist, nft_id : {}, Seal-Path : {}",
					APICALL::CAPSULESET,
					verified_data.nft_id,
					enclave_sealpath
				);

				error!("{}, requester : {}", description, request.owner_address);

				return (
					StatusCode::INTERNAL_SERVER_ERROR,
					Json(json!({
						"status": status,
						"nft_id": verified_data.nft_id,
						"enclave_account": enclave_account,
						"description": description,
					})),
				);
			};

			let file_path = enclave_sealpath.clone()
				+ "capsule_" + &verified_data.nft_id.to_string()
				+ ".keyshare";

			// CREATE KEY-SHARE FILE ON ENCLAVE DISK
			let mut f = match std::fs::File::create(file_path.clone()) {
				Ok(file) => file,
				Err(err) => {
					let status = ReturnStatus::DATABASEFAILURE;
					let description = format!(
						"TEE Key-share {:?}: error in setting the new Keyshare for nft_id.{} on enclave disk (creation).",
						APICALL::CAPSULESET,
						verified_data.nft_id,
					);

					error!(
						"{}, Error : {}, requester : {}",
						description, err, request.owner_address
					);

					return (
						StatusCode::INTERNAL_SERVER_ERROR,
						Json(json!({
							"status": status,
							"nft_id": verified_data.nft_id,
							"enclave_account": enclave_account,
							"description": description,
						})),
					);
				},
			};

			// WRITE KEY-SHARE DATA TO FILE
			match f.write_all(&verified_data.keyshare) {
				Ok(_) => info!(
					"Capsule key-share is successfully stored to TEE, nft_id = {}  Owner = {}",
					verified_data.nft_id, request.owner_address
				),
				Err(err) => {
					let status = ReturnStatus::DATABASEFAILURE;
					let description = format!(
						"TEE Key-share {:?}: error in setting the new Keyshare for nft_id.{} on enclave disk (write).",
						APICALL::CAPSULESET,
						verified_data.nft_id,
					);

					error!(
						"{}, Error :{}, requester : {}",
						description, err, request.owner_address
					);

					return (
						StatusCode::INTERNAL_SERVER_ERROR,
						Json(json!({
							"status": status,
							"nft_id": verified_data.nft_id,
							"enclave_account": enclave_account,
							"description": description,
						})),
					);
				},
			};

			// Send extrinsic to Capsule-Pallet as Storage-Oracle
			match capsule_keyshare_oracle(
				state.clone(),
				enclave_keypair.clone(),
				verified_data.nft_id,
			)
			.await
			{
				Ok(txh) => {
					info!(
						"Proof of storage has been sent to blockchain nft-pallet, nft_id = {}  Owner = {}  tx-hash = {}",
						verified_data.nft_id, request.owner_address, txh
					);

					// Log file for tracing the capsule key-share VIEW history in Marketplace.
					let file_path = enclave_sealpath + &verified_data.nft_id.to_string() + ".log";

					if !std::path::Path::new(&file_path).exists() {
						let mut file = std::fs::File::create(file_path).unwrap(); // TODO: manage unwrap()

						match File::create(file_path.clone()) {
							Ok(_) => {
								let mut log_file_struct = LogFile::new();
								let log_account = LogAccount::new(
									request.owner_address.to_string(),
									RequesterType::OWNER,
								);
								let new_log =
									LogStruct::new(block_number, log_account, LogType::STORE);
								log_file_struct.insert_new_capsule_log(new_log);

								match serde_json::to_vec(&log_file_struct).map(|log_buf| {
									File::create(file_path.clone())
										.and_then(|mut file| file.write_all(&log_buf))
								}) {
									Ok(_) => {
										info!(
											"Log file for nft_id : {} is successfully created, path : {}",
											verified_data.nft_id, file_path
										);
									},
									Err(err) => {
										error!(
											"Error in creating log file for nft_id : {}, path : {}, Error : {}",
											verified_data.nft_id, file_path, err
										);
									},
								}
							},
							Err(err) => {
								error!(
									"Error in creating log file for nft_id : {}, path : {} error : {}",
									verified_data.nft_id, file_path, err
								);
							},
						}
					} else {
						// Log file exists : Secret-NFT is converted to Capsule
						update_log_file_view(
							block_number,
							file_path,
							request.owner_address.to_string(),
							RequesterType::OWNER,
							LogType::STORE,
							"capsule",
						);
					}

					(
						StatusCode::OK,
						Json(json!({
							"status": ReturnStatus::STORESUCCESS,
							"nft_id": verified_data.nft_id,
							"enclave_account": enclave_account,
							"description":"Capsule key-share is successfully stored to TEE".to_string(),
						})),
					)
				},

				Err(err) => {
					let err_str = err.to_string();
					let message = format!(
						"Error sending proof of storage to chain, Capsule nft_id : {}, Error : {err_str}" , verified_data.nft_id
					);

					error!("{}, owner = {}", message, request.owner_address);

					info!("Removing the capsule key-share from TEE due to previous error, nft_id : {}", verified_data.nft_id);

					match std::fs::remove_file(file_path.clone()) {
						Ok(_) => info!(
							"Capsule key-share is successfully removed from TEE, nft_id : {}",
							verified_data.nft_id
						),
						Err(err) => error!(
							"Error in removing capsule key-share from TEE, nft_id : {}, Error : {}",
							verified_data.nft_id, err
						),
					}

					(
						StatusCode::GATEWAY_TIMEOUT,
						Json(json!({
							"status": ReturnStatus::ORACLEFAILURE,
							"nft_id": verified_data.nft_id,
							"enclave_account": enclave_account,
							"description": message,
						})),
					)
				},
			}
		},

		// REQUEST DATA-FIELD IS NOT VALID
		Err(err) => {
			let parsed_data = match request.parse_store_data() {
				Ok(parsed_data) => parsed_data,
				Err(e) => {
					return e.express_verification_error(
						APICALL::CAPSULESET,
						request.owner_address.to_string(),
						0,
						enclave_account,
					)
				},
			};

			err.express_verification_error(
				APICALL::CAPSULESET,
				request.owner_address.to_string(),
				parsed_data.nft_id,
				enclave_account,
			)
		},
	}
}

/* **********************
	 RETRIEVE KEY-SHARE
********************** */
/// Retrieve capsule key-share from TEE
/// # Arguments
/// * `state` - StateConfig
/// * `request` - RetrieveKeysharePacket
/// # Returns
/// * `Json` - ReturnStatus

#[axum::debug_handler]
pub async fn capsule_retrieve_keyshare(
	State(state): State<SharedState>,
	Json(request): Json<RetrieveKeysharePacket>,
) -> impl IntoResponse {
	debug!("3-14 API : capsule retrieve keyshare");

	let shared_state = &state.read().await;
	let enclave_account = shared_state.get_accountid();
	let enclave_sealpath = SEALPATH;

	match request.verify_retrieve_request(state.clone(), "capsule").await {
		Ok(verified_data) => {
			// DOES KEY-SHARE EXIST?
			let file_path = enclave_sealpath.clone()
				+ "capsule_" + &verified_data.nft_id.to_string()
				+ ".keyshare";
			if !std::path::Path::new(&file_path).is_file() {
				let status = ReturnStatus::KEYNOTEXIST;
				let description = format!(
					"TEE Key-share {:?}: error nft_id.{} key-share does not exist on enclave.",
					APICALL::CAPSULERETRIEVE,
					verified_data.nft_id,
				);

				error!("{}, requester : {}", description, request.requester_address);

				return (
					StatusCode::NOT_FOUND,
					Json(json!({
						"status": status,
						"nft_id": verified_data.nft_id,
						"enclave_account": enclave_account,
						"description": description,
					})),
				);
			}

			// OPEN CAPSULE KEY-SHARE
			let mut file = match std::fs::File::open(file_path) {
				Ok(file) => file,
				Err(err) => {
					let status = ReturnStatus::KEYNOTACCESSIBLE;
					let description = format!(
						"TEE Key-share {:?}: error can not read nft_id.{} key-share on enclave.",
						APICALL::CAPSULERETRIEVE,
						verified_data.nft_id,
					);

					error!(
						"{}, Error : {}, requester : {}",
						description, err, request.requester_address
					);

					return (
						StatusCode::NO_CONTENT,
						Json(json!({
							"status": status,
							"nft_id": verified_data.nft_id,
							"enclave_account": enclave_account,
							"description": description,
						})),
					);
				},
			};

			// READ CAPSULE KEY-SHARE
			let mut capsule_keyshare = Vec::<u8>::new();
			match file.read_to_end(&mut capsule_keyshare) {
				Ok(_) => {
					info!(
						"key-shares of {} retrieved by {}",
						verified_data.nft_id, request.requester_address
					)
				},

				Err(err) => {
					let status = ReturnStatus::KEYNOTREADABLE;
					let description = format!(
						"TEE Key-share {:?}: error can not read nft_id.{} key-share from enclave.",
						APICALL::CAPSULERETRIEVE,
						verified_data.nft_id,
					);

					error!(
						"{} , Error : {} , requester : {}",
						description, err, request.requester_address
					);

					return (
						StatusCode::NO_CONTENT,
						Json(json!({
							"status": status,
							"nft_id": verified_data.nft_id,
							"enclave_account": enclave_account,
							"description": description,
						})),
					);
				},
			};

			// Put a VIEWING history log
			let file_path = enclave_sealpath + &verified_data.nft_id.to_string() + ".log";

			match get_current_block_number(state.clone()).await {
				Ok(block_number) => {
					update_log_file_view(
						block_number,
						file_path,
						request.requester_address.to_string(),
						request.requester_type,
						LogType::VIEW,
						"capsule",
					);

					let serialized_keyshare = StoreKeyshareData {
						nft_id: verified_data.nft_id,
						keyshare: capsule_keyshare,
						auth_token: AuthenticationToken { block_number, block_validation: 15 },
					}
					.serialize();
					// TODO : SIGN the response
					(
						StatusCode::OK,
						Json(json!({
							"status": ReturnStatus::RETRIEVESUCCESS,
							"nft_id": verified_data.nft_id,
							"enclave_account": enclave_account,
							"keyshare_data": serialized_keyshare,
							"description": "Success retrieving Capsule key-share.".to_string(),
						})),
					)
				},
				Err(err) => (
					StatusCode::NOT_ACCEPTABLE,
					Json(json!({
						"status": ReturnStatus::InvalidBlockNumber,
						"nft_id": verified_data.nft_id,
						"enclave_account": enclave_account,
						"description": format!("Fail retrieving Capsule key-share. {}", err),
					})),
				),
			}
		},

		Err(err) => {
			let parsed_data = match request.parse_retrieve_data() {
				Ok(parsed_data) => parsed_data,
				Err(e) => {
					return e.express_verification_error(
						APICALL::CAPSULERETRIEVE,
						request.requester_address.to_string(),
						0,
						enclave_account,
					)
				},
			};

			err.express_verification_error(
				APICALL::CAPSULERETRIEVE,
				request.requester_address.to_string(),
				parsed_data.nft_id,
				enclave_account,
			)
		},
	}
}

/* **********************
	 REMOVE KEY-SHARE
********************** */
#[derive(Serialize)]
pub struct RemoveKeyshareResponse {
	status: ReturnStatus,
	nft_id: u32,
	enclave_account: String,
	description: String,
}

/// Remove key-share from enclave
/// # Arguments
/// * `state` - StateConfig
/// * `request` - RemoveKeysharePacket
/// # Returns
/// * `RemoveKeyshareResponse`

#[axum::debug_handler]
pub async fn capsule_remove_keyshare(
	State(state): State<SharedState>,
	Json(request): Json<RemoveKeysharePacket>,
) -> impl IntoResponse {
	debug!("3-11 API : capsule remove keyshare");

	let shared_state = &state.read().await;
	let enclave_account = shared_state.get_accountid();
	let enclave_sealpath = SEALPATH;

	// Check if CAPSULE is burnt
	let capsule_status = match get_onchain_nft_data(state.clone(), request.nft_id).await {
		Some(_) => true, // not burnt
		_ => false,      // burnt
	};

	if capsule_status {
		return Json(RemoveKeyshareResponse {
			status: ReturnStatus::NOTBURNT,
			nft_id: request.nft_id,
			enclave_account,
			description:
				"Error removing capsule key-share from TEE, Capsule is not in burnt state."
					.to_string(),
		});
	}

	if !std::path::Path::new(&enclave_sealpath).exists() {
		info!("Error removing capsule key-share from TEE : seal path does not exist, Capsule nft_id : {}, path : {}", request.nft_id, enclave_sealpath);

		return Json(RemoveKeyshareResponse {
			status: ReturnStatus::DATABASEFAILURE,
			nft_id: request.nft_id,
			enclave_account,
			description: "Error removing capsule key-share from TEE, use another enclave please."
				.to_string(),
		});
	};

	let file_path =
		enclave_sealpath.clone() + "capsule_" + &request.nft_id.to_string() + ".keyshare";
	let exist = std::path::Path::new(file_path.as_str()).exists();

	if !exist {
		warn!(
				"Error removing capsule key-share from TEE : Capsule nft_id does not exist, nft_id = {}",
				request.nft_id
			);

		return Json(RemoveKeyshareResponse {
			status: ReturnStatus::KEYNOTEXIST,
			nft_id: request.nft_id,
			enclave_account,
			description:
				"Error removing capsule key-share from TEE : Capsule nft_id does not exist"
					.to_string(),
		});
	}

	match std::fs::remove_file(file_path) {
		Ok(_) => {
			let file_path = enclave_sealpath.clone() + &request.nft_id.to_string() + ".log";

			match std::fs::remove_file(file_path) {
				Ok(_) => info!("Successfully removed capsule log-file."),
				Err(err) => warn!("Error removing capsule log-file : {}", err),
			}

			info!(
				"Successfully removed capsule key-share from TEE, Capsule nft_id : {}",
				request.nft_id
			);
			Json(RemoveKeyshareResponse {
				status: ReturnStatus::REMOVESUCCESS,
				nft_id: request.nft_id,
				enclave_account,
				description: "Keyshare ia successfully removed from enclave.".to_string(),
			})
		},

		Err(err) => {
			info!("Error removing Capsule key-share from TEE : error in removing file on disk, nft_id : {}, Error : {}", request.nft_id, err);
			Json(RemoveKeyshareResponse {
					status: ReturnStatus::DATABASEFAILURE,
					nft_id: request.nft_id,
					enclave_account,
					description:
						"Error removing Capsule key-share from TEE, try again or contact cluster admin please."
							.to_string(),
				})
		},
	}
}
