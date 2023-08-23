use crate::{
	chain::helper,
	servers::state::{
		get_accountid, get_blocknumber, get_nft_availability, remove_nft_availability,
		set_nft_availability, SharedState,
	},
};

use axum::{extract::State, http::StatusCode, response::IntoResponse, Json};

use std::{
	fs::{File, OpenOptions},
	io::{Read, Write},
};

use tracing::{debug, error, info, warn};

use axum::extract::Path as PathExtract;

use crate::chain::{
	constants::SEALPATH,
	core::{capsule_keyshare_oracle, get_current_block_number, get_onchain_nft_data},
	log::*,
	verify::*,
};
use serde::Serialize;
use serde_json::to_value;

/* **********************
 KEY-SHARE AVAILABLE API
********************** */

#[derive(Serialize)]
pub struct CapsuleExistsResponse {
	enclave_account: String,
	block_number: u32,
	nft_id: u32,
	exists: bool,
}

/// check if the capsule key-share is available
/// # Arguments
/// * `state` - The state of the enclave
/// * `nft_id` - The nft_id of the capsule
/// # Returns
/// If successfull, block_number is last blocknumber where keyshare is updated
/// I Error happens, block_number is 0
/// If nftid is not available, block_number is the current block_number
pub async fn is_capsule_available(
	State(state): State<SharedState>,
	PathExtract(nft_id): PathExtract<u32>,
) -> impl IntoResponse {
	info!("CAPSULE AVAILABILITY CHECK for {}", nft_id);

	let enclave_account = get_accountid(&state).await;
	let current_block_number = get_blocknumber(&state).await;

	match get_nft_availability(&state, nft_id).await {
		Some(av) => {
			if av.nft_type == helper::NftType::Capsule {
				debug!("CAPSULE AVAILABILITY CHECK : CAPSULE key-share exist, nft_id : {}, updated on block {}", nft_id, av.block_number);
				return (
					StatusCode::OK,
					Json(CapsuleExistsResponse {
						enclave_account,
						block_number: av.block_number,
						nft_id,
						exists: true,
					}),
				)
					.into_response();
			} else {
				debug!("CAPSULE AVAILABILITY CHECK : NFTID is NOT a capsule, nft_id : {}", nft_id);
			}
		},
		None => {
			debug!(
				"CAPSULE AVAILABILITY CHECK : CAPSULE key-share doest NOT exist, nft_id : {}",
				nft_id
			);
		},
	}

	(
		StatusCode::OK,
		Json(CapsuleExistsResponse {
			enclave_account,
			block_number: current_block_number,
			nft_id,
			exists: false,
		}),
	)
		.into_response()
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

// TODO [future rate-limiting] : check the request for signed data and prevent flooding requests.

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
	debug!("\n\t**\nGET CAPSULE VIEWS\n\t**\n");

	let enclave_account = get_accountid(&state).await;

	let capsule_state = match get_onchain_nft_data(&state, nft_id).await {
		Some(data) => data.state,
		_ => {
			info!("GET CAPSULE VIEWS : nft_id.{} does not exist onchain.", nft_id);
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
		info!("GET CAPSULE VIEWS : nft_id.{} is not a capsule", nft_id);

		return (
			StatusCode::NOT_ACCEPTABLE,
			Json(CapsuleViewResponse {
				enclave_account,
				nft_id,
				log: LogFile::new(),
				description: "nft_id is not a capsule".to_string(),
			}),
		);
	}

	let file_path = format!("{SEALPATH}/{nft_id}.log");

	// CHECK LOG-FILE PATH
	if !std::path::Path::new(&file_path).exists() {
		error!(
			"GET CAPSULE VIEWS : log path does not exist on this enclave, Capsule nft_id : {}, path : {}",
			nft_id, file_path
		);

		return (
			StatusCode::NOT_FOUND,
			Json(CapsuleViewResponse {
				enclave_account,
				nft_id,
				log: LogFile::new(),
				description: "Capsule does not exist on this enclave".to_string(),
			}),
		);
	};

	// OPEN LOG-FILE
	let mut log_file = match OpenOptions::new().read(true).open(file_path.clone()) {
		Ok(f) => f,
		Err(err) => {
			let message = format!(
				"GET CAPSULE VIEWS : Error retrieving Capsule key-share access-log : can not open the log file, Capsule nft_id : {}, path : {}, error : {err:?}",
				nft_id, file_path);

			error!(message);

			sentry::with_scope(
				|scope| {
					scope.set_tag("capsule-log-view", nft_id.to_string());
				},
				|| sentry::capture_message(&message, sentry::Level::Error),
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
			debug!("GET CAPSULE VIEWS : successfully retrieved log file for nft_id : {}", nft_id);

			match serde_json::from_str(&log_data) {
				Ok(log) => {
					info!(
						"GET CAPSULE VIEWS : successfully deserialized log file for nft_id : {}",
						nft_id
					);

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
					let message = format!(
						"GET CAPSULE VIEWS : Error retrieving Capsule key-share access-log : can not deserialize the log file, Capsule nft_id : {}, path : {}",
						nft_id, file_path
					);

					error!(message);

					sentry::with_scope(
						|scope| {
							scope.set_tag("capsule-log-view", nft_id.to_string());
						},
						|| sentry::capture_message(&message, sentry::Level::Error),
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
			let message = format!(
				"GET CAPSULE VIEWS : Error retrieving Capsule key-share access-log : can not read the log file, Capsule nft_id : {}, path : {}",
				nft_id, file_path
			);

			error!(message);

			sentry::with_scope(
				|scope| {
					scope.set_tag("capsule-log-view", nft_id.to_string());
				},
				|| sentry::capture_message(&message, sentry::Level::Error),
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
	debug!("\n\t*****\nCAPSULE SET KEYSHARE API\n\t*****\n");

	let enclave_account = get_accountid(&state).await;
	let block_number = get_blocknumber(&state).await;

	match request.verify_store_request(&state, "capsule").await {
		// DATA-FILED IS VALID
		Ok(verified_data) => {
			// IS ENCLAVE SEAL-PATH READY?
			if !std::path::Path::new(SEALPATH).exists() {
				let status = ReturnStatus::DATABASEFAILURE;
				let description = format!(
					"TEE Key-share {:?}: seal path doe not exist, nft_id : {}, Seal-Path : {}",
					APICALL::CAPSULESET,
					verified_data.nft_id,
					SEALPATH
				);

				let message = format!("{}, requester : {}", description, request.owner_address);

				error!(message);

				sentry::with_scope(
					|scope| {
						scope.set_tag("capsule-set-keyshare", verified_data.nft_id.to_string());
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
			};

			// If it is an update keyshare request :
			if let Some(av) = get_nft_availability(&state, verified_data.nft_id).await {
				let file_path = format!(
					"{SEALPATH}/capsule_{}_{}.keyshare",
					verified_data.nft_id, av.block_number
				);

				match std::fs::remove_file(file_path.clone()) {
					Ok(_) => debug!(
						"TEE Key-share {:?}: Remove the old keyshare of the capsule nft_id.{} from enclave disk. {}",
						APICALL::CAPSULESET,
						verified_data.nft_id, file_path),
					Err(err) => {
						let message = format!(
						"TEE Key-share {:?}: Error Removing the old keyshare of the capsule nft_id.{} from enclave disk, path : {file_path} ,err: {err:?}.",
						APICALL::CAPSULESET, verified_data.nft_id);

						error!(message);

						sentry::with_scope(
							|scope| {
								scope.set_tag(
									"capsule-set-keyshare",
									verified_data.nft_id.to_string(),
								);
							},
							|| sentry::capture_message(&message, sentry::Level::Error),
						);
					},
				}
			}

			// Block Number is set at 0 until Synced state is detected
			let file_path = format!("{SEALPATH}/capsule_{}_{0}.keyshare", verified_data.nft_id);

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

					let message = format!(
						"{}, Path: {}, Error : {}, requester : {}",
						description, file_path, err, request.owner_address
					);

					error!(message);

					sentry::with_scope(
						|scope| {
							scope.set_tag("capsule-set-keyshare", verified_data.nft_id.to_string());
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

			// WRITE KEY-SHARE DATA TO FILE
			match f.write_all(&verified_data.keyshare) {
				Ok(_) => info!(
					"Capsule key-share is successfully stored to TEE, nft_id = {} Owner = {}",
					verified_data.nft_id, request.owner_address
				),
				Err(err) => {
					let status = ReturnStatus::DATABASEFAILURE;
					let description = format!(
						"TEE Key-share {:?}: error in setting the new Keyshare for nft_id.{} on enclave disk (write).",
						APICALL::CAPSULESET,
						verified_data.nft_id,
					);
					let message = format!(
						"{}, Error :{}, requester : {}",
						description, err, request.owner_address
					);
					error!(message);

					sentry::with_scope(
						|scope| {
							scope.set_tag("capsule-set-keyshare", verified_data.nft_id.to_string());
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

			// Send extrinsic to Capsule-Pallet as Storage-Oracle
			match capsule_keyshare_oracle(&state, verified_data.nft_id).await {
				Ok(txh) => {
					info!(
						"Proof of storage has been sent to blockchain nft-pallet, nft_id = {} Owner = {} tx-hash = {}",
						verified_data.nft_id, request.owner_address, txh
					);

					// Set Block Number to 0 until Synced event detected
					set_nft_availability(
						&state,
						(
							verified_data.nft_id,
							helper::Availability {
								block_number: 0, //block_number,
								nft_type: helper::NftType::Capsule,
							},
						),
					)
					.await;

					// Log file for tracing the capsule key-share VIEW history in Marketplace.
					let file_path = format!("{SEALPATH}/{}.log", verified_data.nft_id);

					if !std::path::Path::new(&file_path).exists() {
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
										let message = format!(
											"Error in creating log file for nft_id : {}, path : {}, Error : {}",
											verified_data.nft_id, file_path, err
										);

										error!(message);

										sentry::with_scope(
											|scope| {
												scope.set_tag(
													"capsule-set-keyshare",
													verified_data.nft_id.to_string(),
												);
											},
											|| {
												sentry::capture_message(
													&message,
													sentry::Level::Error,
												)
											},
										);
									},
								}
							},
							Err(err) => {
								let message = format!(
									"Error in creating log file for nft_id : {}, path : {} error : {}",
									verified_data.nft_id, file_path, err
								);

								error!(message);

								sentry::with_scope(
									|scope| {
										scope.set_tag(
											"capsule-set-keyshare",
											verified_data.nft_id.to_string(),
										);
									},
									|| sentry::capture_message(&message, sentry::Level::Error),
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
						Json(
							to_value(ApiErrorResponse {
								status: ReturnStatus::STORESUCCESS,
								nft_id: verified_data.nft_id,
								enclave_account,
								description: "Capsule key-share is successfully stored to TEE"
									.to_string(),
							})
							.unwrap(),
						),
					)
				},

				Err(err) => {
					let err_str = err.to_string();
					let description = format!(
						"Error sending proof of storage to chain, Capsule nft_id : {}, Error : {err_str}" , verified_data.nft_id
					);

					let message = format!("{}, owner = {}", description, request.owner_address);

					error!(message);

					sentry::with_scope(
						|scope| {
							scope.set_tag("capsule-set-keyshare", verified_data.nft_id.to_string());
						},
						|| sentry::capture_message(&message, sentry::Level::Error),
					);

					info!("Removing the capsule key-share from TEE due to previous error, nft_id : {}", verified_data.nft_id);

					match std::fs::remove_file(file_path.clone()) {
						Ok(_) => info!(
							"Capsule key-share is successfully removed from TEE, nft_id : {}",
							verified_data.nft_id
						),
						Err(err) => {
							let message = format!(
							"Error in removing capsule key-share from TEE, nft_id : {}, Error : {}",
							verified_data.nft_id, err);

							error!(message);

							sentry::with_scope(
								|scope| {
									scope.set_tag(
										"capsule-set-keyshare",
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
								description,
							})
							.unwrap(),
						),
					)
				},
			}
		},

		// REQUEST DATA-FIELD IS NOT VALID
		Err(err) => {
			let parsed_data = match request.parse_store_data() {
				Ok(parsed_data) => parsed_data,
				Err(err) => {
					return err.express_verification_error(
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
	debug!("\n\t*****\nCAPSULE RETRIEVE KEYSHARE API\n\t*****\n");

	let enclave_account = get_accountid(&state).await;

	match request.verify_retrieve_request(&state, "capsule").await {
		Ok(verified_data) => {
			// DOES KEY-SHARE EXIST?
			let av = match get_nft_availability(&state, verified_data.nft_id).await {
				Some(av) => {
					if av.nft_type == helper::NftType::Capsule {
						av
					} else {
						let status = ReturnStatus::KEYNOTEXIST;
						let description = "NFTID is not a capsule.".to_string();

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
					let description = "Capsule Keyshare is not available.".to_string();

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

			let file_path =
				format!("{SEALPATH}/capsule_{}_{}.keyshare", verified_data.nft_id, av.block_number);

			if !std::path::Path::new(&file_path).is_file() {
				let status = ReturnStatus::KEYNOTEXIST;
				let description = format!(
					"TEE Key-share {:?}: error nft_id.{} key-share does not exist on enclave.",
					APICALL::CAPSULERETRIEVE,
					verified_data.nft_id,
				);

				let message = format!("{}, requester : {}", description, request.requester_address);

				error!(message);

				sentry::with_scope(
					|scope| {
						scope
							.set_tag("capsule-retrieve-keyshare", verified_data.nft_id.to_string());
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

			// OPEN CAPSULE KEY-SHARE
			let mut file = match std::fs::File::open(file_path) {
				Ok(file) => file,
				Err(err) => {
					let status = ReturnStatus::KEYNOTACCESSIBLE;
					let description = format!(
						"TEE Key-share {:?}: error can not open nft_id.{} key-share on enclave.",
						APICALL::CAPSULERETRIEVE,
						verified_data.nft_id,
					);

					let message = format!(
						"{}, Error : {}, requester : {}",
						description, err, request.requester_address
					);

					error!(message);

					sentry::with_scope(
						|scope| {
							scope.set_tag(
								"capsule-retrieve-keyshare",
								verified_data.nft_id.to_string(),
							);
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

					let message = format!(
						"{} , Error : {} , requester : {}",
						description, err, request.requester_address
					);

					error!(message);

					sentry::with_scope(
						|scope| {
							scope.set_tag(
								"capsule-retrieve-keyshare",
								verified_data.nft_id.to_string(),
							);
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
			let file_path = format!("{SEALPATH}/{}.log", verified_data.nft_id);

			match get_current_block_number(&state).await {
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
					// TODO [future - security] : SIGN the response
					(
						StatusCode::OK,
						Json(serde_json::json!({
							"status": ReturnStatus::RETRIEVESUCCESS,
							"nft_id": verified_data.nft_id,
							"enclave_account": enclave_account,
							"keyshare_data": serialized_keyshare,
							"description": "Success retrieving Capsule key-share.".to_string(),
						})),
					)
				},
				Err(err) => {
					let status = ReturnStatus::InvalidBlockNumber;
					let description = format!("Fail retrieving Capsule key-share. {}", err);
					(
						StatusCode::NOT_ACCEPTABLE,
						Json(
							to_value(ApiErrorResponse {
								status,
								nft_id: verified_data.nft_id,
								enclave_account,
								description,
							})
							.unwrap(),
						),
					)
				},
			}
		},

		Err(err) => {
			let parsed_data = match request.parse_retrieve_data() {
				Ok(parsed_data) => parsed_data,
				Err(err) => {
					return err.express_verification_error(
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

/// Remove keyshare from the enclave
/// # Arguments
/// * `request` - RemoveKeysharePacket
/// # Returns
/// * `RemoveKeyshareResponse` - Response of the remove keyshare request
#[axum::debug_handler]
pub async fn capsule_remove_keyshare(
	State(state): State<SharedState>,
	Json(request): Json<RemoveKeysharePacket>,
) -> impl IntoResponse {
	debug!("\n\t*****\nCAPSULE REMOVE KEYSHARE API\n\t*****\n");
	let enclave_account = get_accountid(&state).await;

	// STRUCTURAL VALIDITY OF REQUEST
	let request_data = match request.verify_remove_request(&state, "capsule-nft").await {
		Ok(rd) => rd,
		Err(err) => {
			let parsed_data = match request.parse_retrieve_data() {
				Ok(parsed_data) => parsed_data,
				Err(err) => {
					return err.express_verification_error(
						APICALL::CAPSULEREMOVE,
						request.requester_address.to_string(),
						0,
						enclave_account,
					)
				},
			};

			return err.express_verification_error(
				APICALL::CAPSULEREMOVE,
				request.requester_address.to_string(),
				parsed_data.nft_id,
				enclave_account,
			);
		},
	};

	// IS IT FROM A METRIC SERVER?
	if !crate::backup::metric::verify_account_id(&state, &request.requester_address.to_string())
		.await
	{
		warn!(
			"CAPSULE REMOVE : Invalid requester, nft-id.{}, requester : {}",
			request_data.nft_id, request.requester_address
		);
		return (
			StatusCode::BAD_REQUEST,
			Json(
				to_value(RemoveKeyshareResponse {
					status: ReturnStatus::REQUESTERVERIFICATIONFAILED,
					nft_id: request_data.nft_id,
					enclave_account,
					description: "Requester is not authorized".to_string(),
				})
				.unwrap(),
			),
		);
	}

	// Is nft burnt?
	if get_onchain_nft_data(&state, request_data.nft_id).await.is_some() {
		error!(
			"CAPSULE REMOVE : capsule is not in burnt state, nft-id.{}, requester : {}",
			request_data.nft_id, request.requester_address
		);
		return (
			StatusCode::BAD_REQUEST,
			Json(
				to_value(RemoveKeyshareResponse {
					status: ReturnStatus::NOTBURNT,
					nft_id: request_data.nft_id,
					enclave_account,
					description:
						"Error removing CAPSULE key-share from TEE, CAPSULE is not in burnt state."
							.to_string(),
				})
				.unwrap(),
			),
		);
	}

	let av = match get_nft_availability(&state, request_data.nft_id).await {
		Some(av) => {
			if av.nft_type == helper::NftType::Secret {
				av
			} else {
				error!(
					"CAPSULE REMOVE : capsule is not in available, nft-id.{}, requester : {}",
					request_data.nft_id, request.requester_address
				);
				return (
					StatusCode::BAD_REQUEST,
					Json(
						to_value(RemoveKeyshareResponse {
							status: ReturnStatus::IDISNOTASECRETNFT,
							nft_id: request_data.nft_id,
							enclave_account,
							description: "NFTID for capsule is not available".to_string(),
						})
						.unwrap(),
					),
				);
			}
		},

		None => {
			return (
				StatusCode::OK,
				Json(
					to_value(RemoveKeyshareResponse {
						status: ReturnStatus::REMOVESUCCESS,
						nft_id: request_data.nft_id,
						enclave_account,
						description: "CAPSULE Keyshare was not available already".to_string(),
					})
					.unwrap(),
				),
			)
		},
	};

	let file_path =
		format!("{SEALPATH}/capsule_{}_{}.keyshare", request_data.nft_id, av.block_number);

	if !std::path::Path::new(file_path.as_str()).exists() {
		info!("REMOVE CAPSULE : file does not exist, nft_id = {}", request_data.nft_id);

		return (
			StatusCode::INTERNAL_SERVER_ERROR,
			Json(
				to_value(RemoveKeyshareResponse {
					status: ReturnStatus::DATABASEFAILURE,
					nft_id: request_data.nft_id,
					enclave_account,
					description: "REMOVE CAPSULE : file does not exist".to_string(),
				})
				.unwrap(),
			),
		);
	}

	match std::fs::remove_file(file_path.clone()) {
		Ok(_) => {
			let log_path = format!("{SEALPATH}/{}.log", request_data.nft_id);
			match std::fs::remove_file(log_path) {
				Ok(_) => info!(
					"REMOVE CAPSULE :  log is successfully removed from enclave. nft_id = {}",
					request_data.nft_id
				),

				Err(err) => {
					error!(
						"REMOVE CAPSULE : Error removing log from Enclave {:?}, nft_id = {}",
						err, request_data.nft_id
					);
				},
			}

			remove_nft_availability(&state, request_data.nft_id).await;
			info!(
				"REMOVE CAPSULE :  Keyshare is successfully removed from enclave. nft_id = {}",
				request_data.nft_id
			);

			(
				StatusCode::OK,
				Json(
					to_value(RemoveKeyshareResponse {
						status: ReturnStatus::REMOVESUCCESS,
						nft_id: request_data.nft_id,
						enclave_account,
						description: "Keyshare is successfully removed from enclave.".to_string(),
					})
					.unwrap(),
				),
			)
		},

		Err(err) => {
			error!("REMOVE CAPSULE :  error in removing file on disk, nft_id : {}, path : {}, Error : {}", request_data.nft_id, file_path, err);
			(StatusCode::INTERNAL_SERVER_ERROR, Json(to_value(RemoveKeyshareResponse {
					status: ReturnStatus::DATABASEFAILURE,
					nft_id: request_data.nft_id,
					enclave_account,
					description:
						"Error removing CAPSULE key-share from TEE, try again or contact cluster admin please."
							.to_string(),
				}).unwrap()))
		},
	}
}
