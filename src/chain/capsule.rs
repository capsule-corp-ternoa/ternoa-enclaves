use crate::servers::http_server::StateConfig;

use axum::{extract::State, response::IntoResponse, Json};
use serde_json::json;

use std::{
	fs::OpenOptions,
	io::{Read, Seek, Write},
};

use tracing::{info, warn};

use axum::extract::Path as PathExtract;

use crate::chain::{
	chain::{capsule_keyshare_oracle, get_current_block_number},
	log::*,
	verify::*,
};
use serde::Serialize;

use super::chain::get_onchain_nft_data;

/* **********************
   KEY-SHARE AVAILABLE API
********************** */

#[derive(Serialize)]
pub struct CapsuleExistsResponse {
	enclave_id: String,
	nft_id: u32,
	exists: bool,
}

pub async fn is_capsule_available(
	State(state): State<StateConfig>,
	PathExtract(nft_id): PathExtract<u32>,
) -> impl IntoResponse {
	let file_path = state.seal_path + "capsule_" + &nft_id.to_string() + ".keyshare";

	if std::path::Path::new(&file_path.clone()).exists() {
		info!("Availability check : path checked, path: {}", file_path);

		return Json(CapsuleExistsResponse { enclave_id: state.identity, nft_id, exists: true })
	} else {
		info!(
			"Availability check : capsule key-share does not exist, Capsule nft_id : {}, path : {}",
			nft_id, file_path
		);

		return Json(CapsuleExistsResponse { enclave_id: state.identity, nft_id, exists: false })
	}
}

/* **********************
	 KEY-SHARE VIEW API
********************** */

#[derive(Serialize)]
pub struct CapsuleViewResponse {
	enclave_id: String,
	nft_id: u32,
	log: LogFile,
	description: String,
}

// TODO: check the request for signed data and prevent flooding requests.
pub async fn capsule_get_views(
	State(state): State<StateConfig>,
	PathExtract(nft_id): PathExtract<u32>,
) -> impl IntoResponse {
	let capsule_state = match get_onchain_nft_data(nft_id).await {
		Some(data) => data.state,
		_ => {
			info!(
				"Error retrieving capsule-nft shares access-log : nft_id.{} does not exist",
				nft_id
			);
			return Json(CapsuleViewResponse {
				enclave_id: state.identity,
				nft_id,
				log: LogFile::new(),
				description: "nft_id does not exist.".to_string(),
			})
		},
	};

	if !capsule_state.is_capsule {
		info!(
			"Error retrieving capsule-nft shares access-log : nft_id.{} is not a capsule-nft",
			nft_id
		);

		return Json(CapsuleViewResponse {
			enclave_id: state.identity,
			nft_id,
			log: LogFile::new(),
			description: "nft_id is not a capsule-nft".to_string(),
		})
	}

	let file_path = state.seal_path + &nft_id.to_string() + ".log";

	// CHECK LOG-FILE PATH
	if !std::path::Path::new(&file_path.clone()).exists() {
		info!(
			"Error retrieving Capsule key-share access-log : log path does not exist, Capsule nft_id : {}, path : {}",
			nft_id, file_path
		);

		return Json(CapsuleViewResponse {
			enclave_id: state.identity,
			nft_id,
			log: LogFile::new(),
			description: "Capsule nft_id does not exist on this enclave".to_string(),
		})
	};

	// OPEN LOG-FILE
	let mut log_file = match OpenOptions::new().read(true).open(file_path.clone()) {
		Ok(f) => f,
		Err(_) => {
			info!(
				"Error retrieving Capsule key-share access-log : can not open the log file, Capsule nft_id : {}, path : {}",
				nft_id, file_path
			);

			return Json(CapsuleViewResponse {
				enclave_id: state.identity,
				nft_id,
				log: LogFile::new(),
				description: "can not retrieve the log of capsule views".to_string(),
			})
		},
	};

	// READ LOG-FILE
	let mut log_data = String::new();
	match log_file.read_to_string(&mut log_data) {
		Ok(_) => {
			info!("successfully retrieved log file for nft_id : {}", nft_id);

			return Json(CapsuleViewResponse {
				enclave_id: state.identity,
				nft_id,
				log: serde_json::from_str(&log_data).expect("error deserailizing json body"), /* TODO: manage expect() */
				description: "successful".to_string(),
			})
		},

		Err(_) => {
			info!(
				"Error retrieving Capsule key-share access-log : can not read the log file, Capsule nft_id : {}, path : {}",
				nft_id, file_path
			);

			return Json(CapsuleViewResponse {
				enclave_id: state.identity,
				nft_id,
				log: LogFile::new(),
				description: "Error reading the log of capsule views".to_string(),
			})
		},
	};
}

/* **********************
	 STORE KEY-SHARE
********************** */

pub async fn capsule_set_keyshare(
	State(state): State<StateConfig>,
	Json(request): Json<StoreKeysharePacket>,
) -> impl IntoResponse {
	match request.verify_store_request("capsule").await {
		// DATA-FILED IS VALID
		Ok(verified_data) => {
			// IS ENCALVE SEAL-PATH READY?
			if !std::path::Path::new(&state.clone().seal_path).exists() {
				let status = ReturnStatus::DATABASEFAILURE;
				let description = format!(
					"TEE Key-share {:?}: seal path doe not exist, nft_id : {}, Seal-Path : {}",
					APICALL::CAPSULESET,
					verified_data.nft_id,
					state.seal_path
				);

				info!("{}, requester : {}", description, request.owner_address);

				return Json(json!({
					"status": status,
					"nft_id": verified_data.nft_id,
					"enclave_id": state.identity,
					"description": description,
				}))
			};

			let file_path = state.seal_path.clone() +
				"capsule_" + &verified_data.nft_id.to_string() +
				".keyshare";

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

					info!(
						"{}, Error : {}, requester : {}",
						description, err, request.owner_address
					);

					return Json(json!({
						"status": status,
						"nft_id": verified_data.nft_id,
						"enclave_id": state.identity,
						"description": description,
					}))
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

					info!("{}, Error :{}, requester : {}", description, err, request.owner_address);

					return Json(json!({
						"status": status,
						"nft_id": verified_data.nft_id,
						"enclave_id": state.identity,
						"description": description,
					}))
				},
			};

			// Send extrinsic to Capsule-Pallet as Storage-Oracle
			match capsule_keyshare_oracle(state.enclave_key.clone(), verified_data.nft_id).await {
				Ok(txh) => {
					info!(
						"Proof of storage has been sent to blockchain nft-pallet, nft_id = {}  Owner = {}  tx-hash = {}",
						verified_data.nft_id, request.owner_address, txh
					);

					// Log file for tracing the capsule key-share VIEW history in Marketplace.
					let file_path = state.seal_path + &verified_data.nft_id.to_string() + ".log";

					if !std::path::Path::new(&file_path).exists() {
						let mut file = std::fs::File::create(file_path.clone()).unwrap(); // TODO: manage unwrap()

						let mut log_file_struct = LogFile::new();
						let log_account = LogAccount::new(
							request.owner_address.to_string(),
							RequesterType::OWNER,
						);
						let new_log = LogStruct::new(log_account, LogType::STORE);
						log_file_struct.insert_new_capsule_log(new_log);

						let log_buf = serde_json::to_vec(&log_file_struct).unwrap(); // TODO: manage unwrap()
						file.write_all(&log_buf).unwrap(); // TODO: manage unwrap()
					} else {
						// Log file exists : Secret-NFT is converted to Capsule
						update_log_file_view(
							file_path.to_string(),
							request.owner_address.to_string(),
							RequesterType::OWNER,
							LogType::STORE,
							"capsule",
						);
					}

					return Json(json!({
						"status": ReturnStatus::STORESUCCESS,
						"nft_id": verified_data.nft_id,
						"enclave_id": state.identity,
						"description":"Capsule key-share is successfully stored to TEE".to_string(),
					}))
				},

				Err(err) => {
					let err_str = err.to_string();
					let message = format!(
						"Error sending proof of storage to chain, Capsule nft_id : {}, Error : {}",
						verified_data.nft_id, err_str
					);

					info!("{}, owner = {}", message, request.owner_address);

					info!("Removing the capsule key-share from TEE due to previous error, nft_id : {}", verified_data.nft_id);
					std::fs::remove_file(file_path.clone()).expect("Can not remove key-share file"); // TODO: manage expect()

					return Json(json!({
						"status": ReturnStatus::ORACLEFAILURE,
						"nft_id": verified_data.nft_id,
						"enclave_id": state.identity,
						"description": message,
					}))
				},
			}
		},

		// REQUEST DATA-FIELD IS NOT VALID
		Err(err) => {
			let parsed_data = match request.parse_store_data() {
				Ok(parsed_data) => parsed_data,
				Err(e) =>
					return e.express_verification_error(
						APICALL::CAPSULESET,
						request.owner_address.to_string(),
						0,
						state.identity,
					),
			};

			err.express_verification_error(
				APICALL::CAPSULESET,
				request.owner_address.to_string(),
				parsed_data.nft_id,
				state.identity,
			)
		},
	}
}

/* **********************
	 RETRIEVE KEY-SHARE
********************** */

pub async fn capsule_retrieve_keyshare(
	State(state): State<StateConfig>,
	Json(request): Json<RetrieveKeysharePacket>,
) -> impl IntoResponse {
	match request.verify_retrieve_request("capsule").await {
		Ok(verified_data) => {
			// DOES KEY-SHARE EXIST?
			let file_path = state.seal_path.clone() +
				"capsule_" + &verified_data.nft_id.to_string() +
				".keyshare";
			if !std::path::Path::new(&file_path).is_file() {
				let status = ReturnStatus::KEYNOTEXIST;
				let description = format!(
					"TEE Key-share {:?}: error nft_id.{} key-share does not exist on enclave.",
					APICALL::CAPSULERETRIEVE,
					verified_data.nft_id,
				);

				info!("{}, requester : {}", description, request.requester_address);

				return Json(json!({
					"status": status,
					"nft_id": verified_data.nft_id,
					"enclave_id": state.identity,
					"description": description,
				}))
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

					info!(
						"{}, Error : {}, requester : {}",
						description, err, request.requester_address
					);

					return Json(json!({
						"status": status,
						"nft_id": verified_data.nft_id,
						"enclave_id": state.identity,
						"description": description,
					}))
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

					info!(
						"{} , Error : {} , requester : {}",
						description, err, request.requester_address
					);

					return Json(json!({
						"status": status,
						"nft_id": verified_data.nft_id,
						"enclave_id": state.identity,
						"description": description,
					}))
				},
			};

			// Put a VIEWING history log
			let file_path = state.seal_path + &verified_data.nft_id.to_string() + ".log";
			update_log_file_view(
				file_path,
				request.requester_address.to_string(),
				request.requester_type,
				LogType::VIEW,
				"capsule",
			);

			let serialized_keyshare = StoreKeyshareData {
				nft_id: verified_data.nft_id,
				keyshare: capsule_keyshare,
				auth_token: AuthenticationToken {
					block_number: get_current_block_number().await,
					block_validation: 100,
				},
			}
			.serialize();

			//			let sig = state.enclave_key.sign(serialized_keyshare.as_bytes());
			//			let sig_str = "0x".to_owned() + &sig).unwrap();

			return Json(json!({
				"status": ReturnStatus::RETRIEVESUCCESS,
				"nft_id": verified_data.nft_id,
				"enclave_id": state.identity,
				"keyshare_data": serialized_keyshare,
				"description": "Success retrieving Capsule key-share.".to_string(),
			}))
		},

		Err(err) => {
			let parsed_data = match request.parse_retrieve_data() {
				Ok(parsed_data) => parsed_data,
				Err(e) =>
					return e.express_verification_error(
						APICALL::CAPSULERETRIEVE,
						request.requester_address.to_string(),
						0,
						state.identity,
					),
			};

			err.express_verification_error(
				APICALL::CAPSULERETRIEVE,
				request.requester_address.to_string(),
				parsed_data.nft_id,
				state.identity,
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
	enclave_id: String,
	description: String,
}

pub async fn capsule_remove_keyshare(
	State(state): State<StateConfig>,
	Json(request): Json<RemoveKeysharePacket>,
) -> impl IntoResponse {
	// Check if CAPSULE is burnt
	let capsule_status = match get_onchain_nft_data(request.nft_id).await {
		Some(_) => true,
		_ => false,
	};

	if !capsule_status {
		return Json(RemoveKeyshareResponse {
			status: ReturnStatus::NOTBURNT,
			nft_id: request.nft_id,
			enclave_id: state.identity,
			description:
				"Error removing capsule key-share from TEE, Capsule is not in burnt state."
					.to_string(),
		})
	}

	if !std::path::Path::new(&state.clone().seal_path).exists() {
		info!("Error removing capsule key-share from TEE : seal path does not exist, Capsule nft_id : {}, path : {}", request.nft_id, state.seal_path);

		return Json(RemoveKeyshareResponse {
			status: ReturnStatus::DATABASEFAILURE,
			nft_id: request.nft_id,
			enclave_id: state.identity,
			description: "Error removing capsule key-share from TEE, use another enclave please."
				.to_string(),
		})
	};

	let file_path =
		state.seal_path.clone() + "capsule_" + &request.nft_id.to_string() + ".keyshare";
	let exist = std::path::Path::new(file_path.as_str()).exists();

	if !exist {
		warn!(
				"Error removing capsule key-share from TEE : Capsule nft_id does not exist, nft_id = {}",
				request.nft_id
			);

		return Json(RemoveKeyshareResponse {
			status: ReturnStatus::KEYNOTEXIST,
			nft_id: request.nft_id,
			enclave_id: state.identity,
			description:
				"Error removing capsule key-share from TEE : Capsule nft_id does not exist"
					.to_string(),
		})
	}

	match std::fs::remove_file(file_path) {
		Ok(_) => {
			let file_path = state.seal_path.clone() + &request.nft_id.to_string() + ".log";
			std::fs::remove_file(file_path.clone()).expect("Error removing capsule log-file."); // TODO: manage expect()

			info!(
				"Successfully removed capsule key-share from TEE, Capsule nft_id : {}",
				request.nft_id
			);
			return Json(RemoveKeyshareResponse {
				status: ReturnStatus::REMOVESUCCESS,
				nft_id: request.nft_id,
				enclave_id: state.identity,
				description: "Keyshare ia successfully removed from enclave.".to_string(),
			})
		},

		Err(err) => {
			info!("Error removing Capsule key-share from TEE : error in removing file on disk, nft_id : {}, Error : {}", request.nft_id, err);
			return Json(RemoveKeyshareResponse {
					status: ReturnStatus::DATABASEFAILURE,
					nft_id: request.nft_id,
					enclave_id: state.identity,
					description:
						"Error removing Capsule key-share from TEE, try again or contact cluster admin please."
							.to_string(),
				});
		},
	}
}
