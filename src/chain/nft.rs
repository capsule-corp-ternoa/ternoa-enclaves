use crate::servers::http_server::StateConfig;

use axum::{extract::State, http::StatusCode, response::IntoResponse, Json};

use std::{
	fs::OpenOptions,
	io::{Read, Seek, Write},
};
use tracing::{info, warn};

use axum::extract::Path as PathExtract;

use crate::chain::{
	chain::{get_current_block_number, nft_keyshare_oracle},
	log::*,
	verify::*,
};
use serde::Serialize;
use serde_json::json;

use super::chain::get_onchain_nft_data;

/* **********************
   KEYSHARE AVAILABLE API
********************** */
#[derive(Serialize)]
pub struct NFTExistsResponse {
	enclave_id: String,
	nft_id: u32,
	exists: bool,
}

pub async fn is_nft_available(
	State(state): State<StateConfig>,
	PathExtract(nft_id): PathExtract<u32>,
) -> impl IntoResponse {
	let file_path = state.seal_path + "nft_" + &nft_id.to_string() + ".keyshare";

	if std::path::Path::new(&file_path.clone()).exists() {
		info!("Availability check : path checked, path: {}", file_path);
		return (
			StatusCode::OK,
			Json(NFTExistsResponse { enclave_id: state.identity, nft_id, exists: true }),
		)
	} else {
		info!(
			"Availability check : NFT key-share does not exist, nft_id : {}, path : {}",
			nft_id, file_path
		);

		return (
			StatusCode::OK,
			Json(NFTExistsResponse { enclave_id: state.identity, nft_id, exists: false }),
		)
	};
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
pub async fn nft_get_views(
	State(state): State<StateConfig>,
	PathExtract(nft_id): PathExtract<u32>,
) -> impl IntoResponse {
	let nft_state = match get_onchain_nft_data(nft_id).await {
		Some(data) => data.state,
		_ => {
			info!(
				"Error retrieving secret-nft shares access-log : nft_id.{} does not exist",
				nft_id
			);
			return Json(NFTViewResponse {
				enclave_id: state.identity,
				nft_id,
				log: LogFile::new(),
				description: "nft_id does not exist.".to_string(),
			})
		},
	};

	if !nft_state.is_secret {
		info!(
			"Error retrieving secret-nft shares access-log : nft_id.{} is not a secret-nft",
			nft_id
		);
		return Json(NFTViewResponse {
			enclave_id: state.identity,
			nft_id,
			log: LogFile::new(),
			description: "nft_id is not a secret-nft".to_string(),
		})
	}

	let file_path = state.seal_path + &nft_id.to_string() + ".log";

	if std::path::Path::new(&file_path.clone()).exists() {
		info!("Log path checked, path: {}", file_path);
	} else {
		info!(
			"Error retrieving NFT key-share access-log : log path doe not exist, nft_id : {}, path : {}",
			nft_id, file_path
		);

		return Json(NFTViewResponse {
			enclave_id: state.identity,
			nft_id,
			log: LogFile::new(),
			description: "nft_id does not exist on this enclave".to_string(),
		})
	};

	let mut log_file = match OpenOptions::new().read(true).open(file_path.clone()) {
		Ok(f) => f,
		Err(_) => {
			info!(
				"Error retrieving NFT key-share access-log : can not open the log file, nft_id : {}, path : {}",
				nft_id, file_path
			);

			return Json(NFTViewResponse {
				enclave_id: state.identity,
				nft_id,
				log: LogFile::new(),
				description: "can not retrieve the log of secret-nft views".to_string(),
			})
		},
	};

	let mut log_data = String::new();
	match log_file.read_to_string(&mut log_data) {
		Ok(_) => {
			info!("successfully retrieved log file for nft_id : {}", nft_id);
			return Json(NFTViewResponse {
				enclave_id: state.identity,
				nft_id,
				log: serde_json::from_str(&log_data).expect("error deserailizing json body"),
				description: "Successful".to_string(),
			})
		},

		Err(_) => {
			info!(
				"Error retrieving NFT key-share access-log : can not read the log file, nft_id : {}, path : {}",
				nft_id, file_path
			);

			return Json(NFTViewResponse {
				enclave_id: state.identity,
				nft_id,
				log: LogFile::new(),
				description: "can not retrieve the log of nft views".to_string(),
			})
		},
	};
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

pub async fn nft_store_keyshare(
	State(state): State<StateConfig>,
	Json(request): Json<StoreKeysharePacket>,
) -> impl IntoResponse {
	match request.verify_store_request("secret-nft").await {
		Ok(verified_data) => {
			if !std::path::Path::new(&state.clone().seal_path).exists() {
				let status = ReturnStatus::DATABASEFAILURE;
				let description = format!(
					"TEE Key-share {:?}: seal path doe not exist, nft_id : {} Seal-Path : {}",
					APICALL::NFTSTORE,
					verified_data.nft_id,
					state.seal_path
				);

				info!("{}, requester : {}", description, request.owner_address);

				return Json(json!({
					"status": status,
					"nft_id": verified_data.nft_id,
					"enclave_id": state.identity,
					"description": "Error storing NFT key-share to TEE, use another enclave please."
					.to_string(),
				}))
			};

			let file_path =
				state.seal_path.clone() + "nft_" + &verified_data.nft_id.to_string() + ".keyshare";
			let exist = std::path::Path::new(file_path.as_str()).exists();

			if exist {
				let status = ReturnStatus::NFTIDEXISTS;
				let description = format!(
					"TEE Key-share {:?}: nft_id.{} already exists",
					APICALL::NFTSTORE,
					verified_data.nft_id,
				);

				info!("{}, requester : {}", description, request.owner_address);

				return Json(json!({
					"status": status,
					"nft_id": verified_data.nft_id,
					"enclave_id": state.identity,
					"description": "Error storing NFT key-share to TEE : nft_id already exists"
					.to_string(),
				}))
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

					return Json(json!({
						"status": status,
						"nft_id": verified_data.nft_id,
						"enclave_id": state.identity,
						"description": "Error storing NFT key-share to TEE, use another enclave please."
						.to_string(),
					}))
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

					return Json(json!({
						"status": status,
						"nft_id": verified_data.nft_id,
						"enclave_id": state.identity,
						"description": "Error storing NFT key-share to TEE, use another enclave please."
						.to_string(),
					}))
				},
			};

			// Send extrinsic to Secret-NFT Pallet as Storage-Oracle
			match nft_keyshare_oracle(state.enclave_key.clone(), verified_data.nft_id).await {
				Ok(txh) => {
					info!(
						"Proof of storage has been sent to blockchain nft-pallet, nft_id = {}  Owner = {}  tx-hash = {}",
						verified_data.nft_id, request.owner_address, txh
					);

					// Log file for tracing the NFT key-share VIEW history in Marketplace.
					let file_path = state.seal_path + &verified_data.nft_id.to_string() + ".log";

					//if !std::path::Path::new(&file_path).exists() {
					let mut file = std::fs::File::create(file_path.clone()).unwrap(); // TODO: manage unwrap()

					let mut log_file_struct = LogFile::new();
					let log_account =
						LogAccount::new(request.owner_address.to_string(), RequesterType::OWNER);
					let new_log = LogStruct::new(log_account, LogType::STORE);
					log_file_struct.insert_new_nft_log(new_log);

					let log_buf = serde_json::to_vec(&log_file_struct).unwrap(); // TODO: manage unwrap()
					file.write_all(&log_buf).unwrap(); // TODO: manage unwrap()

					return Json(json!({
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
					std::fs::remove_file(file_path.clone()).expect("Can not remove Keyshare file");

					return Json(json!({
						"status": ReturnStatus::ORACLEFAILURE,
						"nft_id": verified_data.nft_id,
						"enclave_id": state.identity,
						"description": message,
					}))
				},
			}
		},

		Err(err) => {
			let parsed_data = match request.parse_store_data() {
				Ok(parsed_data) => parsed_data,
				Err(e) =>
					return e.express_verification_error(
						APICALL::NFTRETRIEVE,
						request.owner_address.to_string(),
						0,
						state.identity,
					),
			};

			err.express_verification_error(
				APICALL::NFTSTORE,
				request.owner_address.to_string(),
				parsed_data.nft_id,
				state.identity,
			)
		},
	}
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

pub async fn nft_retrieve_keyshare(
	State(state): State<StateConfig>,
	Json(request): Json<RetrieveKeysharePacket>,
) -> impl IntoResponse {
	match request.verify_retrieve_request("secret-nft").await {
		Ok(verified_data) => {
			let file_path =
				state.seal_path.clone() + "nft_" + &verified_data.nft_id.to_string() + ".keyshare";

			if !std::path::Path::new(&file_path).is_file() {
				let status = ReturnStatus::KEYNOTEXIST;
				let description =
					format!("TEE Key-share {:?}: file path does not exist", APICALL::NFTRETRIEVE);

				info!(
					"{}, file path : {}, requester : {}",
					description, file_path, request.requester_address
				);

				return Json(json!({
					"status": status,
					"nft_id": verified_data.nft_id,
					"enclave_id": state.identity,
					"description": description,
				}))
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

					info!("{}, requester : {}", description, request.requester_address);

					return Json(json!({
						"status": status,
						"nft_id": verified_data.nft_id,
						"enclave_id": state.identity,
						"description": description,
					}))
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
				"secret-nft",
			);

			//
			let serialized_keyshare = StoreKeyshareData {
				nft_id: verified_data.nft_id,
				keyshare: nft_keyshare,
				auth_token: AuthenticationToken {
					block_number: get_current_block_number().await,
					block_validation: 100,
				},
			}
			.serialize();

			//			let sig = state.enclave_key.sign(serialized_keyshare.as_bytes());
			//			let sig_str = "0x".to_owned() + &&sig).unwrap();

			let status = ReturnStatus::RETRIEVESUCCESS;
			let description = format!(
				"TEE Key-share {:?}: Success retrieving nft_id key-share.",
				APICALL::NFTRETRIEVE
			);

			info!("{}, requester : {}", description, request.requester_address);

			return Json(json!({
				"status": status,
				"nft_id": verified_data.nft_id,
				"enclave_id": state.identity,
				"keyshare_data": serialized_keyshare,
				"description": description,
			}))
		},

		Err(err) => {
			let parsed_data = match request.parse_retrieve_data() {
				Ok(parsed_data) => parsed_data,
				Err(e) =>
					return e.express_verification_error(
						APICALL::NFTRETRIEVE,
						request.requester_address.to_string(),
						0,
						state.identity,
					),
			};

			err.express_verification_error(
				APICALL::NFTRETRIEVE,
				request.requester_address.to_string(),
				parsed_data.nft_id,
				state.identity,
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

pub async fn nft_remove_keyshare(
	State(state): State<StateConfig>,
	Json(request): Json<RemoveKeysharePacket>,
) -> impl IntoResponse {
	let nft_status = match get_onchain_nft_data(request.nft_id).await {
		Some(x) => true,
		_ => false,
	};

	if nft_status {
		info!("Error removing NFT key-share from TEE : nft is not in burnt state, nft-id.{}, requester : {}", request.nft_id, request.requester_address);
		return Json(RemoveKeyshareResponse {
			status: ReturnStatus::NOTBURNT,
			nft_id: request.nft_id,
			enclave_id: state.identity,
			description: "Error removing NFT key-share from TEE, NFT is not in burnt state."
				.to_string(),
		})
	}

	if !std::path::Path::new(&state.clone().seal_path).exists() {
		info!("Error removing NFT key-share from TEE : seal path does not exist, nft_id : {}, path : {}", request.nft_id, state.seal_path);
		return Json(RemoveKeyshareResponse {
			status: ReturnStatus::DATABASEFAILURE,
			nft_id: request.nft_id,
			enclave_id: state.identity,
			description: "Error removing NFT key-share from TEE, use another enclave please."
				.to_string(),
		})
	};

	let file_path = state.seal_path.clone() + "nft_" + &request.nft_id.to_string() + ".keyshare";

	let exist = std::path::Path::new(file_path.as_str()).exists();

	if !exist {
		info!(
			"Error removing NFT key-share from TEE : nft_id does not exist, nft_id = {}",
			request.nft_id
		);

		return Json(RemoveKeyshareResponse {
			status: ReturnStatus::DATABASEFAILURE,
			nft_id: request.nft_id,
			enclave_id: state.identity,
			description: "Error removing NFT key-share from TEE : nft_id does not exist"
				.to_string(),
		})
	}

	match std::fs::remove_file(file_path.clone()) {
		Ok(_) => {
			let file_path = state.seal_path.clone() + &request.nft_id.to_string() + ".log";
			std::fs::remove_file(file_path.clone()).expect("Error removing nft log-file.");

			info!("Keyshare is successfully removed from enclave. nft_id = {}", request.nft_id);

			return Json(RemoveKeyshareResponse {
				status: ReturnStatus::REMOVESUCCESS,
				nft_id: request.nft_id,
				enclave_id: state.identity,
				description: "Keyshare is successfully removed from enclave.".to_string(),
			})
		},

		Err(err) => {
			info!("Error removing NFT key-share from TEE : error in removing file on disk, nft_id : {}, path : {}, Error : {}", request.nft_id, file_path, err);
			return Json(RemoveKeyshareResponse {
					status: ReturnStatus::DATABASEFAILURE,
					nft_id: request.nft_id,
					enclave_id: state.identity,
					description:
						"Error removing NFT key-share from TEE, try again or contact cluster admin please."
							.to_string(),
				});
		},
	};
}
