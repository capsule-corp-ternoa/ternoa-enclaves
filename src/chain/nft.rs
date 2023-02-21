use crate::servers::http_server::StateConfig;

use axum::{extract::State, http::StatusCode, response::IntoResponse, Json};

use std::{
	fs::OpenOptions,
	io::{Read, Seek, Write},
};
use tracing::{error, info, warn};

use axum::extract::Path as PathExtract;

use crate::chain::{
	chain::{get_current_block_number, nft_keyshare_oracle},
	verify::*,
};
use serde::Serialize;
use serde_json::json;

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
	log: String,
}

// TODO: check the request for signed data and prevent flooding requests.
pub async fn nft_get_views(
	State(state): State<StateConfig>,
	PathExtract(nft_id): PathExtract<u32>,
) -> impl IntoResponse {
	let status = get_onchain_status(nft_id).await;

	if !status.is_secret {
		info!(
			"Error retrieving secret-nft shares access-log : nft_id.{} is not a secret-nft",
			nft_id
		);
		return (
			StatusCode::OK,
			Json(NFTViewResponse {
				enclave_id: state.identity,
				nft_id,
				log: "nft_id is not a secret-nft".to_string(),
			}),
		)
	}

	let file_path = state.seal_path + "nft_" + &nft_id.to_string() + ".log";

	if std::path::Path::new(&file_path.clone()).exists() {
		info!("Log path checked, path: {}", file_path);
	} else {
		info!(
			"Error retrieving NFT key-share access-log : log path doe not exist, nft_id : {}, path : {}",
			nft_id, file_path
		);

		return (
			StatusCode::OK,
			Json(NFTViewResponse {
				enclave_id: state.identity,
				nft_id,
				log: "nft_id does not exist on this enclave".to_string(),
			}),
		)
	};

	let mut log_file = match OpenOptions::new().read(true).open(file_path.clone()) {
		Ok(f) => f,
		Err(_) => {
			info!(
				"Error retrieving NFT key-share access-log : can not open the log file, nft_id : {}, path : {}",
				nft_id, file_path
			);

			return (
				StatusCode::OK,
				Json(NFTViewResponse {
					enclave_id: state.identity,
					nft_id,
					log: "can not retrieve the log of secret-nft views".to_string(),
				}),
			)
		},
	};

	let mut log_data = String::new();
	match log_file.read_to_string(&mut log_data) {
		Ok(_) => {
			info!("successfully retrieved log file for nft_id : {}", nft_id);
			return (
				StatusCode::OK,
				Json(NFTViewResponse { enclave_id: state.identity, nft_id, log: log_data }),
			)
		},

		Err(_) => {
			info!(
				"Error retrieving NFT key-share access-log : can not read the log file, nft_id : {}, path : {}",
				nft_id, file_path
			);

			return (
				StatusCode::OK,
				Json(NFTViewResponse {
					enclave_id: state.identity,
					nft_id,
					log: "can not retrieve the log of nft views".to_string(),
				}),
			)
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
	let verified_data = request.verify_store_request().await;

	match verified_data {
		Ok(data) => {
			let nft_status = get_onchain_status(data.nft_id).await;

			if !nft_status.is_secret {
				let status = ReturnStatus::IDISNOTASECRETNFT;
				let description = format!(
					"TEE Key-share {:?}: nft-id.{} is not a secret-nft",
					APICALL::NFTSTORE,
					data.nft_id
				);

				info!("{}, requester : {}", description, request.owner_address);

				return Json(json!({
					"status": status,
					"nft_id": data.nft_id,
					"enclave_id": state.identity,
					"description": description,
				}))
			}

			if !nft_status.is_syncing_secret {
				let status = ReturnStatus::NOTSYNCING;
				let description = format!(
					"TEE Key-share {:?}: nft-id.{} is not in syncing mode",
					APICALL::NFTSTORE,
					data.nft_id
				);

				info!("{}, requester : {}", description, request.owner_address);

				return Json(json!({
					"status": status,
					"nft_id": data.nft_id,
					"enclave_id": state.identity,
					"description": description,
				}))
			}

			if !std::path::Path::new(&state.clone().seal_path).exists() {
				let status = ReturnStatus::DATABASEFAILURE;
				let description = format!(
					"TEE Key-share {:?}: seal path doe not exist, nft_id : {} Seal-Path : {}",
					APICALL::NFTSTORE,
					data.nft_id,
					state.seal_path
				);

				info!("{}, requester : {}", description, request.owner_address);

				return Json(json!({
					"status": status,
					"nft_id": data.nft_id,
					"enclave_id": state.identity,
					"description": "Error storing NFT key-share to TEE, use another enclave please."
					.to_string(),
				}))
			};

			let file_path =
				state.seal_path.clone() + "nft_" + &data.nft_id.to_string() + ".keyshare";
			let exist = std::path::Path::new(file_path.as_str()).exists();

			if exist {
				let status = ReturnStatus::NFTIDEXISTS;
				let description = format!(
					"TEE Key-share {:?}: nft_id.{} already exists",
					APICALL::NFTSTORE,
					data.nft_id,
				);

				info!("{}, requester : {}", description, request.owner_address);

				return Json(json!({
					"status": status,
					"nft_id": data.nft_id,
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
						data.nft_id,
						file_path,
						err
					);

					info!("{}, requester : {}", description, request.owner_address);

					return Json(json!({
						"status": status,
						"nft_id": data.nft_id,
						"enclave_id": state.identity,
						"description": "Error storing NFT key-share to TEE, use another enclave please."
						.to_string(),
					}))
				},
			};

			match f.write_all(&data.data) {
				Ok(_) => info!(
					"Keyshare is stored to TEE, nft_id = {}  Owner = {}",
					data.nft_id, request.owner_address
				),

				Err(err) => {
					let status = ReturnStatus::DATABASEFAILURE;
					let description = format!(
						"TEE Key-share {:?}: error in writing data to file, nft_id : {} path : {}, error: {}",
						APICALL::NFTSTORE,
						data.nft_id,
						file_path,
						err
					);

					info!("{}, requester : {}", description, request.owner_address);

					return Json(json!({
						"status": status,
						"nft_id": data.nft_id,
						"enclave_id": state.identity,
						"description": "Error storing NFT key-share to TEE, use another enclave please."
						.to_string(),
					}))
				},
			};

			// Send extrinsic to Secret-NFT Pallet as Storage-Oracle
			match nft_keyshare_oracle(state.enclave_key.clone(), data.nft_id).await {
				Ok(txh) => {
					info!(
						"Proof of storage has been sent to blockchain nft-pallet, nft_id = {}  Owner = {}  tx-hash = {}",
						data.nft_id, request.owner_address, txh
					);

					// Log file for tracing the NFT key-share VIEW history in Marketplace.
					let file_path = state.seal_path + "nft_" + &data.nft_id.to_string() + ".log";
					std::fs::File::create(file_path.clone()).unwrap();

					return Json(json!({
						"status": ReturnStatus::STORESUCCESS,
						"nft_id": data.nft_id,
						"enclave_id": state.identity,
						"description": "Keyshare is successfully stored to TEE".to_string(),
					}))
				},

				Err(err) => {
					let err_str = err.to_string();
					let message = format!(
						"Error sending proof of storage to chain, nft_id : {}, Error : {}",
						data.nft_id, err_str
					);

					info!(message);

					warn!(
						"Removing the NFT key-share from TEE due to previous error, nft_id : {}",
						data.nft_id
					);
					std::fs::remove_file(file_path.clone()).expect("Can not remove Keyshare file");

					return Json(json!({
						"status": ReturnStatus::ORACLEFAILURE,
						"nft_id": data.nft_id,
						"enclave_id": state.identity,
						"description": message,
					}))
				},
			}
		},

		Err(err) => err.express_verification_error(
			APICALL::NFTSTORE,
			request.owner_address.to_string(),
			request.parse_store_data().unwrap().nft_id,
			state.identity,
		),
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
	let verified_req = request.verify_retrieve_request().await;

	match verified_req {
		Ok(data) => {
			let nft_status = get_onchain_status(data.nft_id).await;
			if !nft_status.is_secret {
				let status = ReturnStatus::IDISNOTASECRETNFT;
				let description = format!(
					"TEE Key-share {:?}: nft-id.{} is not a secret-nft",
					APICALL::NFTRETRIEVE,
					data.nft_id
				);

				info!("{}, requester : {}", description, request.owner_address);

				return Json(json!({
					"status": status,
					"nft_id": data.nft_id,
					"enclave_id": state.identity,
					"description": description,
				}))
			}

			let file_path =
				state.seal_path.clone() + "nft_" + &data.nft_id.to_string() + ".keyshare";

			if !std::path::Path::new(&file_path).is_file() {
				let status = ReturnStatus::KEYNOTEXIST;
				let description = format!(
					"TEE Key-share {:?}: file path does not exist, file_path : {}",
					APICALL::NFTRETRIEVE,
					file_path
				);

				info!("{}, requester : {}", description, request.owner_address);

				return Json(json!({
					"status": status,
					"nft_id": data.nft_id,
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
						data.nft_id,
						err
					);

					info!("{}, requester : {}", description, request.owner_address);

					return Json(json!({
						"status": status,
						"nft_id": data.nft_id,
						"enclave_id": state.identity,
						"description": description,
					}))
				},
			};

			let mut nft_keyshare = Vec::<u8>::new();

			match file.read_to_end(&mut nft_keyshare) {
				Ok(_) => {
					info!("Keyshare of {} retrieved by {}", data.nft_id, request.owner_address)
				},

				Err(err) => {
					let status = ReturnStatus::KEYNOTREADABLE;
					let description = format!(
						"TEE Key-share {:?}: can not read keyshare file, nft_id : {} Error : {}",
						APICALL::NFTRETRIEVE,
						data.nft_id,
						err
					);

					info!("{}, requester : {}", description, request.owner_address);

					return Json(json!({
						"status": status,
						"nft_id": data.nft_id,
						"enclave_id": state.identity,
						"description": description,
					}))
				},
			};

			// Put a VIEWING history log
			let file_path = state.seal_path + "nft_" + &data.nft_id.to_string() + ".log";
			let mut log_file = OpenOptions::new()
				.append(true)
				.open(file_path)
				.expect("Unable to open log file");

			log_file.seek(std::io::SeekFrom::End(0)).unwrap();

			let time: chrono::DateTime<chrono::offset::Utc> = std::time::SystemTime::now().into();
			let log_data = request.owner_address.to_string() +
				" Viewed the keyshare on " +
				time.format("%Y-%m-%d %H:%M:%S").to_string().as_str() +
				"\n";

			log_file.write(log_data.as_bytes()).expect("write to log failed");

			let serialized_keyshare = StoreKeyshareData {
				nft_id: data.nft_id,
				data: nft_keyshare,
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

			info!("{}, requester : {}", description, request.owner_address);

			return Json(json!({
				"status": status,
				"keyshare_data": serialized_keyshare,
				"enclave_id": state.identity,
				"description": description,
			}))
		},

		Err(err) => err.express_verification_error(
			APICALL::NFTRETRIEVE,
			request.owner_address.to_string(),
			request.parse_retrieve_data().unwrap().nft_id,
			state.identity,
		),
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
	let nft_status = get_onchain_status(request.nft_id).await;
	if !nft_status.is_burnt {
		info!("Error removing NFT key-share to TEE : nft is not in burnt state, nft-id.{}, requester : {}", request.nft_id, request.owner_address);
		return Json(RemoveKeyshareResponse {
			status: ReturnStatus::NOTBURNT,
			nft_id: request.nft_id,
			enclave_id: state.identity,
			description: "Error removing NFT key-share from TEE, NFT is not in burnt state."
				.to_string(),
		})
	}

	if !std::path::Path::new(&state.clone().seal_path).exists() {
		info!("Error removing NFT key-share to TEE : seal path does not exist, nft_id : {}, path : {}", request.nft_id, state.seal_path);
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
			return 
				Json(RemoveKeyshareResponse {
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
