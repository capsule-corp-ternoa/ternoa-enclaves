use crate::servers::http_server::StateConfig;

use axum::{extract::State, http::StatusCode, response::IntoResponse, Json};

use std::fs::OpenOptions;
use std::io::{Read, Seek, Write};

use tracing::{error, info, warn};

use axum::extract::Path as PathExtract;

use crate::chain::chain::{capsule_secret_share_oracle, get_current_block_number};
use crate::chain::verify::*;
use serde::Serialize;

/* **********************
   SECRET AVAILABLE API
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
	let file_path = state.seal_path + "capsule_" + &nft_id.to_string() + ".secret";

	if std::path::Path::new(&file_path.clone()).exists() {
		info!("Availability check : path checked, path: {}", file_path);
		return (
			StatusCode::OK,
			Json(CapsuleExistsResponse { enclave_id: state.identity, nft_id, exists: true }),
		);
	} else {
		info!(
			"Availability check : secret does not exist, Capsule nft_id : {}, path : {}",
			nft_id, file_path
		);

		return (
			StatusCode::OK,
			Json(CapsuleExistsResponse { enclave_id: state.identity, nft_id, exists: false }),
		);
	};
}

/* **********************
	 SECRET VIEW API
********************** */

#[derive(Serialize)]
pub struct CapsuleViewResponse {
	enclave_id: String,
	nft_id: u32,
	log: String,
}

// TODO: check the request for signed data and prevent flooding requests.
pub async fn capsule_get_views_handler(
	State(state): State<StateConfig>,
	PathExtract(nft_id): PathExtract<u32>,
) -> impl IntoResponse {
	let file_path = state.seal_path + "capsule_" + &nft_id.to_string() + ".log";

	if std::path::Path::new(&file_path.clone()).exists() {
		info!("Log path checked, path: {}", file_path);
	} else {
		error!(
			"Error retrieving Capsule secret-share access-log : log path does not exist, Capsule nft_id : {}, path : {}",
			nft_id, file_path
		);

		return (
			StatusCode::OK,
			Json(CapsuleViewResponse {
				enclave_id: state.identity,
				nft_id,
				log: "Capsule nft_id does not exist on this enclave".to_string(),
			}),
		);
	};

	let mut log_file = match OpenOptions::new().read(true).open(file_path.clone()) {
		Ok(f) => f,
		Err(_) => {
			error!(
				"Error retrieving Capsule secret-share access-log : can not open the log file, Capsule nft_id : {}, path : {}",
				nft_id, file_path
			);

			return (
				StatusCode::OK,
				Json(CapsuleViewResponse {
					enclave_id: state.identity,
					nft_id,
					log: "can not retrieve the log of capsule views".to_string(),
				}),
			);
		},
	};

	let mut log_data = String::new();
	match log_file.read_to_string(&mut log_data) {
		Ok(_) => {
			info!("successfully retrieved log file for nft_id : {}", nft_id);
			return (
				StatusCode::OK,
				Json(CapsuleViewResponse { enclave_id: state.identity, nft_id, log: log_data }),
			);
		},

		Err(_) => {
			error!(
				"Error retrieving Capsule secret-share access-log : can not read the log file, Capsule nft_id : {}, path : {}",
				nft_id, file_path
			);

			return (
				StatusCode::OK,
				Json(CapsuleViewResponse {
					enclave_id: state.identity,
					nft_id,
					log: "can not retrieve the log of capsule views".to_string(),
				}),
			);
		},
	};
}

/* **********************
	 STORE SECRET
********************** */
#[derive(Serialize)]
pub struct SecretSetResponse {
	status: ReturnStatus,
	nft_id: u32,
	enclave_id: String,
	description: String,
}

pub async fn capsule_set_secret_shares(
	State(state): State<StateConfig>,
	Json(received_secret): Json<SecretStorePacket>,
) -> impl IntoResponse {
	let verified_secret = received_secret.verify_request().await;

	match verified_secret {
		Ok(secret) => {
			let status = get_onchain_status(secret.nft_id).await;
			if !status.is_syncing_capsule {
				error!(
					"Error storing capsule secret-share to TEE : capsule is not syncing, Capsule nft_id : {}, path : {}",
					secret.nft_id, state.seal_path
				);

				return (
					StatusCode::OK,
					Json(SecretSetResponse {
						status: ReturnStatus::CAPSULENOTSYNCING,
						nft_id: secret.nft_id,
						enclave_id: state.identity,
						description:
							"Error storing capsule secret-share to TEE, Capsule is not in syncing mode."
								.to_string(),
					}),
				);
			}

			if std::path::Path::new(&state.clone().seal_path).exists() {
				info!("Seal path checked, path: {}", state.seal_path.clone());
			} else {
				error!("Error storing capsule secret-share to TEE : seal path does not exist, Capsule nft_id : {}, path : {}", secret.nft_id, state.seal_path);

				return (
					StatusCode::OK,
					Json(SecretSetResponse {
						status: ReturnStatus::DATABASEFAILURE,
						nft_id: secret.nft_id,
						enclave_id: state.identity,
						description:
							"Error storing capsule secret-share to TEE, use another enclave please."
								.to_string(),
					}),
				);
			};

			let file_path =
				state.seal_path.clone() + "capsule_" + &secret.nft_id.to_string() + ".secret";

			let mut f = match std::fs::File::create(file_path.clone()) {
				Ok(file) => file,
				Err(err) => {
					error!("Error storing capsule secret-share to TEE : error in creating file on disk, Capsule nft_id : {}, path : {}, Error : {}", secret.nft_id, file_path, err);

					return (
						StatusCode::OK,
						Json(SecretSetResponse {
							status: ReturnStatus::DATABASEFAILURE,
							nft_id: secret.nft_id,
							enclave_id: state.identity,
							description:
								"Error storing capsule secret-share to TEE, use another enclave please."
									.to_string(),
						}),
					);
				},
			};

			match f.write_all(&secret.data) {
				Ok(_) => info!(
					"Secret is successfully stored to TEE, nft_id = {}  Owner = {}",
					secret.nft_id, received_secret.owner_address
				),
				Err(err) => {
					error!("Error storing capsule secret-share to TEE : error in writing data to file, Capsule nft_id : {}, path: {}, Error : {}", secret.nft_id, file_path, err);

					return (
						StatusCode::OK,
						Json(SecretSetResponse {
							status: ReturnStatus::DATABASEFAILURE,
							nft_id: secret.nft_id,
							enclave_id: state.identity,
							description:
								"Error storing capsule secret-share to TEE, use another enclave please."
									.to_string(),
						}),
					);
				},
			};

			// Send extrinsic to Secret-Capsule Pallet as Storage-Oracle
			match capsule_secret_share_oracle(state.enclave_key.clone(), secret.nft_id).await {
				Ok(txh) => {
					info!(
						"Proof of storage has been sent to secret-capsule-pallet, nft_id = {}  Owner = {}  tx-hash = {}",
						secret.nft_id, received_secret.owner_address, txh
					);

					// Log file for tracing the capsule secret-share VIEW history in Marketplace.
					let file_path =
						state.seal_path + "capsule_" + &secret.nft_id.to_string() + ".log";
					std::fs::File::create(file_path.clone()).unwrap();

					return (
						StatusCode::OK,
						Json(SecretSetResponse {
							status: ReturnStatus::STORESUCCESS,
							nft_id: secret.nft_id,
							enclave_id: state.identity,
							description: "Secret is successfully stored to TEE".to_string(),
						}),
					);
				},

				Err(err) => {
					error!(
						"Error sending proof of storage to chain, Capsule nft_id : {}, Error : {}",
						secret.nft_id, err
					);

					std::fs::remove_file(file_path.clone()).expect("Can not remove secret file");

					return (
						StatusCode::OK,
						Json(SecretSetResponse {
							status: ReturnStatus::ORACLEFAILURE,
							nft_id: secret.nft_id,
							enclave_id: state.identity,
							description: "Error sending proof of storage to chain.".to_string(),
						}),
					);
				},
			}
		},

		Err(err) => {
			match err {
				VerificationError::INVALIDSIGNERSIG(e) => {
					warn!("Error setting Capsule secret-share to TEE : Invalid Request Signature, {:?}", e);

					return (
					StatusCode::OK,
					Json(SecretSetResponse {
						status: ReturnStatus::INVALIDSIGNERSIGNATURE,
						nft_id: received_secret.parse_secret().nft_id,
						enclave_id: state.identity,
						description: "Error setting Capsule secret-share to TEE : Invalid Request Signature"
							.to_string(),
					}),
				);
				},

				VerificationError::INVALIDOWNER => {
					warn!("Error setting Capsule secret-share to TEE : Invalid Capsule Owner");

					return (
						StatusCode::OK,
						Json(SecretSetResponse {
							status: ReturnStatus::INVALIDOWNER,
							nft_id: received_secret.parse_secret().nft_id,
							enclave_id: state.identity,
							description:
								"Error setting Capsule secret-share to TEE : Invalid Capsule Owner"
									.to_string(),
						}),
					);
				},

				VerificationError::INVALIDOWNERSIG(e) => {
					warn!("Error setting Capsule secret-share to TEE : Request signature is invalid. {:?}", e);

					return (
					StatusCode::OK,
					Json(SecretSetResponse {
						status: ReturnStatus::EXPIREDSIGNER,
						nft_id: received_secret.parse_secret().nft_id,
						enclave_id: state.identity,
						description: "Error setting Capsule secret-share to TEE : Request signature is invalid."
							.to_string(),
					}),
				);
				},

				VerificationError::SIGNERVERIFICATIONFAILED => {
					warn!("Error setting Capsule secret-share to TEE : Signer signature verification failed.");

					return (
					StatusCode::OK,
					Json(SecretSetResponse {
						status: ReturnStatus::INVALIDSIGNERSIGNATURE,
						nft_id: received_secret.parse_secret().nft_id,
						enclave_id: state.identity,
						description: "Error setting Capsule secret-share to TEE : Signer signature verification failed."
							.to_string(),
					}),
				);
				},

				VerificationError::OWNERVERIFICATIONFAILED => {
					warn!("Error setting Capsule secret-share to TEE : Capsule ownership-validation failed.");

					return (
					StatusCode::OK,
					Json(SecretSetResponse {
						status: ReturnStatus::EXPIREDSIGNER,
						nft_id: received_secret.parse_secret().nft_id,
						enclave_id: state.identity,
						description: "Error setting Capsule secret-share to TEE : Capsule ownership-validation failed."
							.to_string(),
					}),
				);
				},

				VerificationError::INVALIDSIGNERACCOUNT => {
					warn!("Error setting Capsule secret-share to TEE : Signer account is invalid.");

					return (
					StatusCode::OK,
					Json(SecretSetResponse {
						status: ReturnStatus::INVALIDSIGNERSIGNATURE,
						nft_id: received_secret.parse_secret().nft_id,
						enclave_id: state.identity,
						description: "Error setting Capsule secret-share to TEE : Signer account is invalid."
							.to_string(),
					}),
				);
				},

				VerificationError::EXPIREDSIGNER => {
					warn!("Error setting Capsule secret-share to TEE : Signer account is expired.");

					return (
					StatusCode::OK,
					Json(SecretSetResponse {
						status: ReturnStatus::EXPIREDSIGNER,
						nft_id: received_secret.parse_secret().nft_id,
						enclave_id: state.identity,
						description: "Error setting Capsule secret-share to TEE : Signer account is expired."
							.to_string(),
					}),
				);
				},

				VerificationError::EXPIREDSECRET => {
					warn!("Error setting Capsule secret-share to TEE : Secret-Data is expired.");

					return (
					StatusCode::OK,
					Json(SecretSetResponse {
						status: ReturnStatus::EXPIREDREQUEST,
						nft_id: received_secret.parse_secret().nft_id,
						enclave_id: state.identity,
						description: "Error setting Capsule secret-share to TEE : Secret-Data is expired."
							.to_string(),
					}),
				);
				},

				VerificationError::IDISNOTASECRET => {
					warn!("Error setting Capsule secret-share to TEE : nft_id is not a capsule.");

					return (
					StatusCode::OK,
					Json(SecretSetResponse {
						status: ReturnStatus::IDISNOTACAPSULE,
						nft_id: received_secret.parse_secret().nft_id,
						enclave_id: state.identity,
						description: "Error setting Capsule secret-share to TEE : nft_id is not a capsule."
							.to_string(),
					}),
				);
				},
			}
		},
	}
}

/* **********************
	 RETRIEVE SECRET
********************** */

#[derive(Serialize)]
pub struct SecretRetrieveResponse {
	status: ReturnStatus,
	enclave_id: String,
	secret_data: String,
	//signature: String,
	description: String,
}

pub async fn capsule_retrieve_secret_shares(
	State(state): State<StateConfig>,
	Json(requested_secret): Json<SecretStorePacket>,
) -> impl IntoResponse {
	let verified_req = requested_secret.verify_request().await;

	match verified_req {
		Ok(data) => {
			let file_path =
				state.seal_path.clone() + "capsule_" + &data.nft_id.to_string() + ".secret";
			if !std::path::Path::new(&file_path).is_file() {
				warn!(
					"Error retrieving capsule secret-share from TEE : file path does not exist, file_path : {}",
					file_path
				);
				return (
					StatusCode::OK,
					Json(SecretRetrieveResponse {
						status: ReturnStatus::CAPSULEIDNOTEXIST,
						enclave_id: state.identity,
						description: "Error retrieving capsule secret-share from TEE : Capsule nft_id does not exist"
							.to_string(),
						secret_data: format!("{{nft_id:{}}}", data.nft_id),
					}),
				);
			}

			let mut file = match std::fs::File::open(file_path) {
				Ok(file) => file,
				Err(err) => {
					error!("Error retrieving capsule secret-share from TEE : can not open secret file, Capsule nft_id : {} Error : {}", data.nft_id, err);

					return (
						StatusCode::OK,
						Json(SecretRetrieveResponse {
							status: ReturnStatus::CAPSULESECRETNOTACCESSIBLE,
							enclave_id: state.identity,
							description:
								"Error retrieving capsule secret-share from TEE : Capsule nft_id does not exist"
									.to_string(),
							secret_data: format!("{{nft_id:{}}}", data.nft_id),
						}),
					);
				},
			};

			let mut capsule_secret_share = Vec::<u8>::new();

			match file.read_to_end(&mut capsule_secret_share) {
				Ok(_) => info!(
					"Secret shares of {} retrieved by {}",
					data.nft_id, requested_secret.owner_address
				),

				Err(err) => {
					error!("Error retrieving capsule secret-share from TEE : can not read secret file, Capsule nft_id : {} Error : {}", data.nft_id, err);

					return (
						StatusCode::OK,
						Json(SecretRetrieveResponse {
							status: ReturnStatus::CAPSULESECRETNOTREADABLE,
							enclave_id: state.identity,
							description:
								"Error retrieving capsule secret-share from TEE : can not read secret data"
									.to_string(),
							secret_data: format!("{{nft_id:{}}}", data.nft_id),
						}),
					);
				},
			};

			// Put a VIEWING history log
			let file_path = state.seal_path + "capsule_" + &data.nft_id.to_string() + ".log";
			let mut log_file = OpenOptions::new()
				.append(true)
				.open(file_path)
				.expect("Unable to open log file");

			log_file.seek(std::io::SeekFrom::End(0)).unwrap();

			let time: chrono::DateTime<chrono::offset::Utc> = std::time::SystemTime::now().into();
			let log_data = requested_secret.owner_address.to_string()
				+ " Viewed the secret on "
				+ time.format("%Y-%m-%d %H:%M:%S").to_string().as_str()
				+ "\n";

			log_file.write(log_data.as_bytes()).expect("write to log failed");

			let serialized_secret = SecretStoreData {
				nft_id: data.nft_id,
				data: capsule_secret_share,
				auth_token: AuthenticationToken {
					block_number: get_current_block_number().await,
					block_validation: 100,
				},
			}
			.serialize();

			//			let sig = state.enclave_key.sign(serialized_secret.as_bytes());
			//			let sig_str = "0x".to_owned() + &serde_json::to_string(&sig).unwrap();

			return (
				StatusCode::OK,
				Json(SecretRetrieveResponse {
					status: ReturnStatus::RETRIEVESUCCESS,
					enclave_id: state.identity,
					description: "Success retrieving Capsule secret-share.".to_string(),
					secret_data: serialized_secret,
					//	signature: sig_str,
				}),
			);
		},

		Err(err) => match err {
			VerificationError::INVALIDOWNERSIG(e) => {
				info!(
					"Error retrieving capsule secret-share from TEE : Invalid Signature, {:?},owner : {}",
					e, requested_secret.owner_address
				);

				return (
					StatusCode::OK,
					Json(SecretRetrieveResponse {
						status: ReturnStatus::INVALIDOWNERSIGNATURE,
						enclave_id: state.identity,
						description: "Error Invalid Signature or Capsule owner".to_string(),
						secret_data: format!("{{nft_id:{}}}", requested_secret.parse_secret().nft_id),
					}),
				);
			},

			VerificationError::INVALIDOWNER => {
				info!(
					"Error retrieving capsule secret-share from TEE : Invalid Owner, owner : {}",
					requested_secret.owner_address
				);
				return (
					StatusCode::OK,
					Json(SecretRetrieveResponse {
						status: ReturnStatus::INVALIDOWNER,
						enclave_id: state.identity,
						description: "Error Invalid Capsule owner".to_string(),
						secret_data: format!("{{nft_id:{}}}", requested_secret.parse_secret().nft_id),
					}),
				);
			},
			VerificationError::INVALIDSIGNERSIG(_) => {
				info!(
					"Error retrieving capsule secret-share from TEE : Invalid Owner, owner : {}",
					requested_secret.owner_address
				);
				return (
					StatusCode::OK,
					Json(SecretRetrieveResponse {
						status: ReturnStatus::INVALIDOWNER,
						enclave_id: state.identity,
						description: "Error Invalid Capsule owner".to_string(),
						secret_data: format!("{{nft_id:{}}}", requested_secret.parse_secret().nft_id),
					}),
				);
			},
			VerificationError::SIGNERVERIFICATIONFAILED => {
				info!(
					"Error retrieving capsule secret-share from TEE : Invalid Owner, owner : {}",
					requested_secret.owner_address
				);
				return (
					StatusCode::OK,
					Json(SecretRetrieveResponse {
						status: ReturnStatus::INVALIDOWNER,
						enclave_id: state.identity,
						description: "Error Invalid Capsule owner".to_string(),
						secret_data: format!("{{nft_id:{}}}", requested_secret.parse_secret().nft_id),
					}),
				);
			},
			VerificationError::OWNERVERIFICATIONFAILED => {
				info!(
					"Error retrieving capsule secret-share from TEE : Invalid Owner, owner : {}",
					requested_secret.owner_address
				);
				return (
					StatusCode::OK,
					Json(SecretRetrieveResponse {
						status: ReturnStatus::INVALIDOWNER,
						enclave_id: state.identity,
						description: "Error Invalid Capsule owner".to_string(),
						secret_data: format!("{{nft_id:{}}}", requested_secret.parse_secret().nft_id),
					}),
				);
			},
			VerificationError::INVALIDSIGNERACCOUNT => {
				info!(
					"Error retrieving capsule secret-share from TEE : Invalid Owner, owner : {}",
					requested_secret.owner_address
				);
				return (
					StatusCode::OK,
					Json(SecretRetrieveResponse {
						status: ReturnStatus::INVALIDOWNER,
						enclave_id: state.identity,
						description: "Error Invalid Capsule owner".to_string(),
						secret_data: format!("{{nft_id:{}}}", requested_secret.parse_secret().nft_id),
					}),
				);
			},
			VerificationError::EXPIREDSIGNER => {
				info!(
					"Error retrieving capsule secret-share from TEE : Invalid Owner, owner : {}",
					requested_secret.owner_address
				);
				return (
					StatusCode::OK,
					Json(SecretRetrieveResponse {
						status: ReturnStatus::INVALIDOWNER,
						enclave_id: state.identity,
						description: "Error Invalid Capsule owner".to_string(),
						secret_data: format!("{{nft_id:{}}}", requested_secret.parse_secret().nft_id),
					}),
				);
			},
			VerificationError::EXPIREDSECRET => {
				info!(
					"Error retrieving capsule secret-share from TEE : Invalid Owner, owner : {}",
					requested_secret.owner_address
				);
				return (
					StatusCode::OK,
					Json(SecretRetrieveResponse {
						status: ReturnStatus::INVALIDOWNER,
						enclave_id: state.identity,
						description: "Error Invalid Capsule owner".to_string(),
						secret_data: format!("{{nft_id:{}}}", requested_secret.parse_secret().nft_id),
					}),
				);
			},

			VerificationError::IDISNOTASECRET => {
				info!(
					"Error retrieving capsule secret-share from TEE : Provided nft_id is not a Capsule : {}",
					requested_secret.owner_address
				);
				return (
					StatusCode::OK,
					Json(SecretRetrieveResponse {
						status: ReturnStatus::IDISNOTACAPSULE,
						enclave_id: state.identity,
						description: "Error: Capsule nft_id is not a Capsule".to_string(),
						secret_data: format!("{{nft_id:{}}}", requested_secret.parse_secret().nft_id),
					}),
				);
			},
		},
	}
}

/* **********************
	 REMOVE SECRET
********************** */
#[derive(Serialize)]
pub struct SecretRemoveResponse {
	status: ReturnStatus,
	nft_id: u32,
	enclave_id: String,
	description: String,
}

pub async fn capsule_remove_secret_shares(
	State(state): State<StateConfig>,
	Json(remove_secret): Json<SecretStorePacket>,
) -> impl IntoResponse {
	let verified_req = remove_secret.verify_remove_request().await;
	match verified_req {
		Ok(secret) => {
			// Check if NFT/CAPSULE is burnt
			let status = get_onchain_status(secret.nft_id).await;
			if status.is_burnt {
				if std::path::Path::new(&state.clone().seal_path).exists() {
					info!("Seal path checked, path: {}", state.seal_path.clone());
				} else {
					error!("Error removing capsule secret-share from TEE : seal path does not exist, Capsule nft_id : {}, path : {}", secret.nft_id, state.seal_path);

					return (
						StatusCode::OK,
						Json(SecretRemoveResponse {
							status: ReturnStatus::DATABASEFAILURE,
							nft_id: secret.nft_id,
							enclave_id: state.identity,
							description:
								"Error removing capsule secret-share from TEE, use another enclave please."
									.to_string(),
						}),
					);
				};

				let file_path =
					state.seal_path.clone() + "capsule_" + &secret.nft_id.to_string() + ".secret";
				let exist = std::path::Path::new(file_path.as_str()).exists();

				if !exist {
					warn!(
						"Error removing capsule secret-share from TEE : Capsule nft_id does not exist, nft_id = {}",
						secret.nft_id
					);

					return (
						StatusCode::OK,
						Json(SecretRemoveResponse {
							status: ReturnStatus::DATABASEFAILURE,
							nft_id: secret.nft_id,
							enclave_id: state.identity,
							description: "Error removing capsule secret-share from TEE : Capsule nft_id does not exist"
								.to_string(),
						}),
					);
				}

				match std::fs::remove_file(file_path) {
					Ok(_) => {
						let file_path = state.seal_path.clone()
							+ "capsule_" + &secret.nft_id.to_string()
							+ ".log";
						std::fs::remove_file(file_path.clone())
							.expect("Error removing capsule log-file.");

						info!("Successfully removed capsule secret-share from TEE, Capsule nft_id : {}", secret.nft_id);
						return (
							StatusCode::OK,
							Json(SecretRemoveResponse {
								status: ReturnStatus::REMOVESUCCESS,
								nft_id: secret.nft_id,
								enclave_id: state.identity,
								description: "Secret ia successfully removed from enclave."
									.to_string(),
							}),
						);
					},

					Err(err) => {
						error!("Error removing capsule secret-share from TEE : error in removing file on disk, Capsule nft_id : {}, Error : {}", secret.nft_id, err);

						return (
							StatusCode::OK,
							Json(SecretRemoveResponse {
								status: ReturnStatus::DATABASEFAILURE,
								nft_id: secret.nft_id,
								enclave_id: state.identity,
								description:
									"Error removing capsule secret-share from TEE, try again or contact cluster admin please."
										.to_string(),
							}),
						);
					},
				};
			} else {
				return (
					StatusCode::OK,
					Json(SecretRemoveResponse {
						status: ReturnStatus::CAPSULENOTBURNT,
						nft_id: secret.nft_id,
						enclave_id: state.identity,
						description:
							"Error removing capsule secret-share from TEE, Capsule is not in burnt state."
								.to_string(),
					}),
				);
			}
		},

		Err(_) => todo!(),
	}
}
