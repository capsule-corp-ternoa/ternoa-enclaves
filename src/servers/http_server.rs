#![allow(dead_code)]
#![allow(unused_imports)]
#![allow(unused_variables)]

use std::{
	fs::File,
	io::Write,
	path::PathBuf,
	sync::Arc,
	time::{Duration, SystemTime},
};

use futures::StreamExt;
use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;

use axum::{
	error_handling::HandleErrorLayer,
	extract::{DefaultBodyLimit, State},
	http::{Method, StatusCode, Uri},
	response::IntoResponse,
	routing::{get, post},
	BoxError, Json, Router,
};

use reqwest;

use sp_core::Pair;

use tower::ServiceBuilder;
use tower_http::cors::{Any, CorsLayer};
use tower_http::limit::RequestBodyLimitLayer;

use anyhow::{anyhow, Error};
use serde_json::{json, Value};
use tracing::{debug, error, info, trace, warn};

use std::time::{Duration, SystemTime};

use crate::{
	backup::admin_bulk::{admin_backup_fetch_bulk, admin_backup_push_bulk},
	backup::admin_nftid::admin_backup_fetch_id,
};

use sentry::integrations::tower::{NewSentryLayer, SentryHttpLayer};

use super::server_common;

pub const CONTENT_LENGTH_LIMIT: usize = 400 * 1024 * 1024;
pub const ENCLAVE_ACCOUNT_FILE: &str = "/nft/enclave_account.key";

/// http server
/// # Arguments
/// # Example
/// ```
/// http_server();
/// ```
pub async fn http_server() -> Result<Router, Error> {
	// TODO [future deployment] : publish the key to release folder of sgx_server repository after being open-sourced.
	

	let enclave_keypair = if std::path::Path::new(enclave_account_file).exists() {
		info!("Enclave Account Exists, Importing it! :, path: {}", enclave_account_file);

			let phrase = match std::fs::read_to_string(ENCLAVE_ACCOUNT_FILE) {
				Ok(phrase) => phrase,
				Err(err) => {
					error!("\t\nENCLAVE START : ERROR reading enclave account file: {:?}", err);
					return Err(anyhow!(err));
				},
			};

			match sp_core::sr25519::Pair::from_phrase(&phrase, None) {
				Ok((keypair, _seed)) => keypair,
				Err(err) => {
					error!("\t\nENCLAVE START : ERROR creating keypair from phrase: {:?}", err);
					return Err(anyhow!(err));
				},
			}
		} else {
			info!("\nENCLAVE START : Creating new Enclave Account, Remember to send 1 CAPS to it!");

			let (keypair, phrase, _s_seed) = sp_core::sr25519::Pair::generate_with_phrase(None);
			let mut ekfile =
				match File::create(ENCLAVE_ACCOUNT_FILE) {
					Ok(file_handle) => {
						debug!("\t\nENCLAVE START : created enclave keypair file successfully");
						file_handle
					},
					Err(err) => {
						error!("\t\nENCLAVE START : Failed to creat enclave keypair file, error : {:?}", err);
						return Err(anyhow!(err));
					},
				};

			match ekfile.write_all(phrase.as_bytes()) {
				Ok(_) => {
					debug!("\t\nENCLAVE START : Write enclave keypair to file successfully");
				},
				Err(err) => {
					error!(
						"\t\nENCLAVE START : Write enclave keypair to file failed, error : {:?}",
						err
					);
					return Err(anyhow!(err));
				},
			}

			keypair
		};



	// ************************************************************************
	let encalve_account_file = "/nft/enclave_account.key";

	debug!("2-1 Generate/Import Encalve Keypair");

	let enclave_keypair = if std::path::Path::new(&(*encalve_account_file)).exists() {
		info!("Enclave Account Exists, Importing it! :, path: {}", encalve_account_file);

		let mut ekfile = File::open(&(*encalve_account_file)).unwrap();
		let mut phrase = String::new();

		match ekfile.read_to_string(&mut phrase) {
			Ok(_) => {
				debug!("2-1-1 read sealed encalve key file successfully");
			},
			Err(e) => {
				debug!("2-1-1 failed to read sealed encalve key file, error : {:?}", e);
				return
			},
		}

		let (keypair, _seed) = match sp_core::sr25519::Pair::from_phrase(&phrase, None) {
			Ok(pair_seed_tuple) => {
				debug!("2-1-2 get pair from phrase successfully");
				pair_seed_tuple
			},
			Err(e) => {
				debug!("2-1-2 failed get pair from phrase, error : {:?}", e);
				return
			},
		};

		keypair
	} else {
		info!("Enclave Start : Creating new Enclave Account, Remember to send 1 CAPS to it!");

		let (keypair, phrase, _s_seed) = sp_core::sr25519::Pair::generate_with_phrase(None);
		let mut ekfile = match File::create(&encalve_account_file) {
			Ok(file_handle) => {
				debug!("\tEnclave Start : created enclave keypair file successfully");
				file_handle
			},
			Err(err) => {
				error!("\tEnclave Start : Failed to creat enclave keypair file, error : {:?}", err);
				return Err(anyhow!(err));
			},
		};

		match ekfile.write_all(phrase.as_bytes()) {
			Ok(_) => {
				debug!("\tEnclave Start : Write enclave keypair to file successfully");
			},
			Err(err) => {
				error!("\tEnclave Start : Write enclave keypair to file failed, error : {:?}", err);
				return Err(anyhow!(err));
			},
		}

		keypair
	};

	let chain_api = match create_chain_api().await {
		Ok(api) => api,
		Err(err) => {
			error!("\nENCLAVE START : get online chain api, error : {:?}", err);
			return Err(anyhow!(err));
		},
	};

	// Initialize runtime tracking blocks
	let current_block_hash = chain_api.rpc().finalized_head().await?;
	let current_block = chain_api.rpc().block(Some(current_block_hash)).await?.unwrap();
	let current_block_number = current_block.block.header.number;
	let last_processed_block = current_block_number;

	// Shared-State between APIs
	let state_config: SharedState = Arc::new(RwLock::new(StateConfig::new(
		enclave_keypair,
		String::new(),
		chain_api.clone(),
		"0.4.1".to_string(),
		last_processed_block,
	)));

	set_blocknumber(&state_config, current_block_number).await;
	set_processed_block(&state_config, last_processed_block).await;

	// Get all cluster and registered enclaves from the chain
	// Also checks if this enclave has been registered.
	info!("\nENCLAVE START : Initialization Cluster Discovery.");
	while let Err(e) = cluster_discovery(&state_config.clone()).await {
		error!("\nENCLAVE START : cluster discovery error : {:?}", e);
		debug!("\nENCLAVE START : Retry Cluster Discovery after a delay...");
		// Wait 7 seconds, then retry
		std::thread::sleep(std::time::Duration::from_secs(7));
	}

	info!("\nENCLAVE START : Cluster Discovery successfull.");

	// Check the previous Sync-State
	info!("\nENCLAVE START : check for sync.state file from previous run ...");
	if std::path::Path::new(&SYNC_STATE_FILE).exists() {
		debug!("\nENCLAVE START : previous sync.state file exists");
		// Resuming enclave
		let past_state = match std::fs::read_to_string(SYNC_STATE_FILE) {
			Ok(state) => state,
			Err(err) => {
				error!("\nENCLAVE START : Error reading enclave's last state file: {:?}", err);
				return Err(anyhow!(err));
			},
		};

		debug!("\nENCLAVE START : previous sync.state file content : '{}'", past_state);

		if !past_state.is_empty() {
			debug!("\nENCLAVE START : previous sync.state is not empty ...");
			if past_state == "setup" {
				debug!("\nENCLAVE START : SETUP-MODE : fetching keyshares ...");
				// Th enclave has been stopped at the middle of fetching data from another enclave
				// Do it again!
				match fetch_keyshares(&state_config, std::collections::HashMap::<u32, u32>::new())
					.await
				{
					Ok(_) => {
						// let current_block_hash = chain_api.rpc().finalized_head().await?;
						// let current_block =
						// 	chain_api.rpc().block(Some(current_block_hash)).await?.unwrap();
						// let current_block_number = current_block.block.header.number;
						// TODO [Disaster recovery] : What if all clusters are down, What block_number should be set as last_sync_block
						let _ = set_sync_state(current_block_number.to_string());
						info!(
							"\nENCLAVE START : SETUP-MODE : First Synchronization of Keyshares complete up to block number : {}.",
							current_block_number
						);
					},
					Err(err) => {
						// TODO : for the primary cluster it should work fine.
						error!("\nENCLAVE START : SETUP-MODE : Error during setup-mode fetch-keyshares : {:?}", err)
					},
				}
			} else {
				// Th enclave has been stopped after being synced to a recent block number
				// Now should crawl the blocks to the current finalized block.
				debug!("\nENCLAVE START : RUNTIME-MODE : previous sync.state was in runtime-mode.");

				let synced_block_number = match past_state.parse::<u32>() {
					Ok(number) => number,
					Err(err) => {
						error!(
							"\nENCLAVE START : Error parsing enclave's last state content: {:?}, state = {:?}",
							err, past_state
						);
						return Err(anyhow!(err));
					},
				};
				debug!(
					"\nENCLAVE START : RUNTIME-MODE : previous sync.state had been synced to block {}",
					synced_block_number
				);

				// Retry if syncing failed
				let mut sync_success = false;

				while !sync_success {
					let current_block_hash = chain_api.rpc().finalized_head().await?;
					let current_block = chain_api.rpc().block(Some(current_block_hash)).await?;
					let current_block_number = current_block.unwrap().block.header.number;

					debug!("\nENCLAVE START : CRAWL : Crawl to current block {}", current_block_number);
					// Changes may happen in clusters and enclaves while this enclave has been down.
					// TODO [future] : use Indexer if the difference between current_block >> past_block is large
					match crawl_sync_events(
						&state_config,
						synced_block_number,
						current_block_number,
					)
					.await
					{
						Ok(cluster_nftid_map) => {
							match fetch_keyshares(&state_config.clone(), cluster_nftid_map).await {
								Ok(_) => {
									let _ = set_sync_state(current_block_number.to_string());
									info!("\nENCLAVE START : CRAWL : Synchronization is complete up to current block");
									sync_success = true;
								},

								Err(fetch_err) => {
									error!("\nENCLAVE START : CRAWL : Error fetching new nftids after resuming the enclave : {:?}", fetch_err);
								},
							}; // FETCH
						},

						Err(crawl_err) => {
							error!(
								"\nENCLAVE START : Error crawling new blocks after resuming the enclave : {:?}",
								crawl_err
							);
							//return Err(anyhow!(crawl_err));
						},
					} // CRAWL

					// Wait 7 seconds, then retry
					debug!("ENCLAVE START : CRAWL : wait 7 seconds before retry");
					std::thread::sleep(std::time::Duration::from_secs(7));
				} // WHILE - RETRY
			} // PAST STATE IS A NUMBER
		}
		// PAST STATE EXISTS
		else {
			warn!("\nENCLAVE START : sync.state file exists, but it is empty : enclave is not registered yet.");
		}
	} else {
		// It is first time starting enclave
		debug!("\nENCLAVE START : sync.state file does not exist.");
		let _ = match File::create(SYNC_STATE_FILE) {
			Ok(file_handle) => {
				info!("\nENCLAVE START : created sync.state file successfully");
				file_handle
			},
			Err(err) => {
				error!("\nENCLAVE START : failed to creat sync.state file, error : {:?}", err);
				return Err(anyhow!(err));
			},
		};
	};

	info!("\nENCLAVE START : define the CORS layer.");
	let _ = CorsLayer::new()
		// allow `GET` and `POST` when accessing the resource
		.allow_methods([Method::GET, Method::POST])
		// allow requests from any origin
		.allow_origin(Any)
		.allow_headers(Any)
		.allow_credentials(true);

	info!("\nENCLAVE START : define the monitor layer : Sentry.");
	let monitor_layer = ServiceBuilder::new()
		.layer(NewSentryLayer::new_from_top())
		.layer(SentryHttpLayer::with_transaction());

	info!("\nENCLAVE START : define the end-points");
	let http_app = Router::new()
		.fallback(fallback)
		// STATE API
		.route("/api/health", get(get_health_status))
		.route("/api/quote", get(ra_get_quote))
		// CENTRALIZED BACKUP API
		.route("/api/backup/fetch-id", post(admin_backup_fetch_id))
		.route("/api/backup/fetch-bulk", post(admin_backup_fetch_bulk))
		.route("/api/backup/push-bulk", post(admin_backup_push_bulk))
		.layer(DefaultBodyLimit::max(CONTENT_LENGTH_LIMIT))
		// NFT SECRET-SHARING API
		.route("/api/secret-nft/get-views-log/:nft_id", get(nft_get_views))
		.route("/api/secret-nft/is-keyshare-available/:nft_id", get(is_nft_available))
		.route("/api/secret-nft/store-keyshare", post(nft_store_keyshare))
		.route("/api/secret-nft/retrieve-keyshare", post(nft_retrieve_keyshare))
		.route("/api/secret-nft/remove-keyshare", post(nft_remove_keyshare))
		// CAPSULE SECRET-SHARING API
		.route("/api/capsule-nft/get-views-log/:nft_id", get(capsule_get_views))
		.route("/api/capsule-nft/is-keyshare-available/:nft_id", get(is_capsule_available))
		.route("/api/capsule-nft/set-keyshare", post(capsule_set_keyshare))
		.route("/api/capsule-nft/retrieve-keyshare", post(capsule_retrieve_keyshare))
		.route("/api/capsule-nft/remove-keyshare", post(capsule_remove_keyshare))
		// SYNCHRONIZATION
		.route("/api/backup/sync-keyshare", post(sync_keyshares))
		// DEV
		.route("/api/set-block/:blocknumber", get(dev_set_block))
		// METRIC SERVER
		// List of all nfts in an Interval [block1,block2] (Migration needed!)
		//.layer(RequestBodyLimitLayer::new(CONTENT_LENGTH_LIMIT))
		.layer(
			ServiceBuilder::new()
				.layer(HandleErrorLayer::new(handle_timeout_error))
				.timeout(Duration::from_secs(30)),
		)
		.layer(monitor_layer)
		.layer(CorsLayer::permissive())
		.with_state(Arc::clone(&state_config.clone()));

	info!("\nENCLAVE START : New Thread for run-time block subscription.");
	// New thread to track latest block
	tokio::spawn(async move {
		// Subscribe to all finalized blocks:
		let mut blocks_sub = match chain_api.blocks().subscribe_finalized().await {
			Ok(sub) => sub,
			Err(e) => {
				error!(" > Unable to subscribe to finalized blocks {:?}", e);
				return;
			},
		};

		// For each new finalized block, get block number
		while let Some(block) = blocks_sub.next().await {
			let block = match block {
				Ok(blk) => blk,
				Err(e) => {
					error!(" > Unable to get finalized block {:?}", e);
					continue;
				},
			};

			let block_number = block.header().number;

			// Write to ShareState block, necessary to prevent Read SharedState
			set_blocknumber(&state_config, block_number).await;
			debug!("New Block : {}", block_number);
			trace!(" > Block Number Thread : block_number state is set to {}", block_number);

			// For block number update, we should reset the nonce as well
			// It is used as a batch of extrinsics for every block
			trace!(
				" > Block Number Thread : nonce before reset is {}",
				get_nonce(&state_config).await
			);
			reset_nonce(&state_config).await;
			trace!(
				" > Block Number Thread : nonce has been reset to {}",
				get_nonce(&state_config).await
			);

			// Extract block body
			let body = block.body().await.unwrap();
			trace!(" > Block Number Thread : got block body.");

			let storage_api = block.storage();

			let (new_nft, is_tee_events) = parse_block_body(body, &storage_api).await.unwrap();
			trace!(" > Block Number Thread : parsed the block body.");

			// A change in clusters/enclaves data is detected.
			if is_tee_events {
				debug!(" > TEE Event processing");
				match cluster_discovery(&state_config.clone()).await {
					Ok(_) => {
						info!("\t > Cluster discovery complete.");
						// New self-identity is found?
						let sync_state = get_sync_state().unwrap();
						if sync_state == "setup" {
							// Here is Identity discovery, thus the first synchronization of all files.
							// An empty HashMap is the wildcard signal to fetch all keyshares from nearby enclave
							match fetch_keyshares(
								&state_config.clone(),
								std::collections::HashMap::<u32, u32>::new(),
							)
							.await
							{
								Ok(_) => {
									// TODO [discussion] : should not Blindly putting current block_number as the last updated keyshare's block_number
									let _ = set_sync_state(block_number.to_string());
									info!("\t\t > First Synchronization of Keyshares complete to the block number: {} .",block_number);
								},

								Err(err) => error!(
									"\t\t > Error during setup-mode fetching keyshares : {:?}",
									err
								),
							}
						}
					},

					// Cluster discovery Error
					Err(err) => {
						error!("\t > Error during running-mode cluster discovery {:?}", err);
						// TODO [decision] : Integrity of clusters is corrupted. what to do? Going to maintenace mode and stop serving to API calls? Wipe?
						continue;
					},
				}
			}

			// Regular CRAWL Check
			let sync_state = get_sync_state().unwrap();

			// IMPORTANT : Check for Runtime mode : if integrity of clusters fails, we'll wait and go back to setup-mode
			if let Ok(last_sync_block) = sync_state.parse::<u32>() {
				debug!(" > Runtime mode : Crawl check : last_sync_block = {}", last_sync_block);
				// If no event has detected in 10 blocks, network disconnections happened, ...
				
				let last_processed_block = get_processed_block(&state_config).await;

				if (block_number - last_processed_block) > 1 {
					debug!(" > Runtime mode : Crawl check : Lagging last processed block : block number = {} > last processed = {}, last synced = {}", block_number, last_processed_block, last_sync_block);
					match crawl_sync_events(&state_config, last_processed_block, block_number).await
					{
						Ok(cluster_nft_map) => {
							info!(
								"\t > Runtime mode : Crawl check : Success crawling from {} to {} .",
								last_processed_block, block_number
							);

							if !cluster_nft_map.is_empty() {
								match fetch_keyshares(&state_config.clone(), cluster_nft_map).await
								{
									Ok(_) => {
										info!("\t > Runtime mode : Crawl check : Success runtime-mode fetching crawled blocks from {} to {} .", last_processed_block, block_number);
										let _ = set_sync_state(block_number.to_string());
									},

									Err(err) => {
										error!(
											"\t > Runtime mode : Crawl check : Error during running-mode nft-based syncing : {:?}",
											err
										);
										// We can not proceed to next nft-based sync.
										// Because it'll update the syncing state
										// A re-try id needed in next block
										continue;
									},
								}
							} else {
								debug!("\t > Runtime mode : Crawl check : no new event detected in past blocks");
								let _ = set_sync_state(last_processed_block.to_string());
							}
						},

						Err(e) => {
							error!(
								"\t > Runtime mode : Crawl check : Error runtime-mode crawling from {} to {} .",
								last_processed_block, block_number
							);
							// We can not proceed to next nft-based sync.
							// Because it'll update the syncing state
							// A re-try id needed in next block
							continue;
						},
					}
				}
			} else {
				debug!("\t <<< Enclaved is not registered >>>");
				// wait until enclave get registered and go to runtime-mode
				continue;
			}

			// New Capsule/Secret are found
			if !new_nft.is_empty() {
				debug!(
					" > Runtime mode : NEW-NFT : New nft/capsul event detected, block number = {}",
					block_number
				);
				match fetch_keyshares(&state_config.clone(), new_nft).await {
								Ok(_) => {
									let _ = set_sync_state(block_number.to_string());
									debug!("\t > Runtime mode : NEW-NFT : Synchronization of Keyshares complete.")
								},
								Err(err) => error!("\t > Runtime mode : NEW-NFT : Error during running-mode nft-based syncing : {:?}", err),
							}
			}

			// TODO : Regular check to use Indexer/Dictionary for missing NFTs?! (with any reason)
			// Maybe in another thread

			// Update runtime block tracking variable
			debug!("\t > Runtime mode : update last processed block");
			set_processed_block(&state_config, block_number).await;
		} // While blocks
	});

	// debug!("\nENCLAVE START : wait 6 seconds to get new block.");
	// tokio::time::sleep(tokio::time::Duration::from_secs(6)).await;

	Ok(http_app)
}

/*  ------------------------------
		ERROR HANDLING
------------------------------ */
/// Handle errors from the router.
/// This is a catch-all handler that will be called for any error that isn't handled by a route.
async fn handle_timeout_error(_method: Method, _uri: Uri, err: BoxError) -> impl IntoResponse {
	debug!("3-1 Timeout Handler start");
	if err.is::<tower::timeout::error::Elapsed>() {
		debug!("3-1-1 Timeout Handler : Request took too long.");
		(StatusCode::REQUEST_TIMEOUT, "Request took too long".to_string()).into_response()
	} else {
		debug!("3-1-1 Timeout Handler : unhandled internal error.");
		(StatusCode::INTERNAL_SERVER_ERROR, format!("Unhandled internal error: {err}"))
			.into_response()
	}
}

/// Handle errors from the router.
async fn fallback(uri: axum::http::Uri) -> impl IntoResponse {
	debug!("3-2 Fallback handler for {uri}");
	(
		StatusCode::BAD_REQUEST,
		Json(json!({
			"status": 432,
			"description": format!("No route to URL : {}",uri),
		})),
	)
		.into_response()
}

/*  ------------------------------
	HEALTH CHECK
------------------------------ */

#[derive(Serialize, Deserialize, Debug)]
pub struct HealthResponse {
	pub block_number: u32,
	pub sync_state: String,
	pub version: String,
	pub description: String,
	pub enclave_address: String,
}

/// Health check endpoint
async fn get_health_status(State(state): State<SharedState>) -> impl IntoResponse {
	debug!("3-3 Healthchek handler.");

	match evalueate_health_status(&state).await {
		Some(response) => {
			debug!("3-3-1 Healthchek exit successfully .");
			response.into_response()
		},

		_ => {
			debug!("3-3-1 Healthchek exited with None.");
			let block_number = get_blocknumber(&state).await;
			let binary_version = get_version(&state).await;
			let enclave_address = get_accountid(&state).await;
			let sync_state = get_sync_state().unwrap();

			(
				StatusCode::INTERNAL_SERVER_ERROR,
				Json(HealthResponse {
					sync_state,
					description: "Healthcheck returned NONE".to_string(),
					block_number,
					version: binary_version,
					enclave_address,
				}),
			)
				.into_response()
		},
	}
}

//#[once(time = 10, sync_writes = true)]
fn evalueate_health_status(state: &StateConfig) -> Option<Json<Value>> {
	let time: chrono::DateTime<chrono::offset::Utc> = SystemTime::now().into();

	let block_number = get_blocknumber(state).await;
	let binary_version = get_version(state).await;
	let enclave_address = get_accountid(state).await;

	debug!("3-3-4 healthcheck : get public key.");
	// TODO: ADD RPC PROBLEM
	let pubkey: [u8; 32] = match enclave_key.as_ref().to_bytes()[64..].try_into() {
		Ok(pk) => pk,
		Err(_e) =>
			return Some(Json(json!({
				"status": 434,
				"date": time.format("%Y-%m-%d %H:%M:%S").to_string(),
				"description": "Error getting encalve public key".to_string(),
				"enclave_address": format!("Error : {}",e),
			}))),
	};

	let enclave_address = sp_core::sr25519::Public::from_raw(pubkey);

	let maintenance = shared_state.get_maintenance();
	if !maintenance.is_empty() {
		return Some((
			StatusCode::PROCESSING,
			Json(HealthResponse {
				sync_state,
				block_number,
				version: binary_version,
				description: maintenance,
				enclave_address,
			}),
		));
	}

	Some((
		StatusCode::OK,
		Json(HealthResponse {
			sync_state,
			block_number,
			version: binary_version,
			description: "SGX server is running!".to_string(),
			enclave_address,
		}),
	))
}

/*  ------------------------------
		SIGNATURE
------------------------------ */

pub fn self_checksig() -> Result<String, String> {
	debug!("3-4 healthcheck : checksig.");

	let binary_path = match sysinfo::get_current_pid() {
		Ok(pid) => {
			debug!("3-4-1 healthcheck : checksig : binary path detected.");
			let path_string = "/proc/".to_owned() + &pid.to_string() + "/exe";
			let binpath = std::path::Path::new(&path_string).read_link().unwrap(); // TODO: manage unwrap()
			binpath
		},
		Err(e) => {
			info!("failed to get current pid: {}", e);
			return Err("Error get binary path".to_string())
		},
	};

	let signed_data = match std::fs::read(binary_path.clone()) {
		Ok(data) => {
			debug!("3-4-2 healthcheck : checksig : binary read successfully.");
			data
		},
		Err(_e) => {
			debug!("3-4-2 healthcheck : error reading binary file.");
			return Err("Error reading binary file".to_string())
		},
	};

	// TODO: Read from github release path
	let sigfile = binary_path.to_string_lossy().to_string() + ".sig";

	debug!("3-4-3 healthcheck : reading signature file.");
	let mut signature_data = match std::fs::read_to_string(sigfile) {
		Ok(sigdata) => {
			debug!("3-4-4 healthcheck : sig file read successfully.");
			sigdata
		},
		Err(_) => {
			debug!("3-4-4 healthcheck : fail reading sig file.");
			return Err("Error reading signature file".to_string())
		},
	};

	signature_data = signature_data.replace('\n', "");

	debug!("3-4-5 healthcheck : verification of binary signature.");
	match cosign::verify(&signed_data, &signature_data) {
		Ok(b) => match b {
			true => Ok("Successful".to_string()),
			false => Ok("Failed".to_string()),
		},
		Err(e) => Err(format!("Binary verification Error, {}", e)),
	}
}

/*  ------------------------------
		CHECKSUM
------------------------------ */
/// This function is called by the health check endpoint
fn self_checksum() -> Result<String, String> {
	// Get binary address on disk
	// BUT in gramine, the binary is simply at root directory!
	let mut binary_path = match sysinfo::get_current_pid() {
		Ok(pid) => {
			let path_string = "/proc/".to_owned() + &pid.to_string() + "/exe";

			let binpath = match std::path::Path::new(&path_string).read_link() {
				Ok(val) => val,
				Err(err) => {
					info!("Error in binpath {:?}", err);
					PathBuf::new()
				},
			};

			binpath
		},
		Err(e) => {
			error!("failed to get current pid: {}", e);
			PathBuf::new()
		},
	};

	// Verify Ternoa checksum/signature
	let bytes = match std::fs::read(binary_path.clone()) {
		Ok(val) => val,
		Err(e) => {
			error!("failed to get current pid: {}", e);
			Vec::new()
		},
	};

	let hash = sha256::digest(bytes.as_slice());

	// TODO: Get checksum from github release
	binary_path.pop(); // remove binary name
	binary_path.push("checksum");

	let binary_hash = match std::fs::read_to_string(binary_path.clone()) {
		Ok(val) => val,
		Err(err) => {
			error!("Error readinf binary path: {err}");
			String::new()
		},
	};

	let binary_hash = binary_hash
		.strip_suffix("\r\n")
		.or(binary_hash.strip_suffix('\n'))
		.unwrap_or(&binary_hash);

	if binary_hash != hash {
		info!("Binary hash doesn't match!");
		Err(hash)
	} else {
		info!("Binary hash match : {}", hash);
		Ok(hash)
	}
}

/*  ------------------------------
	DOWNLOADER
------------------------------ */
/// This function is called by the health check endpoint
/// It downloads the binary from github release
pub fn downloader(url: &str) -> Result<String, Error> {
	let response = match reqwest::blocking::get(url) {
		Ok(resp) => resp,
		Err(e) => return Err(anyhow!("Error accessing url: {}", e)),
	};

	let content = match response.text() {
		Ok(s) => s,
		Err(e) => return Err(anyhow!("Error reading response: {}", e)),
	};

	Ok(content)
}
