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

use subxt::ext::sp_core::{sr25519, Pair};

use tower::ServiceBuilder;
use tower_http::cors::{Any, CorsLayer};
use tower_http::limit::RequestBodyLimitLayer;

use anyhow::{anyhow, Error};
use serde_json::{json, Value};
use tracing::{debug, error, info, trace, warn};

use crate::{
	attestation::ra::ra_get_quote,
	backup::{
		admin_nftid::admin_backup_push_id,
		metric::{metric_reconcilliation, set_crawl_block},
		sync::{
			cluster_discovery, crawl_sync_events, fetch_keyshares, get_sync_state,
			parse_block_body, set_sync_state, sync_keyshares, SyncedNFT,
		},
	},
	chain::{
		capsule::{
			capsule_get_views, capsule_remove_keyshare, capsule_retrieve_keyshare,
			capsule_set_keyshare, is_capsule_available,
		},
		constants::{
			CONTENT_LENGTH_LIMIT, ENCLAVE_ACCOUNT_FILE, RETRY_COUNT, RETRY_DELAY, SEALPATH,
			SYNC_STATE_FILE, VERSION,
		},
		core::create_chain_api,
		helper,
		nft::{
			is_nft_available, nft_get_views, nft_remove_keyshare, nft_retrieve_keyshare,
			nft_store_keyshare,
		},
	},
	servers::state::{
		get_accountid, get_blocknumber, get_identity, get_maintenance, get_nonce,
		get_processed_block, get_version, reset_nonce, set_blocknumber, set_processed_block,
		SharedState, StateConfig, get_nft_availability_map_len,
	},
};

use crate::{
	backup::admin_bulk::{admin_backup_fetch_bulk, admin_backup_push_bulk},
	backup::admin_nftid::admin_backup_fetch_id,
};

use sentry::integrations::tower::{NewSentryLayer, SentryHttpLayer};

use super::server_common;

/// http server app
pub async fn http_server() -> Result<Router, Error> {
	info!("ENCLAVE START : Generate/Import Enclave Keypair");

	let enclave_keypair = if std::path::Path::new(&ENCLAVE_ACCOUNT_FILE).exists() {
		info!(
			"ENCLAVE START : Enclave Account Exists, Importing it! :, path: {}",
			ENCLAVE_ACCOUNT_FILE
		);

		let phrase = match std::fs::read_to_string(ENCLAVE_ACCOUNT_FILE) {
			Ok(phrase) => phrase,
			Err(err) => {
				error!("\tENCLAVE START : ERROR reading enclave account file: {err:?}");
				return Err(anyhow!(err));
			},
		};

		match sr25519::Pair::from_phrase(&phrase, None) {
			Ok((keypair, _seed)) => keypair,
			Err(err) => {
				error!("\tENCLAVE START : ERROR creating keypair from phrase: {err:?}");
				return Err(anyhow!(err));
			},
		}
	} else {
		info!("ENCLAVE START : Creating new Enclave Account, Remember to send 1 CAPS to it!");

		let (keypair, phrase, _s_seed) = sr25519::Pair::generate_with_phrase(None);
		let mut ekfile = match File::create(ENCLAVE_ACCOUNT_FILE) {
			Ok(file_handle) => {
				debug!("\tENCLAVE START : created enclave keypair file successfully");
				file_handle
			},
			Err(err) => {
				error!("\tENCLAVE START : Failed to creat enclave keypair file, error : {err:?}");
				return Err(anyhow!(err));
			},
		};

		match ekfile.write_all(phrase.as_bytes()) {
			Ok(_) => {
				debug!("\tENCLAVE START : Write enclave keypair to file successfully");
			},
			Err(err) => {
				error!("\tENCLAVE START : Write enclave keypair to file failed, error : {:?}", err);
				return Err(anyhow!(err));
			},
		}

		keypair
	};

	let chain_api = match create_chain_api().await {
		Ok(api) => api,
		Err(err) => {
			error!("ENCLAVE START : get online chain api, error : {err:?}");
			return Err(anyhow!(err));
		},
	};

	// Initialize runtime tracking blocks
	let current_block_hash = chain_api.rpc().finalized_head().await?;
	let current_block = match chain_api.rpc().block(Some(current_block_hash)).await? {
		Some(blk) => blk,
		None => return Err(anyhow!("ENCLAVE START : unable to get current block")),
	};
	let current_block_number = current_block.block.header.number;
	let last_processed_block = current_block_number;

	let keyshare_list = helper::query_keyshare_file(SEALPATH.to_string())?;

	// Shared-State between APIs
	let state_config: SharedState = Arc::new(RwLock::new(StateConfig::new(
		enclave_keypair,
		String::new(),
		chain_api.clone(),
		VERSION.to_string(),
		last_processed_block,
		keyshare_list,
	)));

	set_blocknumber(&state_config, current_block_number).await;
	set_processed_block(&state_config, last_processed_block).await;

	// Get all cluster and registered enclaves from the chain
	// Also checks if this enclave has been registered.
	info!("ENCLAVE START : Initialization Cluster Discovery.");
	while let Err(err) = cluster_discovery(&state_config.clone()).await {
		error!("ENCLAVE START : cluster discovery error : {err:?}");
		debug!("ENCLAVE START : Retry Cluster Discovery after a delay...");
		std::thread::sleep(std::time::Duration::from_secs(RETRY_DELAY.into()));
	}

	info!("ENCLAVE START : Cluster Discovery successfull.");

	// Check the previous Sync-State
	info!("ENCLAVE START : check for sync.state file from previous run ...");
	if std::path::Path::new(&SYNC_STATE_FILE).exists() {
		debug!("ENCLAVE START : previous sync.state file exists");
		// Resuming enclave
		let past_state = match std::fs::read_to_string(SYNC_STATE_FILE) {
			Ok(state) => state,
			Err(err) => {
				error!("ENCLAVE START : Error reading enclave's last state file: {err:?}");
				return Err(anyhow!(err));
			},
		};

		debug!("ENCLAVE START : previous sync.state file content : '{}'", past_state);

		if !past_state.is_empty() {
			debug!("ENCLAVE START : previous sync.state is not empty ...");
			if past_state == "setup" {
				debug!("ENCLAVE START : SETUP-MODE : fetching keyshares ...");
				// Th enclave has been stopped at the middle of fetching data from another enclave
				// Do it again!

				// Retry until successfully fetch keyshares or discover if it is primary
				for _retry in 0..RETRY_COUNT {
					match fetch_keyshares(
						&state_config,
						&std::collections::HashMap::<u32, SyncedNFT>::new(),
					)
					.await
					{
						Ok(_) => {
							// TODO [Disaster recovery] : What if all clusters are down, What block_number should be set as last_sync_block
							let _ = set_sync_state(current_block_number.to_string());
							info!(
								"ENCLAVE START : SETUP-MODE : First Synchronization of Keyshares complete up to block number : {}.",
								current_block_number
							);
							break;
						},
						Err(err) => {
							// For the primary cluster it should work fine.
							error!("ENCLAVE START : SETUP-MODE : Error during setup-mode fetch-keyshares : {err:?}");
							debug!("ENCLAVE START : SETUP-MODE : waiting before retry");
							std::thread::sleep(std::time::Duration::from_secs(RETRY_DELAY.into()));
						},
					} // FETCH
				} // RETRY FETCH
			} else {
				// Th enclave has been stopped after being synced to a recent block number
				// Now should crawl the blocks to the current finalized block.
				debug!("ENCLAVE START : RUNTIME-MODE : previous sync.state was in runtime-mode.");

				let synced_block_number = match past_state.parse::<u32>() {
					Ok(number) => number,
					Err(err) => {
						error!(
							"ENCLAVE START : Error parsing enclave's last state content: {:?}, state = {:?}",
							err, past_state
						);
						return Err(anyhow!(err));
					},
				};
				debug!(
					"ENCLAVE START : RUNTIME-MODE : previous sync.state had been synced to block {}",
					synced_block_number
				);

				// Retry if syncing failed
				for _sync_retry in 0..RETRY_COUNT {
					let current_block_hash = chain_api.rpc().finalized_head().await?;
					let current_block_number =
						match chain_api.rpc().block(Some(current_block_hash)).await? {
							Some(blk) => blk.block.header.number,
							None => {
								let message = "ENCLAVE START : CRAWL : Error getting block number"
									.to_string();
								error!(message);
								return Err(anyhow!(message));
							},
						};

					debug!(
						"ENCLAVE START : CRAWL : Crawl to current block {}",
						current_block_number
					);
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
							// Empty map has another meaning
							if !cluster_nftid_map.is_empty() {
								for _fetch_retry in 0..RETRY_COUNT {
									match fetch_keyshares(&state_config.clone(), &cluster_nftid_map)
										.await
									{
										Ok(_) => {
											let _ =
												set_sync_state(current_block_number.to_string());
											info!("ENCLAVE START : SYNC : FETCH : DONE.");
											break; // FETCH-RETRY
										},

										Err(fetch_err) => {
											error!("ENCLAVE START : CRAWL : Error fetching new nftids after resuming the enclave : {:?}", fetch_err);
											// Wait 7 seconds, then retry
											debug!(
												"ENCLAVE START : CRAWL : FETCH : wait before retry"
											);
											std::thread::sleep(std::time::Duration::from_secs(
												RETRY_DELAY.into(),
											));
										},
									}; // FETCH
								} // FETCH RETRY
							}
							info!("ENCLAVE START : SYNC : DONE.");
							break; // SYNC-RETRY
						},

						Err(crawl_err) => {
							error!(
								"ENCLAVE START : Error crawling new blocks after resuming the enclave : {:?}",
								crawl_err
							);
							// Wait 7 seconds, then retry
							debug!("ENCLAVE START : CRAWL : wait before retry");
							std::thread::sleep(std::time::Duration::from_secs(RETRY_DELAY.into()));
							//return Err(anyhow!(crawl_err));
						},
					} // CRAWL
				} // SYNC RETRY
			} // PAST STATE IS A NUMBER
		}
		// PAST STATE EXISTS
		else {
			warn!("ENCLAVE START : sync.state file exists, but it is empty : enclave is not registered yet.");
		}
	} else {
		// It is first time starting enclave
		debug!("ENCLAVE START : sync.state file does not exist.");
		let _ = match File::create(SYNC_STATE_FILE) {
			Ok(file_handle) => {
				info!("ENCLAVE START : created sync.state file successfully");
				file_handle
			},
			Err(err) => {
				error!("ENCLAVE START : failed to creat sync.state file, error : {err:?}");
				return Err(anyhow!(err));
			},
		};
	};

	info!("ENCLAVE START : define the CORS layer.");
	let _ = CorsLayer::new()
		// allow `GET` and `POST` when accessing the resource
		.allow_methods([Method::GET, Method::POST])
		// allow requests from any origin
		.allow_origin(Any)
		.allow_headers(Any)
		.allow_credentials(true);

	info!("ENCLAVE START : define the monitor layer : Sentry.");
	let monitor_layer = ServiceBuilder::new()
		.layer(NewSentryLayer::new_from_top())
		.layer(SentryHttpLayer::with_transaction());

	info!("ENCLAVE START : define the end-points");
	let http_app = Router::new()
		.fallback(fallback)
		// STATE API
		.route("/api/health", get(get_health_status))
		.route("/api/quote", get(ra_get_quote))
		// CENTRALIZED BACKUP API
		.route("/api/backup/fetch-id", post(admin_backup_fetch_id))
		.route("/api/backup/push-id", post(admin_backup_push_id))
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
		// METRIC SERVER
		.route("/api/metric/interval-nft-list", post(metric_reconcilliation))
		.route("/api/metric/set-crawl-block", post(set_crawl_block))
		.layer(
			ServiceBuilder::new()
				.layer(HandleErrorLayer::new(handle_timeout_error))
				.timeout(Duration::from_secs(30)),
		)
		.layer(monitor_layer)
		.layer(CorsLayer::permissive())
		.with_state(Arc::clone(&state_config.clone()));

	info!("ENCLAVE START : New Thread for run-time block subscription.");
	// New thread to track latest block
	tokio::spawn(async move {
		// Subscribe to all finalized blocks:
		let mut blocks_sub = match chain_api.blocks().subscribe_finalized().await {
			Ok(sub) => sub,
			Err(err) => {
				error!(" > Unable to subscribe to finalized blocks {err:?}");
				return;
			},
		};

		// For each new finalized block, get block number
		while let Some(block) = blocks_sub.next().await {
			let block = match block {
				Ok(blk) => blk,
				Err(err) => {
					error!(" > Unable to get finalized block {err:?}");
					continue;
				},
			};

			let block_number = block.header().number;

			// Write to ShareState block, necessary to prevent Read SharedState
			set_blocknumber(&state_config, block_number).await;
			trace!("New Block : {}", block_number);
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
			let body = match block.body().await {
				Ok(body) => {
					trace!(" > Block Number Thread : got block body.");
					body
				},
				Err(err) => {
					error!(" > Block Number Thread : Unable to get block body : {err:?}");
					continue;
				},
			};

			let storage_api = block.storage();

			let (new_nft, is_tee_events) =
				match parse_block_body(block_number, body, &storage_api).await {
					Ok(tuple) => {
						trace!(" > Block Number Thread : parsed the block body.");
						tuple
					},
					Err(err) => {
						error!(" > Block Number Thread : Unable to parse the block body : {err:?}");
						continue;
					},
				};

			// A change in clusters/enclaves data is detected.
			if is_tee_events {
				debug!(" > TEE Event processing");
				match cluster_discovery(&state_config.clone()).await {
					Ok(_) => {
						info!("\t > Cluster discovery complete.");
						// New self-identity is found?
						let sync_state = match get_sync_state() {
							Ok(st) => st,
							Err(err) => {
								error!(" > Block Number Thread : TEE Event : Cluster Discovery : Can not get sync state : {err:?}");
								continue;
							},
						};

						if sync_state == "setup" {
							// Here is Identity discovery, thus the first synchronization of all files.
							// An empty HashMap is the wildcard signal to fetch all keyshares from nearby enclave
							for _retry in 0..RETRY_COUNT {
								match fetch_keyshares(
									&state_config.clone(),
									&std::collections::HashMap::<u32, SyncedNFT>::new(),
								)
								.await
								{
									Ok(_) => {
										// TODO [discussion] : should not Blindly putting current block_number as the last updated keyshare's block_number
										let _ = set_sync_state(block_number.to_string());
										info!("\t\t > SETUP Synchronization of Keyshares complete to the block number: {} .",block_number);
										break; // BREAK THE RETRY
									},

									Err(err) => {
										error!(
										"\t\t > Error during setup-mode fetching keyshares : {:?}",
										err);
										debug!("\t > Setup after Runtime > Fetch Keyshares : wait before retry");
										std::thread::sleep(std::time::Duration::from_secs(
											RETRY_DELAY.into(),
										));
									},
								} // FETCH
							} // RETRY FETCH
						}
					},

					// Cluster discovery Error
					Err(err) => {
						error!("\t > Error during running-mode cluster discovery {err:?}");
						// TODO [decision] : Integrity of clusters is corrupted. what to do? Going to maintenace mode and stop serving to API calls? Wipe?
						continue;
					},
				}
			} // TEE EVENT

			// New Capsule/Secret are found
			if !new_nft.is_empty() {
				debug!(
					" > Runtime mode : NEW-NFT : New nft/capsul event detected, block number = {}",
					block_number
				);

				for _retry in 0..RETRY_COUNT {
					match fetch_keyshares(&state_config.clone(), &new_nft).await {
						Ok(_) => {
							let _ = set_sync_state(block_number.to_string());
							debug!("\t > Runtime mode : NEW-NFT : Synchronization of Keyshares complete.");
							break;
						},
						Err(err) => {
							error!("\t > Runtime mode : NEW-NFT : Error during running-mode nft-based syncing : {err:?}");
							debug!("\t > Runtime mode : NEW-NFT : wait before retry");
							std::thread::sleep(std::time::Duration::from_secs(RETRY_DELAY.into()));
						},
					} // FETCH
				} // RETRY FETCH
			}
			// TODO : Regular check to use Indexer/Dictionary for missing NFTs?! (with any reason)
			// Maybe in another thread

			// Regular CRAWL Check
			let sync_state = match get_sync_state() {
				Ok(st) => st,
				Err(err) => {
					error!(" > Block Number Thread : Can not get sync state : {err:?}");
					continue;
				},
			};

			// IMPORTANT : Check for Runtime mode : if integrity of clusters fails, we'll wait and go back to setup-mode
			if let Ok(last_sync_block) = sync_state.parse::<u32>() {
				trace!(" > Runtime mode : SyncStat = {}", sync_state);
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
								for _retry in 0..RETRY_COUNT {
									match fetch_keyshares(&state_config.clone(), &cluster_nft_map)
										.await
									{
										Ok(_) => {
											info!("\t > Runtime mode : Crawl check : Success runtime-mode fetching crawled blocks from {} to {} .", last_processed_block, block_number);
											let _ = set_sync_state(block_number.to_string());
											break;
										},

										Err(err) => {
											error!(
												"\t > Runtime mode : Crawl check : Error during running-mode nft-based syncing : {:?}",
												err
											);
											// We can not proceed to next nft-based sync.
											// Because it'll update the syncing state
											// A retry id needed in next block
											debug!("\t > Runtime mode : Crawl check : Fetch Keyshares : wait before retry");
											std::thread::sleep(std::time::Duration::from_secs(
												RETRY_DELAY.into(),
											));
										},
									} //Fetch
								} //Retry Fetch
							} else {
								debug!("\t > Runtime mode : Crawl check : no new event detected in past blocks");
								let _ = set_sync_state(last_processed_block.to_string());
							}
						},

						Err(err) => {
							error!(
								"\t > Runtime mode : Crawl check : Error runtime-mode crawling from {} to {} .",
								last_processed_block, block_number
							);
							// We can not proceed to next nft-based sync.
							// Because it'll update the syncing state
							// A retry id needed in next block
							debug!("\t > Runtime mode : Crawl check : wait before retry");
							std::thread::sleep(std::time::Duration::from_secs(RETRY_DELAY.into()));
							continue;
						},
					} // EVENTS CRAWLER
				} // BLOCK LAG DETECTED
			} else {
				// Non Numeric SyncState file content:
				if block_number % 10 == 0 {
					if get_identity(&state_config).await.is_none() {
						debug!("\t <<< Enclave has is not registered >>>");
					} else {
						debug!("\t <<< Enclave has never Synced >>>");
					}
				}
				// Prevent Crawling after first registration
				set_processed_block(&state_config, block_number).await;
				continue;
			}

			// Update runtime block tracking variable
			trace!("\t > Runtime mode : update last processed block");
			set_processed_block(&state_config, block_number).await;
		} // While blocks
	});

	// debug!("ENCLAVE START : wait 6 seconds to get new block.");
	// tokio::time::sleep(tokio::time::Duration::from_secs(6)).await;

	Ok(http_app)
}

/* ------------------------------
		ERROR HANDLING
------------------------------ */
/// Handle errors from the router.
/// This is a catch-all handler that will be called for any error that isn't handled by a route.
async fn handle_timeout_error(method: Method, uri: Uri, err: BoxError) -> impl IntoResponse {
	debug!("Timeout Handler start");

	let message = format!(
		"Timeout Handler : Request timeout, method: {:?}, uri: {}, error: {}",
		method, uri, err
	);
	warn!(message);
	sentry::with_scope(
		|scope| {
			scope.set_tag("timeout", uri.to_string());
		},
		|| sentry::capture_message(&message, sentry::Level::Error),
	);

	if err.is::<tower::timeout::error::Elapsed>() {
		debug!("Timeout Handler : Request timeout.");
		(StatusCode::REQUEST_TIMEOUT, "Request took too long".to_string()).into_response()
	} else {
		debug!("Timeout Handler : unhandled internal error.");
		(StatusCode::INTERNAL_SERVER_ERROR, format!("Unhandled internal error: {err}"))
			.into_response()
	}
}

/// Handle errors from the router.
async fn fallback(uri: axum::http::Uri) -> impl IntoResponse {
	let message = format!("Fallback on uri: {}", uri);

	sentry::with_scope(
		|scope| {
			scope.set_tag("fallback", uri.to_string());
		},
		|| sentry::capture_message(&message, sentry::Level::Debug),
	);

	debug!("FALLBACK : {uri}");
	(
		StatusCode::BAD_REQUEST,
		Json(json!({"description": format!("No route to URL : {}",uri),
		})),
	)
		.into_response()
}

/* ------------------------------
	HEALTH CHECK
------------------------------ */

#[derive(Serialize, Deserialize, Debug)]
pub struct HealthResponse {
	pub chain: String,
	pub block_number: u32,
	pub sync_state: String,
	pub secrets_number: u32,
	pub version: String,
	pub description: String,
	pub enclave_address: String,
}

/// Health check endpoint
async fn get_health_status(State(state): State<SharedState>) -> impl IntoResponse {
	debug!("\t Healthcheck handler");

	match evalueate_health_status(&state).await {
		Some(response) => {
			debug!("Healthcheck exit successfully .");
			response.into_response()
		},

		_ => {
			let message = "Healthcheck handler : exited with None.".to_string();
			error!(message);
			sentry::with_scope(
				|scope| {
					scope.set_tag("health-check", "None");
				},
				|| sentry::capture_message(&message, sentry::Level::Error),
			);

			let block_number = get_blocknumber(&state).await;
			let binary_version = get_version(&state).await;
			let enclave_address = get_accountid(&state).await;
			let sync_state = match get_sync_state() {
				Ok(st) => st,
				Err(err) => {
					error!("Healthcheck handler : error : unable to read the sync state");
					"Unknown".to_string()
				},
			};
			let secrets_number = get_nft_availability_map_len(&state).await;

			let chain = if cfg!(feature = "main-net") {
				"main-net".to_string()
			} else if cfg!(feature = "alpha-net") {
				"alpha-net".to_string()
			} else if cfg!(feature = "dev0-net") {
				"dev0-net".to_string()
			} else if cfg!(feature = "dev1-net") {
				"dev1-net".to_string()
			} else {
				"local-net".to_string()
			};

			(
				StatusCode::INTERNAL_SERVER_ERROR,
				Json(HealthResponse {
					chain,
					sync_state,
					secrets_number,
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

/// Health check endpoint
/// This function is called by the health check endpoint
/// It returns a JSON object with the following fields :
async fn evalueate_health_status(
	state: &SharedState,
) -> Option<(StatusCode, Json<HealthResponse>)> {
	//let time: chrono::DateTime<chrono::offset::Utc> = SystemTime::now().into();

	let block_number = get_blocknumber(state).await;
	let binary_version = get_version(state).await;
	let enclave_address = get_accountid(state).await;

	debug!("Healthcheck : get public key.");
	// TODO [error handling] : ADD RPC PROBLEM/TIMEOUT
	let sync_state = match get_sync_state() {
		Ok(st) => st,
		Err(err) => {
			error!("Healthcheck : error : unable to get sync state");
			return None;
		},
	};
	let secrets_number = get_nft_availability_map_len(state).await;
	let maintenance = get_maintenance(state).await;

	let chain = if cfg!(feature = "main-net") {
		"main-net".to_string()
	} else if cfg!(feature = "alpha-net") {
		"alpha-net".to_string()
	} else if cfg!(feature = "dev0-net") {
		"dev0-net".to_string()
	} else if cfg!(feature = "dev1-net") {
		"dev1-net".to_string()
	} else {
		"local-net".to_string()
	};

	if !maintenance.is_empty() {
		return Some((
			StatusCode::PROCESSING,
			Json(HealthResponse {
				chain,
				sync_state,
				secrets_number,
				block_number,
				version: binary_version,
				description: maintenance,
				enclave_address,
			}),
		));
	}

	let status = match sync_state.as_str() {
		"" => StatusCode::NO_CONTENT,
		"setup" => StatusCode::NOT_EXTENDED,
		_ => if sync_state.parse::<u32>().is_ok() {
			StatusCode::OK
		}else{
			StatusCode::NOT_ACCEPTABLE
		}
	};

	Some((
		status,
		Json(HealthResponse {
			chain,
			sync_state,
			secrets_number,
			block_number,
			version: binary_version,
			description: "SGX server is running!".to_string(),
			enclave_address,
		}),
	))
}
