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
use hyper::Method;
use serde::{Deserialize, Serialize};
use tokio::{sync::RwLock, time::timeout};

use axum::{
	error_handling::HandleErrorLayer,
	extract::{DefaultBodyLimit, State},
	http::{StatusCode, Uri},
	response::IntoResponse,
	routing::{get, post},
	BoxError, Json, Router,
};

use reqwest;

use subxt::ext::sp_core::{sr25519, Pair};

use tower::ServiceBuilder;
use tower_http::{
	cors::{Any, CorsLayer},
	limit::RequestBodyLimitLayer,
};

use anyhow::{anyhow, Error};
use serde_json::{json, Value};
use tracing::{debug, error, info, trace, warn};

use crate::{
	attestation::ra::ra_get_quote,
	constants::{
		CONTENT_LENGTH_LIMIT, ENCLAVE_ACCOUNT_FILE, RETRY_COUNT, RETRY_DELAY, SEALPATH,
		SYNC_STATE_FILE, VERSION,
	},
	core::{
		capsule::{
			capsule_get_views, capsule_remove_keyshare, capsule_retrieve_keyshare,
			capsule_set_keyshare, is_capsule_available,
		},
		chain::create_chain_api,
		helper,
		nft::{
			is_nft_available, nft_get_views, nft_remove_keyshare, nft_retrieve_keyshare,
			nft_store_keyshare,
		},
	},
	replication::{
		admin_nftid::admin_backup_push_id,
		metric::{metric_reconcilliation, set_crawl_block},
		sync::{
			cluster_discovery, crawl_sync_events, fetch_keyshares, get_sync_state,
			parse_block_body, set_sync_state, sync_keyshares, SyncedNFT,
		},
	},
	server::state::{
		get_accountid, get_blocknumber, get_chain_rpc_renew, get_identity, get_maintenance,
		get_nft_availability_map_len, get_nonce, get_processed_block, get_version, reset_nonce,
		set_blocknumber, set_chain_api, set_chain_api_renew, set_processed_block, SharedState,
		StateConfig,
	},
};

use crate::replication::{
	admin_bulk::{admin_backup_fetch_bulk, admin_backup_push_bulk},
	admin_nftid::admin_backup_fetch_id,
};

use super::{server_common, state::get_chain_api};

/// http server app
pub async fn http_server() -> Result<Router, Error> {
	let state_config = initialize_enclave_state().await?;

	info!("ENCLAVE START : define the CORS layer.");
	let cors_layer = CorsLayer::new()
		// allow `GET` and `POST` when accessing the resource
		.allow_methods([Method::GET, Method::POST])
		// allow requests from any origin
		.allow_headers(Any)
		.allow_origin(Any)
		.expose_headers(Any);

	info!("ENCLAVE START : define the monitor layer : Sentry.");
	let monitor_layer = ServiceBuilder::new()
		.layer(sentry_tower::NewSentryLayer::new_from_top())
		.layer(sentry_tower::SentryHttpLayer::with_transaction());

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
		.layer(cors_layer)
		.with_state(Arc::clone(&state_config.clone()));

	info!("ENCLAVE START : New Thread for run-time block subscription.");
	subscribe_block_events(state_config).await;

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

	// sentry::with_scope(
	// 	|scope| {
	// 		scope.set_tag("fallback", uri.to_string());
	// 	},
	// 	|| sentry::capture_message(&message, sentry::Level::Debug),
	// );

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
	pub secrets_number: Option<u32>,
	pub version: String,
	pub description: String,
	pub enclave_address: String,
}

/// Health check endpoint
async fn get_health_status(State(state): State<SharedState>) -> impl IntoResponse {
	trace!("\t Healthcheck handler Start");

	match evalueate_health_status(&state).await {
		Some(response) => {
			trace!("Healthcheck handler exit successfully .");
			response.into_response()
		},

		_ => {
			let message = "Healthcheck handler error : exited with None.".to_string();
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
					error!("Healthcheck handler error : unable to read the sync state");
					"Unknown".to_string()
				},
			};
			let secrets_number = Some(get_nft_availability_map_len(&state).await);

			let chain = if cfg!(feature = "mainnet") {
				"mainnet".to_string()
			} else if cfg!(feature = "alphanet") {
				"alphanet".to_string()
			} else if cfg!(feature = "dev0") {
				"dev0".to_string()
			} else if cfg!(feature = "dev1") {
				"dev1".to_string()
			} else {
				"localchain".to_string()
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

	trace!("Healthcheck : get public key.");
	// TODO [error handling] : ADD RPC PROBLEM/TIMEOUT
	let sync_state = match get_sync_state() {
		Ok(st) => st,
		Err(err) => {
			error!("Healthcheck : error : unable to get sync state");
			return None;
		},
	};

	trace!("Healthcheck handler : get availability map");
	let secrets_number = Some(get_nft_availability_map_len(state).await);

	trace!("Healthcheck handler : get maintenance");
	let maintenance = get_maintenance(state).await;

	let chain = if cfg!(feature = "mainnet") {
		"mainnet".to_string()
	} else if cfg!(feature = "alphanet") {
		"alphanet".to_string()
	} else if cfg!(feature = "dev0") {
		"dev0".to_string()
	} else if cfg!(feature = "dev1") {
		"dev1".to_string()
	} else {
		"localchain".to_string()
	};

	if !maintenance.is_empty() {
		trace!("Healthcheck handler : maintenance mode");
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

	trace!("Healthcheck handler : get sync status");
	let status = match sync_state.as_str() {
		"" => StatusCode::PARTIAL_CONTENT,
		"setup" => StatusCode::RESET_CONTENT,
		_ =>
			if sync_state.parse::<u32>().is_ok() {
				StatusCode::OK
			} else {
				StatusCode::NOT_ACCEPTABLE
			},
	};

	trace!("Healthcheck handler : state={status:?}");

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

/*
	Initialize the enclave :
	- Creating/Fetching the confidential keypair
	- Update the internal state of enclave (to be used between threads)
	- Check the synchronization state of secrets from the last start
*/

async fn initialize_enclave_state() -> Result<SharedState, Error> {
	// Confidential Keypair of Enclave
	// The public key part of the keypair is the Identity of enclave i.e for registeration on chain
	// Also used for signing all communications
	// The seed phrase will be sealed on the disk to be used in next start
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

	// New Websocket RPC connection to the blockchain
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
		keyshare_list,
	)));

	// Update the shared-state with chain block states
	set_blocknumber(&state_config, current_block_number).await;
	set_processed_block(&state_config, last_processed_block).await;

	// Search all of clusters and registered enclaves from the blockchain
	// Also checks if this enclave has been registered on chain
	info!("ENCLAVE START : Initialization Cluster Discovery.");

	for _retry in 0..RETRY_COUNT {
		if let Err(err) = cluster_discovery(&state_config.clone()).await {
			error!("ENCLAVE START : cluster discovery error : {err:?}");
			debug!("ENCLAVE START : Retry Cluster Discovery after a delay...");
			std::thread::sleep(std::time::Duration::from_secs(RETRY_DELAY.into()));
		} else {
			info!("ENCLAVE START : Cluster Discovery Successful.");
			break;
		}
	}

	// Check the previous Synchronization State
	// The Sync State may have multiple states :
	// 1- file does not exists : first time enclave starting
	// 2- file is empty : enclave is not registered on chain
	// 3- file contains "setup" string : enclave has been stopped during synchronization
	// 4- file contains a blocknumber : the enclave is synchronized the data up to the blocknumber
	// that contains NFT
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
							// [Disaster recovery] : What if all clusters are down, What
							// block_number should be set as last_sync_block
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
				// Now it should crawl the blocks to the current finalized block.
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
					// TODO [future] : use Indexer if the difference between current_block >>
					// past_block is large
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
		// First time the enclave is starting
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

	Ok(state_config)
}

/*
	Subscribe to blockchain events :
	- Parse every block
		- Check TEE Pallet events
		- Check TC events
		- Check Secret/Capsule events
	- Crawl to current block if enclave is lagging
*/

async fn subscribe_block_events(state_config: SharedState) {
	// Get current rpc connection
	let chain_api = get_chain_api(&state_config).await;

	// New thread to track latest block
	tokio::spawn(async move {
		// Subscribe to all finalized blocks:
		let mut blocks_sub = match chain_api.blocks().subscribe_finalized().await {
			Ok(sub) => sub,
			Err(err) => {
				error!("-- Subscription Task : Unable to subscribe to finalized blocks {err:?}");
				return;
			},
		};

		// For each new finalized block, get block_number
		loop {
			// Is there any request to reset rpc connection?
			if get_chain_rpc_renew(&state_config).await {
				info!("-- Subscription Task : Renew the RPC ...");

				// New Websocket RPC connection to the blockchain
				let chain_api = match create_chain_api().await {
					Ok(api) => api,
					Err(err) => {
						error!("-- Subscription Task : get online chain api, error : {err:?}");
						continue;
					},
				};

				set_chain_api(&state_config, chain_api.clone()).await;

				// Subscribe to all finalized blocks:
				blocks_sub = match chain_api.blocks().subscribe_finalized().await {
					Ok(sub) => sub,
					Err(err) => {
						error!("-- Subscription Task : Unable to update subscribe to finalized blocks {err:?}");
						continue;
					},
				};

				set_chain_api_renew(&state_config, false).await;
			}

			// Wait for new block
			let some_block = match timeout(Duration::from_secs(30), blocks_sub.next()).await {
				Ok(block) => block,
				Err(err) => {
					error!("-- Subscription Task : Block Subscription timeout {err:?}");

					// New Websocket RPC connection to the blockchain
					info!("-- Subscription Task : Reconnecting RPC ...");
					let chain_api = match create_chain_api().await {
						Ok(api) => api,
						Err(err) => {
							error!("-- Subscription Task : get online chain api, error : {err:?}");
							continue;
						},
					};

					set_chain_api(&state_config, chain_api.clone()).await;

					// Subscribe to all finalized blocks:
					blocks_sub = match chain_api.blocks().subscribe_finalized().await {
						Ok(sub) => sub,
						Err(err) => {
							error!("-- Subscription Task : Unable to update subscribe to finalized blocks {err:?}");
							continue;
						},
					};

					continue;
				},
			};

			let ok_block = match some_block {
				Some(ok_block) => ok_block,
				None => {
					warn!("-- Subscription Task : Unable to get some block");
					set_chain_api_renew(&state_config, true).await;
					continue;
				},
			};

			// Check if captured finalized block
			let block = match ok_block {
				Ok(block) => block,
				Err(err) => {
					warn!("-- Subscription Task : Unable to get finalized block {err:?}");
					set_chain_api_renew(&state_config, true).await;
					continue;
				},
			};

			let block_number = block.header().number;

			// Write to ShareState block, necessary to prevent Read SharedState
			set_blocknumber(&state_config, block_number).await;

			// For block number update, we should reset the nonce as well
			// It is used as a batch of extrinsics for every block
			trace!(
				"-- Subscription Task : nonce before reset is {}",
				get_nonce(&state_config).await
			);

			reset_nonce(&state_config).await;

			trace!(
				"-- Subscription Task : nonce has been reset to {}",
				get_nonce(&state_config).await
			);

			// Extract block body
			let body = match block.body().await {
				Ok(body) => {
					trace!("-- Subscription Task : got block body.");
					body
				},
				Err(err) => {
					// Usually : Rpc ClientError Restart Needed
					// "Networking or low-level protocol error: WebSocket connection error: i/o
					// error: Connection reset by peer"
					set_chain_api_renew(&state_config, true).await;
					error!("-- Subscription Task : Unable to get block body : {err:?}");
					continue;
				},
			};

			let storage_api = block.storage();

			let (new_nft, is_tee_events) =
				match parse_block_body(&state_config, block_number, body, &storage_api).await {
					Ok(tuple) => {
						trace!("-- Subscription Task : parsed the block body.");
						tuple
					},
					Err(err) => {
						error!("-- Subscription Task : Unable to parse the block body : {err:?}");
						continue;
					},
				};

			// A change in clusters/enclaves data is detected.
			if is_tee_events {
				debug!("-- Subscription Task : TEE Event processing");
				match cluster_discovery(&state_config.clone()).await {
					Ok(_) => {
						info!("\t-- Subscription Task : Cluster discovery complete.");
						// New self-identity is found?
						let sync_state = match get_sync_state() {
							Ok(st) => st,
							Err(err) => {
								error!("-- Subscription Task : Block Number Thread : TEE Event : Cluster Discovery : Can not get sync state : {err:?}");
								continue;
							},
						};

						if sync_state == "setup" {
							// Here is Identity discovery, thus the first synchronization of all
							// files. An empty HashMap is the wildcard signal to fetch all keyshares
							// from nearby enclave
							for _retry in 0..RETRY_COUNT {
								match fetch_keyshares(
									&state_config.clone(),
									&std::collections::HashMap::<u32, SyncedNFT>::new(),
								)
								.await
								{
									Ok(_) => {
										// [discussion] : should not Blindly put current
										// block_number as the last updated keyshare's block_number
										let _ = set_sync_state(block_number.to_string());
										info!("\t\t-- Subscription Task : SETUP Synchronization of Keyshares complete to the block number: {} .",block_number);
										break; // BREAK THE RETRY
									},

									Err(err) => {
										error!(
										"\t\t-- Subscription Task : Error during setup-mode fetching keyshares : {:?}",
										err);
										debug!("\t-- Subscription Task : Setup after Runtime > Fetch Keyshares : wait before retry");
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
						error!("\t-- Subscription Task : Error during running-mode cluster-discovery {err:?}");
						// TODO [decision] : Integrity of clusters is corrupted. what to do? Going
						// to maintenace mode and stop serving to API calls? Wipe?
						continue;
					},
				}
			} // TEE EVENT

			// New Capsule/Secret are found
			if !new_nft.is_empty() {
				debug!(
					"-- Subscription Task :  : NEW-NFT : New nft/capsule event detected, block number = {}",
					block_number
				);

				for _retry in 0..RETRY_COUNT {
					match fetch_keyshares(&state_config.clone(), &new_nft).await {
						Ok(_) => {
							let _ = set_sync_state(block_number.to_string());
							debug!("\t-- Subscription Task : NEW-NFT : Synchronization of Keyshares complete.");
							break;
						},
						Err(err) => {
							error!("\t-- Subscription Task : NEW-NFT : Error during running-mode nft-based syncing : {err:?}");
							debug!("\t-- Subscription Task : NEW-NFT : wait before retry");
							std::thread::sleep(std::time::Duration::from_secs(RETRY_DELAY.into()));
						},
					} // FETCH
				} // RETRY FETCH
			}

			// TODO? : Regular check to use Indexer/Dictionary for missing NFTs?! (with any reason)

			// Read from sync file
			let sync_state = match get_sync_state() {
				Ok(st) => st,
				Err(err) => {
					error!("-- Subscription Task : Can not get sync state : {err:?}");
					continue;
				},
			};

			// Regular CRAWL Check
			if let Ok(last_sync_block) = sync_state.parse::<u32>() {
				trace!("-- Subscription Task : SyncStat = {}", sync_state);

				let last_processed_block = get_processed_block(&state_config).await;

				// Missed any block?
				if (block_number - last_processed_block) > 1 {
					debug!("-- Subscription Task : Crawl check : Lagging last processed block : block number = {} > last processed = {}, last synced = {}", block_number, last_processed_block, last_sync_block);
					match crawl_sync_events(&state_config, last_processed_block, block_number).await
					{
						Ok(cluster_nft_map) => {
							info!(
								"\t-- Subscription Task : Crawl check : Success crawling from {} to {} .",
								last_processed_block, block_number
							);

							if !cluster_nft_map.is_empty() {
								for _retry in 0..RETRY_COUNT {
									match fetch_keyshares(&state_config.clone(), &cluster_nft_map)
										.await
									{
										Ok(_) => {
											info!("\t-- Subscription Task : Crawl check : Success runtime-mode fetching crawled blocks from {} to {} .", last_processed_block, block_number);
											let _ = set_sync_state(block_number.to_string());
											break;
										},

										Err(err) => {
											error!(
												"\t-- Subscription Task : Crawl check : Error during running-mode nft-based syncing : {:?}",
												err
											);
											// We can not proceed to next nft-based sync.
											// Because it'll update the syncing state
											// A retry id needed in next block
											debug!("\t-- Subscription Task : Crawl check : Fetch Keyshares : wait before retry");
											std::thread::sleep(std::time::Duration::from_secs(
												RETRY_DELAY.into(),
											));
										},
									} //Fetch
								} //Retry Fetch
							} else {
								debug!("\t-- Subscription Task : Crawl check : no new event detected in past blocks");
								let _ = set_sync_state(last_processed_block.to_string());
							}
						},

						Err(err) => {
							error!(
								"\t-- Subscription Task : Crawl check : Error runtime-mode crawling from {} to {} .",
								last_processed_block, block_number
							);
							// We can not proceed to next nft-based sync.
							// Because it'll update the syncing state
							// A retry id needed in next block
							debug!("\t-- Subscription Task : Crawl check : wait before retry");
							std::thread::sleep(std::time::Duration::from_secs(RETRY_DELAY.into()));
							continue;
						},
					} // EVENTS CRAWLER
				} // BLOCK LAG DETECTED
			} else {
				// Non Numeric SyncState file content:
				if block_number % 10 == 0 {
					if get_identity(&state_config).await.is_none() {
						debug!("\t-- Subscription Task : <<< Enclave is not registered >>>");
					} else {
						debug!("\t-- Subscription Task : <<< Enclave is never Synced >>>");
					}
				}
				// Prevent Crawling after first registration
				set_processed_block(&state_config, block_number).await;
				continue;
			}

			// Update runtime block tracking variable
			trace!("\t-- Subscription Task : update last processed block");
			set_processed_block(&state_config, block_number).await;
		} // While blocks
	});
}
