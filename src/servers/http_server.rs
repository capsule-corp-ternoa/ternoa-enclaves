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
use tracing::{debug, error, info, trace};

use std::time::{Duration, SystemTime};

use crate::{
	backup::admin_bulk::{admin_backup_fetch_bulk, admin_backup_push_bulk},
	backup::admin_nftid::admin_backup_fetch_id,
};

use sentry::integrations::tower::{NewSentryLayer, SentryHttpLayer};

use super::server_common;

/// StateConfig shared by all routes
#[derive(Clone)]
pub struct StateConfig {
	enclave_key: sp_core::sr25519::Pair,
	seal_path: String,
	identity: String,
	maintenance: String,
	rpc_client: DefaultApi,
	current_block: u32,
	binary_version: String,
}

impl StateConfig {
	pub fn new(
		enclave_key: sp_core::sr25519::Pair,
		seal_path: String,
		identity: String,
		maintenance: String,
		rpc_client: DefaultApi,
		binary_version: String,
	) -> StateConfig {
		StateConfig {
			enclave_key,
			seal_path,
			identity,
			maintenance,
			rpc_client,
			current_block: 0,
			binary_version,
		}
	}

	pub fn get_key(&self) -> sp_core::sr25519::Pair {
		self.enclave_key.clone()
	}

	pub fn set_key(&mut self, keypair: sp_core::sr25519::Pair) {
		self.enclave_key = keypair;
	}

	pub fn get_seal_path(&self) -> String {
		self.seal_path.clone()
	}

	pub fn set_seal_path(&mut self, path: String) {
		self.seal_path = path;
	}

	pub fn get_identity(&self) -> String {
		self.identity.clone()
	}

	pub fn set_identity(&mut self, id: String) {
		self.identity = id;
	}

	pub fn get_maintenance(&self) -> String {
		self.maintenance.clone()
	}

	pub fn set_maintenance(&mut self, message: String) {
		self.maintenance = message;
	}

	pub fn get_rpc_client(&self) -> DefaultApi {
		self.rpc_client.clone()
	}

	pub fn set_current_block(&mut self, block_number: u32) {
		self.current_block = block_number;
	}

	pub fn get_current_block(&self) -> u32 {
		self.current_block
	}

	pub fn get_binary_version(&self) -> String {
		self.binary_version.clone()
	}
}

pub type SharedState = Arc<RwLock<StateConfig>>;

const CONTENT_LENGTH_LIMIT: usize = 400 * 1024 * 1024;

/// http server
/// # Arguments
/// * `identity` - identity
/// * `seal_path` - seal path
/// # Example
/// ```
/// http_server("identity", "seal_path");
/// ```
pub async fn http_server(identity: &str, seal_path: &str) -> Result<Router, Error> {
	// TODO: publish the key to release folder of sgx_server repository after being open-sourced.
	let enclave_account_file = "/nft/enclave_account.key";

	let enclave_keypair = if std::path::Path::new(enclave_account_file).exists() {
		info!("Enclave Account Exists, Importing it! :, path: {}", enclave_account_file);

		let phrase = match std::fs::read_to_string(enclave_account_file) {
			Ok(phrase) => phrase,
			Err(err) => {
				error!("Error reading enclave account file: {:?}", err);
				return Err(anyhow!(err));
			},
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
		info!("Creating new Enclave Account, Remember to send 1 CAPS to it!");

		let (keypair, phrase, _s_seed) = sp_core::sr25519::Pair::generate_with_phrase(None);
		let mut ekfile = match File::create(&encalve_account_file) {
			Ok(file_handle) => {
				debug!("2-1-3 created encalve keypair file successfully");
				file_handle
			},
			Err(err) => {
				error!("2-1-3 failed to creat encalve keypair file, error : {:?}", err);
				return Err(anyhow!(err));
			},
		};

		match ekfile.write_all(phrase.as_bytes()) {
			Ok(_) => {
				debug!("2-1-4 write encalve keypair to file successfully");
			},
			Err(err) => {
				error!("2-1-4 write encalve keypair to file failed, error : {:?}", err);
				return Err(anyhow!(err));
			},
		}

		keypair
	};

	let rpc = match create_chain_api().await {
		Ok(api) => api,
		Err(err) => {
			error!("2-1-5 get online chain api, error : {:?}", err);
			return Err(anyhow!(err));
		},
	};

	let state_config: SharedState = Arc::new(RwLock::new(StateConfig::new(
		enclave_keypair,
		seal_path.to_owned(),
		identity.to_string(),
		String::new(),
		rpc.clone(),
		"0.4.0".to_string(),
	)));

	let _ = CorsLayer::new()
		// allow `GET` and `POST` when accessing the resource
		.allow_methods([Method::GET, Method::POST])
		// allow requests from any origin
		.allow_origin(Any)
		.allow_headers(Any)
		.allow_credentials(true);

	let monitor_layer = ServiceBuilder::new()
		.layer(NewSentryLayer::new_from_top())
		.layer(SentryHttpLayer::with_transaction());

	debug!("2-2 Defining Routes");
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
		//.layer(RequestBodyLimitLayer::new(CONTENT_LENGTH_LIMIT))
		.layer(
			ServiceBuilder::new()
				.layer(HandleErrorLayer::new(handle_timeout_error))
				.timeout(Duration::from_secs(20)),
		)
		.layer(monitor_layer)
		.layer(CorsLayer::permissive())
		.with_state(Arc::clone(&state_config));

	tokio::spawn(async move {
		// Subscribe to all finalized blocks:
		let mut blocks_sub = match rpc.blocks().subscribe_finalized().await {
			Ok(sub) => sub,
			Err(e) => {
				error!(" Unable to subscribe to finalized blocks {:?}", e);
				return;
			},
		};

		// For each new finalized block, get block number
		while let Some(block) = blocks_sub.next().await {
			let block = match block {
				Ok(blk) => blk,
				Err(e) => {
					error!(" Unable to get finalized block {:?}", e);
					continue;
				},
			};

			let block_number = block.header().number;

			let shared_state_write = &mut state_config.write().await;
			trace!("Block Number Thread : got shared state to write.");

			shared_state_write.set_current_block(block_number);
			debug!("Block Number Thread : block_number state is set to {}", block_number);
		}
	});

	info!("Wait for 3 seconds to update the block number");
	tokio::time::sleep(tokio::time::Duration::from_secs(3)).await;

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
/// Health check endpoint
async fn get_health_status(State(state): State<SharedState>) -> impl IntoResponse {
	debug!("3-3 Healthchek handler.");

	match evalueate_health_status(state).await {
		Some(response) => {
			debug!("3-3-1 Healthchek exit successfully .");
			response.into_response()
		},

		_ => {
			debug!("3-3-1 Healthchek exited with None.");
			(
				StatusCode::INTERNAL_SERVER_ERROR,
				Json(json!({
					"status": 666,
					"description": "Healthcheck returned NONE".to_string()
				})),
			)
				.into_response()
		},
	}
}

//#[once(time = 10, sync_writes = true)]
fn evalueate_health_status(state: &StateConfig) -> Option<Json<Value>> {
	let time: chrono::DateTime<chrono::offset::Utc> = SystemTime::now().into();

	let shared_state = state.read().await;
	let block_number = shared_state.get_current_block();
	let enclave_key = shared_state.get_key();
	let binary_version = shared_state.get_binary_version();

	debug!("3-3-4 healthcheck : get public key.");

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
			Json(json!({
				"status": 500,
				"date": time.format("%Y-%m-%d %H:%M:%S").to_string(),
				"block_number": block_number,
				"version": binary_version,
				"description": maintenance,
				"enclave_address": enclave_address,
			})),
		));
	}

	Some((
		StatusCode::OK,
		Json(json!({
			"status": 200,
			"date": time.format("%Y-%m-%d %H:%M:%S").to_string(),
			"block_number": block_number,
			"version": binary_version,
			"description": "SGX server is running!".to_string(),
			"enclave_address": enclave_address,
		})),
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
