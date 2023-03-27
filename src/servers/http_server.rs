#![allow(dead_code)]
#![allow(unused_imports)]
#![allow(unused_variables)]

use axum::{
	error_handling::HandleErrorLayer,
	extract::State,
	http::{Method, StatusCode, Uri},
	routing::{get, post},
	BoxError, Json, Router,
};

use reqwest;

use sp_core::Pair;
use tower_http::cors::{Any, CorsLayer};

use anyhow::{anyhow, Error};
use tower::ServiceBuilder;

use serde_json::{json, Value};
use tracing::{debug, error, info};

use std::time::{Duration, SystemTime};

use crate::{chain::{
	capsule::{
		capsule_get_views, capsule_remove_keyshare, capsule_retrieve_keyshare,
		capsule_set_keyshare, is_capsule_available,
	},
	nft::{
		is_nft_available, nft_get_views, nft_remove_keyshare, nft_retrieve_keyshare,
		nft_store_keyshare,
	},
}, attestation::ra::ra_get_quote};

use crate::{
	backup::admin::{admin_backup_fetch_bulk, admin_backup_push_bulk},
	sign::cosign,
};

use sentry::integrations::tower::{NewSentryLayer, SentryHttpLayer};

use std::{fs::File, io::Write};

use super::server_common;

/// StateConfig shared by all routes
#[derive(Clone)]
pub struct StateConfig {
	pub enclave_key: sp_core::sr25519::Pair,
	pub seal_path: String,
	pub identity: String,
}

/// http server
/// # Arguments
/// * `domain` - domain name
/// * `port` - port number
/// * `identity` - identity
/// * `seal_path` - seal path
/// # Example
/// ```
/// http_server("localhost", 8080, "identity", "seal_path");
/// ```
pub async fn http_server(domain: &str, port: &u16, identity: &str, seal_path: &str) {
	// TODO: publish the key to release folder of sgx_server repository after being open-sourced.
	let enclave_account_file = "/nft/enclave_account.key";

	let enclave_keypair = if std::path::Path::new(enclave_account_file).exists() {
		info!("Enclave Account Exists, Importing it! :, path: {}", enclave_account_file);

		let phrase = match std::fs::read_to_string(enclave_account_file) {
			Ok(phrase) => phrase,
			Err(err) => {
				error!("Error reading enclave account file: {:?}", err);
				return
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
			Err(e) => {
				debug!("2-1-3 failed to creat encalve keypair file, error : {:?}", e);
				return
			},
		};

		match ekfile.write_all(phrase.as_bytes()) {
			Ok(_) => {
				debug!("2-1-4 write encalve keypair to file successfully");
			},
			Err(e) => {
				debug!("2-1-4 write encalve keypair to file failed, error : {:?}", e);
				return
			},
		}

		keypair
	};

	let state_config = StateConfig {
		enclave_key: enclave_keypair,
		seal_path: seal_path.to_owned(),
		identity: identity.to_string(),
	};

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
		.route("/api/backup/fetch-bulk", post(admin_backup_fetch_bulk))
		.route("/api/backup/push-bulk", post(admin_backup_push_bulk))
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
		.layer(
			ServiceBuilder::new()
				.layer(HandleErrorLayer::new(handle_timeout_error))
				.timeout(Duration::from_secs(10)),
		)
		.layer(monitor_layer)
		.layer(CorsLayer::permissive())
		.with_state(state_config);

	debug!("2-3 Starting Server with routes");
	match server_common::serve(http_app, domain, port).await {
		Ok(_) => debug!("2-4 server exited successfully"),
		Err(e) => error!("2-4 server exited with error : {:?}", e),
	}
}

/*  ------------------------------
		ERROR HANDLING
------------------------------ */
/// Handle errors from the router.
/// This is a catch-all handler that will be called for any error that isn't handled by a route.
async fn handle_timeout_error(_method: Method, _uri: Uri, err: BoxError) -> (StatusCode, String) {
	debug!("3-1 Timeout Handler start");
	if err.is::<tower::timeout::error::Elapsed>() {
		debug!("3-1-1 Timeout Handler : Request took too long.");
		(StatusCode::REQUEST_TIMEOUT, "Request took too long".to_string())
	} else {
		debug!("3-1-1 Timeout Handler : unhandled internal error.");
		(StatusCode::INTERNAL_SERVER_ERROR, format!("Unhandled internal error: {err}"))
	}
}

/// Handle errors from the router.
async fn fallback(uri: axum::http::Uri) -> Json<Value> {
	debug!("3-2 Fallback handler for {uri}");
	Json(json!({
		"status": 432,
		"description": format!("No route to {}",uri),
	}))
}

/*  ------------------------------
	HEALTH CHECK
------------------------------ */
/// Health check endpoint
async fn get_health_status(State(state): State<StateConfig>) -> Json<Value> {
	debug!("3-3 Healthchek handler.");
	match evalueate_health_status(&state) {
		Some(json_val) => {
			debug!("3-3-1 Healthchek exit successfully .");
			json_val
		},

		_ => {
			debug!("3-3-1 Healthchek exited with None.");
			Json(json!({
				"status": 433,
				"description": "Healthcheck returned NONE".to_string()
			}))
		},
	}
}

//#[once(time = 10, sync_writes = true)]
fn evalueate_health_status(state: &StateConfig) -> Option<Json<Value>> {
	let time: chrono::DateTime<chrono::offset::Utc> = SystemTime::now().into();

	debug!("3-3-4 healthcheck : get public key.");
	let pubkey: [u8; 32] = match state.enclave_key.as_ref().to_bytes()[64..].try_into() {
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

	Some(Json(json!({
		"status": 200,
		"date": time.format("%Y-%m-%d %H:%M:%S").to_string(),
		"description": "SGX server is running!".to_string(),
		"enclave_address": enclave_address,
		//"quote": quote_vec,
	})))
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
