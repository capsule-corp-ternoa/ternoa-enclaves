use axum::{
	extract::State,
	http::{Method, StatusCode},
	routing::{get, get_service, post},
	Json, Router,
};

use reqwest;

use sp_core::Pair;
use tower_http::{
	cors::{Any, CorsLayer},
	services::ServeDir,
};

use tower::ServiceBuilder;

use anyhow::{anyhow, Error};

use serde_json::{json, Value};
use tracing::{error, info};

use std::{path::PathBuf, time::SystemTime};

use crate::servers::server_common;

use crate::chain::{
	capsule::{
		capsule_get_views, capsule_remove_keyshare, capsule_retrieve_keyshare,
		capsule_set_keyshare, is_capsule_available,
	},
	nft::{
		is_nft_available, nft_get_views, nft_remove_keyshare, nft_retrieve_keyshare,
		nft_store_keyshare,
	},
};

use crate::{
	backup::admin::{backup_fetch_keyshares, backup_push_keyshares},
	pgp::cosign,
};

use cached::proc_macro::once;
use sentry::integrations::tower::{NewSentryLayer, SentryHttpLayer};

use std::{
	fs::File,
	io::{Read, Write},
};

#[derive(Clone)]
pub struct StateConfig {
	pub enclave_key: sp_core::sr25519::Pair,
	pub seal_path: String,
	pub identity: String,
}

/* HTTP Server */
pub async fn http_server(domain: &str, port: &u16, identity: &str, seal_path: &str) {
	// TODO: publish the key to release folder of sgx_server repository after being open-sourced.
	let encalve_account_file = "/nft/enclave_account.key";

	let enclave_keypair = if std::path::Path::new(&encalve_account_file.clone()).exists() {
		info!("Enclave Account Exists, Importing it! :, path: {}", encalve_account_file);

		let mut ekfile = File::open(&encalve_account_file.clone()).unwrap();
		let mut phrase = String::new();
		ekfile.read_to_string(&mut phrase).unwrap();
		let (keypair, _seed) = sp_core::sr25519::Pair::from_phrase(&phrase, None).unwrap();

		keypair
	} else {
		info!("Creating new Enclave Account, Remember to send 1 CAPS to it!");
		let (keypair, phrase, s_seed) = sp_core::sr25519::Pair::generate_with_phrase(None);
		let mut ekfile = File::open(&encalve_account_file.clone()).unwrap();
		ekfile.write_all(phrase.as_bytes()).unwrap();

		keypair

		/*
		let mut entropy = [0u8; 32];
		rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut entropy);
		let enclave_pair = sp_core::sr25519::Pair::from_entropy(&entropy, None);
		enclave_pair.0
		*/
	};

	let state_config = StateConfig {
		enclave_key: enclave_keypair,
		seal_path: seal_path.to_owned(),
		identity: identity.to_string(),
	};

	let assets_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("assets");

	let _cors = CorsLayer::new()
		// allow `GET` and `POST` when accessing the resource
		.allow_methods([Method::GET, Method::POST])
		// allow requests from any origin
		.allow_origin(Any)
		.allow_headers(Any)
		.allow_credentials(true);

	let monitor_layer = ServiceBuilder::new()
		.layer(NewSentryLayer::new_from_top())
		.layer(SentryHttpLayer::with_transaction());

	let http_app = Router::new()
		.fallback_service(
			get_service(ServeDir::new(assets_dir).append_index_html_on_directories(true))
				.handle_error(|error: std::io::Error| async move {
					(
						StatusCode::INTERNAL_SERVER_ERROR,
						format!("Unhandled internal error: {}", error),
					)
				}),
		)
		// STATE API
		.route("/api/health", get(get_health_status))
		// CENTRALIZED BACKUP API
		.route("/api/backup/fetch-keyshares", post(backup_fetch_keyshares))
		.route("/api/backup/push-keyshares", post(backup_push_keyshares))
		.route("/api/backup/fetch-bulk", post(backup_fetch_keyshares))
		.route("/api/backup/push-bulk", post(backup_push_keyshares))
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
		.layer(monitor_layer)
		.layer(CorsLayer::permissive())
		.with_state(state_config);

	server_common::serve(http_app, domain, port).await.unwrap(); // TODO: manage unwrap()
}

async fn get_health_status(State(state): State<StateConfig>) -> Json<Value> {
	evalueate_health_status(&state).unwrap()
}

#[once(time = 1000, option = true, sync_writes = true)]
fn evalueate_health_status(state: &StateConfig) -> Option<Json<Value>> {
	let time: chrono::DateTime<chrono::offset::Utc> = SystemTime::now().into();

	//let quote_vec = attestation::ra::generate_quote();

	let checksum = self_checksum();

	let binary_path = match sysinfo::get_current_pid() {
		Ok(pid) => {
			let path_string = "/proc/".to_owned() + &pid.to_string() + "/exe";
			let binpath = std::path::Path::new(&path_string).read_link().unwrap(); // TODO: manage unwrap()
			binpath
		},
		Err(e) => {
			info!("failed to get current pid: {}", e);
			std::path::PathBuf::new()
		},
	};

	let signed_data = std::fs::read(binary_path.clone()).unwrap(); // TODO: manage unwrap()

	// TODO: Read from github release path
	let sigfile = binary_path.to_string_lossy().to_string() + ".sig";

	let mut signature_data = std::fs::read_to_string(sigfile).unwrap(); // TODO: manage unwrap()

	signature_data = signature_data.replace("\n", "");

	let signature = match cosign::verify(&signed_data, &signature_data) {
		Ok(b) => match b {
			true => "Successful".to_string(),
			false => "Failed".to_string(),
		},
		Err(e) => format!("Binary verification Error, {}", e),
	};

	let pubkey: [u8; 32] = state.enclave_key.as_ref().to_bytes()[64..].try_into().unwrap(); // TODO: manage unwrap()

	let enclave_address = sp_core::sr25519::Public::from_raw(pubkey);

	Some(Json(json!({
		"status": 200,
		"date": time.format("%Y-%m-%d %H:%M:%S").to_string(),
		"description": "SGX server is running!".to_string(),
		"enclave_address": enclave_address,
		"binary_hash" : checksum,
		"binary_signature": signature,
		//"quote": quote_vec,
	})))
}

fn self_checksum() -> Result<String, String> {
	// Get binary address on disk
	// BUT in gramine, the binary is simply at root directory!
	let mut binary_path = match sysinfo::get_current_pid() {
		Ok(pid) => {
			let path_string = "/proc/".to_owned() + &pid.to_string() + "/exe";
			let binpath = std::path::Path::new(&path_string).read_link().unwrap(); // TODO: manage unwrap()
			binpath
		},
		Err(e) => {
			error!("failed to get current pid: {}", e);
			std::path::PathBuf::new()
		},
	};

	// Verify Ternoa checksum/signature
	let bytes = std::fs::read(binary_path.clone()).unwrap(); // TODO: manage unwrap()
	let hash = sha256::digest(bytes.as_slice());

	// TODO: Get checksum from github release
	binary_path.pop(); // remove binary name
	binary_path.push("checksum");

	let binary_hash = std::fs::read_to_string(binary_path.clone()).expect(&format!(
		"Binary-checksum path not found : {}",
		binary_path.clone().to_str().unwrap()
	)); // TODO: manage expect()

	let binary_hash = binary_hash
		.strip_suffix("\r\n")
		.or(binary_hash.strip_suffix("\n"))
		.unwrap_or(&binary_hash);

	if binary_hash != hash {
		info!("Binary hash doesn't match!");
		return Err(hash)
	} else {
		info!("Binary hash match : {}", hash);
		return Ok(hash)
	}
}

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
