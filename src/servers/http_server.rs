use axum::{
	extract::State,
	http::{Method, StatusCode},
	routing::{get, get_service, post},
	Json, Router,
};

use serde_json::{json, Value};
use std::time::SystemTime;

use crate::servers::server_common;

use std::path::PathBuf;
use tower_http::{
	cors::{Any, CorsLayer},
	services::ServeDir,
};

use crate::chain::{
	capsule::{
		capsule_get_views_handler, capsule_remove_secret_shares, capsule_retrieve_secret_shares,
		capsule_set_secret_shares, is_capsule_available,
	},
	chain::{get_nft_data_handler, rpc_query, submit_tx},
	nft::{
		is_nft_available, nft_get_views_handler, nft_remove_secret_shares,
		nft_retrieve_secret_shares, nft_store_secret_shares,
	},
};

use crate::backup::admin::{backup_fetch_secrets, backup_push_secrets};
use crate::pgp::cosign;

#[derive(Clone)]
pub struct StateConfig {
	pub enclave_key: sp_core::sr25519::Pair,
	pub seal_path: String,
	pub identity: String,
}

/* HTTP Server */
pub async fn http_server(
	port: &u16,
	identity: &str,
	certfile: &str,
	keyfile: &str,
	seal_path: &str,
) {

	let mut entropy = [0u8; 32];
	rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut entropy);
	let enclave_pair = sp_core::sr25519::Pair::from_entropy(&entropy, None);

	let state_config = StateConfig {
		enclave_key: enclave_pair.0,
		seal_path: seal_path.to_owned(),
		identity: identity.to_string(),
	};

	let assets_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("assets");

	let cors = CorsLayer::new()
		// allow `GET` and `POST` when accessing the resource
		.allow_methods([Method::GET, Method::POST])
		// allow requests from any origin
		.allow_origin(Any);

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
		.layer(cors)
		// STATE API
		.route("/health", get(get_health_status))
		// CENTRALIZED BACKUP API
		.route("/api/backup/fetchEnclaveSecrets", post(backup_fetch_secrets))
		.route("/api/backup/pushEnclaveSecrets", post(backup_push_secrets))
		// NFT SECRET SHARING API
		.route("/api/nft/getViewsLog/:nft_id", get(nft_get_views_handler))
		.route("/api/nft/isSecretAvailable/:nft_id", get(is_nft_available))
		.route("/api/nft/storeSecretShares", post(nft_store_secret_shares))
		.route("/api/nft/retrieveSecretShares", post(nft_retrieve_secret_shares))
		.route("/api/nft/removeSecretShares", post(nft_remove_secret_shares))
		// CAPSULE SECRET SHARING API
		.route("/api/capsule/getViewsLog/:capsule_id", get(capsule_get_views_handler))
		.route("/api/capsule/isSecretAvailable/:nft_id", get(is_capsule_available))
		.route("/api/capsule/setSecretShares", post(capsule_set_secret_shares))
		.route("/api/capsule/retrieveSecretShares", post(capsule_retrieve_secret_shares))
		.route("/api/capsule/removeSecretShares", post(capsule_remove_secret_shares))
		// TEST APIS
		.route("/api/getNFTData/:nft_id", get(get_nft_data_handler))
		.route("/api/rpcQuery/:blocknumber", get(rpc_query))
		.route("/api/submitTx/:amount", get(submit_tx))
		.with_state(state_config);

	server_common::serve(http_app, port, certfile, keyfile).await;
}

/*  -------------Handlers------------- */

// TODO: check the request for signed data and prevent flooding requests.
async fn get_health_status(State(state): State<StateConfig>) -> Json<Value> {
	let time: chrono::DateTime<chrono::offset::Utc> = SystemTime::now().into();

	// TODO: cache the quote for 24 hours, not to generate it in every call.
	//let quote_vec = attestation::ra::generate_quote();

	let checksum = self_checksum();

	let binary_path = match sysinfo::get_current_pid() {
		Ok(pid) => {
			let path_string = "/proc/".to_owned() + &pid.to_string() + "/exe";
			let binpath = std::path::Path::new(&path_string).read_link().unwrap();
			binpath
		},
		Err(e) => {
			tracing::error!("failed to get current pid: {}", e);
			std::path::PathBuf::new()
		},
	};

	let signed_data = std::fs::read(binary_path.clone()).unwrap();

	// TODO: Read from github release path
	let sigfile = binary_path.to_string_lossy().to_string() + ".sig";

	let mut signature_data = std::fs::read_to_string(sigfile).unwrap();

	signature_data = signature_data.replace("\n", "");

	let signature = match cosign::verify(&signed_data, &signature_data) {
		Ok(b) => match b {
			true => "Successful".to_string(),
			false => "Failed".to_string(),
		},
		Err(e) => format!("Binary verification Error, {}", e),
	};

	let pubkey: [u8; 32] = state.enclave_key.as_ref().to_bytes()[64..].try_into().unwrap();

	let enclave_address = sp_core::sr25519::Public::from_raw(pubkey);

	Json(json!({
		"status": 200,
		"date": time.format("%Y-%m-%d %H:%M:%S").to_string(),
		"description": "SGX server is running!".to_string(),
		"enclave_address": enclave_address,
		"binary_hash" : checksum,
		"binary_signature": signature,
		//"quote": quote_vec,
	}))
}

fn self_checksum() -> Result<String, String> {
	// Get binary address on disk
	// BUT in gramine, the binary is simply at root directory!
	let mut binary_path = match sysinfo::get_current_pid() {
		Ok(pid) => {
			let path_string = "/proc/".to_owned() + &pid.to_string() + "/exe";
			let binpath = std::path::Path::new(&path_string).read_link().unwrap();
			binpath
		},
		Err(e) => {
			tracing::error!("failed to get current pid: {}", e);
			std::path::PathBuf::new()
		},
	};

	// Verify Ternoa checksum/signature
	let bytes = std::fs::read(binary_path.clone()).unwrap();
	let hash = sha256::digest(bytes.as_slice());
	
	// TODO: Get checksum from github release 
	binary_path.pop(); // remove binary name
	binary_path.push("checksum");

	let binary_hash = std::fs::read_to_string(binary_path.clone()).expect(&format!(
		"Binary-checksum path not found : {}",
		binary_path.clone().to_str().unwrap()
	));

	let binary_hash = binary_hash
		.strip_suffix("\r\n")
		.or(binary_hash.strip_suffix("\n"))
		.unwrap_or(&binary_hash);

	if binary_hash != hash {
		tracing::error!("Binary hash doesn't match!");
		return Err(hash);
	} else {
		tracing::info!("Binary hash match : {}", hash);
		return Ok(hash);
	}
}
