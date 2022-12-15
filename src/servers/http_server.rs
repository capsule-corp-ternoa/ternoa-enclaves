use axum::{
	http::{Method, StatusCode},
	routing::{get, get_service, post},
	Json, Router,
	extract::State,
};

use serde_json::{json, Value};
use sp_core::{Pair, crypto::Ss58Codec};
use std::time::SystemTime;

use crate::servers::server_common;

use std::path::PathBuf;
use tower_http::{
	cors::{Any, CorsLayer},
	services::ServeDir,
};

use crate::chain::{
	chain::{get_nft_data_handler, rpc_query, submit_tx},
	nft::{retrieve_secret_shares, store_secret_shares},
};

use crate::backup::admin::{backup_fetch_secrets, backup_push_secrets};
use crate::attestation;


#[derive(Clone)]
pub struct StateConfig {
	pub owner_key: schnorrkel::Keypair,
	pub enclave_key: sp_core::sr25519::Pair,
	pub seal_path: String,
}

/* HTTP Server */
pub async fn http_server(
	port: &u16,
	account: &str,
	certfile: &str,
	keyfile: &str,
	seal_path: &str,
) {
	let account_keys: Vec<&str> = account.split("_").collect();
	let private_bytes = hex::decode(account_keys[0]).expect("Error reading account data");
	let public_bytes = hex::decode(account_keys[1]).expect("Error reading account data");
	let account_pair = schnorrkel::Keypair {secret: schnorrkel::SecretKey::from_bytes(&private_bytes).unwrap(), public: schnorrkel::PublicKey::from_bytes(&public_bytes).unwrap() };
	
	let (enclave_pair, _) = sp_core::sr25519::Pair::generate();
	
	let state_config = StateConfig { owner_key: account_pair, enclave_key: enclave_pair, seal_path: seal_path.to_owned() };

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
		.route("/health", get(get_health_status))
		.layer(cors)
		// TEST APIS
		//.route("/api/generateKey", get(generate_key))
		//.route("/api/getPublicKey", get(get_public_key))
		//.route("/api/getPublicKeyUrl", get(get_public_key_url))
		.route("/api/getNFTData/:nft_id", get(get_nft_data_handler))
		.route("/api/rpcQuery/:blocknumber", get(rpc_query))
		.route("/api/submitTx/:amount", get(submit_tx))
		// CENTRALIZED BACKUP API
		.route("/api/backup/fetchEnclaveSecrets", post(backup_fetch_secrets))
		.route("/api/backup/pushEnclaveSecrets", post(backup_push_secrets))
		// SECRET SHARING API
		.route("/api/nft/storeSecretShares", post(store_secret_shares))
		.route("/api/nft/retrieveSecretShares", post(retrieve_secret_shares))
		.with_state(state_config);

	server_common::serve(http_app, port, certfile, keyfile).await;
}

/*  -------------Handlers------------- */
async fn get_health_status(State(state): State<StateConfig>,) -> Json<Value> {
	let time = SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).unwrap();

	Json(json!({
		"status": 200,
		"date": time.as_secs(),
		"description": "SGX server healthy!".to_string(),
		"encalve_address": state.enclave_key.public().to_ss58check(),
		"operator_address": sp_core::sr25519::Public::from_raw(state.owner_key.public.to_bytes()).to_ss58check(),
		"binary_hash" : self_check(),
		"quote": attestation::ra::generate_quote(),
	}))
}

fn self_check() -> Result<String, String> {
	// Check running address

	use sysinfo::get_current_pid;

	let mut binary_path = match get_current_pid() {
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

	// Verify Ternoa hash/signature
	let bytes = std::fs::read(binary_path.clone()).unwrap();
	let hash = sha256::digest(bytes.as_slice());

	binary_path.pop(); // binary name
	binary_path.pop(); // release
	binary_path.pop(); // target
	binary_path.push("SHA256");
	let binary_hash = std::fs::read_to_string(binary_path.clone())
		.expect(&format!("path not found : {}", binary_path.clone().to_str().unwrap()));

	if binary_hash != hash {
		tracing::error!("Binary hash doesn't match!");
		return Err(hash);
	} else {
		tracing::info!("Binary hash match : {}", hash);
		return Ok(hash);
	}
	
}
