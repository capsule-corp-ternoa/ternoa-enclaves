use axum::{
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
	chain::{get_nft_data_handler, rpc_query, submit_tx},
	nft::{retrieve_secret_shares, store_secret_shares},
};

use crate::backup::admin::{backup_fetch_secrets, backup_push_secrets};

#[derive(Clone)]
pub struct StateConfig {
	pub ternoa_key: Vec<u8>,
	pub secret_path: String,
}

/* HTTP Server */
pub async fn http_server(
	port: &u16,
	account: Vec<u8>,
	certfile: &str,
	keyfile: &str,
	secret_path: &str,
) {
	let state_config = StateConfig { ternoa_key: account, secret_path: secret_path.to_owned() };

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
async fn get_health_status() -> Json<Value> {
	let time = SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).unwrap();

	Json(json!({
		"status": 200,
		"date": time.as_secs(),
		"description": "SGX server healthy!".to_string()
	}))
}
