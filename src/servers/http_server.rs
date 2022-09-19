use axum::{
    http::{HeaderValue, Method, StatusCode},
    routing::{get, get_service, post},
    Router,
};

use crate::server_common;
use std::path::PathBuf;
use tower_http::{cors::Any, cors::CorsLayer, services::ServeDir};

use crate::chain::chain::{get_constant, get_nft_data_handler, rpc_query, submit_tx};
use crate::chain::nft::{retrieve_secret_shares, store_secret_shares};
use crate::keys::pgp_keys::{generate_key, get_public_key, get_public_key_url};

/* HTTP Server */
pub async fn http_server(port: &u16) {
    let assets_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("assets");
    let cors = CorsLayer::new()
        // allow `GET` and `POST` when accessing the resource
        .allow_methods([Method::GET, Method::POST])
        // allow requests from any origin
        .allow_origin(Any)
        /* .allow_origin(
            ("http://127.0.0.1:".to_owned() + &port.to_string())
                .parse::<HeaderValue>()
                .unwrap(),
        )*/
        ;

    let http_app = Router::new()
        .fallback(
            get_service(ServeDir::new(assets_dir).append_index_html_on_directories(true))
                .handle_error(|error: std::io::Error| async move {
                    (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        format!("Unhandled internal error: {}", error),
                    )
                }),
        )
        .route("/", get(health_handler))
        .layer(cors)
        // TEST APIS
        .route("/api/generateKey", get(generate_key))
        .route("/api/getPublicKey", get(get_public_key))
        .route("/api/getPublicKeyUrl", get(get_public_key_url))
        .route("/api/getNFTData/:nft_id", get(get_nft_data_handler))
        .route("/api/rpcQuery/:blocknumber", get(rpc_query))
        .route("/api/submitTx/:amount", get(submit_tx))
        // SECRET SHARING API
        .route("/api/nft/storeSecretShares", post(store_secret_shares))
        .route("/api/nft/retrieveSecretShares",get(retrieve_secret_shares),
        );

    server_common::serve(http_app, port).await;
}

/* Different Responses  */

// TEXT
async fn health_handler() -> &'static str {
    "Server is running!\n"
}
