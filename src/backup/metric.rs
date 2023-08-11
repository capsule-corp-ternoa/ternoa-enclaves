use crate::{
	backup::sync::ValidationResult,
	chain::{
		constants::{MAX_BLOCK_VARIATION, MAX_VALIDATION_PERIOD},
		core::{get_metric_server, MetricServer},
	},
	servers::state::{get_blocknumber, SharedState},
};
use axum::{extract::State, response::IntoResponse, Json};
use hex::{FromHex, FromHexError};
use hyper::StatusCode;
use serde::{Deserialize, Serialize};
use serde_json::json;
use sp_core::{
	crypto::{PublicError, Ss58Codec},
	sr25519::{Public, Signature},
	Pair,
};

use tracing::{debug, error};

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct AuthenticationToken {
	pub block_number: u32,
	pub block_validation: u8,
	pub data_hash: String,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct MetricNftListRequest {
	pub metric_account: String,
	pub block_interval: String,
	pub auth_token: String,
	pub signature: String,
}

impl AuthenticationToken {
	pub async fn is_valid(&self, last_block_number: u32) -> ValidationResult {
		if last_block_number < self.block_number - MAX_BLOCK_VARIATION {
			// for finalization delay
			debug!(
				"METRIC : last block number = {} < request block number = {}",
				last_block_number, self.block_number
			);
			return ValidationResult::ExpiredBlockNumber;
		}

		if self.block_validation > (MAX_VALIDATION_PERIOD as u8) {
			// A finite validity period
			return ValidationResult::InvalidPeriod;
		}

		if last_block_number
			> self.block_number + ((self.block_validation + MAX_BLOCK_VARIATION as u8) as u32)
		{
			// validity period
			return ValidationResult::FutureBlockNumber;
		}

		ValidationResult::Success
	}
}

async fn verify_account_id(state: &SharedState, account_id: &str) -> bool {
	debug!("METRIC : Verify Metric-Server Accound Id");

	if let Some(metric_vec) = get_metric_server(state).await {
		let contain: Vec<MetricServer> = metric_vec
			.into_iter()
			.filter(|ms| ms.metrics_server_address.to_string() == account_id)
			.collect();
		if contain.len() == 1 {
			return true;
		}
	} else {
		error!("METRIC : No metric server is registered on blockchain.");
	}

	false
}

fn get_public_key(account_id: &str) -> Result<Public, PublicError> {
	let pk: Result<Public, PublicError> =
		Public::from_ss58check(account_id).map_err(|err: PublicError| {
			debug!("METRIC : Error constructing public key {:?}", err);
			err
		});

	pk
}

fn get_signature(signature: String) -> Result<Signature, FromHexError> {
	let stripped = match signature.strip_prefix("0x") {
		Some(sig) => sig,
		None => signature.as_str(),
	};

	match <[u8; 64]>::from_hex(stripped) {
		Ok(s) => {
			let sig = Signature::from_raw(s);
			Ok(sig)
		},
		Err(err) => Err(err),
	}
}

fn verify_signature(account_id: &str, signature: String, message: &[u8]) -> bool {
	match get_public_key(account_id) {
		Ok(pk) => match get_signature(signature) {
			Ok(val) => sp_core::sr25519::Pair::verify(&val, message, &pk),
			Err(err) => {
				debug!("METRIC : Error get signature {:?}", err);
				false
			},
		},
		Err(_) => {
			debug!("METRIC : Error get public key from account-id");
			false
		},
	}
}

async fn update_health_status(state: &SharedState, message: String) {
	let shared_state_write = &mut state.write().await;
	debug!("METRIC : got shared state to write.");

	shared_state_write.set_maintenance(message);
	debug!("METRIC : Maintenance state is set.");
}

pub async fn error_handler(message: String, state: &SharedState) -> impl IntoResponse {
	error!(message);
	update_health_status(state, String::new()).await;
	(StatusCode::BAD_REQUEST, Json(json!({ "error": message })))
}

/* --------------------
  METRIC GET NFT LIST
--------------------*/
pub async fn metric_reconcilliation(
	State(state): State<SharedState>,
	Json(request): Json<MetricNftListRequest>,
) -> impl IntoResponse {
	debug!("\n\t**\nMETRIC GET NFT LIST IN BLOCK INTERVAL\n\t**\n");
	let last_block_number = get_blocknumber(&state).await;

	debug!("METRIC GET NFT LIST : VERIFY ACCOUNT ID");
	if verify_account_id(&state, &request.metric_account).await {
		let message =
			"METRIC GET NFT LIST : Error : Requester Account is not authorized".to_string();
		return error_handler(message, &state).await.into_response();
	};

	let mut auth = request.auth_token.clone();

	if auth.starts_with("<Bytes>") && auth.ends_with("</Bytes>") {
		auth = match auth.strip_prefix("<Bytes>") {
			Some(stripped) => stripped.to_owned(),
			_ => {
				return error_handler(
					"METRIC GET NFT LIST : Strip Token prefix error".to_string(),
					&state,
				)
				.await
				.into_response();
			},
		};

		auth = match auth.strip_suffix("</Bytes>") {
			Some(stripped) => stripped.to_owned(),
			_ => {
				return error_handler(
					"METRIC GET NFT LIST : Strip Token suffix error".to_string(),
					&state,
				)
				.await
				.into_response();
			},
		}
	}

	let auth_token: AuthenticationToken = match serde_json::from_str(&auth) {
		Ok(token) => token,
		Err(e) => {
			let message = format!(
				"METRIC GET NFT LIST : Error : Authentication token is not parsable : {}",
				e
			);
			return error_handler(message, &state).await.into_response();
		},
	};

	debug!("METRIC GET NFT LIST : VERIFY SIGNATURE");
	if !verify_signature(
		&request.metric_account.clone(),
		request.signature.clone(),
		request.auth_token.as_bytes(),
	) {
		return error_handler("METRIC GET NFT LIST : Invalid Signature".to_string(), &state)
			.await
			.into_response();
	}

	debug!("METRIC GET NFT LIST : Validating the authentication token");
	let validity = auth_token.is_valid(last_block_number).await;
	match validity {
		ValidationResult::Success => debug!("METRIC GET NFT LIST : Authentication token is valid."),
		_ => {
			let message = format!(
				"METRIC GET NFT LIST : Authentication Token is not valid, or expired : {:?}",
				validity
			);
			return error_handler(message, &state).await.into_response();
		},
	}

	let hash = sha256::digest(request.block_interval.as_bytes());

	if auth_token.data_hash != hash {
		return error_handler("METRIC GET NFT LIST : Mismatch Data Hash".to_string(), &state)
			.await
			.into_response();
	}

	let interval: Vec<u32> = match serde_json::from_str(&request.block_interval) {
		Ok(interval) => interval,
		Err(e) => {
			let message = format!(
				"METRIC GET NFT LIST : Error : Authentication token is not parsable : {}",
				e
			);
			return error_handler(message, &state).await.into_response();
		},
	};

	if interval.len() != 2 || interval[0] >= interval[1] {
		let message = "METRIC GET NFT LIST : Error : Invalid provided block interval".to_string();
		return error_handler(message, &state).await.into_response();
	}

	let shared_state_read = state.read().await;
	let nft_list = shared_state_read.get_nft_availability_map();
	let nftid: Vec<u32> = nft_list
		.into_iter()
		.filter(|(_, v)| v.block_number > interval[0] && v.block_number < interval[1])
		.map(|(k, _)| k)
		.collect();

	(
		StatusCode::OK,
		Json(json!({
			"nftid": nftid
		})),
	)
		.into_response()
}