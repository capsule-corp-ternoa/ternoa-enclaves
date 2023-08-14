#![allow(dead_code)]
#![allow(unused_imports)]

use std::{
	collections::HashMap,
	ffi::OsStr,
	fs::{self, remove_file},
	io::{self, Write},
	net::SocketAddr,
	os::unix::prelude::PermissionsExt,
	path::Path,
};

use axum::{
	body::StreamBody, extract::ConnectInfo, extract::State, http::header, http::StatusCode,
	response::IntoResponse, Json,
};
use hex::{FromHex, FromHexError};
use reqwest::tls;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use sp_core::{
	crypto::{PublicError, Ss58Codec},
	sr25519::{self, Signature},
	Pair,
};

use subxt::{
	blocks::{BlockBody, ExtrinsicEvents},
	rpc::types::BlockNumber,
	storage::Storage,
	utils::AccountId32,
	OnlineClient, PolkadotConfig,
};

use tokio_util::io::ReaderStream;

use tracing::{debug, error, info, trace, warn};
use zip::result::ZipError;

use crate::{
	attestation::ra::{get_quote_content, write_user_report_data, QuoteResponse},
	backup::zipdir::{add_list_zip, zip_extract},
	chain::{
		constants::{
			ATTESTATION_SERVER_URL, MAX_BLOCK_VARIATION, MAX_VALIDATION_PERIOD, SEALPATH,
			SYNC_STATE_FILE, VERSION,
		},
		core::{
			ternoa,
			ternoa::nft::events::{CapsuleSynced, SecretNFTSynced},
		},
		helper::{Availability, NftType},
	},
	servers::{
		http_server::HealthResponse,
		state::{
			get_accountid, get_blocknumber, get_chain_api, get_clusters, get_identity, get_keypair,
			get_nft_availability, set_clusters, set_identity, set_nft_availability, SharedState,
		},
	},
};

use anyhow::{anyhow, Result};

/* ---------------------------------------
	SYNC NEW KEYSHARES TO OTHER ENCLAVES
------------------------------------------ */
#[derive(Debug, Clone)]
pub struct Enclave {
	slot: u32,
	operator_account: AccountId32,
	enclave_account: AccountId32,
	enclave_url: String,
}

#[derive(Debug, Clone, PartialEq)]
pub enum ClusterType {
	Public,
	Private,
	Admin,
	Disabled,
}

#[derive(Debug, Clone)]
pub struct Cluster {
	id: u32,
	cluster_type: ClusterType,
	enclaves: Vec<Enclave>,
}

/* *************************************
	FETCH  NFTID DATA STRUCTURES
**************************************** */
// Validity time of Keyshare Data
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct AuthenticationToken {
	pub block_number: u32,
	pub block_validation: u8,
	pub data_hash: String,
	pub quote_hash: String,
}

/// Fetch NFTID Data
#[derive(Serialize, Deserialize, Debug)]
pub struct FetchIdPacket {
	enclave_account: String,
	nftid_vec: String,
	quote: String,
	auth_token: String,
	signature: String,
}

/// Fetch NFTID Response
#[derive(Serialize)]
pub struct FetchIdResponse {
	data: String,
	signature: String,
}

/* ----------------------------------
AUTHENTICATION TOKEN IMPLEMENTATION
----------------------------------*/
#[derive(Debug)]
pub enum ValidationResult {
	Success,
	ErrorRpcCall,
	ExpiredBlockNumber,
	FutureBlockNumber,
	InvalidPeriod,
}

/// Retrieving the stored Keyshare
impl AuthenticationToken {
	pub async fn is_valid(&self, last_block_number: u32) -> ValidationResult {
		if last_block_number < self.block_number - MAX_BLOCK_VARIATION {
			// for finalization delay
			debug!(
				"last block number = {} < request block number = {}",
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

/* *************************************
		 VERIFICATION FUNCTIONS
**************************************** */

fn verify_account_id(
	slot_enclaves: Vec<(u32, Enclave)>,
	account_id: &String,
	address: SocketAddr,
) -> Option<(u32, Enclave)> {
	// TODO [future security] : can we check requester URL or IP? What if it uses proxy?
	debug!("Verify Accound Id : Requester Address : {}", address);

	let registered =
		slot_enclaves.iter().find(|(_, enclave)| {
			enclave.enclave_account.to_string() == *account_id
		} /*&& (address == enclave.enclave_url)*/);

	registered.cloned()
}

fn get_public_key(account_id: &str) -> Result<sr25519::Public, PublicError> {
	let pk: Result<sr25519::Public, PublicError> = sr25519::Public::from_ss58check(account_id)
		.map_err(|err: PublicError| {
			debug!("Error constructing public key {:?}", err);
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
			let sig = sr25519::Signature::from_raw(s);
			Ok(sig)
		},
		Err(err) => Err(err),
	}
}

fn verify_signature(account_id: &str, signature: String, message: &[u8]) -> bool {
	match get_public_key(account_id) {
		Ok(pk) => match get_signature(signature) {
			Ok(val) => sr25519::Pair::verify(&val, message, &pk),
			Err(err) => {
				debug!("Error get signature {:?}", err);
				false
			},
		},
		Err(_) => {
			debug!("Error get public key from account-id");
			false
		},
	}
}

async fn update_health_status(state: &SharedState, message: String) {
	let shared_state_write = &mut state.write().await;
	debug!("got shared state to write.");

	shared_state_write.set_maintenance(message);
	debug!("Maintenance state is set.");
}

pub async fn error_handler(message: String, state: &SharedState) -> impl IntoResponse {
	error!(message);
	update_health_status(state, String::new()).await;
	(StatusCode::BAD_REQUEST, Json(json!({ "error": message })))
}

/// Sync Key Shares (Server Side)
/// This function is used to backup the key shares of the validators
/// # Arguments
/// * `state` - StateConfig
/// * `backup_request` - BackupRequest

#[axum::debug_handler]
pub async fn sync_keyshares(
	State(state): State<SharedState>,
	ConnectInfo(addr): ConnectInfo<SocketAddr>,
	Json(request): Json<FetchIdPacket>,
) -> impl IntoResponse {
	debug!("\n\t----\nSYNC KEYSHARES : START\n\t----\n");

	//update_health_status(&state, "Enclave is Syncing Keyshare, please wait...".to_string()).await;

	let last_block_number = get_blocknumber(&state).await;

	debug!("SYNC KEYSHARES : START CLUSTER DISCOVERY");
	let slot_enclaves = slot_discovery(&state).await;

	debug!("SYNC KEYSHARES : VERIFY ACCOUNT ID");
	let requester = match verify_account_id(slot_enclaves, &request.enclave_account, addr) {
		Some(enclave) => enclave,
		None => {
			let message = format!(
				"SYNC KEYSHARES : Error : Requester is not authorized, address: {}, ",
				addr
			);

			return error_handler(message, &state).await.into_response();
		},
	};

	let mut auth = request.auth_token.clone();

	if auth.starts_with("<Bytes>") && auth.ends_with("</Bytes>") {
		auth = match auth.strip_prefix("<Bytes>") {
			Some(stripped) => stripped.to_owned(),
			_ => {
				return error_handler(
					"SYNC KEYSHARES : Strip Token prefix error".to_string(),
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
					"SYNC KEYSHARES : Strip Token suffix error".to_string(),
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
			let message =
				format!("SYNC KEYSHARES : Error : Authentication token is not parsable : {}", e);
			return error_handler(message, &state).await.into_response();
		},
	};

	debug!("SYNC KEYSHARES : VERIFY SIGNATURE");
	if !verify_signature(
		&request.enclave_account.clone(),
		request.signature.clone(),
		request.auth_token.as_bytes(),
	) {
		return error_handler("SYNC KEYSHARES : Invalid Signature".to_string(), &state)
			.await
			.into_response();
	}

	debug!("SYNC KEYSHARES : Validating the authentication token");
	let validity = auth_token.is_valid(last_block_number).await;
	match validity {
		ValidationResult::Success => debug!("SYNC KEYSHARES : Authentication token is valid."),
		_ => {
			let message = format!(
				"SYNC KEYSHARES : Authentication Token is not valid, or expired : {:?}",
				validity
			);
			return error_handler(message, &state).await.into_response();
		},
	}

	let hash = sha256::digest(request.nftid_vec.as_bytes());

	if auth_token.data_hash != hash {
		return error_handler("SYNC KEYSHARES : Mismatch Data Hash".to_string(), &state)
			.await
			.into_response();
	}

	let nftidv: Vec<String> = match serde_json::from_str(&request.nftid_vec) {
		Ok(v) => v,
		Err(e) => {
			let message = format!("SYNC KEYSHARES : unable to deserialize nftid vector : {:?}", e);
			return error_handler(message, &state).await.into_response();
		},
	};

	//let nftids: Vec<String> = nftidv.iter().map(|x| x.to_string()).collect::<Vec<String>>();

	// TODO [future reliability] check nftids , is empty, are they in range, ...

	// Create a client
	let client = match reqwest::Client::builder()
		// This is for development, will be removed for production certs
		.danger_accept_invalid_certs(true)
		.https_only(true)
		.use_rustls_tls()
		// .min_tls_version(if cfg!(any(feature = "mainnet", feature = "alphanet")) {
		// 	tls::Version::TLS_1_3
		// } else {
		// 	tls::Version::TLS_1_0
		// })
		.build()
	{
		Ok(client) => client,
		Err(e) => {
			let message = format!("SYNC KEYSHARES : unable to build a Reqwest client : {:?}", e);
			return error_handler(message, &state).await.into_response();
		},
	};

	let mut enclave_url = requester.1.enclave_url.clone();
	while enclave_url.ends_with('/') {
		enclave_url.pop();
	}

	// ------------------------ WEBSOCKET START -------------------------
	// Communication between Enclaves will be in websocket protocol (full-duplex).
	// This part of code is not possible with HTTP protocl

	// let health_request_url = enclave_url.clone() + "/api/health";
	// debug!("SYNC KEYSHARES : Healthcheck the requester {}", health_request_url);

	// let mut retry_check = false;
	// while !retry_check {
	// 	let health_response = match client
	// 		.get(health_request_url.clone())
	// 		.send()
	// 		.await
	// 	{
	// 		Ok(res) => res,
	// 		Err(err) => {
	// 			let message = format!("SYNC KEYSHARES : Healthcheck : Error getting health-check response from the enclave requesting for syncing : {} : {:?}", health_request_url, err);
	// 			error!(message);
	// 			warn!("SYNC KEYSHARES : Healthcheck : Delay and Retry ");
	// 			// A delay to prevent conflict
	// 			tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;
	// 			continue;
	// 			//return error_handler(message, &state).await.into_response();
	// 		},
	// 	};
	// 	// Analyze the Response
	// 	let health_status = health_response.status();

	// 	// TODO [decision] : Should it be OK or Synching? Solution = (Specific StatusCode for Wildcard)

	// 	if health_status != StatusCode::OK {
	// 		let message = format!(
	// 			"SYNC KEYSHARES : Healthcheck : requester enclave {} is not ready for syncing",
	// 			requester.1.enclave_url
	// 		);
	// 		return error_handler(message, &state).await.into_response();
	// 	}

	// 	let health_body: HealthResponse = match health_response.json().await {
	// 		Ok(body) => body,
	// 		Err(e) => {
	// 			let message = format!(
	// 				"SYNC KEYSHARES : Healthcheck : can not deserialize the body : {} : {:?}",
	// 				requester.1.enclave_url, e
	// 			);
	// 			error!(message);
	// 			HealthResponse {
	// 				block_number: 0,
	// 				sync_state: "0".to_string(),
	// 				version: "0.0".to_string(),
	// 				description: "Error".to_string(),
	// 				enclave_address: "0000".to_string(),
	// 			}
	// 			//return error_handler(message, &state).await.into_response();
	// 		},
	// 	};

	// 	debug!(
	// 		"SYNC KEYSHARES : Health-Check Result for url : {}, Status: {:?}, \n body: {:#?}",
	// 		requester.1.enclave_url, health_status, health_body
	// 	);

	// 	retry_check = true;
	// }

	// debug!("SYNC KEYSHARES : REQUEST QUOTE");
	// let quote_request_url = enclave_url.clone() + "/api/quote";
	// debug!("SYNC KEYSHARES : REQUEST QUOTE the requester {}", quote_request_url);

	// let quote_response = match client.get(quote_request_url).send().await {
	// 	Ok(resp) => resp,
	// 	Err(err) => {
	// 		let message =
	// 			format!("Error reading quote from the enclave requesting for syncing : {:?}", err);
	// 		return error_handler(message, &state).await.into_response();
	// 	},
	// };

	// ------------------------ WEBSOCKET END -------------------------

	let quote_hash = sha256::digest(request.quote.as_bytes());

	if auth_token.quote_hash != quote_hash {
		return error_handler("SYNC KEYSHARES : Mismatch Quote Hash".to_string(), &state)
			.await
			.into_response();
	}

	let quote_body: QuoteResponse = match serde_json::from_str(&request.quote) {
		Ok(body) => body,
		Err(e) => {
			let message = format!(
				"SYNC KEYSHARES : Quote : can not deserialize the quote : {} : {:?}",
				requester.1.enclave_url, e
			);
			return error_handler(message, &state).await.into_response();
		},
	};

	debug!(
		"SYNC KEYSHARES : Quote Result for url : {} is {:#?}",
		requester.1.enclave_url, quote_body
	);

	let attest_response = match client
		.post(ATTESTATION_SERVER_URL)
		.body(json!({"data": quote_body.data}).to_string())
		.header(header::CONTENT_TYPE, "application/json")
		.send()
		.await
	{
		Ok(resp) => resp,
		Err(err) => {
			let message = format!(
					"SYNC KEYSHARES : Attestation : can not get response from attestation server : {:?}", err);
			return error_handler(message, &state).await.into_response();
		},
	};

	let attestation_json = match attest_response.text().await {
		Ok(resp) => resp,
		Err(e) => {
			let message = format!("Error getting attestation response {:?}", e);
			return error_handler(message, &state).await.into_response();
		},
	};

	debug!(
		"SYNC KEYSHARES : Attestation Result for url : {} is \n {:#?}\n\n",
		requester.1.enclave_url, attestation_json,
	);

	let attest_dynamic_json: Value = match serde_json::from_str::<Value>(&attestation_json) {
		Ok(dj) => dj,
		Err(e) => {
			let message =
				format!("SYNC KEYSHARES : Error deserializing attestation response {:?}", e);
			return error_handler(message, &state).await.into_response();
		},
	};

	let report: Value = match serde_json::from_value(attest_dynamic_json["report"].clone()) {
		Ok(report) => report,
		Err(e) => {
			let message =
				format!("SYNC KEYSHARES : Error deserializing attestation report {:?}", e);
			return error_handler(message, &state).await.into_response();
		},
	};

	debug!("SYNC KEYSHARES : report['exit status'] = {}", report["exit status"]);

	if report["exit status"] == "0" {
		let quote: Value = match serde_json::from_value(attest_dynamic_json["quote"].clone()) {
			Ok(quote) => quote,
			Err(e) => {
				let message =
					format!("SYNC KEYSHARES : Error deserializing attestation quote {:?}", e);
				return error_handler(message, &state).await.into_response();
			},
		};

		debug!("SYNC KEYSHARES : quote['report_data'] = {}", quote["report_data"]);

		if let Some(report_data) = quote["report_data"].as_str() {
			let token = request.enclave_account.clone()
				+ "_" + &auth_token.clone().block_number.to_string();
			debug!("SYNC KEYSHARES : report_data token  = {}", token);

			if !verify_signature(
				&request.enclave_account.clone(),
				report_data.to_string(),
				token.as_bytes(),
			) {
				return error_handler("SYNC KEYSHARES : Invalid Signature".to_string(), &state)
					.await
					.into_response();
			}

			let parse_token: Vec<&str> = token.split('_').collect();
			if request.enclave_account != parse_token[0] {
				return error_handler("SYNC KEYSHARES : TOKEN : Mismatch between <Requester Account> and <Report Data Token>".to_string(), &state)
					.await
					.into_response();
			} else {
				match parse_token[1].parse::<u32>() {
					Ok(token_block) => {
						if (token_block != auth_token.block_number)
							|| (last_block_number < token_block)
							|| (last_block_number - token_block > 5)
						{
							let message = format!("SYNC KEYSHARES : TOKEN : Incompatible block numbers :\n Current blocknumber: {} >~ Token blocknumber: {} == Request blocknumber: {} ?", last_block_number, token_block, auth_token.block_number);
							return error_handler(message, &state).await.into_response();
						}
					},

					Err(e) => {
						return error_handler(format!("SYNC KEYSHARES : TOKEN : Can not parse Token Block Number {} , error = {:?}", parse_token[1], e), &state)
							.await
							.into_response();
					},
				} // VALID TOKEN BLOCK
			} // PARSE TOKEN
		}
		// SUCCESS REPORT_DATA TOKEN
		else {
			let message =
				format!("SYNC KEYSHARES : Failed to get 'report_data; from th quote : {}", quote);
			return error_handler(message, &state).await.into_response();
		} // FAILED REPORT DATA
	}
	// APPROVED ATTESTATION REPORT
	else {
		let message = format!("SYNC KEYSHARES : Attestation IAS report failed : {}", report);
		return error_handler(message, &state).await.into_response();
	} // FAILED ATTESTATION REPORT

	let backup_file = "/temporary/backup.zip".to_string();
	//let counter = 1;
	// remove previously generated backup
	if std::path::Path::new(&backup_file.clone()).exists() {
		match std::fs::remove_file(backup_file.clone()) {
			Ok(_) => {
				debug!("SYNC KEYSHARES : Successfully removed previous zip file")
			},
			Err(e) => {
				let message =
					format!("SYNC KEYSHARES : Error : Can not remove previous backup file : {}", e);
				warn!(message);
				//return Json(json!({ "error": message })).into_response()
				//backup_file = format!("/temporary/backup-{counter}.zip");
			},
		}
	}

	debug!("SYNC KEYSHARES : Start zippping file");
	add_list_zip(SEALPATH, nftidv, &backup_file);

	// `File` implements `AsyncRead`
	debug!("SYNC KEYSHARES : Opening backup file");
	let file = match tokio::fs::File::open(backup_file).await {
		Ok(file) => file,
		Err(err) => {
			return Json(json!({
				"error": format!("SYNC KEYSHARES : Backup File not found: {}", err)
			}))
			.into_response()
		},
	};

	// convert the `AsyncRead` into a `Stream`
	debug!("SYNC KEYSHARES : Create reader-stream");
	let stream = ReaderStream::new(file);

	// convert the `Stream` into an `axum::body::HttpBody`
	debug!("SYNC KEYSHARES : Create body-stream");
	let body = StreamBody::new(stream);

	let headers = [
		(header::CONTENT_TYPE, "text/toml; charset=utf-8"),
		(header::CONTENT_DISPOSITION, "attachment; filename=\"Backup.zip\""),
	];

	//update_health_status(&state, String::new()).await;

	debug!("SYNC KEYSHARES : Sending the backup data to the client ...");
	(headers, body).into_response()
}

/* --------------------------------
	FETCH KEYSHARES FROM ENCLAVES
----------------------------------- */

pub async fn fetch_keyshares(
	state: &SharedState,
	new_nft: &HashMap<u32, u32>,
) -> Result<u32, anyhow::Error> {
	debug!("\n\t----\nFETCH KEYSHARES : START\n\t----\n");

	let mut last_synced = 0u32;
	let last_block_number = get_blocknumber(state).await;
	let account_id = get_accountid(state).await;
	let account_keypair = get_keypair(state).await;

	// (clustse, slot)
	let enclave_identity = match get_identity(state).await {
		Some(id) => id,
		None => {
			let message =
				"FETCH KEYSHARES : Error : No identity : Current enclave is not registered yet"
					.to_string();
			error!(message);
			return Err(anyhow!(message));
		},
	};

	// TODO [future reliability] Check if new nfts are already on the disk and updated, check nftids , if they are in range, ...

	// Convert HashMap to Vector of nftid
	let nftids: Vec<String> = new_nft
		.clone()
		.into_iter()
		// Ignore it, if it is in current cluster
		.filter(|(_, cluster)| *cluster != enclave_identity.0)
		.map(|kv| kv.0.to_string())
		.collect();

	// Encode nftid to String
	// If HashMap is empty, then it is called by a setup syncronization
	let nftids_str = if new_nft.is_empty() {
		// Empty nftid vector is used with Admin_bulk backup, that's why we use wildcard for synchronization
		// It is the first time running enclave
		// TODO [reliability] Pagination request is needed i.e ["*", 100, 2] page size is 100, offset 2
		// TODO : for pagination, a new endpoint needed to report the number of keyshares stored on target enclave.
		match serde_json::to_string(&vec!["*".to_string()]) {
			Ok(strg) => strg,
			Err(e) => {
				let message = format!(
					"FETCH KEYSHARES : Error : can not convert Wildcard to string! : {:?}",
					e
				);
				error!(message);
				return Err(anyhow!(message));
			},
		}
	} else if nftids.is_empty() {
		// nftids are all filtered out : they are already stored on this cluster
		let message =
			"FETCH KEYSHARES : the new nft is ORIGINALLY stored on this cluster".to_string();
		debug!(message);
		return Ok(last_block_number);
	} else {
		// Normal : there are some nftid in the list
		match serde_json::to_string(&nftids) {
			Ok(strng) => strng,
			Err(e) => {
				let message =
					format!("FETCH KEYSHARES : Error : can not convert NFTIDs to string : {:?}", e);
				error!(message);
				return Err(anyhow!(message));
			},
		}
	};

	let nftid_hash = sha256::digest(nftids_str.as_bytes());

	let user_data_token = account_id.clone() + "_" + &last_block_number.to_string();
	debug!("FETCH KEYSHARES : QUOTE : report_data token  = {}", user_data_token);

	let user_data = account_keypair.sign(user_data_token.as_bytes());
	debug!("FETCH KEYSHARES : QUOTE : report_data signature  = {:?}", user_data);

	match write_user_report_data(None, &user_data.0) {
		Ok(_) => debug!("FETCH KEYSHARES : QUOTE : Successfully wrote user_data into the quote."),
		Err(e) => {
			let message =
				format!(
				"FETCH KEYSHARES : QUOTE : Error -> can not write user_data to the quote : {:?}", e);
			error!(message);
			return Err(anyhow!(message));
		},
	};

	let quote = match get_quote_content() {
		Ok(quote) => match serde_json::to_string(&QuoteResponse {
			block_number: last_block_number,
			data: hex::encode(quote),
		}) {
			Ok(ser_quote) => ser_quote,
			Err(e) => {
				let message =
					format!("FETCH KEYSHARES : QUOTE : Can not serialize the quote : {:?}", e);
				error!(message);
				return Err(anyhow!(message));
			},
		},
		Err(e) => {
			let message = format!("FETCH KEYSHARES : QUOTE : Can not genrate the quote : {:?}", e);
			error!(message);
			return Err(anyhow!(message));
		},
	};

	let quote_hash = sha256::digest(quote.clone());

	let auth = AuthenticationToken {
		block_number: last_block_number,
		block_validation: 15,
		data_hash: nftid_hash,
		quote_hash,
	};

	let auth_str = match serde_json::to_string(&auth) {
		Ok(authstr) => authstr,
		Err(e) => {
			let message = format!(
				"FETCH KEYSHARES : AUTH : Can not serialize the authentication token : {:?}",
				e
			);
			error!(message);
			return Err(anyhow!(message));
		},
	};

	let sig = account_keypair.sign(auth_str.as_bytes());
	let sig_str = format!("{}{:?}", "0x", sig);

	let request = FetchIdPacket {
		enclave_account: account_id,
		nftid_vec: nftids_str,
		auth_token: auth_str,
		signature: sig_str,
		quote,
	};

	let request_body = match serde_json::to_string(&request) {
		Ok(body) => {
			debug!("FETCH KEYSHARES : Request Body : {:#?}\n", body);
			body
		},
		Err(e) => {
			let message =
				format!("FETCH KEYSHARES : REQUEST : Can not serialize the request body : {:?}", e);
			error!(message);
			return Err(anyhow!(message));
		},
	};

	// The available enclaves in the same slot of current enclave, with their clusterid
	debug!("FETCH KEYSHARES : START SLOT DISCOVERY");
	let slot_enclaves = slot_discovery(state).await;
	if slot_enclaves.is_empty() {
		// TODO : What about first cluster? should it continue as the Primary cluster in running-mode?
		// TODO : otherwise we should have two clusters registered before starting enclaves with sync capability.
		if get_identity(state).await.is_some() {
			warn!("FETCH KEYSHARES : No other similar slots found in other clusters, is this primary cluster?");
			return Ok(last_block_number);
		} else {
			// not registered
			error!("FETCH KEYSHARES : This enclave is not registered yet.");
			return Err(anyhow!(
				"FETCH KEYSHARES : Slot discovery failed because of not-registered enclave"
			));
		}
	}

	// Check other enclaves for new NFT keyshares
	let nft_clusters: Vec<u32> = new_nft.clone().into_values().collect();
	debug!("FETCH KEYSHARES : nfts-cluster {:?}\n", nft_clusters);

	let client = reqwest::Client::builder()
		// This is for development, will be removed for production certs
		.danger_accept_invalid_certs(true)
		.https_only(true)
		// WebPKI
		//.use_rustls_tls()
		.use_native_tls()
		// .min_tls_version(if cfg!(any(feature = "mainnet", feature = "alphanet")) {
		// 	tls::Version::TLS_1_3
		// } else {
		// 	tls::Version::TLS_1_0
		// })
		//.connection_verbose(true)
		.build()?;

	// TODO [future reliability] : use metric-server ranking instead of simple loop
	for (cluster_id, enclave) in slot_enclaves {
		debug!("FETCH KEYSHARES : Fetch from enclave : \n Cluster: {} \n Slot: {}\n Operator: {}\n Enclave_Account: {}\n URL: {}\n\n", 
			cluster_id, enclave.slot,enclave.operator_account,enclave.enclave_account,enclave.enclave_url);
		// Is the 'enclave' of 'slot_enclave' in the cluster that nftid is "originally" stored?
		// We can remove this condition if we want to search whole the slot
		// It is faster for Runtime synchronization
		// It may be problematic for First time Synchronization
		// Because it is possible that original enclave is down now.
		if !new_nft.is_empty() && !nft_clusters.contains(&cluster_id) {
			debug!(
				"FETCH KEYSHARES : NFTs does not belong to cluster {}, continue to next cluster",
				cluster_id
			);
			continue; // Next Cluster
		}

		let mut enclave_url = enclave.enclave_url.clone();
		while enclave_url.ends_with('/') {
			enclave_url.pop();
		}

		let request_url = enclave_url.clone() + "/api/health";

		debug!("FETCH KEYSHARES : HEALTH CHECK");
		debug!("FETCH KEYSHARES : request url : {}", request_url);
		let health_response = match client.clone().get(request_url.clone()).send().await {
			Ok(res) => res,
			Err(err) => {
				error!(
						"FETCH KEYSHARES : Error getting health-check response from syncing target enclave : {} : \n{:#?}",
						request_url, err
					);
				debug!("FETCH KEYSHARES : continue with next syncing target enclave");
				continue; // Next Cluster
			},
		};
		// Analyze the Response
		let health_status = health_response.status();

		trace!("FETCH KEYSHARES : HEALTH CHECK : health response : {:#?}\n", health_response);
		//debug!("FETCH KEYSHARES : HEALTH CHECK : health response : {:?}\n", health_response.text().await?);

		let response_body: HealthResponse = match health_response.json().await {
			Ok(body) => body,
			Err(e) => {
				let message = format!(
					"FETCH KEYSHARES : Healthcheck : can not deserialize the body : {} : {:#?}",
					enclave.enclave_url, e
				);
				warn!(message);
				continue; // Next Cluster
			},
		};

		debug!(
			"FETCH KEYSHARES : Health-Check Result for url : {} is \n{:#?}",
			enclave.enclave_url, response_body
		);

		if health_status != StatusCode::OK {
			let message = format!(
				"FETCH KEYSHARES : Healthcheck Failed on url: {}, status : {:#?}, reason : {}",
				enclave.enclave_url, health_status, response_body.description
			);
			error!(message);
			continue; // Next Cluster
		} else {
			last_synced = match response_body.sync_state.parse::<u32>() {
				Ok(blk) => blk,
				Err(_) => {
					let message = format!(
						"FETCH KEYSHARES : Healthcheck Parse Error on url: {}, status : {:#?}, sync_state : {}",
						enclave.enclave_url, health_status, response_body.sync_state
					);
					error!(message);
					continue; // Next Cluster
				},
			};
		}

		let request_url = enclave_url.clone() + "/api/backup/sync-keyshare";

		debug!("FETCH KEYSHARES : request for nft-keyshares");
		debug!("FETCH KEYSHARES : request url : {}", request_url);

		let fetch_response = client
			.clone()
			.post(request_url)
			.body(request_body.clone())
			.header(hyper::http::header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
			.send()
			.await;

		let fetch_response = match fetch_response {
			Ok(res) => res,
			Err(err) => {
				error!("FETCH KEYSHARES : Fetch response error: {:#?}", err);
				continue; // Next Cluster
				 //return Err(anyhow!(err));
			},
		};

		let fetch_headers = fetch_response.headers();
		trace!("FETCH KEYSHARES : zip response header : {:?}", fetch_headers);

		let fetch_body_bytes = fetch_response.bytes().await?;
		trace!("FETCH KEYSHARES : zip body length : {}", fetch_body_bytes.len());

		let backup_file = SEALPATH.to_string() + "backup.zip";
		let mut zipfile = match std::fs::File::create(backup_file.clone()) {
			Ok(file) => file,
			Err(e) => {
				let message = format!("FETCH KEYSHARES : Can not create file on disk : {}", e);
				warn!(message);
				return Err(anyhow!(message));
			},
		};

		// TODO [decision - reliability] : What if the "chosen" Enclave is not ready? (low probability for runtime sync)

		match zipfile.write_all(&fetch_body_bytes) {
			Ok(_) => debug!("FETCH KEYSHARES : zip file is stored on disk."),
			Err(e) => {
				let message = format!(
					"FETCH KEYSHARES : Error writing received nft zip file to disk{:#?}",
					e
				);
				error!(message);
				return Err(anyhow!(message));
			},
		}

		// Check if keyshares are invalid
		match sync_zip_extract(state, &backup_file).await {
			Ok(_) => debug!("FETCH KEYSHARES : zip_extract success"),
			Err(e) => {
				let message = format!("FETCH KEYSHARES : extracting zip file {:?}", e);
				error!(message);
				// TODO : return the error to sentry or other places.
				//return Err(anyhow!(message));
			},
		}

		match remove_file(backup_file) {
			Ok(_) => debug!("FETCH KEYSHARES : remove zip file successful"),
			Err(e) => {
				let message = format!(
					"FETCH KEYSHARES : Backup success with Error in removing zip file, {:?}",
					e
				);
				error!(message);
				//return Err(anyhow!(message));
			},
		};
	}

	Ok(last_synced)
}

/* ----------------------------
		CLUSTER DISCOVERY
------------------------------ */

// Crawl and parse registered clusters and enclaves from on-chain data
pub async fn cluster_discovery(state: &SharedState) -> Result<bool, anyhow::Error> {
	debug!("\tCLUSTER DISCOVERY : get api");
	let api = get_chain_api(state).await;

	let max_cluster_address = ternoa::storage().tee().next_cluster_id();

	let storage = match api.storage().at_latest().await {
		Ok(storage) => storage,
		Err(err) => {
			error!("\tCLUSTER DISCOVERY : Failed to get storage: {:#?}", err);
			return Err(err.into());
		},
	};

	debug!("\tCLUSTER DISCOVERY : get next (max) cluster index");
	let max_cluster_index = match storage.fetch(&max_cluster_address).await? {
		Some(cluster) => cluster,
		None => {
			error!("\tCLUSTER DISCOVERY : Failed to fetch next cluster index.");
			return Err(anyhow!("\tCLUSTER DISCOVERY : Failed to fetch next cluster index."));
		},
	};

	let mut clusters = Vec::<Cluster>::new();

	debug!("\tCLUSTER DISCOVERY : loop on cluster index");
	for index in 0..max_cluster_index {
		let cluster_data_address = ternoa::storage().tee().cluster_data(index);

		debug!("\t\tCLUSTER DISCOVERY : get cluster data of cluster {}", index);
		let cluster_data = match storage.fetch(&cluster_data_address).await {
			Ok(data) => match data {
				Some(clstr) => {
					debug!("\nCLUSTER DISCOVERY : cluster[{}] : data = {:?}\n", index, clstr);
					clstr
				},
				None => {
					error!(
							"\t\tCLUSTER DISCOVERY : Failed to 'open' the fetched Cluster Data, Cluster Num.{}",
							index
						);
					debug!("CLUSTER DISCOVERY : cluster[{}] data = {:?}\n", index, data);
					debug!("\t\tCLUSTER DISCOVERY : continue to next cluster (because of previous error)");
					continue;
				},
			},
			Err(err) => {
				error!(
					"\tCLUSTER DISCOVERY : Failed to 'fetch' Cluster.{} Data : {:?}",
					index, err
				);
				continue;
			},
		};

		let mut enclaves = Vec::<Enclave>::new();

		// This is necessary to have a clonable structure
		type TernoaClusterType = ternoa::runtime_types::ternoa_tee::types::ClusterType;
		let cluster_type = match cluster_data.cluster_type {
			TernoaClusterType::Disabled => ClusterType::Disabled,
			TernoaClusterType::Admin => ClusterType::Admin,
			TernoaClusterType::Public => ClusterType::Public,
			TernoaClusterType::Private => ClusterType::Private,
		};

		debug!(
			"\t\tCLUSTER DISCOVERY : loop on enclaves of fetched cluster-data of cluster {}",
			index
		);
		for (operator_account, slot) in cluster_data.enclaves.0 {
			debug!("\t\t\tCLUSTER DISCOVERY : cluster-{} Slot-{}", index, slot);
			let enclave_data_address =
				ternoa::storage().tee().enclave_data(operator_account.clone());
			let enclave_data =
				match storage.fetch(&enclave_data_address).await? {
					Some(data) => data,
					None => {
						let message = format!(
						"\t\t\tCLUSTER DISCOVERY : Failed to fetch enclave data for Operator : {}",	operator_account);
						error!(message);
						warn!("The Integrity of cluster-{} is corrupted, Check with Technical-Committee.", index);
						//continue;
						return Err(anyhow!(message));
					},
				};

			let enclave_url = String::from_utf8(enclave_data.api_uri.0.to_vec())?;

			enclaves.push(Enclave {
				slot,
				operator_account,
				enclave_account: enclave_data.enclave_address,
				enclave_url,
			})
		}
		clusters.push(Cluster { id: index, enclaves, cluster_type });
	}

	set_clusters(state, clusters).await;

	// Update self-identity if changed, for the new enclave is vital, then unlikely.
	debug!("CLUSTER DISCOVERY : SELF-IDENTITY");
	let identity = self_identity(state).await;

	set_identity(state, identity).await;

	Ok(identity.is_some())
}

/* ----------------------
	Find own slot number
-------------------------*/
// Result is Option((cluster.id, enclave.slot))
pub async fn self_identity(state: &SharedState) -> Option<(u32, u32)> {
	debug!("\nSELF-IDENTITY : Start");
	let chain_clusters = get_clusters(state).await;
	let self_enclave_account = get_accountid(state).await;
	let self_identity = get_identity(state).await;
	debug!("SELF-IDENTITY : previous identity (cluster, slot) : {:?}", self_identity);

	for cluster in chain_clusters {
		for enclave in cluster.enclaves {
			if enclave.enclave_account.to_string() == self_enclave_account {
				debug!(
					"\tSELF-IDENTITY : similar enclave-account found on cluster.{} slot.{}",
					cluster.id, enclave.slot
				);
				// Is this the registeration time?
				// TODO [decision - development] : Prevent others from accessing enclave during setup mode.
				match self_identity {
					None => {
						info!(
							"\t\tSELF-IDENTITY : NEW REGISTRATION DETECTET FOR cluster.{} slot.{}",
							cluster.id, enclave.slot
						);
						info!("\t\tSELF-IDENTITY : ENTERING SETUP-MODE.");
						let _ = set_sync_state("setup".to_owned());
						return Some((cluster.id, enclave.slot));
					},

					Some(identity) => {
						if identity.1 != enclave.slot {
							error!("\n*****\nERROR! SLOT HAS BEEN CHANGED. IT IS DANGEROUS ACT BY TC. ENCLAVE MUST WIPE EVERYTHING.\n*****\n");
							warn!("WIPE EVERYTHING ...");

							let read_dir =
								match fs::read_dir("/nft") {
									Ok(rd) => rd,
									Err(e) => {
										error!("\t\tSELF-IDENTITY : CAN NOT READ THE SEAL DIRECTORY {:?}",e);
										return None;
									},
								};

							for dir_entry in read_dir {
								let path = match dir_entry {
									Ok(de) => de.path(),
									Err(e) => {
										error!("\t\tSELF-IDENTITY : CAN NOT GET A PATH IN THE SEAL DIRECTORY ENTRY {:?}",e);
										return None;
									},
								};
								let extension = match path.extension() {
									Some(ext) => ext,
									None => {
										error!("\t\tSELF-IDENTITY : CAN NOT GET EXTENTION OF AN ENTRY PATH OF THE SEAL DIRECTORY {:?}",path);
										return None;
									},
								};
								if extension == OsStr::new("keyshare")
									|| extension == OsStr::new("log")
								{
									warn!("SELF-IDENTITY : REMOVING : {:?}", path);
									let _ = fs::remove_file(path);
								}
							}

							debug!("SELF-IDENTITY : back to setup mode with new identity");
							let _ = set_sync_state("setup".to_owned());
							return Some((cluster.id, enclave.slot));
						} else if identity.0 != cluster.id {
							warn!("SELF-IDENTITY : DANGEROUS ACT FROM TECHNICAL COMMITTEE, CHANGING CLUSTER AT RUNTIME.");
							return Some((cluster.id, enclave.slot));
						} else {
							debug!("SELF-IDENTITY : Identity did not change.");
							return Some((cluster.id, enclave.slot));
						}
					},
				}
			}
		}
	}

	// IS THIS AN UNREGISTERATION?
	if self_identity.is_some() {
		warn!("\n*****\nENCLAVE HAS BEEN UNREGISTERED!\n*****\n");
		let _ = set_sync_state("".to_owned());
	}

	None
}

/* ----------------------------
		SLOT DISCOVERY
------------------------------ */
// List of api_url of all the enclaves in all clusters with the same slot number as current enclave
// This is essential for Synchronization and backup
pub async fn slot_discovery(state: &SharedState) -> Vec<(u32, Enclave)> {
	debug!("SLOT-DISCOVERY : start");
	let chain_clusters = get_clusters(state).await;

	let mut slot_enclave = Vec::<(u32, Enclave)>::new();

	let identity = match get_identity(state).await {
		Some(id) => id,
		None => {
			error!("SLOT-DISCOVERY : Error finding self-identity onchain, this enclave may have not been registered on blockchain yet.");
			// EMPTY
			return slot_enclave;
		},
	};

	// Search all the clusters
	for cluster in chain_clusters {
		// Only Public Clusters can Sync
		if cluster.cluster_type == ClusterType::Public {
			// Enclave can not request itself (same cluster)!
			if cluster.id != identity.0 {
				// Search enclaves in other cluster
				for enclave in cluster.enclaves {
					// Same slot number?
					if enclave.slot == identity.1 {
						slot_enclave.push((cluster.id, enclave));
						break;
					}
				}
			}
		}
	}
	debug!("\t\tSLOT-DISCOVERY : DONE");
	slot_enclave
}

/* --------------------------------------
	 EVENTS CRAWLER (Maintenace Mode)
----------------------------------------- */
// Detect new NFT synced event and look for corresponding enclaves-slot containing the keyshare
// It is part of "Running Enclave Synchronization"
// Result : HashMap of all <NFTID, ClusterID>.
pub async fn crawl_sync_events(
	state: &SharedState,
	from_block_num: u32,
	to_block_num: u32,
) -> Result<HashMap<u32, u32>, anyhow::Error> {
	debug!("CRAWLING ...");

	let api = get_chain_api(state).await;

	// Storage to find the cluster of an enclave which contains specific NFTID
	let storage_api = api.storage().at_latest().await?;

	// Hashmap for fetch nftid-cluste
	let mut nftid_cluster_map = HashMap::<u32, u32>::new();

	for block_counter in from_block_num..=to_block_num {
		// Find block hash
		debug!("\tCRAWLER : block number  = {}", block_counter);
		let block_number = BlockNumber::from(block_counter);
		let block_hash = match api.rpc().block_hash(Some(block_number)).await? {
			Some(hash) => hash,
			None => return Err(anyhow!("\t\tCRAWLER : error getting block hash.")),
		};

		// Read the block from blockchain
		let block = api.blocks().at(block_hash).await?;

		// Extract block body
		let body = block.body().await?;

		// Extract block events
		//let events = block.events().await?;

		let (parsed, _) = parse_block_body(body, &storage_api).await?;
		nftid_cluster_map.extend(parsed);
	}

	Ok(nftid_cluster_map)
}

/* --------------------------------------
			 PARSE BLOCK BODY
----------------------------------------- */

pub async fn parse_block_body(
	body: BlockBody<PolkadotConfig, OnlineClient<PolkadotConfig>>,
	storage: &Storage<PolkadotConfig, OnlineClient<PolkadotConfig>>,
) -> Result<(HashMap<u32, u32>, bool)> {
	trace!("BLOCK-PARSER");
	let mut new_nft = HashMap::<u32, u32>::new();
	let mut update_cluster_data = false;

	// For all extrinsics in the block body
	for ext in body.extrinsics().iter() {
		let ext = ext?;
		let pallet = ext.pallet_name()?;
		let call = ext.variant_name()?;
		//debug!("  - crawler extrinsic  = {} : {}", pallet, call);

		match pallet.to_uppercase().as_str() {
			"NFT" => {
				let events = ext.events().await?;
				match call.to_uppercase().as_str() {
					// Capsule
					"ADD_CAPSULE_SHARD" => {
						// Capsule Synced Detected?
						match find_events_capsule_synced(&events) {
							Some(nftid) => {
								// Get one of enclaves AccountId32
								match find_event_capsule_shard_added(&events, nftid) {
									Some(enclave_account) => {
										let enclave_operator_address = ternoa::storage().tee().enclave_account_operator(enclave_account.clone());
										let enclave_operator_account = match storage.fetch(&enclave_operator_address).await? {
											Some(id) => id,
											None => {
												error!("BLOCK-PARSER : NFT : ADD_CAPSULE_SHARD : ERROR : Can not get 'operator account' from enclave account {}, for capsule NFT_ID: {}", enclave_account.to_string(), nftid);
												continue
											},
										};

										let enclave_cluster_address = ternoa::storage().tee().enclave_cluster_id(enclave_operator_account.clone());
										let cluster_id = match storage.fetch(&enclave_cluster_address).await? {
											Some(id) => id,
											None => {
												error!("BLOCK-PARSER : NFT : ADD_CAPSULE_SHARD : ERROR : Can not get 'cluster_id' from operator {}, for capsule NFT_ID: {}", enclave_operator_account.to_string(), nftid);
												continue
											},
										};
										new_nft.insert(nftid, cluster_id);
										info!("BLOCK-PARSER : NFT : ADD_CAPSULE_SHARD : CAPSULE SYNCED EVENT DETECTED, Cluster_ID {}, NFT_ID: {}", cluster_id, nftid);
									},
									None => debug!("BLOCK-PARSER : NFT : ADD_CAPSULE_SHARD : ERROR : Capsule Synced Event Detected, BUT there is not corresponding CapsuleShardAdded event for nft_id: {}", nftid),
								}
							},
							None => debug!(
							"BLOCK-PARSER : NFT : ADD_CAPSULE_SHARD : Capsule Synced Event *NOT* Detected for addCapsuleShard Extrinsic"
						),
						}
					}, // end - capsule shard

					// Secret
					"ADD_SECRET_SHARD" => {
						// Secret-NFT Synced Detected?
						match find_events_secret_synced(&events) {
							Some(nftid) => {
								// Get one of enclaves AccountId32
								match find_event_secret_shard_added(&events, nftid) {
									Some(enclave_account) => {
										let enclave_operator_address = ternoa::storage().tee().enclave_account_operator(enclave_account.clone());
										let enclave_operator_account = match storage.fetch(&enclave_operator_address).await? {
											Some(id) => id,
											None => {
												error!("BLOCK-PARSER : NFT : ADD_SECRET_SHARD : ERROR : Can not get operator account from enclave account {}, for secret NFT_ID: {}", enclave_account.to_string(), nftid);
												continue
											},
										};

										let enclave_cluster_address = ternoa::storage().tee().enclave_cluster_id(enclave_operator_account.clone());
										let cluster_id = match storage.fetch(&enclave_cluster_address).await? {
											Some(id) => id,
											None => {
												error!("BLOCK-PARSER : NFT : ADD_SECRET_SHARD : ERROR : Can not get cluster_id from enclave account {}, for secret NFT_ID: {}", enclave_account.to_string(), nftid);
												continue
											},
										};
										new_nft.insert(nftid, cluster_id);
										info!("BLOCK-PARSER : NFT : ADD_SECRET_SHARD : Secret-NFT Synced Event Detected, Cluster_ID {}, NFT_ID: {}", cluster_id, nftid);
									},
									None => debug!("BLOCK-PARSER : NFT : ADD_SECRET_SHARD : Secret-NFT Synced Event Detected, but there is not corresponding ShardAdded event for nft_id: {}", nftid),
								}
							},
							None => debug!("BLOCK-PARSER : NFT : ADD_SECRET_SHARD : Secret-NFT Synced Event NOT Detected for addSecretShard Extrinsic"),
						}
					}, // end - secret shard

					_ => debug!("BLOCK-PARSER : NFT : extrinsic is not about shards : {}", call),
				} // end - call
			}, // end  - NFT pallet

			// If the extrinsic pallet is TC
			"TECHNICALCOMMITTEE" => {
				let events = ext.events().await?;
				for evnt in events.iter() {
					let event = evnt?;
					let pallet = event.pallet_name();

					// If the event is TEE
					if pallet.to_uppercase().as_str() == "TEE" {
						// TODO [decision] : There may be Metric Server updates that we should exclude
						update_cluster_data = true;
						info!("BLOCK-PARSER : TECHNICALCOMMITTEE : TechnicalCommittee extrinsic for TEE detected");
					}
				}
			},

			// If the extrinsic pallet is TEE and it is successfull
			"TEE" => {
				let events = ext.events().await?;
				for evnt in events.iter() {
					let event = evnt?;
					let pallet = event.pallet_name();
					let variant = event.variant_name();
					// If the event is successful
					if pallet.to_uppercase().as_str() == "SYSTEM" && variant.to_uppercase().as_str() == "EXTRINSICSUCCESS" {
						// TODO [question] : Check if this condition is meaningful
						update_cluster_data = true;
						debug!("BLOCK-PARSER : TEE : tee-pallet extrinsic detected, it should wait for TC.");
					}
				}
			},

			"TIMESTAMP" => continue,

			_ => trace!("BLOCK-PARSER : [not a nft, tc, tee or timestamp pallet] extrinsic Pallet = {} call = {}", pallet, call),
		} // end - match pallet
	} // end - extrinsics loop

	Ok((new_nft, update_cluster_data))
}

/* -----------------------
	HELPER FUNCTIONS
--------------------------*/

// Return list of nftids that are synced in this block
pub fn find_events_capsule_synced(events: &ExtrinsicEvents<PolkadotConfig>) -> Option<u32> {
	// Get events for the latest block:
	let cevt = events.find::<CapsuleSynced>();
	for e in cevt {
		match e {
			Ok(ev) => {
				debug!("\t\tFIND_EVENTS_CAPSULE_SYNCED - capsule synced: nft_id: {:?}", ev.nft_id);
				return Some(ev.nft_id);
			},
			Err(err) => {
				debug!("\t\tFIND_EVENTS_CAPSULE_SYNCED - error reading capsule synced : {:?}", err);
			},
		}
	}
	None
}

// Return list of nftids that are synced in this block
pub fn find_events_secret_synced(events: &ExtrinsicEvents<PolkadotConfig>) -> Option<u32> {
	// Get events for the latest block:
	let sevt = events.find::<SecretNFTSynced>();

	for e in sevt {
		match e {
			Ok(ev) => {
				debug!("\t\tFIND_EVENTS_SECRET_SYNCED - secret synced: nft_id: {:?}", ev.nft_id);
				return Some(ev.nft_id);
			},
			Err(err) => {
				debug!("\t\tFIND_EVENTS_SECRET_SYNCED - error reading secret synced : {:?}", err);
			},
		}
	}
	None
}

// Return enclave Account, it can be used to find the cluster
pub fn find_event_capsule_shard_added(
	events: &ExtrinsicEvents<PolkadotConfig>,
	nftid: u32,
) -> Option<AccountId32> {
	let acevt = events.find::<ternoa::nft::events::CapsuleShardAdded>();

	for e in acevt {
		match e {
			Ok(ev) => {
				if ev.nft_id == nftid {
					debug!("\t\tFIND_EVENT_CAPSULE_SHARD_ADDED - found a capsule added for given nftid : {}", nftid);
					return Some(ev.enclave);
				}
			},
			Err(err) => {
				debug!(
					"\t\tFIND_EVENT_CAPSULE_SHARD_ADDED - error reading capsule added : {:?}",
					err
				);
			},
		}
	}

	None
}

// Return enclave Account, it can be used to find the cluster
pub fn find_event_secret_shard_added(
	events: &ExtrinsicEvents<PolkadotConfig>,
	nftid: u32,
) -> Option<AccountId32> {
	let asevt = events.find::<ternoa::nft::events::ShardAdded>();

	for e in asevt {
		match e {
			Ok(ev) => {
				if ev.nft_id == nftid {
					debug!("\t\tFIND_EVENT_SECRET_SHARD_ADDED - found a secret added for given nftid : {}", nftid);
					return Some(ev.enclave);
				}
			},
			Err(err) => {
				debug!(
					"\t\tFIND_EVENT_SECRET_SHARD_ADDED - error reading secret added : {:?}",
					err
				);
			},
		}
	}

	None
}

// Read Sync State File
pub fn get_sync_state() -> Result<String> {
	match std::fs::read_to_string(SYNC_STATE_FILE) {
		Ok(state) => Ok(state),
		Err(e) => Err(e.into()),
	}
}

// Write to Sync State File
pub fn set_sync_state(state: String) -> Result<()> {
	let mut statefile =
		std::fs::OpenOptions::new().write(true).truncate(true).open(SYNC_STATE_FILE)?;

	let _len = statefile.write(state.as_bytes())?;

	Ok(())
}

/* ----------------------------
		EXTRACT ARCHIVE
-------------------------------*/
use async_zip::base::read::seek::ZipFileReader;
use tokio::fs::{create_dir_all, OpenOptions};
use tokio_util::compat::{TokioAsyncReadCompatExt, TokioAsyncWriteCompatExt};

pub async fn sync_zip_extract(
	state: &SharedState,
	zip_file_name: &str,
) -> Result<(), async_zip::error::ZipError> {
	let infile = match tokio::fs::File::open(zip_file_name).await {
		Ok(file) => file,
		Err(e) => {
			error!("FETCH KEYSHARES : ZIP EXTRACT : error opening zip file : {:?}", e);
			return Err(e.into());
		},
	};

	let archive = infile.compat();

	let mut reader = match ZipFileReader::new(archive).await {
		Ok(archive) => archive,
		Err(e) => {
			error!("FETCH KEYSHARES : ZIP EXTRACT : error opening file as zip-archive: {:?}", e);
			return Err(e);
		},
	};

	for index in 0..reader.file().entries().len() {
		let entry =
			match reader.file().entries().get(index) {
				Some(entry) => entry,
				None => {
					error!("FETCH KEYSHARES : ZIP EXTRACT : error extracting file from archive, index {}", index);
					continue;
				},
			};

		let entry_name = match entry.entry().filename().as_str() {
			Ok(name) => name,
			Err(e) => {
				error!(
					"FETCH KEYSHARES : ZIP EXTRACT : error extract entry name from archive, index {} : {:?}",
					index, e
				);
				continue;
			},
		};

		let entry_path = Path::new(&entry_name);

		let entry_is_dir = match entry.entry().dir() {
			Ok(dir) => dir,
			Err(e) => {
				warn!(
					"FETCH KEYSHARES : ZIP EXTRACT : error determining entry type from archive, index {} : {:?}",
					index, e
				);
				continue;
			},
		};

		let entry_permission = entry.entry().unix_permissions().unwrap_or(0o664);

		// Legacy line of code
		if entry_name.contains("__MACOSX") {
			//(*archived_file.name()).contains("__MACOSX") {
			continue;
		}

		// ENTRY IS DIRECTORY?
		if entry_is_dir {
			warn!(
				"FETCH KEYSHARES : ZIP EXTRACT : syncing directory is not supported : {:?}",
				entry_name
			);
			continue;
		}

		// Validate Entry extension
		match entry_path.extension() {
			Some(ext) => match ext.to_str() {
				Some(exts) => match exts {
					"keyshare" => {
						tracing::trace!(
							"FETCH KEYSHARES : ZIP EXTRACT : valid extension : {}",
							exts
						);
					},
					_ => {
						warn!("FETCH KEYSHARES : ZIP EXTRACT : Invalid file extension for synchronization : {:?}", entry_path);
						continue;
					},
				},
				None => {
					error!("FETCH KEYSHARES : ZIP EXTRACT : error converting file-extension to string : {:?}", entry_path);
					continue;
				},
			},
			None => {
				error!(
					"FETCH KEYSHARES : ZIP EXTRACT : error extracting file-extension : {:?}",
					entry_path
				);
				continue;
			},
		};

		let file_name = match entry_path.file_stem() {
			Some(name) => match name.to_str() {
				Some(s) => s,
				None => {
					error!(
						"FETCH KEYSHARES : ZIP EXTRACT : error extracting file-name : convert to string : {:?}",
						name
					);
					continue;
				},
			},

			None => {
				error!(
					"FETCH KEYSHARES : ZIP EXTRACT : error extracting file-name : {:?}",
					entry_path
				);
				continue;
			},
		};

		let name_parts: Vec<&str> = file_name.split('_').collect();

		// GENERAL FORMAT VALIDATION
		if name_parts.len() != 3 || (name_parts[0] != "nft" && name_parts[0] != "capsule") {
			error!(
				"FETCH KEYSHARES : ZIP EXTRACT : Invalid file name : structure : {:?}",
				name_parts
			);
			continue;
		}

		let nftid = match name_parts[1].parse::<u32>() {
			Ok(nftid) => nftid,
			Err(e) => {
				error!(
					"FETCH KEYSHARES : ZIP EXTRACT : Invalid file name, nftid : {:?} : {:?}",
					name_parts, e
				);
				continue;
			},
		};

		let block_number = match name_parts[2].parse::<u32>() {
			Ok(bn) => bn,
			Err(e) => {
				error!(
					"FETCH KEYSHARES : ZIP EXTRACT : Invalid file name : block_number {:?}, : {:?}",
					name_parts, e
				);
				continue;
			},
		};

		match get_nft_availability(state, nftid).await {
			// NEW NFT KEY
			None => {
				debug!(
					"FETCH KEYSHARES : ZIP EXTRACT : NEW NFT : a new incoming nftid {} on block_number {}",
					nftid, block_number
				);

				let out_file_path =
					format!("{}{}_{}_{}.keyshare", SEALPATH, name_parts[0], nftid, block_number);

				// CREATE NEW FILE ON DISK
				let outfile = match OpenOptions::new()
					.write(true)
					.create_new(true)
					.open(&out_file_path)
					.await
				{
					Ok(ofile) => {
						debug!(
							"FETCH KEYSHARES : ZIP EXTRACT : NEW NFT : create {:?}",
							out_file_path
						);
						ofile
					},

					Err(e) => {
						error!(
							"FETCH KEYSHARES : ZIP EXTRACT : NEW NFT : error creating the file {:?} for {:?} : {:?}",
							out_file_path, entry_path, e
						);

						continue;
						//return Err(e.into());
					},
				};

				// DEFINE AVAILABILITY FOR MAP
				let availability = Availability {
					block_number,
					nft_type: if name_parts[0] == "nft" {
						NftType::Secret
					} else {
						NftType::Capsule
					},
				};

				// IT IS A MUTABLE BORROW, HAD TO PUT IT HERE
				let entry_reader = match reader.reader_without_entry(index).await {
					Ok(rdr) => rdr,
					Err(e) => {
						error!(
							"FETCH KEYSHARES : ZIP EXTRACT : NEW NFT : error reading file from archive, index {} : {:?}",
							index, e
						);
						continue;
					},
				};

				// WRITE CONTENT TO FILE
				match futures_util::io::copy(entry_reader, &mut outfile.compat_write()).await {
					Ok(n) => debug!(
						"FETCH KEYSHARES : ZIP EXTRACT : NEW NFT : successfuly copied {} bytes",
						n
					),
					Err(e) => {
						error!("FETCH KEYSHARES : ZIP EXTRACT : NEW NFT : error copying data to file : {:?}", e);
						continue;
						//return Err(e.into());
					},
				}

				// SET PERMISSION
				match fs::set_permissions(
					out_file_path,
					fs::Permissions::from_mode(entry_permission.into()),
				) {
					Ok(_) => {
						tracing::trace!("FETCH KEYSHARES : ZIP EXTRACT : NEW NFT : Permission set.")
					},
					Err(e) => {
						warn!("FETCH KEYSHARES : ZIP EXTRACT : NEW NFT : error setting permission : {:?}", e);
						continue;
					},
				};

				// UPDATE MAP
				set_nft_availability(state, (nftid, availability)).await;
			},

			// UPDATE CAPSULE/HYBRID KEY
			Some(av) => {
				if av.block_number >= block_number {
					// OUTDATED SYNC FILE?
					warn!("FETCH KEYSHARES : ZIP EXTRACT : UPDATE CAPSUL : block number is older than current nftid {} : current block_number {}, incoming block_number {}", nftid, av.block_number, block_number);
					continue;
				} else if name_parts[0] == "nft" {
					// SECRET ?
					warn!("FETCH KEYSHARES : ZIP EXTRACT : UPDATE CAPSUL : secrets update is not acceptable nftid {} : current block_number {}, incoming block_number {}", nftid, av.block_number, block_number);
					continue;
				} else if name_parts[0] == "capsule" && av.nft_type == NftType::Secret {
					// HYBRID
					warn!("FETCH KEYSHARES : ZIP EXTRACT : UPDATE HYBRID : NFT type conversion detected : nftid {} : current nft_type {:?} <> incoming nft_type {}", nftid, av.nft_type, name_parts[0]);

					// NEW FILE NAME
					let out_file_path =
						format!("{}capsule_{}_{}.keyshare", SEALPATH, nftid, block_number);

					// CREATE FILE
					let outfile = match OpenOptions::new()
						.write(true)
						.create_new(true)
						.open(&out_file_path)
						.await
					{
						Ok(ofile) => {
							debug!(
								"FETCH KEYSHARES : ZIP EXTRACT : UPDATE HYBRID : create {:?} for {:?}",
								out_file_path, entry_path
							);
							ofile
						},
						Err(e) => {
							error!(
								"FETCH KEYSHARES : ZIP EXTRACT : UPDATE HYBRID : error creating the file {:?} for {:?} : {:?}",
								out_file_path, entry_path, e
							);
							//return Err(zip::result::ZipError::Io(e));
							continue;
						},
					};

					// MUTABLE BORROW, HAD TO PUT IT HERE
					let entry_reader = match reader.reader_without_entry(index).await {
						Ok(rdr) => rdr,
						Err(e) => {
							error!("FETCH KEYSHARES : ZIP EXTRACT : UPDATE HYBRID : error reading file from archive, index {} : {:?}", index, e);
							continue;
						},
					};

					// WRITE SECRETS TO FILE
					match futures_util::io::copy(entry_reader, &mut outfile.compat_write()).await {
						Ok(n) => trace!("FETCH KEYSHARES : ZIP EXTRACT : UPDATE HYBRID : successfuly copied {} bytes", n),
						Err(e) => {
							error!("FETCH KEYSHARES : ZIP EXTRACT : UPDATE HYBRID : error copying data to file : {:?}", e);
							//return Err(zip::result::ZipError::Io(e));
							continue;
						},
					}

					match fs::set_permissions(
						out_file_path,
						fs::Permissions::from_mode(entry_permission.into()),
					) {
						Ok(_) => tracing::trace!(
							"FETCH KEYSHARES : ZIP EXTRACT : UPDATE HYBRID : Permission set."
						),
						Err(e) => {
							warn!("FETCH KEYSHARES : ZIP EXTRACT : UPDATE HYBRID : error setting permission : {:?}", e);
							continue;
						},
					};

					// UPDATE THE MAP
					set_nft_availability(
						state,
						(nftid, Availability { block_number, nft_type: NftType::Hybrid }),
					)
					.await;
				// WE DO NOT REMOVE PREVIOUS NFT FILE, IT IS HYBRID NOW
				} else {
					// UPDATE CAPSULE KEY
					debug!(
							"FETCH KEYSHARES : ZIP EXTRACT : UPDATE CAPSUL : an incoming capsule update with nftid {} on block_number {}",
							nftid, block_number
						);

					let out_file_path =
						format!("{}capsule_{}_{}.keyshare", SEALPATH, nftid, block_number);

					let outfile = match OpenOptions::new()
						.write(true)
						.create_new(true)
						.open(&out_file_path)
						.await
					{
						Ok(ofile) => {
							debug!(
								"FETCH KEYSHARES : ZIP EXTRACT : UPDATE CAPSUL : create {:?}",
								out_file_path
							);
							ofile
						},

						Err(e) => {
							error!(
								"FETCH KEYSHARES : ZIP EXTRACT : UPDATE CAPSUL : error creating the file {:?} for {:?} : {:?}",
								out_file_path, entry_path, e
							);

							continue;
							//return Err(e.into());
						},
					};

					let entry_reader = match reader.reader_without_entry(index).await {
						Ok(rdr) => rdr,
						Err(e) => {
							error!("FETCH KEYSHARES : ZIP EXTRACT : UPDATE CAPSUL : error reading file from archive, index {} : {:?}", index, e);
							continue;
						},
					};
					// WRITE CONTENT TO FILE
					match futures_util::io::copy(entry_reader, &mut outfile.compat_write()).await {
						Ok(n) => debug!("FETCH KEYSHARES : ZIP EXTRACT : UPDATE CAPSUL : successfuly copied {} bytes", n),
						Err(e) => {
							error!("FETCH KEYSHARES : ZIP EXTRACT : UPDATE CAPSUL : error copying data to file : {:?}", e);
							continue
							//return Err(e.into());
						},
					}

					match fs::set_permissions(
						out_file_path,
						fs::Permissions::from_mode(entry_permission.into()),
					) {
						Ok(_) => tracing::trace!(
							"FETCH KEYSHARES : ZIP EXTRACT : UPDATE CAPSUL : Permission set."
						),
						Err(e) => {
							warn!("FETCH KEYSHARES : ZIP EXTRACT : UPDATE CAPSUL : error setting permission : {:?}", e);
							continue;
						},
					};

					let availability = Availability { block_number, nft_type: NftType::Capsule };

					set_nft_availability(state, (nftid, availability)).await;

					let old_file_path =
						format!("{}/capsule_{}_{}.keyshare", SEALPATH, nftid, av.block_number);
					match std::fs::remove_file(old_file_path.clone()) {
						Ok(_) => {
							debug!("FETCH KEYSHARES : ZIP EXTRACT : UPDATE CAPSUL : removed outdated file {}", old_file_path)
						},
						Err(e) => error!(
							"FETCH KEYSHARES : ZIP EXTRACT : UPDATE CAPSUL : Error removing outdated file {} : {:?}",
							old_file_path, e
						),
					}
				}
			},
		}; // AVAILABILITY CONDITION
	} // FILE in ZIP-ARCHIVE

	Ok(())
}

/* -----------------------------
			TESTS
--------------------------------*/

#[cfg(test)]

mod test {
	use axum::{
		body::Body,
		http::{self, Request, StatusCode},
	};
	use serde_json::Value;
	use sp_core::Pair;
	use std::{collections::BTreeMap, sync::Arc};
	use tokio::sync::RwLock;
	use tower::Service; // for `call`
	use tower::ServiceExt;
	use tracing::{info, Level};
	use tracing_subscriber::FmtSubscriber; // for `oneshot` and `ready`

	use crate::{
		chain::{core::create_chain_api, helper},
		servers::state::StateConfig,
	};

	use super::*;

	#[tokio::test]
	async fn test_cluster_discovery() {
		let subscriber = FmtSubscriber::builder().with_max_level(Level::DEBUG).finish();
		tracing::subscriber::set_global_default(subscriber)
			.expect("main: setting default subscriber failed");

		// Test environment
		let api = create_chain_api().await.unwrap();
		let (enclave_keypair, _, _) = sp_core::sr25519::Pair::generate_with_phrase(None);

		let state_config: SharedState = Arc::new(RwLock::new(StateConfig::new(
			enclave_keypair,
			String::new(),
			api.clone(),
			VERSION.to_string(),
			0,
			BTreeMap::<u32, helper::Availability>::new(),
		)));

		let mut app = match crate::servers::http_server::http_server().await {
			Ok(r) => r,
			Err(err) => {
				error!("Error creating http server {}", err);
				return;
			},
		};

		// Request : Health-Check
		let request1 = Request::builder()
			.method(http::Method::GET)
			.uri("/api/health")
			.header(http::header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
			.body(Body::empty())
			.unwrap();

		// Response
		let response = ServiceExt::<Request<Body>>::ready(&mut app)
			.await
			.unwrap()
			.call(request1)
			.await
			.unwrap();

		// Analyze the Response
		assert_eq!(response.status(), StatusCode::OK);
		let body = hyper::body::to_bytes(response.into_body()).await.unwrap();
		let body: Value = serde_json::from_slice(&body).unwrap();
		println!("Health Check Result: {:#?}", body);

		// Wait
		info!("Wait for 6 seconds to update the block number between requests");
		tokio::time::sleep(tokio::time::Duration::from_secs(6)).await;

		let clusters = cluster_discovery(&state_config.clone()).await;
		println!("{:?}\n", clusters);

		/* ----------------------------
		   Test Finding NFT add Shard
		------------------------------*/
		let cluster_nft_map = crawl_sync_events(&state_config, 550, 560).await;
		println!("\n To be fetched from cluster-slot : {:?}\n", cluster_nft_map.unwrap());

		/* ------------------------------
		  Test Finding TEE update ext.
		--------------------------------*/
		let test_block_number: u32 = 1364585;
		let block_number = BlockNumber::from(test_block_number); // Block contains a failed request
		let block_hash = api
			.rpc()
			.block_hash(Some(block_number))
			.await
			.unwrap()
			.expect("Can not find block hash");

		// Read the block from blockchain
		let block = api.blocks().at(block_hash).await.unwrap();

		// Extract block body
		let body = block.body().await.unwrap();

		let storage_api = block.storage();
		//(new_nft, update_cluster_data)
		let (_, tee_events) = parse_block_body(body, &storage_api).await.unwrap();
		println!("\n A tee event has happened, fetch the cluster data? : {}\n", tee_events);
	}
}
