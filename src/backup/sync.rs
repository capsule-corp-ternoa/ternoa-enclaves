#![allow(dead_code)]

use std::{
	collections::HashMap,
	ffi::OsStr,
	fs::{self, remove_file},
	io::Write,
	net::SocketAddr,
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

use crate::{
	attestation::ra::QuoteResponse,
	backup::zipdir::{add_list_zip, zip_extract},
	chain::core::{
		ternoa,
		ternoa::nft::events::{CapsuleSynced, SecretNFTSynced},
	},
	servers::{
		http_server::HealthResponse,
		state::{
			get_accountid, get_blocknumber, get_chain_api, get_clusters, get_identity, get_keypair,
			set_clusters, set_identity, SharedState,
		},
	},
};

use anyhow::{anyhow, Result};

//TODO [code style - reliability] : manage unwrap()

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

#[derive(Debug, Clone)]
pub struct Cluster {
	id: u32,
	is_public: bool, // TODO : ENUM
	enclaves: Vec<Enclave>,
}

const SEALPATH: &str = "/nft/";
const RETRY_COUNT: u8 = 12;
const MAX_VALIDATION_PERIOD: u8 = 20;
const MAX_BLOCK_VARIATION: u8 = 5;
const MAX_STREAM_SIZE: usize = 1000 * 3 * 1024; // 3KB is the size of keyshare, 1000 is maximum number of ext in block

// only for dev
#[cfg(any(feature = "mainnet", feature = "alphanet"))]
pub const SYNC_STATE_FILE: &str = "/nft/sync.state";

#[cfg(any(feature = "dev-1", feature = "dev-0"))]
pub const SYNC_STATE_FILE: &str = "/sync.state";

/* *************************************
	FETCH  NFTID DATA STRUCTURES
**************************************** */
// Validity time of Keyshare Data
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct AuthenticationToken {
	pub block_number: u32,
	pub block_validation: u8,
	pub data_hash: String,
}

/// Fetch NFTID Data
#[derive(Serialize, Deserialize, Debug)]
pub struct FetchIdPacket {
	enclave_account: String,
	nftid_vec: String,
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
		if last_block_number < self.block_number - (MAX_BLOCK_VARIATION as u32) {
			// for finalization delay
			debug!(
				"last block number = {} < request block number = {}",
				last_block_number, self.block_number
			);
			return ValidationResult::ExpiredBlockNumber;
		}

		if self.block_validation > MAX_VALIDATION_PERIOD {
			// A finite validity period
			return ValidationResult::InvalidPeriod;
		}

		if last_block_number
			> self.block_number + ((self.block_validation + MAX_BLOCK_VARIATION) as u32)
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
	let client = reqwest::Client::builder()
		// TODO : only for dev
		.danger_accept_invalid_certs(true)
		.https_only(true)
		// .min_tls_version(if cfg!(any(feature = "mainnet", feature = "alphanet")) {
		// 	tls::Version::TLS_1_3
		// } else {
		// 	tls::Version::TLS_1_0
		// })
		.build()
		.unwrap();

	let mut enclave_url = requester.1.enclave_url.clone();
	while enclave_url.ends_with('/') {
		enclave_url.pop();
	}

	let health_request_url = enclave_url.clone() + "/api/health";
	debug!("SYNC KEYSHARES : HEALTH-CHECK the requester {}", health_request_url);

	let health_response = match client
		.get(health_request_url.clone())
		.send()
		.await
	{
		Ok(res) => res,
		Err(err) => {
			let message = format!("Error getting health-check response from the enclave requesting for syncing : {} : {:?}", health_request_url, err);
			return error_handler(message, &state).await.into_response();
		},
	};
	// Analyze the Response
	let health_status = health_response.status();

	// TODO [decision] : Should it be OK or Synching? Solution = (Specific StatusCode for Wildcard)

	if health_status != StatusCode::OK {
		let message = format!(
			"SYNC KEYSHARES : Healthcheck : requester enclave {} is not ready for syncing",
			requester.1.enclave_url
		);
		return error_handler(message, &state).await.into_response();
	}

	let health_body: HealthResponse = match health_response.json().await {
		Ok(body) => body,
		Err(e) => {
			let message = format!(
				"SYNC KEYSHARES : Healthcheck : can not deserialize the body : {} : {:?}",
				requester.1.enclave_url, e
			);
			error!(message);

			HealthResponse {
				block_number: 0,
				sync_state: "0".to_string(),
				version: "0.0".to_string(),
				description: "Error".to_string(),
				enclave_address: "0000".to_string(),
			}
			//return error_handler(message, &state).await.into_response();
		},
	};

	debug!(
		"SYNC KEYSHARES : Health-Check Result for url : {}, Status: {:?}, \n body: {:#?}",
		requester.1.enclave_url, health_status, health_body
	);

	debug!("SYNC KEYSHARES : REQUEST QUOTE");
	let quote_request_url = enclave_url.clone() + "/api/quote";
	debug!("SYNC KEYSHARES : REQUEST QUOTE the requester {}", quote_request_url);

	let quote_response = match client.get(quote_request_url).send().await {
		Ok(resp) => resp,
		Err(err) => {
			let message =
				format!("Error reading quote from the enclave requesting for syncing : {:?}", err);
			return error_handler(message, &state).await.into_response();
		},
	};

	let quote_body: QuoteResponse = match quote_response.json().await {
		Ok(body) => body,
		Err(e) => {
			let message = format!(
				"SYNC KEYSHARES : Healthcheck : can not deserialize the body : {} : {:?}",
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
		.post("https://dev-c1n1.ternoa.network:9100/attest")
		.body(quote_body.data)
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
		"SYNC KEYSHARES : Attestation Result for url : {} is {:#?}",
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

	if report["exit status"] != "0" {
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
			let token =
				request.enclave_account.clone() + "_" + &auth_token.block_number.to_string();
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
		} else {
			let message =
				format!("SYNC KEYSHARES : Failed to get 'report_data; from th quote : {}", quote);
			return error_handler(message, &state).await.into_response();
		}
	} else {
		let message = format!("SYNC KEYSHARES : Attestation IAS report failed : {}", report);
		return error_handler(message, &state).await.into_response();
	}

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
	new_nft: HashMap<u32, u32>,
) -> Result<(), anyhow::Error> {
	debug!("\n\t----\nFETCH KEYSHARES : START\n\t----\n");

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
		// Empty nftid vector is used with Admin_bulk backup, that's why we use wildcard
		// It is the first time running enclave
		// TODO [reliability] Pagination request is needed i.e ["*", 100, 2] page size is 100, offset 2
		// TODO : for pagination, a new endpoint needed to report the number of keyshares stored on target enclave.
		serde_json::to_string(&vec!["*".to_string()]).unwrap()
	} else if nftids.is_empty() {
		let message = "FETCH KEYSHARES : the new nft is already stored on this cluster".to_string();
		debug!(message);
		return Ok(());
	} else {
		serde_json::to_string(&nftids).unwrap()
	};

	let hash = sha256::digest(nftids_str.as_bytes());

	let auth = AuthenticationToken {
		block_number: last_block_number,
		block_validation: 15,
		data_hash: hash,
	};

	let auth_str = serde_json::to_string(&auth).unwrap();
	let sig = account_keypair.sign(auth_str.as_bytes());
	let sig_str = format!("{}{:?}", "0x", sig);

	let request = FetchIdPacket {
		enclave_account: account_id,
		nftid_vec: nftids_str,
		auth_token: auth_str,
		signature: sig_str,
	};

	let request_body = serde_json::to_string(&request).unwrap();
	debug!("FETCH KEYSHARES : Request Body : {:#?}\n", request);

	// The available enclaves in the same slot of current enclave, with their clusterid
	debug!("FETCH KEYSHARES : START SLOT DISCOVERY");
	let slot_enclaves = slot_discovery(state).await;
	if slot_enclaves.is_empty() {
		// TODO : What about first cluster? should it continue as the Primary cluster in running-mode?
		// TODO : otherwise we should have two clusters registered before starting enclaves with sync capability.
		if get_identity(state).await.is_some() {
			warn!("FETCH KEYSHARES : No other similar slots found in other clusters, is this primary cluster?");
			return Ok(());
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
		.danger_accept_invalid_certs(true)
		.https_only(true)
		// .min_tls_version(if cfg!(any(feature = "mainnet", feature = "alphanet")) {
		// 	tls::Version::TLS_1_3
		// } else {
		// 	tls::Version::TLS_1_0
		// })
		.build()?;

	// TODO [future reliability] : use metric-server ranking instead of simple loop
	for enclave in slot_enclaves {
		debug!("FETCH KEYSHARES : Fetch from enclave : \n Cluster: {} \n Slot: {}\n Operator: {}\n Enclave_Account: {}\n URL: {}\n\n", 
			enclave.0, enclave.1.slot,enclave.1.operator_account,enclave.1.enclave_account,enclave.1.enclave_url);
		// Is the 'enclave' of 'slot_enclave' in the cluster that nftid is "originally" stored?
		// We can remove this condition if we want to search whole the slot
		// It is faster for Runtime synchronization
		// It may be problematic for First time Synchronization
		// Because it is possible that original enclave is down now.
		if !new_nft.is_empty() && !nft_clusters.contains(&enclave.0) {
			debug!(
				"FETCH KEYSHARES : NFTs are not belong to cluster {}, continue to next cluster",
				enclave.0
			);
			continue;
		}

		let mut enclave_url = enclave.1.enclave_url.clone();
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
				continue;
			},
		};
		// Analyze the Response
		let health_status = health_response.status();

		debug!("FETCH KEYSHARES : HEALTH CHECK : health response : {:#?}\n", health_response);
		//debug!("FETCH KEYSHARES : HEALTH CHECK : health response : {:?}\n", health_response.text().await?);

		let response_body: HealthResponse = match health_response.json().await {
			Ok(body) => body,
			Err(e) => {
				let message = format!(
					"FETCH KEYSHARES : Healthcheck : can not deserialize the body : {} : {:#?}",
					enclave.1.enclave_url, e
				);
				warn!(message);
				continue;
			},
		};

		debug!(
			"FETCH KEYSHARES : Health-Check Result for url : {} is {:#?}",
			enclave.1.enclave_url, response_body
		);

		// TODO [developmet - reliability] : Mark and retry later if health is not ready
		// TODO : for initial wild-card, get the last_synced filed from health-check body and set it as fetch_keyshare successful update state (instead of current_block)
		if health_status != StatusCode::OK {
			let message = format!(
				"FETCH KEYSHARES : Healthcheck Failed on url: {}, status : {:#?}, reason : {}",
				enclave.1.enclave_url, health_status, response_body.description
			);
			warn!(message);
			//continue;
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
				continue;
				//return Err(anyhow!(err));
			},
		};

		let fetch_headers = fetch_response.headers();
		debug!("FETCH KEYSHARES : response header: {:?}", fetch_headers);

		let fetch_body_bytes = fetch_response.bytes().await?;
		debug!("FETCH KEYSHARES : body length : {}", fetch_body_bytes.len());

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
				let message =
					format!("FETCH KEYSHARES : Error writing received nft zip file to disk{:#?}", e);
				error!(message);
				return Err(anyhow!(message));
			},
		}

		// TODO [future reliability] : Verify fetch data before writing them on the disk
		// Check if keyshares are invalid
		match zip_extract(&backup_file, SEALPATH) {
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

	Ok(())
}

/* ----------------------------
		CLUSTER DISCOVERY
------------------------------ */

// Crawl and parse registered clusters and enclaves from on-chain data
pub async fn cluster_discovery(state: &SharedState) -> Result<bool, anyhow::Error> {
	debug!("\tCLUSTER DISCOVERY : get api");
	let api = get_chain_api(state).await; //create_chain_api().await.unwrap();

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
			Ok(data) => {
				match data {
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
				}
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
		let is_public = cluster_data.is_public;

		debug!(
			"\t\tCLUSTER DISCOVERY : loop on enclaves of fetched cluster0data of cluster {}",
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
		clusters.push(Cluster { id: index, enclaves, is_public });
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
					"\tSELF-IDENTITY : similar enclave-account  found on cluster.{} slot.{}",
					cluster.id, enclave.slot
				);
				// Is this the registeration time?
				// TODO [decision - development] : Prevent others from accessing enclave during setup mode.
				match self_identity {
					None => {
						info!(
							"\t\tSELF-IDENTITY : NEW REGISTRATION DETECTET ON cluster.{} slot.{}",
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

							for path in fs::read_dir("/nft").unwrap() {
								let path = path.unwrap().path();
								let extension = path.extension().unwrap();
								if extension == OsStr::new("keyshare")
									|| extension == OsStr::new("log")
								{
									warn!("REMOVING : {:?}", path);
									let _ = fs::remove_file(path);
								}
							}

							debug!("SELF-IDENTITY : back to setup mode with new identity");
							let _ = set_sync_state("setup".to_owned());
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
	debug!("\nBLOCK-PARSER");
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
	use std::sync::Arc;
	use tokio::sync::RwLock;
	use tower::Service; // for `call`
	use tower::ServiceExt;
	use tracing::{info, Level};
	use tracing_subscriber::FmtSubscriber; // for `oneshot` and `ready`

	use crate::{chain::core::create_chain_api, servers::state::StateConfig};

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
			"0.4.1".to_string(),
			0,
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
