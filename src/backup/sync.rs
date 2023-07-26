#![allow(dead_code)]

use std::{collections::HashMap, fs::remove_file, io::Write, net::SocketAddr};

use axum::{
	body::StreamBody, extract::ConnectInfo, extract::State, http::header, http::StatusCode,
	response::IntoResponse, Json,
};
use hex::{FromHex, FromHexError};
use reqwest::tls;
use serde::{Deserialize, Serialize};
use serde_json::json;

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
		get_chain_api, ternoa,
		ternoa::nft::events::{CapsuleSynced, SecretNFTSynced},
	},
	servers::{http_server::HealthResponse, state::SharedState},
};

use anyhow::{anyhow, Result};

//TODO [code style - reliability] : manage unwrap()

/* ---------------------------------------
	SYNCH NEW KEYSHARES TO OTHER ENCLAVES
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
	is_public: bool,
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
	debug!("API : Sync fetch NFTID");

	//update_health_status(&state, "Enclave is Syncing Keyshare, please wait...".to_string()).await;

	let shared_state_read = state.read().await;
	let last_block_number = shared_state_read.get_current_block();
	drop(shared_state_read);

	let slot_enclaves = slot_discovery(&state).await;

	let requester = match verify_account_id(slot_enclaves, &request.enclave_account, addr) {
		Some(enclave) => enclave,
		None => {
			let message =
				format!("Sync Keyshare : Error : Requester is not authorized, address: {}, ", addr);

			return error_handler(message, &state).await.into_response();
		},
	};

	let mut auth = request.auth_token.clone();

	if auth.starts_with("<Bytes>") && auth.ends_with("</Bytes>") {
		auth = match auth.strip_prefix("<Bytes>") {
			Some(stripped) => stripped.to_owned(),
			_ => {
				return error_handler(
					"Sync Keyshare : Strip Token prefix error".to_string(),
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
					"Sync Keyshare : Strip Token suffix error".to_string(),
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
				format!("Sync Keyshare : Error : Authentication token is not parsable : {}", e);
			return error_handler(message, &state).await.into_response();
		},
	};

	if !verify_signature(
		&request.enclave_account,
		request.signature.clone(),
		request.auth_token.as_bytes(),
	) {
		return error_handler("Sync Keyshare : Invalid Signature".to_string(), &state)
			.await
			.into_response();
	}

	debug!("Sync Keyshare : Validating the authentication token");
	let validity = auth_token.is_valid(last_block_number).await;
	match validity {
		ValidationResult::Success => debug!("Sync Keyshare : Authentication token is valid."),
		_ => {
			let message = format!(
				"Sync Keyshare : Authentication Token is not valid, or expired : {:?}",
				validity
			);
			return error_handler(message, &state).await.into_response();
		},
	}

	let hash = sha256::digest(request.nftid_vec.as_bytes());

	if auth_token.data_hash != hash {
		return error_handler("Sync Keyshare : Mismatch Data Hash".to_string(), &state)
			.await
			.into_response();
	}

	let nftidv: Vec<String> = match serde_json::from_str(&request.nftid_vec) {
		Ok(v) => v,
		Err(e) => {
			let message = format!("Sync Keyshare : unable to deserialize nftid vector : {:?}", e);
			return error_handler(message, &state).await.into_response();
		},
	};

	//let nftids: Vec<String> = nftidv.iter().map(|x| x.to_string()).collect::<Vec<String>>();

	// TODO [future reliability] check nftids , is empty, are in range, ...

	// Create a client
	let client = reqwest::Client::builder()
		.https_only(true)
		.min_tls_version(tls::Version::TLS_1_3)
		.build()
		.unwrap();

	let health_response = client
		.get(requester.1.enclave_url.clone() + "/api/health")
		.send()
		.await
		.unwrap();
	// Analyze the Response
	let health_status = health_response.status();

	// TODO [decision] : Should it be OK or Synching? Solution = (Specific StatusCode for Wildcard)

	// if health_status != StatusCode::OK {
	// 	let message = format!(
	// 		"Synch Keyshares : Healthcheck : requester enclave {} is not ready for synching",
	// 		requester.1.enclave_url
	// 	);
	// 	return error_handler(message, &state).await.into_response();
	// }

	let health_body: HealthResponse = match health_response.json().await {
		Ok(body) => body,
		Err(e) => {
			let message = format!(
				"Synch Keyshares : Healthcheck : can not deserialize the body : {} : {:?}",
				requester.1.enclave_url, e
			);
			return error_handler(message, &state).await.into_response();
		},
	};

	debug!(
		"Fetch Keyshares : Health-Check Result for url : {}, Status: {:?}, \n body: {:#?}",
		requester.1.enclave_url, health_status, health_body
	);

	let quote_response =
		client.get(requester.1.enclave_url.clone() + "/api/quote").send().await.unwrap();

	let quote_body: QuoteResponse = match quote_response.json().await {
		Ok(body) => body,
		Err(e) => {
			let message = format!(
				"Synch Keyshares : Healthcheck : can not deserialize the body : {} : {:?}",
				requester.1.enclave_url, e
			);
			return error_handler(message, &state).await.into_response();
		},
	};

	debug!(
		"Fetch Keyshares : Quote Result for url : {} is {:#?}",
		requester.1.enclave_url, quote_body
	);

	let attest_response = client
		.post("https://dev-c1n1.ternoa.network:9100/attest")
		.body(quote_body.data)
		.send()
		.await
		.unwrap();
	// TODO [development : attestation] : extract user_data and verify the signature and block_number
	debug!(
		"Fetch Keyshares : Attestation Result for url : {} is {:#?}",
		requester.1.enclave_url,
		attest_response.text().await.unwrap()
	);

	let backup_file = "/temporary/backup.zip".to_string();
	//let counter = 1;
	// remove previously generated backup
	if std::path::Path::new(&backup_file.clone()).exists() {
		match std::fs::remove_file(backup_file.clone()) {
			Ok(_) => {
				debug!("Sync Keyshare : Successfully removed previous zip file")
			},
			Err(e) => {
				let message =
					format!("Sync Keyshare : Error : Can not remove previous backup file : {}", e);
				warn!(message);
				//return Json(json!({ "error": message })).into_response()
				//backup_file = format!("/temporary/backup-{counter}.zip");
			},
		}
	}

	debug!("Sync Keyshare : Start zippping file");
	add_list_zip(SEALPATH, nftidv, &backup_file);

	// `File` implements `AsyncRead`
	debug!("Sync Keyshare : Opening backup file");
	let file = match tokio::fs::File::open(backup_file).await {
		Ok(file) => file,
		Err(err) => {
			return Json(json!({
				"error": format!("Sync Keyshare : Backup File not found: {}", err)
			}))
			.into_response()
		},
	};

	// convert the `AsyncRead` into a `Stream`
	debug!("Sync Keyshare : Create reader-stream");
	let stream = ReaderStream::new(file);

	// convert the `Stream` into an `axum::body::HttpBody`
	debug!("Sync Keyshare : Create body-stream");
	let body = StreamBody::new(stream);

	let headers = [
		(header::CONTENT_TYPE, "text/toml; charset=utf-8"),
		(header::CONTENT_DISPOSITION, "attachment; filename=\"Backup.zip\""),
	];

	//update_health_status(&state, String::new()).await;

	debug!("Sync Keyshare : Sending the backup data to the client ...");
	(headers, body).into_response()
}

/* --------------------------------
	FETCH KEYSHARES FROM ENCLAVES
----------------------------------- */

pub async fn fetch_keyshares(
	state: &SharedState,
	new_nft: HashMap<u32, u32>,
) -> Result<(), anyhow::Error> {
	debug!("Fetch Keyshares from slot enclaves");

	let shared_state_read = state.read().await;
	let last_block_number = shared_state_read.get_current_block();
	let account_id = shared_state_read.get_accountid();
	let account_keypair = shared_state_read.get_key();

	// (clustse, slot)
	let enclave_identity = match shared_state_read.get_identity() {
		Some(id) => id,
		None => {
			let message =
				"Fetch Keyshares Error : No identity : Current enclave is not registered yet"
					.to_string();
			error!(message);
			return Err(anyhow!(message));
		},
	};

	drop(shared_state_read);

	// TODO [future reliability] Check if new nfts are already on the disk and updated, check nftids , if they are in range, ...

	// Convert HashMap to Vector of nftid
	let nftids: Vec<u32> = new_nft
		.clone()
		.into_iter()
		// Ignore it, if it is in current cluster
		.filter(|(_, cluster)| *cluster != enclave_identity.0)
		.map(|kv| kv.0)
		.collect();

	// Encode nftid to String
	// If HashMap is empty, then it is called by a setup syncronization
	let nftids_str = if new_nft.is_empty() {
		// Empty nftid vector is used with Admin_bulk backup, that's why we use wildcard
		// It is the first time running enclave
		// TODO [reliability] Pagination request is needed i.e ["*", 100, 2] page size is 100, offset 2
		serde_json::to_string(&vec!["*".to_string()]).unwrap()
	} else if nftids.is_empty() {
		let message = "Fetch Keyshares : the new nft is already stored on this cluster".to_string();
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
	trace!("Fetch Keyshares : Request Body : {:#?}\n", request_body);

	// The available enclaves in the same slot of current enclave, with their clusterid
	let slot_enclaves = slot_discovery(state).await;
	if slot_enclaves.is_empty() {
		let message = "Fetch Keyshares : No other similar slots detected, enclave is not registered or there is no other cluster.".to_string();
		error!(message);
		return Err(anyhow!(message));
	}

	// Check other enclaves for new NFT keyshares
	let nft_clusters: Vec<u32> = new_nft.into_values().collect();

	let client = reqwest::Client::builder()
		.https_only(true)
		.min_tls_version(tls::Version::TLS_1_3)
		.build()?;

	// TODO [future reliability] : use metric-server ranking instead of simple loop
	for enclave in slot_enclaves {
		// Is the enclave in the cluster that nftid is originally stored?
		// We can remove this condition if we want to search whole the slot
		// It is faster for Runtime synchronization
		// It may be problematic for First time Synchronization
		// Because it is possible that original encalve is down now.
		if !nft_clusters.contains(&enclave.0) {
			continue;
		}

		let health_response =
			client.get(enclave.1.enclave_url.clone() + "/api/health").send().await?;
		// Analyze the Response
		let health_status = health_response.status();
		let response_body: HealthResponse = match health_response.json().await {
			Ok(body) => body,
			Err(e) => {
				let message = format!(
					"Fetch Keyshares : Healthcheck : can not deserialize the body : {} : {:?}",
					enclave.1.enclave_url, e
				);
				warn!(message);
				continue;
			},
		};

		trace!(
			"Fetch Keyshares : Health-Check Result for url : {} is {:#?}",
			enclave.1.enclave_url,
			response_body
		);

		// TODO [developmet - reliability] : Mark and retry later if health is not ready
		if health_status != StatusCode::OK {
			let message = format!(
				"Fetch Keyshares : Healthcheck Failed on url: {}, status : {:?}, reason : {}",
				enclave.1.enclave_url, health_status, response_body.description
			);
			warn!(message);
			continue;
		}

		let fetch_response = client
			.post(enclave.1.enclave_url + "/api/sync-keyshare")
			.body(request_body.clone())
			.header(hyper::http::header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
			.send()
			.await?;

		//let fetch_headers = fetch_response.headers();
		//debug!("response header: {:?}", fetch_headers);

		let fetch_body_bytes = fetch_response.bytes().await?;
		debug!("body length : {}", fetch_body_bytes.len());

		let backup_file = SEALPATH.to_string() + "backup.zip";
		let mut zipfile = match std::fs::File::create(backup_file.clone()) {
			Ok(file) => file,
			Err(e) => {
				let message = format!("Fetch Keyshares : Can not create file on disk : {}", e);
				warn!(message);
				return Err(anyhow!(message));
			},
		};

		// TODO [decision - reliability] : What if the "right" Enclave is not ready? (low probability for runtime synch)

		match zipfile.write_all(&fetch_body_bytes) {
			Ok(_) => debug!("Fetch Keyshares : zip file is stored on disk."),
			Err(e) => {
				let message =
					format!("Fetch Keyshares : Error writing received nft zip file to disk{:?}", e);
				error!(message);
				return Err(anyhow!(message));
			},
		}

		// TODO [future reliability] : Verify fetch data before writing them on the disk
		// Check if keyshares are invalid
		match zip_extract(&backup_file, SEALPATH) {
			Ok(_) => debug!("Fetch Keyshares : zip_extract success"),
			Err(e) => {
				let message = format!("Fetch Keyshares : extracting zip file {:?}", e);
				error!(message);
				return Err(anyhow!(message));
			},
		}

		match remove_file(backup_file) {
			Ok(_) => debug!("Fetch Keyshares : remove zip file successful"),
			Err(e) => {
				let message = format!(
					"Fetch Keyshares : Backup success with Error in removing zip file, {:?}",
					e
				);
				return Err(anyhow!(message));
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
	debug!("Start Cluster Discovery");
	let api = get_chain_api(state.clone()).await; //create_chain_api().await.unwrap();

	let max_cluster_address = ternoa::storage().tee().next_cluster_id();

	let storage = match api.storage().at_latest().await {
		Ok(storage) => storage,
		Err(err) => {
			error!("Cluster Discovery : Failed to get storage: {:#?}", err);
			return Err(err.into());
		},
	};

	let max_cluster_index = match storage.fetch(&max_cluster_address).await? {
		Some(cluster) => cluster,
		None => {
			error!("Cluster Discovery : Failed to fetch next cluster index.");
			return Err(anyhow!("Cluster Discovery : Failed to fetch next cluster index."));
		},
	};

	let mut clusters = Vec::<Cluster>::new();

	for index in 0..max_cluster_index {
		let cluster_data_address = ternoa::storage().tee().cluster_data(index);

		let cluster_data = match storage.fetch(&cluster_data_address).await {
			Ok(data) => {
				debug!("Cluster Discovery :  cluster[{}] data = {:?}", index, data);
				match data {
					Some(clstr) => clstr,
					None => {
						error!(
							"Cluster Discovery : Failed to open Cluster Data, Cluster Num.{}",
							index
						);
						continue;
					},
				}
			},
			Err(err) => {
				error!("Cluster Discovery : Failed to fetch Cluster.{} Data : {:?}", index, err);
				continue;
			},
		};

		let mut enclaves = Vec::<Enclave>::new();
		let is_public = cluster_data.is_public;

		for (operator_account, slot) in cluster_data.enclaves.0 {
			let enclave_data_address =
				ternoa::storage().tee().enclave_data(operator_account.clone());
			let enclave_data = match storage.fetch(&enclave_data_address).await? {
				Some(data) => data,
				None => {
					error!(
						"Cluster Discovery : Failed to fetch enclave data. Operator : {}",
						operator_account.to_string()
					);
					return Err(anyhow!(
						"Failed to fetch enclave data. Operator : {}",
						operator_account.to_string()
					));
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

	// TODO [code style] : Is there other way for alternating between state READ/WRITE
	{
		// Open for write
		let write_state = &mut state.write().await;
		write_state.set_clusters(clusters);
	}

	// Update self-identity if changed, for the new enclave is vital, then unlikely.
	let identity = self_identity(state).await;

	{
		// Open for write
		let write_state = &mut state.write().await;
		write_state.set_identity(identity);
	}

	Ok(identity.is_some())
}

/* ----------------------
	Find own slot number
-------------------------*/
// Result is Option((cluster.id, enclave.slot))
pub async fn self_identity(state: &SharedState) -> Option<(u32, u32)> {
	let read_state = state.read().await;
	let chain_clusters = read_state.get_clusters();
	let self_enclave_account = read_state.get_accountid();
	let self_identity = read_state.get_identity();

	for cluster in chain_clusters {
		for enclave in cluster.enclaves {
			if enclave.enclave_account.to_string() == self_enclave_account {
				// TODO [decision - development] : Should we check that TC may move the Encalve to other cluster or slot?!!
				// Is this the registeration time?
				// TODO [decision - development] : Prevent others from accessing enclave during setup mode.
				if self_identity.is_none() {
					let _ = set_sync_state("setup".to_owned());
				}

				return Some((cluster.id, enclave.slot));
			}
		}
	}

	None
}

/* ----------------------------
		SLOT DISCOVERY
------------------------------ */
// List of api_url of all the enclaves in all clusters with the same slot number as current enclave
// This is essential for Synchronization and backup
pub async fn slot_discovery(state: &SharedState) -> Vec<(u32, Enclave)> {
	let read_state = state.read().await;
	let chain_clusters = read_state.get_clusters();

	let mut slot_enclave = Vec::<(u32, Enclave)>::new();

	let identity = match read_state.get_identity() {
		Some(id) => id,
		None => {
			error!("Error finding self-identity onchain, this enclave may have not been registered on blockchain yet.");
			return slot_enclave;
		},
	};

	// Search all the clusters
	for cluster in chain_clusters {
		// Enclave can not request itself!
		if cluster.id != identity.0 {
			// Search enclaves in a cluster
			for enclave in cluster.enclaves {
				// Same slot number?
				if enclave.slot == identity.1 {
					slot_enclave.push((cluster.id, enclave));
					break;
				}
			}
		}
	}

	slot_enclave
}

/* --------------------------------------
	 EVENTS CRAWLER (Maintenace Mode)
----------------------------------------- */
// Detect new NFT synced event and look for corresponding enclaves-slot containing the keyshare
// It is part of "Running Enclave Synchronization"
// Result : HashMap of all <NFTID, ClusterID>.
pub async fn crawl_sync_events(
	state: SharedState,
	from_block_num: u32,
	to_block_num: u32,
) -> Result<HashMap<u32, u32>, anyhow::Error> {
	let api = get_chain_api(state).await;

	// Storage to find the cluster of an enclave which contains specific NFTID
	let storage_api = api.storage().at_latest().await?;

	// Hashmap for fetch nftid-cluste
	let mut nftid_cluster_map = HashMap::<u32, u32>::new();

	for block_counter in from_block_num..=to_block_num {
		// Find block hash
		debug!("crawler : block number  = {}", block_counter);
		let block_number = BlockNumber::from(block_counter);
		let block_hash = match api.rpc().block_hash(Some(block_number)).await? {
			Some(hash) => hash,
			None => return Err(anyhow!("crawler : error getting block hash.")),
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
												error!("  - Can not get operator account from enclave account {}, for capsule NFT_ID: {}", enclave_account.to_string(), nftid);
												continue
											},
										};

										let enclave_cluster_address = ternoa::storage().tee().enclave_cluster_id(enclave_operator_account.clone());
										let cluster_id = match storage.fetch(&enclave_cluster_address).await? {
											Some(id) => id,
											None => {
												error!("  - Can not get cluster_id from operator {}, for capsule NFT_ID: {}", enclave_operator_account.to_string(), nftid);
												continue
											},
										};
										new_nft.insert(nftid, cluster_id);
										info!("  - Capsule Synced Event Detected, Cluster_ID {}, NFT_ID: {}", cluster_id, nftid);
									},
									None => debug!("  - Capsule Synced Event Detected, but there is not corresponding CapsuleShardAdded event for nft_id: {}", nftid),
								}
							},
							None => debug!(
							"  - Capsule Synced Event NOT Detected for addCapsuleShard Extrinsic"
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
												error!("  - Can not get operator account from enclave account {}, for secret NFT_ID: {}", enclave_account.to_string(), nftid);
												continue
											},
										};

										let enclave_cluster_address = ternoa::storage().tee().enclave_cluster_id(enclave_operator_account.clone());
										let cluster_id = match storage.fetch(&enclave_cluster_address).await? {
											Some(id) => id,
											None => {
												error!("  - Can not get cluster_id from enclave account {}, for secret NFT_ID: {}", enclave_account.to_string(), nftid);
												continue
											},
										};
										new_nft.insert(nftid, cluster_id);
										info!("  - Secret-NFT Synced Event Detected, Cluster_ID {}, NFT_ID: {}", cluster_id, nftid);
									},
									None => debug!("  - Secret-NFT Synced Event Detected, but there is not corresponding ShardAdded event for nft_id: {}", nftid),
								}
							},
							None => debug!("  - Secret-NFT Synced Event NOT Detected for addSecretShard Extrinsic"),
						}
					}, // end - secret shard

					_ => debug!("  - NFT extrinsic is not about shards : {}", call),
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
						debug!("  \t - TechnicalCommittee extrinsic for TEE detected");
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
						debug!("  \t - TEE extrinsic detected, it should wait for TC.");
					}
				}
			},

			"TIMESTAMP" => continue,

			_ => trace!("  \t ---- [not a nft, tc, tee or timestamp pallet] extrinsic Pallet = {} call = {}", pallet, call),
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
				debug!("  - capsule synced: nft_id: {:?}", ev.nft_id);
				return Some(ev.nft_id);
			},
			Err(err) => {
				debug!("  - error reading capsule synced : {:?}", err);
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
				debug!("  - secret synced: nft_id: {:?}", ev.nft_id);
				return Some(ev.nft_id);
			},
			Err(err) => {
				debug!("  - error reading secret synced : {:?}", err);
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
					debug!("  - found a capsule added for given nftid : {}", nftid);
					return Some(ev.enclave);
				}
			},
			Err(err) => {
				debug!("  - error reading capsule added : {:?}", err);
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
					debug!("  - found a secret added for given nftid : {}", nftid);
					return Some(ev.enclave);
				}
			},
			Err(err) => {
				debug!("  - error reading secret added : {:?}", err);
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
		let cluster_nft_map = crawl_sync_events(state_config, 550, 560).await;
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
