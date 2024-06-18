#![allow(unused_imports)]
#![allow(unused_variables)]
#![allow(dead_code)]

use anyhow::anyhow;
use binrw::{io::Cursor, BinRead, BinReaderExt};

use clap::Parser;
use hex::{FromHex, FromHexError};
use serde_json::{json, Value};
use subxt::{
	backend::{legacy::LegacyRpcMethods, rpc::RpcClient},
	config::polkadot::PolkadotExtrinsicParamsBuilder,
	ext::sp_core::{
		crypto::{PublicError, Ss58Codec},
		sr25519::{self, Signature},
		Pair, H256,
	},
	storage::{StaticAddress, StaticStorageKey},
	tx::{PairSigner, Signer as SubxtSigner, TxStatus},
	utils::{AccountId32, Yes},
	Error, OnlineClient, PolkadotConfig,
};

use reqwest::header;

use std::{
	collections::BTreeMap,
	io::{Read, Write},
};

use std::fs::{remove_file, File};
use tracing::{debug, error, info, warn};

use serde::{Deserialize, Serialize};

#[cfg_attr(
	feature = "mainnet",
	subxt::subxt(runtime_metadata_path = "../artifacts/ternoa_mainnet.scale")
)]
#[cfg_attr(
	feature = "alphanet",
	subxt::subxt(runtime_metadata_path = "../artifacts/ternoa_alphanet.scale")
)]
#[cfg_attr(
	feature = "dev1",
	subxt::subxt(runtime_metadata_path = "../artifacts/ternoa_dev1.scale")
)]
#[cfg_attr(
	feature = "dev0",
	subxt::subxt(runtime_metadata_path = "../artifacts/ternoa_dev0.scale")
)]

pub mod ternoa {}
use self::ternoa::runtime_types::ternoa_pallets_primitives::nfts::NFTData;
pub type DefaultApi = OnlineClient<PolkadotConfig>;
pub type ApiRpc = (OnlineClient<PolkadotConfig>, LegacyRpcMethods<PolkadotConfig>);

// -------------- CHAIN API --------------
/// Get the chain API
/// # Returns
/// * `DefaultApi` - The chain API

pub async fn get_chain_api() -> Result<ApiRpc, Error> {
	debug!("CHAIN : get chain API");

	let rpc_endoint = if cfg!(feature = "mainnet") {
		"wss://mainnet.ternoa.io:443".to_string()
	} else if cfg!(feature = "alphanet") {
		"wss://alphanet.ternoa.com:443".to_string()
	} else if cfg!(feature = "betanet") {
		"wss://betanet.ternoa.com:443".to_string()
	} else if cfg!(feature = "dev1") {
		"wss://dev-1.ternoa.network:443".to_string()
	} else if cfg!(feature = "dev0") {
		"wss://dev-0.ternoa.network:443".to_string()
	} else {
		"ws://localhost:9944".to_string()
	};

	// Chain API
	let api = DefaultApi::from_url(rpc_endoint.clone()).await?;

	// Legacy RPC
	let rpc_client = RpcClient::from_url(rpc_endoint.clone()).await?;
	let legacy_rpc = LegacyRpcMethods::<PolkadotConfig>::new(rpc_client.clone());
	//let api = OnlineClient::<PolkadotConfig>::from_rpc_client(rpc_client.clone()).await?;

	Ok((api, legacy_rpc))
}

/// Get the current block number
/// # Returns
/// * `u32` - The current block number
pub async fn get_current_block_number() -> Result<u32, Error> {
	let (api, _) = match get_chain_api().await {
		Ok(al) => al,
		Err(err) => return Err(err),
	};

	let block = match api.blocks().at_latest().await {
		Ok(blk) => blk,
		Err(err) => return Err(err),
	};

	Ok(block.number())
}

fn get_public_key(account_id: &str) -> Result<sr25519::Public, PublicError> {
	let pk: Result<sr25519::Public, PublicError> = sr25519::Public::from_ss58check(account_id)
		.map_err(|err: PublicError| {
			debug!("Error constructing public key {err:?}");
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
				debug!("Error get signature {err:?}");
				false
			},
		},
		Err(_) => {
			debug!("Error get public key from account-id");
			false
		},
	}
}

/* *************************************
		FETCH BULK DATA STRUCTURES
**************************************** */

// Validity time of Keyshare Data
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct FetchAuthenticationToken {
	pub block_number: u32,
	pub block_validation: u32,
}

/// Fetch Bulk Data
#[derive(Serialize, Deserialize)]
pub struct FetchBulkPacket {
	admin_account: String,
	auth_token: String, //FetchAuthenticationToken,
	signature: String,
}

/// Fetch Bulk Response
#[derive(Serialize)]
pub struct FetchBulkResponse {
	data: String,
	signature: String,
}

/* *************************************
		STORE BULK DATA STRUCTURES
**************************************** */

// Validity time of Keyshare Data
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct StoreAuthenticationToken {
	pub block_number: u32,
	pub block_validation: u32,
	pub data_hash: String,
}

/// Store Bulk Packet
#[derive(Serialize, Deserialize)]
pub struct StoreBulkPacket {
	admin_account: String,
	restore_file: Vec<u8>,
	auth_token: StoreAuthenticationToken,
	signature: String,
}

#[derive(Serialize, Deserialize)]
pub struct FetchBulkPacketOld {
	admin_account: String,
	auth_token: FetchAuthenticationToken,
	signature: String,
}

/* *************************************
		ADMIN ID DATA STRUCTURES
**************************************** */

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct IdAuthenticationToken {
	pub block_number: u32,
	pub block_validation: u32,
	pub data_hash: String,
}

/// Fetch NFTID Data
#[derive(Serialize, Deserialize, Debug)]
pub struct IdPacket {
	admin_account: String,
	id_vec: String,
	auth_token: String,
	signature: String,
}

/* *************************************
		METRIC DATA STRUCTURES
**************************************** */

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct ReconAuthenticationToken {
	pub block_number: u32,
	pub block_validation: u32,
	pub data_hash: String,
}

/// Fetch NFTID Data
#[derive(Serialize, Deserialize, Debug)]
pub struct ReconPacket {
	metric_account: String,
	block_interval: String,
	auth_token: String,
	signature: String,
}

/* *************************************
		ATTESTATION
**************************************** */

#[derive(BinRead, Deserialize, Debug)]
pub struct ParsedQuote {
	pub header: QuoteHeader,
	pub body: QuoteBody,
}

#[derive(BinRead, Deserialize, Debug)]
pub struct QuoteHeader {
	pub version: u16,
	pub attestation_key_type: u16,
	reserved1: u32,
	pub qe_svn: u16,
	pub pce_svn: u16,

	#[br(big, count = 16)]
	pub qe_vendor_id: Vec<u8>,

	#[br(big, count = 20)]
	pub user_data: Vec<u8>,
}

#[derive(BinRead, Deserialize, Debug)]
pub struct QuoteBody {
	#[br(big, count = 16)]
	pub cpu_svn: Vec<u8>,

	pub misc_select: u32,

	#[br(big, count = 28)]
	reserved1: Vec<u8>,

	#[br(big, count = 16)]
	pub attributes: Vec<u8>,

	#[br(big, count = 32)]
	pub mrenclave: Vec<u8>,

	#[br(big, count = 32)]
	reserved2: Vec<u8>,

	#[br(big, count = 32)]
	pub mrsigner: Vec<u8>,

	#[br(big, count = 96)]
	reserved3: Vec<u8>,

	pub isv_prod_id: u16,
	pub isv_svn: u16,

	#[br(big, count = 60)]
	reserved4: Vec<u8>,

	#[br(big, count = 64)]
	pub report_data: Vec<u8>,
}

fn parse_quote(quote: &[u8]) -> Result<ParsedQuote, anyhow::Error> {
	if quote.len() != 432 {
		error!("Quote len  = {}", quote.len());
		return Err(anyhow!("Report quote body size is wrong"));
	}

	let mut quote_reader = Cursor::new(quote);
	let parsed_quote: ParsedQuote = quote_reader.read_ne().unwrap();
	Ok(parsed_quote)
}

#[derive(Deserialize, Clone, Debug)]
#[allow(non_snake_case)]
pub struct ReportResponse {
	pub id: String,
	pub timestamp: String,
	pub version: u8,
	pub attestationType: String,
	pub teeType: String,
	pub isvQuoteStatus: String,
	pub isvQuoteBody: String,
	pub tcbEvaluationDataNumber: u8,
	pub tcbDate: String,
	pub nonce: String,
	pub advisoryURL: String,
	pub advisoryIDs: Vec<String>,
}

#[derive(Deserialize, Clone, Debug)]
#[allow(non_snake_case)]
pub struct AttestationResponse {
	pub account: String,
	pub report: String,
	pub signature: String,
}

/* *************************************
			INPUT ARGUMENTS
**************************************** */

#[derive(Parser, Debug, Clone)]
#[command(author, version, about, long_about = None)]
struct Args {
	/// Request type : [retrieve, store] for secrets
	/// Request type : [fetch-bulk, push-bulk, fetch-id, push-id] for backup
	/// Request type : [reconcilliation] for metrics
	/// Request type : [attest] for remote attestation
	#[arg(short, long, default_value_t = String::new())]
	request: String,

	/// Seed Phrase for Admin or NFT-Owner
	#[arg(short, long, default_value_t = String::new())]
	seed: String,

	/// Path to (ZIP-) File, containing sealed NFT key-shares backups
	#[arg(short, long, default_value_t = String::new())]
	file: String,

	/// NFTID of the secret to be stored or retrived, If 'Custom-Data' option is present, this
	/// option will be ignored
	#[arg(short, long, default_value_t = 0)]
	nftid: u32,

	/// NFTID Vector of the secret to be fetched or pushed by admin
	#[arg(short, long, default_value_t = String::new())]
	id_vec: String,

	/// Block-Number Interval as a Vector to check the nft-ids in that interval
	#[arg(short, long, default_value_t = String::new())]
	block_interval: String,

	/// Path to (ZIP-) File, containing sealed NFT key-shares backups
	#[arg(short, long, default_value_t = String::new())]
	quote: String,

	/// Secret_data for storing keyshares in enclave
	#[arg(long, default_value_t = String::new())]
	secret_share: String,

	/// BlockNumber (Optional)
	#[arg(short, long, default_value_t = 0)]
	block_number: u32,

	/// Number of blocks after the current block number which after it, the request is invalid.
	/// (Optional)
	#[arg(short, long, default_value_t = 15)]
	expire: u8,

	/// Custom Data, right format is "NFTID_SecretShare_CurrentBlockNumber_Expire"
	#[arg(short, long, default_value_t = String::new())]
	custom_data: String,

	/// Enclave URL, right format is "https://enclave.address"
	#[arg(short, long, default_value_t = String::new())]
	enclave_url: String,

}

/* *************************************
				MAIN
**************************************** */
#[tokio::main]
async fn main() {
	let args = Args::parse();

	if args.seed.is_empty() {
		println!("\n Seed-phrase can not be empty! \n");
		return;
	}

	if args.nftid > 0 || !args.custom_data.is_empty() {
		match args.request.to_lowercase().as_str() {
			"retrieve" => generate_retrieve_request(args.clone()).await,
			"store" => generate_store_request(args).await,
			_ => println!("\n Please provide a valid request type \n"),
		}
		return;
	} else if std::path::Path::new(&args.file).exists() {
		match args.request.to_lowercase().as_str() {
			"push-bulk" => generate_push_bulk(args.seed.clone(), args.file).await,
			"fetch-bulk" => generate_fetch_bulk(args.seed.clone()).await,
			_ => println!("\n Please provide a valid request type \n"),
		}
		return;
	} else if !args.id_vec.is_empty() {
		match args.request.to_lowercase().as_str() {
			"push-id" => generate_push_id(args.seed.clone(), args.id_vec).await,
			"fetch-id" => generate_fetch_id(args.seed.clone(), args.id_vec).await,
			_ => println!("\n Please provide a valid request type \n"),
		}
		return;
	} else if !args.block_interval.is_empty() {
		match args.request.to_lowercase().as_str() {
			"reconcilliation" => {
				generate_reconcilliation(args.seed.clone(), args.block_interval).await
			},
			_ => println!("\n Please provide a valid request type \n"),
		}
		return;
	} else if !args.enclave_url.is_empty() {
		match args.request.to_lowercase().as_str() {
			"attest" => attest(args.seed.clone(), args.enclave_url).await.unwrap(),
			_ => println!("\n Please provide a valid request type \n"),
		}
		return;
	} else {
		println!("\n Please provide either a valid NFTID, ID_VEC, ENCLAVE_URL or Custom Data \n");
		return;
	}
}

/* ************************
	 ADMIN FETCH BULK
*************************/

async fn generate_fetch_bulk(seed_phrase: String) {
	let admin = sr25519::Pair::from_phrase(&seed_phrase, None).unwrap().0;

	let current_block_number = get_current_block_number().await.unwrap();

	let admin_account = admin.public().to_ss58check();
	let auth =
		FetchAuthenticationToken { block_number: current_block_number, block_validation: 10 };
	let auth_str = serde_json::to_string(&auth).unwrap();
	let signature = admin.sign(auth_str.as_bytes());

	let packet = FetchBulkPacket {
		admin_account,
		auth_token: auth_str,
		signature: format!("{}{:?}", "0x", signature),
	};

	println!(
		"================================== Backup Fetch Bulk Packet = \n{}\n",
		serde_json::to_string_pretty(&packet).unwrap()
	);
}

/* ************************
	 ADMIN PUSH BULK
*************************/
async fn generate_push_bulk(seed_phrase: String, file_path: String) {
	let admin = sr25519::Pair::from_phrase(&seed_phrase, None).unwrap().0;

	let current_block_number = get_current_block_number().await.unwrap();

	let admin_account = admin.public().to_ss58check();

	let mut zipdata = Vec::new();
	let mut zipfile = std::fs::File::open(&file_path).unwrap();
	let _ = zipfile.read_to_end(&mut zipdata).unwrap();

	let hash = sha256::digest(zipdata.as_slice());

	let auth = StoreAuthenticationToken {
		block_number: current_block_number,
		block_validation: 10,
		data_hash: hash,
	};

	let auth_str = serde_json::to_string(&auth).unwrap();
	let sig = admin.sign(auth_str.as_bytes());
	let sig_str = format!("{}{:?}", "0x", sig);

	println!(
		"================================== Push Bulk Packet = \n Admin:\t\t {} \n Auth_Token:\t {} \n Signature:\t {} \n ",
		admin.public(),
		auth_str,
		sig_str
	);
}

/* ************************
	 ADMIN FETCH ID
*************************/

async fn generate_fetch_id(seed_phrase: String, id_vec: String) {
	let admin = sr25519::Pair::from_phrase(&seed_phrase, None).unwrap().0;

	let current_block_number = get_current_block_number().await.unwrap();

	let admin_account = admin.public().to_ss58check();
	let hash = sha256::digest(id_vec.as_bytes());
	let auth = IdAuthenticationToken {
		block_number: current_block_number,
		block_validation: 10,
		data_hash: hash,
	};
	let auth_str = serde_json::to_string(&auth).unwrap();
	let sig = admin.sign(auth_str.as_bytes());
	let signature = format!("0x{:?}", sig);

	let packet = IdPacket { admin_account, id_vec, auth_token: auth_str, signature };

	println!(
		"================================== Backup Fetch ID Packet = \n{}\n",
		serde_json::to_string_pretty(&packet).unwrap()
	);
}

/* ************************
	 ADMIN PUSH ID
*************************/
async fn generate_push_id(seed_phrase: String, id_vec: String) {
	let admin = sr25519::Pair::from_phrase(&seed_phrase, None).unwrap().0;

	let block_number = get_current_block_number().await.unwrap();

	let admin_account = admin.public().to_ss58check();

	let data_hash = sha256::digest(id_vec.as_bytes());

	let auth = IdAuthenticationToken { block_number, block_validation: 10, data_hash };

	let auth_str = serde_json::to_string(&auth).unwrap();
	let sig = admin.sign(auth_str.as_bytes());
	let signature = format!("0x{:?}", sig);

	let packet = IdPacket { admin_account, id_vec, auth_token: auth_str, signature };

	println!(
		"================================== Backup Push ID Packet = \n{}\n",
		serde_json::to_string_pretty(&packet).unwrap()
	);
}

/* ************************
  METRIC RECONCILLIATION
*************************/

async fn generate_reconcilliation(seed_phrase: String, block_interval: String) {
	let metric = sr25519::Pair::from_phrase(&seed_phrase, None).unwrap().0;

	let current_block_number = get_current_block_number().await.unwrap();

	let metric_account = metric.public().to_ss58check();
	let hash = sha256::digest(block_interval.as_bytes());
	let auth = ReconAuthenticationToken {
		block_number: current_block_number,
		block_validation: 10,
		data_hash: hash,
	};
	let auth_str = serde_json::to_string(&auth).unwrap();
	let sig = metric.sign(auth_str.as_bytes());
	let signature = format!("0x{:?}", sig);

	let packet = ReconPacket { metric_account, block_interval, auth_token: auth_str, signature };

	println!(
		"================================== Backup Fetch ID Packet = \n{}\n",
		serde_json::to_string_pretty(&packet).unwrap()
	);
}

/* ************************
  SECRET STORE REQUEST
*************************/
// Validity time of Keyshare Data
#[derive(Serialize, Clone, Debug, PartialEq)]
pub struct AuthenticationToken {
	pub block_number: u32,
	pub block_validation: u32,
}

// Keyshare Data structure
#[derive(Clone, Debug, PartialEq)]
pub struct StoreKeyshareData {
	pub nft_id: u32,
	pub keyshare: Vec<u8>,
	pub auth_token: AuthenticationToken,
}

// Packet-signer and validity of it
#[derive(Serialize, Clone, PartialEq, Debug)]
pub struct PacketSigner {
	account: sr25519::Public,
	auth_token: AuthenticationToken,
}

#[derive(Serialize, Clone)]
pub struct StoreKeysharePacket {
	pub owner_address: sr25519::Public,

	// Signed by owner
	signer_address: String,
	signersig: String,

	// Signed by signer
	pub data: String,
	pub signature: String,
}

async fn generate_store_request(args: Args) {
	let owner = sr25519::Pair::from_phrase(&args.seed, None).unwrap().0;
	let signer = sr25519::Pair::generate().0;

	let current_block_number = if args.block_number > 0 {
		args.block_number
	} else {
		get_current_block_number().await.unwrap()
	};

	let signer_address =
		format!("{}_{}_{}", signer.public().to_ss58check(), current_block_number, args.expire);
	let signersig = owner.sign(signer_address.as_bytes());

	let secret_share = if !args.secret_share.is_empty() {
		args.secret_share
	} else {
		"This-is-a-Sample-Secret!@#$%^&*()1234567890".to_string()
	};

	let data = if !args.custom_data.is_empty() {
		args.custom_data
	} else {
		format!("{}_{}_{}_{}", args.nftid, secret_share, current_block_number, args.expire)
	};

	let signature = signer.sign(data.as_bytes());

	let packet = StoreKeysharePacket {
		owner_address: owner.public(),
		signer_address,
		signersig: format!("{}{:?}", "0x", signersig),
		data,
		signature: format!("{}{:?}", "0x", signature),
	};

	println!(
		"\n================================== Secret Store Request = \n{}\n",
		serde_json::to_string_pretty(&packet).unwrap()
	);
}

#[derive(Serialize, Debug, Clone, Copy)]
pub enum RequesterType {
	OWNER,
	DELEGATEE,
	RENTEE,
	NONE,
}

#[derive(Serialize, Clone)]
pub struct RetrieveKeysharePacket {
	pub requester_address: sr25519::Public,
	pub requester_type: RequesterType,
	pub data: String,
	pub signature: String,
}

async fn generate_retrieve_request(args: Args) {
	if args.nftid == 0 && args.custom_data.is_empty() {
		println!("\n NFTID is unknown! \n");
		return;
	}

	let current_block_number = get_current_block_number().await.unwrap();
	let owner = sr25519::Pair::from_phrase(&args.seed, None).unwrap().0;

	let data = if !args.custom_data.is_empty() {
		args.custom_data
	} else {
		format!("{}_{}_{}", args.nftid, current_block_number, args.expire)
	};

	let signature = owner.sign(data.as_bytes());

	let packet = RetrieveKeysharePacket {
		requester_address: owner.public(),
		requester_type: RequesterType::OWNER,
		data,
		signature: format!("{}{:?}", "0x", signature),
	};

	println!(
		"\n================================== Secret Retrieve Request = \n{}\n",
		serde_json::to_string_pretty(&packet).unwrap()
	);
}

/* ************************
	 ATTESTATION
*************************/
#[derive(Serialize, Clone)]
pub struct AttestationPacket {
	pub account_id: String,
	pub data: String,
	pub signature: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct QuoteResponse {
	pub block_number: u32,
	pub data: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct HealthResponse {
	pub chain: String,
	pub block_number: u32,
	pub sync_state: String,
	pub secrets_number: Option<u32>,
	pub version: String,
	pub description: String,
	pub enclave_address: String,
}

async fn attest(seed_phrase: String, attested_enclave_url: String) -> Result<(), anyhow::Error> {
	const ATTESTATION_SERVER_URL: &str = if cfg!(any(feature = "alphanet", features = "betanet")) {
		// PRODUCTION-KEY when binary is built by github
		"https://alphanet-attestation.ternoa.network/dcap_attest"
	} else if cfg!(feature = "mainnet") {
		// PRODUCTION-KEY when binary is built by github
		"https://mainnet-attestation.ternoa.network/dcap_attest"
	} else {
		// DEVELOPMENT-KEY when binary is built locally
		"https://dev-attestation.ternoa.network/dcap_attest"
	};

	let mut enclave_url = attested_enclave_url.clone();
	while enclave_url.ends_with('/') {
		enclave_url.pop();
	}

	let current_block_number = get_current_block_number().await?;

	// Create a client
	let client = reqwest::Client::builder()
		.danger_accept_invalid_certs(!cfg!(any(feature = "mainnet", feature = "alphanet")))
		.https_only(true)
		.build()?;

	// Get Health from the target Enclave
	let health_response = client.clone().get(enclave_url.clone() + "/api/health").send().await?;
	let health_response_status = health_response.status();
	let health_response_body = health_response.text().await?;
	let health_body: HealthResponse = serde_json::from_str(&health_response_body)?;
	println!(
		"Health Result for url {} is \n status: {:#?}\n health: {:#?}",
		enclave_url, health_response_status, health_body
	);

	// Get Quote from the target Enclave
	let quote_response = client.clone().get(enclave_url.clone() + "/api/quote").send().await?;

	let quote_response_status = quote_response.status();
	let quote_response_body = quote_response.text().await?;
	let quote_body: QuoteResponse = serde_json::from_str(&quote_response_body)?;

	println!(
		"Quote Result for url {} is \n status: {:#?}\n quote: {:#?}",
		enclave_url, quote_response_status, quote_body
	);

	let signer_pair = sr25519::Pair::from_phrase(&seed_phrase, None).unwrap().0;
	let signer_public = signer_pair.public().to_ss58check();
	let signature = signer_pair.sign(quote_body.data.as_bytes());

	let packet = AttestationPacket {
		account_id: signer_public,
		data: quote_response_body,
		signature: format!("{}{:?}", "0x", signature),
	};

	let attestation_request_str = serde_json::to_string(&packet).unwrap();

	// REQUEST TO ATTESTATION SERVER
	let attestation_raw_response = client
		.post(ATTESTATION_SERVER_URL)
		.body(attestation_request_str)
		.header(header::CONTENT_TYPE, "application/json")
		.send()
		.await?;

	let attestation_body = attestation_raw_response.text().await?;

	// PARSE THE ATTESTATION REPORT
	let attestation_response: AttestationResponse = serde_json::from_str(&attestation_body)?;

	println!("Attestation Result for url : {} is \n {:#?}\n\n", enclave_url, attestation_response,);

	// Verify signature of Attestation Server response
	if !verify_signature(
		&attestation_response.account,
		attestation_response.signature,
		attestation_response.report.as_bytes(),
	) {
		let message = "Invalid Report Signature".to_string();
		return Err(anyhow::Error::msg(message));
	}

	println!("Stringified report map : {}", attestation_response.report);

	// Deserialize Report
	let report: ReportResponse = serde_json::from_str(&attestation_response.report)?;

	println!("report = {:#?}", report);

	// We need to compare sending and receiving quote
	// to make sure the receiving report, belongs to the proper quote
	if !quote_body.data.starts_with(&report.isvQuoteBody) {
		println!("Requested Quote = {} \n Returned Quote = {:?}", quote_body.data, report.isvQuoteBody);
		let message = "Quote Mismatch".to_string();
		return Err(anyhow::Error::msg(message));
	}

	// Deserialize the quote
	let parsed_quote: ParsedQuote = match serde_json::from_str(&report.isvQuoteBody) {
		Ok(pq) => pq,

		Err(err) => {
			let message = format!("Error deserializing Quote from attestation report {err:?}");
			return Err(anyhow::Error::msg(message));
		},
	};

	// Verify Report_Data
	let report_data_token = format!(
		"{}_{}",
		health_body.enclave_address, quote_body.block_number
	);

	debug!("report_data token = {report_data_token}");

	if !verify_signature(
		&health_body.enclave_address.clone(),
		hex::encode(parsed_quote.body.report_data),
		report_data_token.as_bytes(),
	) {
		let message = "Invalid Report-Data Signature".to_string();
		return Err(anyhow::Error::msg(message));
	}

	Ok(())
}
