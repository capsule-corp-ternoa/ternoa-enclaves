use binrw::{io::Cursor, BinRead, BinReaderExt};

use crate::helper;
use serde::{Deserialize, Serialize};
use subxt::ext::sp_core::{crypto::Ss58Codec, sr25519, Pair};
use tracing::{debug, error, info};

use anyhow::anyhow;
use base64::{engine::general_purpose, prelude::*};
use reqwest::header;

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

#[derive(Serialize, Clone)]
pub struct AttestationPacket {
	pub account_id: String,
	pub data: String,
	pub signature: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct QuoteResponse {
	pub block_number: u32,
	pub quote: String,
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

pub async fn attest(
	seed_phrase: String,
	attested_enclave_url: String,
) -> Result<(), anyhow::Error> {
	const ATTESTATION_SERVER_URL: &str = if cfg!(any(feature = "alphanet", features = "betanet")) {
		// PRODUCTION-KEY when binary is built by github
		//"https://alphanet-attestation.ternoa.network/attest_dcap"
		"http://dev-c1n1.ternoa.network:3000/attest_dcap"
	} else if cfg!(feature = "mainnet") {
		// PRODUCTION-KEY when binary is built by github
		"https://mainnet-attestation.ternoa.network/attest_dcap"
	} else {
		// DEVELOPMENT-KEY when binary is built locally
		"https://dev-attestation.ternoa.network/attest_dcap"
	};

	let mut enclave_url = attested_enclave_url.clone();
	while enclave_url.ends_with('/') {
		enclave_url.pop();
	}

	//let current_block_number = helper::get_current_block_number().await?;

	// Create a client
	let client = reqwest::Client::builder()
		.danger_accept_invalid_certs(!cfg!(any(feature = "mainnet", feature = "alphanet")))
		.https_only(false)
		.build()?;

	// Get Health from the target Enclave
	let health_response = client.clone().get(enclave_url.clone() + "/api/health").send().await?;
	let health_response_status = health_response.status();
	let health_response_body = health_response.text().await?;
	let health_body: HealthResponse = serde_json::from_str(&health_response_body)?;

	info!(
		"Health Result for url {} \n\n status: {:#?}\n health: {:#?}",
		enclave_url, health_response_status, health_body
	);

	// Get Quote from the target Enclave
	let quote_response = client.clone().get(enclave_url.clone() + "/api/quote").send().await?;

	let quote_response_status = quote_response.status();
	let quote_response_body = quote_response.text().await?;
	let quote_body: QuoteResponse = serde_json::from_str(&quote_response_body)?;

	debug!(
		"Quote Result for url {} \n\n status: {:#?}\n quote: {:#?}",
		enclave_url, quote_response_status, quote_body
	);

	let signer_pair = sr25519::Pair::from_phrase(&seed_phrase, None).unwrap().0;
	let signer_public = signer_pair.public().to_ss58check();
	let signature = signer_pair.sign(quote_response_body.as_bytes());

	let packet = AttestationPacket {
		account_id: signer_public,
		data: quote_response_body,
		signature: format!("{}{:?}", "0x", signature),
	};

	let attestation_request_str = serde_json::to_string(&packet).unwrap();

	debug!("Sending attestation Request: \n\n {:#?}", attestation_request_str);

	// REQUEST TO ATTESTATION SERVER
	let attestation_raw_response = client
		.post(ATTESTATION_SERVER_URL)
		.body(attestation_request_str)
		.header(header::CONTENT_TYPE, "application/json")
		.send()
		.await?;

	let attestation_body = attestation_raw_response.text().await?;
	debug!("Attestation Response Body:\n\n {:#?}", attestation_body);

	// PARSE THE ATTESTATION REPORT
	let attestation_response: AttestationResponse = serde_json::from_str(&attestation_body)?;

	debug!("Attestation Result for url {} \n\n {:#?}", enclave_url, attestation_response,);

	// Verify signature of Attestation Server response
	if !helper::verify_signature(
		&attestation_response.account,
		attestation_response.signature,
		attestation_response.report.as_bytes(),
	) {
		let message = "Invalid Report Signature".to_string();
		error!(message);
		return Err(anyhow::Error::msg(message));
	}

	debug!("Stringified report map : {}", attestation_response.report);

	// Deserialize Report
	let report: ReportResponse = serde_json::from_str(&attestation_response.report)?;

	println!("report = {:#?}", report);

	// We need to compare sending and receiving quote
	// to make sure the receiving report, belongs to the proper quote
	if !quote_body.quote.starts_with(&report.isvQuoteBody) {
		error!(
			"Requested Quote = {} \n Returned Quote = {:?}",
			quote_body.quote, report.isvQuoteBody
		);
		let message = "Quote Mismatch".to_string();
		error!(message);
		return Err(anyhow::Error::msg(message));
	}

	// Deserialize the quote
	let quote_body_bytes = match general_purpose::STANDARD.decode(&report.isvQuoteBody) {
		Ok(qbb) => qbb,
		Err(err) => {
			let message = format!("Error decoding isvQuote from base64 to bytes {err:?}");
			error!(message);
			return Err(anyhow::Error::msg(message));
		},
	};

	let parsed_quote: ParsedQuote = match parse_quote(&quote_body_bytes) {
		Ok(pq) => pq,

		Err(err) => {
			let message = format!("Error deserializing Quote from attestation report {err:?}");
			error!(message);
			return Err(anyhow::Error::msg(message));
		},
	};

	// Verify Report_Data
	let report_data_token = format!("{}_{}", health_body.enclave_address, quote_body.block_number);

	debug!("report_data token = {report_data_token}");

	if !helper::verify_signature(
		&health_body.enclave_address.clone(),
		hex::encode(parsed_quote.body.report_data),
		report_data_token.as_bytes(),
	) {
		let message = "Invalid Report-Data Signature".to_string();
		error!(message);
		return Err(anyhow::Error::msg(message));
	}

	info!("Remote Attestation Successful");

	Ok(())
}
