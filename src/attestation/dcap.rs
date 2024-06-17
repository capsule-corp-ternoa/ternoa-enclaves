#![allow(dead_code)]

use anyhow::anyhow;
use binrw::{io::Cursor, BinRead, BinReaderExt};
use serde::Deserialize;
use tracing::error;

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
