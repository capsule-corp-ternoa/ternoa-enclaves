use crate::helper;
use serde::{Deserialize, Serialize};
use subxt::ext::sp_core::{crypto::Ss58Codec, sr25519, Pair};

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

/* ************************
  METRIC RECONCILLIATION
*************************/

pub async fn generate_reconcilliation(seed_phrase: String, block_interval: String) {
	let metric = sr25519::Pair::from_phrase(&seed_phrase, None).unwrap().0;

	let current_block_number = helper::get_current_block_number().await.unwrap();

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
