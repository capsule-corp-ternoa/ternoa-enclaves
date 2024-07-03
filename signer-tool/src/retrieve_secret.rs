use crate::helper;
use serde::Serialize;
use subxt::ext::sp_core::{sr25519, Pair};

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

pub async fn generate_retrieve_request(args: helper::Args) {
	if args.nftid == 0 && args.custom_data.is_empty() {
		println!("\n NFTID is unknown! \n");
		return;
	}

	let current_block_number = helper::get_current_block_number().await.unwrap();
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
