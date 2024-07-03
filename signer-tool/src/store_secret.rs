use crate::helper;
use serde::Serialize;
use subxt::ext::sp_core::{crypto::Ss58Codec, sr25519, Pair};

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

pub async fn generate_store_request(args: helper::Args) {
	let owner = sr25519::Pair::from_phrase(&args.seed, None).unwrap().0;
	let signer = sr25519::Pair::generate().0;

	let current_block_number = if args.block_number > 0 {
		args.block_number
	} else {
		helper::get_current_block_number().await.unwrap()
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
