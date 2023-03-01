use axum::{extract::Path as PathExtract, response::IntoResponse};
use futures::future::join_all;
use serde::Serialize;

use std::fmt;
use subxt::{
	metadata::DecodeStaticType,
	storage::{address::Yes, StaticStorageAddress},
	tx::PairSigner,
	utils::AccountId32,
	OnlineClient, PolkadotConfig,
};
use tracing::{debug, info};

use self::ternoa::runtime_types::ternoa_pallets_primitives::nfts::NFTData;

//const TERNOA_RPC: &'static str = "wss://alphanet.ternoa.com:443";
//const TERNOA_RPC: &'static str = "wss://dev-1.ternoa.network:443";
const TERNOA_RPC: &str = "wss://dev-0.ternoa.network:443";

//#[subxt::subxt(runtime_metadata_path = "./credentials/artifacts/ternoa_alphanet.scale")]
#[subxt::subxt(runtime_metadata_path = "./credentials/artifacts/ternoa_dev0.scale")]
pub mod ternoa {}

type DefaultApi = OnlineClient<PolkadotConfig>;

#[derive(Serialize)]
pub enum ReturnStatus {
	RETRIEVESUCCESS,
	NFTNOTFOUND,
	BLOCKNOTFOUND,
}

// -------------- CHAIN API --------------

pub async fn get_chain_api(url: String) -> DefaultApi {
	debug!("5-1 get chain API");
	if url.is_empty() {
		TERNOA_RPC.to_string()
	} else {
		url
	};
	// Create a client to use:

	DefaultApi::from_url(TERNOA_RPC).await.unwrap()
}

// -------------- RPC QUERY --------------

#[derive(Serialize)]
struct JsonRPC {
	status: ReturnStatus,
	input: String,
	output: String,
}

pub async fn get_current_block_number() -> u32 {
	let api = get_chain_api(TERNOA_RPC.into()).await;

	let hash = api.rpc().finalized_head().await.unwrap();
	let last_block = api.rpc().block(Some(hash)).await.unwrap().unwrap();
	last_block.block.header.number
}

pub async fn rpc_query(PathExtract(block_number): PathExtract<u32>) -> impl IntoResponse {
	let api = get_chain_api(TERNOA_RPC.into()).await;
	// RPC : Get Block-Hash
	let block_hash = api.rpc().block_hash(Some(block_number.into())).await.unwrap();

	if let Some(hash) = block_hash {
		info!("Block hash for block number {block_number}: {hash}");
		axum::Json(JsonRPC {
			status: ReturnStatus::RETRIEVESUCCESS,
			input: "block_number=".to_owned() + &block_number.to_string(),
			output: "block_hash=".to_owned() + &block_hash.unwrap().to_string(),
		})
	} else {
		info!("Block number {block_number} not found.");
		axum::Json(JsonRPC {
			status: ReturnStatus::BLOCKNOTFOUND,
			input: "block_number=".to_owned() + &block_number.to_string(),
			output: "Block number not found.".to_string(),
		})
	}
}

// -------------- TRANSACTION --------------

#[derive(Serialize)]
struct JsonTX {
	status: u16,
	amount: u128,
	sender: String,
	receiver: String,
	tx_hash: String,
}

use sp_keyring::AccountKeyring;

pub async fn submit_tx(PathExtract(amount): PathExtract<u128>) -> impl IntoResponse {
	let api = get_chain_api(TERNOA_RPC.into()).await;

	let signer = PairSigner::new(AccountKeyring::Alice.pair());
	let dest = AccountKeyring::Bob.to_account_id().into();

	// Create a transaction to submit:
	let tx = ternoa::tx().balances().transfer(dest, amount);

	// submit the transaction with default params:
	let hash = match api.tx().sign_and_submit_default(&tx, &signer).await {
		Ok(h) => h,
		Err(e) => {
			info!("Balance transfer extrinsic Error: {}", e);

			return axum::Json(JsonTX {
				status: 430,
				amount,
				sender: String::from("ALICE"),
				receiver: String::from("BOB"),
				tx_hash: e.to_string(),
			})
		},
	};

	info!("Balance transfer extrinsic submitted: {}", hash);

	axum::Json(JsonTX {
		status: 200,
		amount,
		sender: String::from("ALICE"),
		receiver: String::from("BOB"),
		tx_hash: hash.to_string(),
	})
}

// -------------- GET NFT/CAPSULE DATA --------------
pub async fn get_onchain_nft_data(nft_id: u32) -> Option<NFTData<AccountId32>> {
	debug!("4-1 get chain NFT DATA");
	let api = get_chain_api(TERNOA_RPC.into()).await;
	let storage_address = ternoa::storage().nft().nfts(nft_id);

	api.storage().at(None).await.unwrap().fetch(&storage_address).await.unwrap()
}

pub async fn get_onchain_delegatee(nft_id: u32) -> Option<AccountId32> {
	debug!("4-2 get chain API");
	let api = get_chain_api(TERNOA_RPC.into()).await;
	let storage_address = ternoa::storage().nft().delegated_nf_ts(nft_id);

	api.storage().at(None).await.unwrap().fetch(&storage_address).await.unwrap()
}

/*
pub struct RentContractData<AccountId, BlockNumber, Balance, AccountSizeLimit>
where
	AccountId: Clone + PartialEq + Debug,
	Balance: Clone + PartialEq + Debug + sp_std::cmp::PartialOrd,
	BlockNumber: Clone + PartialEq + Debug + sp_std::cmp::PartialOrd + AtLeast32BitUnsigned + Copy,
	AccountSizeLimit: Get<u32>,
{
	/// Start block of the contract.
	pub start_block: Option<BlockNumber>,
	/// Renter of the NFT.
	pub renter: AccountId,
	/// Rentee of the NFT.
	pub rentee: Option<AccountId>,
	/// Duration of the renting contract.
	pub duration: Duration<BlockNumber>,
	/// Acceptance type of the renting contract.
	pub acceptance_type: AcceptanceType<AccountList<AccountId, AccountSizeLimit>>,
	/// Renter can cancel.
	pub renter_can_revoke: bool,
	/// Rent fee paid by rentee.
	pub rent_fee: RentFee<Balance>,
	/// Optional cancellation fee for renter.
	pub renter_cancellation_fee: CancellationFee<Balance>,
	/// Optional cancellation fee for rentee.
	pub rentee_cancellation_fee: CancellationFee<Balance>,
}
*/
pub async fn get_onchain_rent_contract(nft_id: u32) -> Option<AccountId32> {
	debug!("4-3 get chain API");
	let api = get_chain_api(TERNOA_RPC.into()).await;
	let storage_address = ternoa::storage().rent().contracts(nft_id);
	let rent_contract_data =
		api.storage().at(None).await.unwrap().fetch(&storage_address).await.unwrap();

	match rent_contract_data {
		Some(data) => Some(data.renter),
		_ => None,
	}
}

// Concurrent NFT Data

/* TODO : use TAIT (Type Alias Implementation Trait) when rust start supporting it https://blog.rust-lang.org/2022/09/22/Rust-1.64.0.html#whats-in-1640-stable

type NFTDataType = Result<Option<<<AddressType as subxt::storage::StorageAddress>::Target as subxt::metadata::DecodeWithMetadata>::Target>, subxt::Error>;

type StorageAddressRequestFuture = Pin<Box<dyn Future<Output = NFTDataType>>>;

impl IntoFuture for AddressType {
	type IntoFuture = StorageAddressRequestFuture;
	type Output = <StorageAddressRequestFuture as Future>::Output;
	fn into_future(self) -> Self::IntoFuture {
		Box::pin(self.send())
	}
}
*/

pub async fn _get_nft_data_batch(nft_ids: Vec<u32>) -> Vec<Option<NFTData<AccountId32>>> {
	debug!("4-4 get nft data batch");
	type AddressType = StaticStorageAddress<DecodeStaticType<NFTData<AccountId32>>, Yes, (), Yes>;

	let api = get_chain_api(TERNOA_RPC.into()).await;

	let nft_address: Vec<AddressType> =
		nft_ids.iter().map(|id| ternoa::storage().nft().nfts(id)).collect();

	let mut fetches = Vec::new();
	for i in 0..nft_ids.len() {
		// Critical line with complex type
		let nft_data_future = api.storage().at(None).await.unwrap().fetch(&nft_address[i]);
		fetches.push(nft_data_future);
	}

	let join_result: Vec<Result<Option<NFTData<AccountId32>>, subxt::Error>> =
		join_all(fetches).await;

	join_result.into_iter().map(|jr| jr.unwrap()).collect()
}

// -------------- GET NFT DATA --------------

#[derive(Serialize)]
struct JsonNFTData {
	status: ReturnStatus,
	nft_id: u32,
	owner: String,
	creator: String,
	offchain_data: String,
}

pub async fn get_parse_nft_data(PathExtract(nft_id): PathExtract<u32>) -> impl IntoResponse {
	let data = get_onchain_nft_data(nft_id).await;
	match data {
		Some(nft_data) => {
			info!("NFT DATA of Num.{} : \n {}", nft_id, nft_data);

			axum::Json(JsonNFTData {
				status: ReturnStatus::RETRIEVESUCCESS,
				nft_id,
				owner: nft_data.owner.clone().to_string(),
				creator: nft_data.creator.clone().to_string(),
				offchain_data: "0x".to_string() + &hex::encode(nft_data.offchain_data.0),
			})
		},

		None => axum::Json(JsonNFTData {
			status: ReturnStatus::NFTNOTFOUND,
			nft_id,
			owner: String::from("Not Found"),
			creator: String::from("Not Found"),
			offchain_data: String::from("Not Found"),
		}),
	}
}

impl fmt::Display for NFTData<AccountId32> {
	fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
		write!(
            f,
            "owner: {:#?},\n creator: {:#?}\n offchain_data: {:#?},\n royalty: {},\n collection_id: {},\n state: {:#?},\n",
            self.owner,
            self.creator,
            //std::str::from_utf8(&self.offchain_data.0).unwrap(),
	    	self.offchain_data.0,
            self.royalty.0,
            self.collection_id.unwrap_or(0u32),
            self.state
        )
	}
}

// -------------- SECRET-NFT SYNC (ORACLE) --------------

// TODO: Define macro for nft/capsule
// TODO: Proof of storage (through heart-beats)
// TODO: Proof of decryption (i.e This key-share belongs to the key for decrypting the corresponding
// nft media file on IPFS)

pub async fn nft_keyshare_oracle(
	keypair: sp_core::sr25519::Pair,
	nft_id: u32,
) -> Result<sp_core::H256, subxt::Error> {
	debug!("4-5 NFT ORACLE");
	let api = get_chain_api(TERNOA_RPC.into()).await;

	// Submit Extrinsic
	let signer = PairSigner::new(keypair);

	// Create a transaction to submit:
	let tx = ternoa::tx().nft().add_secret_shard(nft_id);

	// submit the transaction with default params:
	api.tx().sign_and_submit_default(&tx, &signer).await
}

// -------------- CAPSULE SYNC (ORACLE) --------------

// TODO: Define macro for nft/capsule
// TODO: Proof of storage (through heart-beats)
// TODO: Proof of decryption (i.e This key-share belongs to the key for decrypting the corresponding
// nft media file on IPFS)

pub async fn capsule_keyshare_oracle(
	keypair: sp_core::sr25519::Pair,
	nft_id: u32,
) -> Result<sp_core::H256, subxt::Error> {
	debug!("4-6 CAPSULE ORACLE");
	let api = get_chain_api(TERNOA_RPC.into()).await;

	// Submit Extrinsic
	let signer = PairSigner::new(keypair);

	// Create a transaction to submit:
	let tx = ternoa::tx().nft().add_capsule_shard(nft_id);

	// submit the transaction with default params:
	api.tx().sign_and_submit_default(&tx, &signer).await
}

/* **********************
		 TEST
********************** */

#[cfg(test)]
mod test {
	use super::*;
	use rand::{thread_rng, Rng};
	use std::time::Instant;

	pub async fn get_constant() -> impl IntoResponse {
		let api = get_chain_api(TERNOA_RPC.into()).await;
		// Build a constant address to query:
		let address = ternoa::constants().balances().existential_deposit();
		// Look it up:
		let existential_deposit = api.constants().at(&address).unwrap();
		info!("Existential Deposit: {}", existential_deposit);
	}

	pub async fn storage_query() -> impl IntoResponse {
		let api = get_chain_api(TERNOA_RPC.into()).await;
		let address = ternoa::storage().system().account_root();

		let mut iter = api.storage().at(None).await.unwrap().iter(address, 10).await.unwrap();
		let mut counter = 0;
		while let Some((key, account)) = iter.next().await.unwrap() {
			info!("{}: {}", hex::encode(key), account.data.free);
			counter += 1;
			if counter > 10 {
				break
			}
		}
	}

	#[tokio::test]
	async fn static_test() {
		rpc_query(axum::extract::Path(1436090)).await;
		get_constant().await;
		storage_query().await;
		submit_tx(axum::extract::Path(12_345)).await;
	}

	#[tokio::test]
	async fn concurrent_nft_test() {
		let mut rng = thread_rng();
		let nft_ids: Vec<u32> = (1..220).map(|_| rng.gen_range(100..11000)).collect();

		// Concurrent (Avg. 0.3 ms/request)
		let start = Instant::now();
		let nft_data_vec = _get_nft_data_batch(nft_ids.clone()).await;
		let elapsed_time = start.elapsed().as_micros();
		info!("\nConcurrent time is {} microseconds", elapsed_time);
		info!("Concurrent NFT Data : {:#?}", nft_data_vec[9].as_ref().unwrap().owner);
	}

	#[tokio::test]
	async fn multiple_nft_test() {
		let nft_ids = (200u32..250).collect::<Vec<u32>>();

		// Single (Avg. 48 ms/request)
		let mut nft_data = vec![get_onchain_nft_data(10).await];
		let start = Instant::now();
		for id in nft_ids.clone() {
			nft_data.push(get_onchain_nft_data(id).await);
		}
		let elapsed_time = start.elapsed().as_micros();
		info!("\nSingle time is {} microseconds", elapsed_time);
		info!("Single NFT Data : {:#?}", nft_data[9].as_ref().unwrap().owner);
	}
}
