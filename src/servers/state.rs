use std::{collections::BTreeMap, sync::Arc};
use subxt::tx::PairSigner;
use tokio::sync::RwLock;

use crate::{
	backup::sync::Cluster,
	chain::{core::DefaultApi, helper},
};

pub type SharedState = Arc<RwLock<StateConfig>>;

/// StateConfig shared by all routes
pub struct StateConfig {
	enclave_key: sp_core::sr25519::Pair,
	enclave_account: String,
	enclave_signer: PairSigner<subxt::PolkadotConfig, sp_core::sr25519::Pair>,
	maintenance: String,
	rpc_client: DefaultApi,
	current_block: u32,
	nonce: u64,
	clusters: Vec<Cluster>,
	// Identity is (ClusterID, SlotID)
	identity: Option<(u32, u32)>,
	binary_version: String,
	// only for dev
	last_processed_block: u32,
	nft_block_map: BTreeMap<u32, helper::Availability>,
}

impl StateConfig {
	pub fn new(
		enclave_key: sp_core::sr25519::Pair,
		maintenance: String,
		rpc_client: DefaultApi,
		binary_version: String,
		last_processed_block: u32,
		nft_block_map: BTreeMap<u32, helper::Availability>,
	) -> StateConfig {
		let public_key = match keypair_to_public(enclave_key.clone()) {
			Some(pk) => pk.to_string(),
			None => {
				tracing::error!("State-Config : error converting keypair to account_id");
				String::new()
			},
		};

		StateConfig {
			enclave_key: enclave_key.clone(),
			enclave_account: public_key,
			enclave_signer: PairSigner::new(enclave_key),
			maintenance,
			rpc_client,
			current_block: 0,
			last_processed_block,
			nonce: 0,
			clusters: Vec::<Cluster>::new(),
			identity: None,
			binary_version,
			nft_block_map,
		}
	}

	pub fn get_key(&self) -> sp_core::sr25519::Pair {
		self.enclave_key.clone()
	}

	pub fn get_accountid(&self) -> String {
		self.enclave_account.clone()
	}

	pub fn get_signer(&self) -> &PairSigner<subxt::PolkadotConfig, sp_core::sr25519::Pair> {
		&self.enclave_signer
	}

	pub fn set_key(&mut self, keypair: sp_core::sr25519::Pair) {
		self.enclave_key = keypair.clone();

		let public_key = match keypair_to_public(keypair.clone()) {
			Some(pk) => pk.to_string(),
			None => {
				tracing::error!("SET-KEY : ERROR : converting keypair to account_id");
				String::new()
			},
		};

		self.enclave_account = public_key;
		self.enclave_signer = PairSigner::new(keypair);
	}

	pub fn get_maintenance(&self) -> String {
		self.maintenance.clone()
	}

	pub fn set_maintenance(&mut self, message: String) {
		self.maintenance = message;
	}

	pub fn get_rpc_client(&self) -> DefaultApi {
		self.rpc_client.clone()
	}

	pub fn _set_rpc_client(&mut self, new_client: DefaultApi) {
		self.rpc_client = new_client;
	}

	pub fn set_current_block(&mut self, block_number: u32) {
		self.current_block = block_number;
	}

	pub fn get_current_block(&self) -> u32 {
		self.current_block
	}

	pub fn set_processed_block(&mut self, last_processed_block: u32) {
		self.last_processed_block = last_processed_block;
	}

	pub fn get_processed_block(&self) -> u32 {
		self.last_processed_block
	}

	pub fn get_nonce(&self) -> u64 {
		self.nonce
	}

	pub fn increment_nonce(&mut self) {
		self.nonce += 1;
	}

	pub async fn reset_nonce(&mut self) {
		let account_id = self.enclave_signer.account_id();
		self.nonce = match self.rpc_client.tx().account_nonce(account_id).await {
			Ok(nonce) => nonce,
			Err(_) => self.nonce + 1, // Does it work?
		};
	}

	pub fn get_binary_version(&self) -> String {
		self.binary_version.clone()
	}

	pub fn set_clusters(&mut self, onchain_clusters: Vec<Cluster>) {
		self.clusters = onchain_clusters;
	}

	pub fn get_clusters(&self) -> Vec<Cluster> {
		self.clusters.clone()
	}

	pub fn get_identity(&self) -> Option<(u32, u32)> {
		// Identity is (ClusterID, SlotID)
		self.identity
	}

	pub fn set_identity(&mut self, identity: Option<(u32, u32)>) {
		// Identity is (ClusterID, SlotID)
		self.identity = identity;
	}

	pub fn get_nft_availability(&self, nftid: u32) -> Option<&helper::Availability> {
		tracing::trace!("\nAVAILABILITY : LOW LEVEL : GET : MAP : {:#?}", self.nft_block_map);
		self.nft_block_map.get(&nftid)
	}

	pub fn get_nft_availability_map(&self) -> BTreeMap<u32, helper::Availability> {
		self.nft_block_map.clone()
	}

	pub fn set_nft_availability(&mut self, nftid_block: (u32, helper::Availability)) {
		// Identity is (ClusterID, SlotID)
		self.nft_block_map.insert(nftid_block.0, nftid_block.1);
		tracing::trace!("\nAVAILABILITY : LOW LEVEL : SET : MAP : {:#?}", self.nft_block_map);
	}

	pub fn remove_nft_availability(&mut self, nftid: u32) {
		// Identity is (ClusterID, SlotID)
		self.nft_block_map.remove(&nftid);
		tracing::trace!("\nAVAILABILITY : LOW LEVEL : REMOVE : MAP : {:#?}", self.nft_block_map);
	}
}

fn keypair_to_public(keypair: sp_core::sr25519::Pair) -> Option<sp_core::sr25519::Public> {
	let pubkey: [u8; 32] = match keypair.as_ref().to_bytes()[64..].try_into() {
		Ok(pk) => pk,
		Err(err) => {
			tracing::error!("converting keypair to public key: {err:?}");
			return None;
		},
	};

	let public_key = sp_core::sr25519::Public::from_raw(pubkey);
	Some(public_key)
}

/* ---------------
 READ HELPERS
----------------*/

pub async fn get_chain_api(state: &SharedState) -> DefaultApi {
	let shared_state_read = state.read().await;

	// If connection is lost, will be very hard to reconnect: https://github.com/paritytech/subxt/issues/551
	// a solution to WS reconnection problem : https://github.com/AcalaNetwork/subway/blob/master/src/client/mod.rs
	// All the subscriptions and waiting extrinsics should be done agian.
	shared_state_read.get_rpc_client()
}

pub async fn get_keypair(state: &SharedState) -> sp_core::sr25519::Pair {
	let shared_state_read = state.read().await;
	shared_state_read.get_key()
}

pub async fn get_accountid(state: &SharedState) -> String {
	let shared_state_read = state.read().await;
	shared_state_read.get_accountid()
}

pub async fn get_nonce(state: &SharedState) -> u64 {
	let shared_state_read = state.read().await;
	shared_state_read.get_nonce()
}

pub async fn get_clusters(state: &SharedState) -> Vec<Cluster> {
	let shared_state_read = state.read().await;
	shared_state_read.get_clusters()
}

pub async fn get_identity(state: &SharedState) -> Option<(u32, u32)> {
	let shared_state_read = state.read().await;
	shared_state_read.get_identity()
}

pub async fn get_version(state: &SharedState) -> String {
	let shared_state_read = state.read().await;
	shared_state_read.get_binary_version()
}

pub async fn get_blocknumber(state: &SharedState) -> u32 {
	let shared_state_read = state.read().await;
	shared_state_read.get_current_block()
}

pub async fn get_processed_block(state: &SharedState) -> u32 {
	let shared_state_read = state.read().await;
	shared_state_read.get_processed_block()
}

pub async fn get_maintenance(state: &SharedState) -> String {
	let shared_state_read = state.read().await;
	shared_state_read.get_maintenance()
}

pub async fn get_nft_availability(state: &SharedState, nftid: u32) -> Option<helper::Availability> {
	let shared_state_read = state.read().await;
	shared_state_read.get_nft_availability(nftid).copied()
}

/* ---------------
 WRITE HELPERS
----------------*/

pub async fn set_blocknumber(state: &SharedState, block_number: u32) {
	let shared_state_write = &mut state.write().await;
	shared_state_write.set_current_block(block_number);
}

pub async fn set_processed_block(state: &SharedState, block_number: u32) {
	let shared_state_write = &mut state.write().await;
	shared_state_write.set_processed_block(block_number);
}

pub async fn set_keypair(state: &SharedState, keypair: sp_core::sr25519::Pair) {
	let shared_state_write = &mut state.write().await;
	shared_state_write.set_key(keypair);
}

pub async fn increment_nonce(state: &SharedState) {
	let shared_state_write = &mut state.write().await;
	shared_state_write.increment_nonce();
}

pub async fn reset_nonce(state: &SharedState) {
	let shared_state_write = &mut state.write().await;
	shared_state_write.reset_nonce().await;
}

pub async fn set_clusters(state: &SharedState, clusters: Vec<Cluster>) {
	let shared_state_write = &mut state.write().await;
	shared_state_write.set_clusters(clusters);
}

pub async fn set_identity(state: &SharedState, id: Option<(u32, u32)>) {
	let shared_state_write = &mut state.write().await;
	shared_state_write.set_identity(id);
}

pub async fn _set_chain_api(state: &SharedState, api: DefaultApi) {
	let shared_state_write = &mut state.write().await;
	shared_state_write._set_rpc_client(api);
}

pub async fn set_nft_availability(state: &SharedState, nftid_block: (u32, helper::Availability)) {
	let shared_state_write = &mut state.write().await;
	shared_state_write.set_nft_availability(nftid_block);
}

pub async fn reset_nft_availability(
	state: &SharedState,
	availability_map: BTreeMap<u32, helper::Availability>,
) {
	let shared_state_write = &mut state.write().await;
	shared_state_write.nft_block_map = availability_map;
}

pub async fn remove_nft_availability(state: &SharedState, nftid: u32) {
	let shared_state_write = &mut state.write().await;
	shared_state_write.remove_nft_availability(nftid);
}
