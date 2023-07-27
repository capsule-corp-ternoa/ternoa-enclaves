use std::sync::Arc;
use tokio::sync::RwLock;

use crate::{backup::sync::Cluster, chain::core::DefaultApi};

pub type SharedState = Arc<RwLock<StateConfig>>;

/// StateConfig shared by all routes
#[derive(Clone)]
pub struct StateConfig {
	enclave_key: sp_core::sr25519::Pair,
	enclave_account: String,
	maintenance: String,
	rpc_client: DefaultApi,
	current_block: u32,
	nonce: u32,
	clusters: Vec<Cluster>,
	// Identity is (ClusterID, SlotID)
	identity: Option<(u32, u32)>,
	binary_version: String,
	// only for dev
	last_processed_block: u32,
}

impl StateConfig {
	pub fn new(
		enclave_key: sp_core::sr25519::Pair,
		maintenance: String,
		rpc_client: DefaultApi,
		binary_version: String,
		last_processed_block: u32,
	) -> StateConfig {
		StateConfig {
			enclave_key: enclave_key.clone(),
			enclave_account: keypair_to_public(enclave_key).unwrap().to_string(),
			maintenance,
			rpc_client,
			current_block: 0,
			last_processed_block,
			nonce: 0,
			clusters: Vec::<Cluster>::new(),
			identity: None,
			binary_version,
		}
	}

	pub fn get_key(&self) -> sp_core::sr25519::Pair {
		self.enclave_key.clone()
	}

	pub fn get_accountid(&self) -> String {
		self.enclave_account.clone()
	}

	pub fn set_key(&mut self, keypair: sp_core::sr25519::Pair) {
		self.enclave_key = keypair;
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

	pub fn get_nonce(&self) -> u32 {
		self.nonce
	}

	pub fn increment_nonce(&mut self) {
		self.nonce += 1;
	}

	pub fn reset_nonce(&mut self) {
		self.nonce = 0;
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
}

fn keypair_to_public(keypair: sp_core::sr25519::Pair) -> Option<sp_core::sr25519::Public> {
	let pubkey: [u8; 32] = match keypair.as_ref().to_bytes()[64..].try_into() {
		Ok(pk) => pk,
		Err(e) => {
			tracing::error!("converting keypair to public key: {:?}", e);
			return None;
		},
	};

	let public_key = sp_core::sr25519::Public::from_raw(pubkey);
	Some(public_key)
}
