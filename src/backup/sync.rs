#![allow(dead_code)]

use std::collections::HashMap;

use subxt::PolkadotConfig;
use subxt::blocks::ExtrinsicEvents;
use subxt::rpc::types::BlockNumber;
use tracing::{error, debug, info, trace};

use crate::chain::core::ternoa::nft::events::{CapsuleSynced, SecretNFTSynced};
use crate::chain::core::{get_chain_api, ternoa};
use crate::servers::http_server::SharedState;
use anyhow::{Result, anyhow};
use subxt::utils::AccountId32;

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
/* ----------------------------
		CLUSTER DISCOVERY
------------------------------ */
// Crawl and parse registered clusters and enclaves on-chain
pub async fn cluster_discovery(state: SharedState) -> Result<Vec<Cluster>, anyhow::Error> {
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
			return Err(anyhow!("Cluster Discovery : Failed to fetch next cluster index."))
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
					error!("Cluster Discovery : Failed to fetch enclave data. Operator : {}", operator_account.to_string());
					return Err(anyhow!("Failed to fetch enclave data. Operator : {}", operator_account.to_string()))
				} ,
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

	let write_state = &mut state.write().await;
	write_state.set_clusters(clusters.clone());

	Ok(clusters)
}

// Find own slot number
pub async fn self_slot(state: SharedState) -> Option<u32> {
	let read_state = state.read().await;
	let chain_clusters = read_state.get_clusters();
	let self_enclave_account = read_state.get_accountid();

	for cluster in chain_clusters {
		for enclave in cluster.enclaves {
			if enclave.enclave_account.to_string() == self_enclave_account {
				return Some(enclave.slot);
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
pub async fn slot_discovery(state: SharedState) -> Vec<String> {
	let read_state = state.read().await;
	let chain_clusters = read_state.get_clusters();

	let slot = self_slot(state.clone()).await.unwrap();

	let mut urls = Vec::<String>::new();
	for cluster in chain_clusters {
		for enclave in cluster.enclaves {
			if enclave.slot == slot {
				urls.push(enclave.enclave_url);
				break;
			}
		}
	}

	urls
}

/* ----------------------------
		EVENTS CRAWLER
------------------------------ */
// Detect new NFT synced event and look for corresponding enclaves-slot containing the keyshare
// It is part of "Running Enclave Synchronization"
pub async fn crawl_sync_events(state: SharedState, from_block_num: u32, to_block_num: u32) -> Result<HashMap::<u32, u32>> {
	let api = get_chain_api(state).await;
	
	// Storage to find the cluster of an enclave which contains specific NFTID
	let storage = match api.storage().at_latest().await {
		Ok(storage) => storage,
		Err(err) => {
			error!("Cluster Discovery : Failed to get storage: {:?}", err);
			return Err(err.into());
		},
	};

	// Hashmap for fetch nftid-cluste 
	let mut nftid_cluster_map = HashMap::<u32, u32>::new();

	for block_counter in from_block_num..=to_block_num {
		// Find block hash
		debug!("crawler : block number  = {}", block_counter);
		let block_number = BlockNumber::from(block_counter);
		let block_hash = api
			.rpc()
			.block_hash(Some(block_number))
			.await?
			.expect("Can not find block hash");
		
		// Read the block from blockchain
		let block = api.blocks().at(block_hash).await?;
		
		// Extract block body
		let body = block.body().await?;
		
		// Extract block events
		//let events = block.events().await?;

		// For all extrinsics in the block body
		for ext in body.extrinsics().iter() {
			let ext = ext?;
			let pallet = ext.pallet_name()?;
			let call = ext.variant_name()?;
			let events = ext.events().await?;
			//debug!("  - crawler extrinsic  = {} : {}", pallet, call);

			if pallet == "NFT" {
				match call {
					// Capsule
					"add_capsule_shard" => {
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
										nftid_cluster_map.insert(nftid, cluster_id);
										info!("  - Capsule Synced Event Detected, Cluster_ID {}, NFT_ID: {}", cluster_id, nftid);
									},
									None => debug!("  - Capsule Synced Event Detected, but there is not corresponding CapsuleShardAdded event for nft_id: {}", nftid),
								}
							},
							None => debug!("  - Capsule Synced Event NOT Detected for addCapsuleShard Extrinsic"),
						}
					},
					
					// Secret
					"add_secret_shard" => {
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
										nftid_cluster_map.insert(nftid, cluster_id);
										info!("  - Secret-NFT Synced Event Detected, Cluster_ID {}, NFT_ID: {}", cluster_id, nftid);
									},
									None => debug!("  - Secret-NFT Synced Event Detected, but there is not corresponding ShardAdded event for nft_id: {}", nftid),
								}
							},
							None => debug!("  - Secret-NFT Synced Event NOT Detected for addSecretShard Extrinsic"),
						}
					},

					_ => debug!("  - NFT extrinsic is not about shards : {}", call),
				}
			}else {
				trace!(" - Extrinsic is not about NFT : Pallet: {}, Call: {}", pallet, call);
			}
		}
	}
	
	Ok(nftid_cluster_map)
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
				return Some(ev.nft_id)
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
				return Some(ev.nft_id)
			},
			Err(err) => {
				debug!("  - error reading secret synced : {:?}", err);
			},
		}
	}
	None
}

// Return enclave Account, it can be used to find the cluster
pub fn find_event_capsule_shard_added(events: &ExtrinsicEvents<PolkadotConfig>, nftid: u32) -> Option<AccountId32> {
	
	let acevt = events.find::<ternoa::nft::events::CapsuleShardAdded>();
	
	for e in acevt {
		match e {
			Ok(ev) => {
				if ev.nft_id == nftid {
					debug!("  - found a capsule added for given nftid : {}", nftid);
					return Some(ev.enclave)
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
pub fn find_event_secret_shard_added(events: &ExtrinsicEvents<PolkadotConfig>, nftid: u32) -> Option<AccountId32> {

	let asevt = events.find::<ternoa::nft::events::ShardAdded>();
	
	for e in asevt {
		match e {
			Ok(ev) => {
				if ev.nft_id == nftid {
					debug!("  - found a secret added for given nftid : {}", nftid);
					return Some(ev.enclave)
				}
			},
			Err(err) => {
				debug!("  - error reading secret added : {:?}", err);
			},
		}
	}

	None
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

	use crate::{chain::core::create_chain_api, servers::http_server::StateConfig};

	use super::*;

	#[tokio::test]
	async fn test_cluster_discovery() {
		let subscriber = FmtSubscriber::builder().with_max_level(Level::DEBUG).finish();
		tracing::subscriber::set_global_default(subscriber)
			.expect("main: setting default subscriber failed");

		// Test environment

		let (enclave_keypair, _, _) = sp_core::sr25519::Pair::generate_with_phrase(None);

		let seal_path = "/tmp/seal".to_owned();
		let state_config: SharedState = Arc::new(RwLock::new(StateConfig::new(
			enclave_keypair,
			seal_path.clone(),
			"Test-Enclave".to_string(),
			String::new(),
			create_chain_api().await.unwrap(),
			"0.3.0".to_string(),
		)));

		let mut app = match crate::servers::http_server::http_server(
			"Test-Enclave",
			seal_path.as_str(),
		)
		.await
		{
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

		let clusters = cluster_discovery(state_config.clone()).await;
		println!("{:?}\n", clusters);

		let cluster_nft_map = crawl_sync_events(state_config, 1323900, 1324200).await;
		println!("To be fetched from cluster-slot : {:?}", cluster_nft_map.unwrap());
	}

	#[tokio::test]
	async fn test_subscribe_sync_events() {}
}
