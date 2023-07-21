#![allow(dead_code)]
#![allow(unused_variables)]

/*
1. Fetch NFT Ids from blockchain (Bootstrap, Resume)
2. Request other enclaves for backups for a set of NFTs.

3. Authentication:
 - Check from blockchain if the enclave is authorised to receive the secret (slot-number based)
4. Fetch the NFT secrets and seal to disk
 */

use graphql_client::*;
use reqwest;
use std::error::Error;

type BigInt = String;
type Cursor = String;

const PAGE_SIZE: i64 = 100;

#[cfg(feature = "mainnet")]
pub const CHAIN_URL: &str = "wss://mainnet.ternoa.network:443";
#[cfg(feature = "mainnet")]
pub const INDEXER_URL: &str = "https://indexer-mainnet.ternoa.dev/";

#[cfg(feature = "alphanet")]
pub const CHAIN_URL: &str = "wss://alphanet.ternoa.com:443";
#[cfg(feature = "alphanet")]
pub const INDEXER_URL: &str = "https://indexer-alphanet.ternoa.dev/";

#[cfg(feature = "dev-0")]
pub const CHAIN_URL: &str = "wss://dev-0.ternoa.com:443";
#[cfg(feature = "dev-0")]
pub const INDEXER_URL: &str = "https://dev-0.ternoa.dev/";

/*  ----------------------------------
	Convert NFTID to NodeID
---------------------------------- */

#[derive(GraphQLQuery)]
#[graphql(
	schema_path = "./query/schema.graphql",
	query_path = "./query/secrets.graphql",
	response_derives = "Debug",
	variable_derives = "Clone",
	normalization = "rust"
)]
pub struct GetNode;

pub async fn get_node_from_id(nftid: u32) -> Result<String, Box<dyn Error>> {
	let client = reqwest::Client::new();
	let variables = get_node::Variables { nftid: nftid.to_string() };
	let request_body = GetNode::build_query(variables);
	let res = client.post(INDEXER_URL).json(&request_body).send().await?;
	let response_body: Response<get_node::ResponseData> = res.json().await?;
	let data = match response_body.data {
		Some(data) => data,
		_ => return Ok("0".to_string()),
	};

	let entity = data.nft_entities.unwrap();
	let node_id = entity.nodes[0].as_ref().unwrap().node_id.clone();

	Ok(node_id)
}

/*  ----------------------------------
Get the Total Number of Synced NFT
---------------------------------- */

#[derive(GraphQLQuery)]
#[graphql(
	schema_path = "./query/schema.graphql",
	query_path = "./query/secrets.graphql",
	response_derives = "Debug",
	variable_derives = "Clone",
	normalization = "rust"
)]
pub struct SyncedInfo;

pub async fn get_total_synced(after_nftid: u32) -> Result<i64, Box<dyn Error>> {
	let client = reqwest::Client::new();
	let variables = synced_info::Variables { after: after_nftid.to_string() };
	let request_body = SyncedInfo::build_query(variables);
	let res = client.post(INDEXER_URL).json(&request_body).send().await?;
	let response_body: Response<synced_info::ResponseData> = res.json().await?;
	if response_body.data.is_none() {
		return Ok(0);
	}
	let entity = response_body.data.unwrap().nft_entities.unwrap();
	let total = entity.total_count;

	Ok(total)
}

/*  ----------------------------------
	Get the List of Synced NFT
---------------------------------- */

#[derive(GraphQLQuery)]
#[graphql(
	schema_path = "./query/schema.graphql",
	query_path = "./query/secrets.graphql",
	response_derives = "Debug",
	variable_derives = "Clone",
	normalization = "rust"
)]
pub struct TotalSynced;

pub async fn get_synced_nft(after_nftid: u32) -> Result<Vec<u32>, Box<dyn Error>> {
	let total = get_total_synced(after_nftid).await?;

	let mut ids: Vec<u32> = Vec::new();

	let client = reqwest::Client::new();
	let mut offset = 0;
	let mut has_nex_page = true;
	// Get all the results
	while has_nex_page {
		let variables = total_synced::Variables {
			page_size: PAGE_SIZE,
			count_offset: offset,
			after: after_nftid.to_string(),
		};
		let request_body = TotalSynced::build_query(variables);
		let res = client.post(INDEXER_URL).json(&request_body).send().await?;
		let response_body: Response<total_synced::ResponseData> = res.json().await?;
		if response_body.data.is_none() {
			return Ok(vec![]);
		}
		let entity = response_body.data.unwrap().nft_entities.unwrap();
		let nodes = entity.nodes;

		for id in &nodes {
			ids.push(id.as_ref().unwrap().nft_id.parse::<u32>().unwrap())
		}

		if entity.page_info.has_next_page {
			offset += PAGE_SIZE;
		} else {
			has_nex_page = false;
		}
	}

	Ok(ids)
}

#[cfg(test)]
mod test {
	use super::*;

	#[tokio::test]
	async fn get_nodeid_test() {
		let node_id = get_node_from_id(76724).await;
		println!("Node Id: {}", node_id.unwrap());
	}

	#[tokio::test]
	async fn get_synced_test() {
		let response = get_synced_nft(75000).await.unwrap();
		println!(
			"Number of synced: {}\n First NFTID: {}, Last NFTID: {}",
			response.len(),
			response[0],
			response[response.len() - 1]
		);
	}
}
