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

const PAGE_SIZE:i64 = 100;

#[derive(GraphQLQuery)]
#[graphql(
	schema_path = "credentials/query/schema.graphql",
	query_path = "credentials/query/secrets.graphql",
	response_derives = "Debug",
	variable_derives = "Clone",
	normalization = "rust"
)]
pub struct TotalSynced;

#[derive(GraphQLQuery)]
#[graphql(
	schema_path = "credentials/query/schema.graphql",
	query_path = "credentials/query/secrets.graphql",
	response_derives = "Debug",
	variable_derives = "Clone",
	normalization = "rust"
)]
pub struct SyncedInfo;


pub const MAINNET_CHAIN_URL: &str = "wss://mainnet.ternoa.network:443";
pub const ALPHANET_CHAIN_URL: &str = "wss://alphanet.ternoa.com:443";
pub const MAINNET_INDEXER_URL: &str = "https://indexer-mainnet.ternoa.dev/";
pub const MAINNET_DICTIONARY_URL: &str = "https://dictionary-mainnet.ternoa.network";
pub const ALPHANET_INDEXER_URL: &str = "https://indexer-alphanet.ternoa.dev/";
pub const ALPHANET_DICTIONARY_URL: &str = "https://dictionary-alphanet.ternoa.network";


pub async fn get_total_synced() -> Result<i64, Box<dyn Error>> {
    let client = reqwest::Client::new();
    let variables = synced_info::Variables{};
    let request_body = SyncedInfo::build_query(variables);
    let res = client.post(MAINNET_INDEXER_URL).json(&request_body).send().await?;
    let response_body: Response<synced_info::ResponseData> = res.json().await?;
    let entity = response_body.data.unwrap().nft_entities.unwrap();
    let total = entity.total_count;

    Ok(total)
}
pub async fn get_synced_nft() -> Result<Vec<u32>, Box<dyn Error>> {
    
    let total = get_total_synced().await?;
    let pages_num = 1+total/PAGE_SIZE;
    let pages_offset = (0..pages_num).map(|x| PAGE_SIZE * x).collect::<Vec<_>>();

    let mut ids: Vec<u32> = Vec::new();
    
    let client = reqwest::Client::new();

    // Get all the results
    for offset in pages_offset {

        let variables = total_synced::Variables{page_size: PAGE_SIZE, count_offset: offset};
        let request_body = TotalSynced::build_query(variables);
        let res = client.post(MAINNET_INDEXER_URL).json(&request_body).send().await?;
        let response_body: Response<total_synced::ResponseData> = res.json().await?;
        let entity = response_body.data.unwrap().nft_entities.unwrap();
        let nodes = entity.nodes;
    
        for id in &nodes {
            ids.push(id.as_ref().unwrap().nft_id.parse::<u32>().unwrap())
        }
    }

	Ok(ids)
}


#[cfg(test)]
mod test {
    use super::*;
	
    #[tokio::test]
	async fn get_synced_test() {
		let response = get_synced_nft().await;
        println!("Number of synced: {}", response.unwrap().len());
	}
}
