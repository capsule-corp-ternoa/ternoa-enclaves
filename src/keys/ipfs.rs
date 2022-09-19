use hyper::{Body, Client as hyperclient, Response};
use hyper_tls::HttpsConnector;
use lazy_static::lazy_static;
use reqwest::{multipart, Client as reqwestclient};
use serde::Deserialize;
use std::env::var;
use std::io::Read;
use std::path::Path;

#[derive(Deserialize)]
pub struct IpfsResponse {
    name: String,
    hash: String,
    size: String,
}

const TERNOA_IPFS_BASE_URL: &'static str = "https://ipfs.ternoa.dev";

lazy_static! {
    pub static ref IPFS_BASE_URL: String = if var("IPFS_BASEURL").is_ok() {
        var("IPFS_BASEURL").unwrap()
    } else {
        TERNOA_IPFS_BASE_URL.to_string()
    };
    pub static ref IPFS_GATEWAY_URL: String = IPFS_BASE_URL.to_owned() + "/ipfs/";
    pub static ref IPFS_API_URL: String = IPFS_BASE_URL.to_owned() + "/api/v0/";
}

pub struct TernoaIpfsApi {
    api_url: String,
    gateway_url: String,
}

impl TernoaIpfsApi {
    pub fn new(apiurl: &String, gateurl: &String) -> Self {
        TernoaIpfsApi {
            api_url: apiurl.to_string(),
            gateway_url: gateurl.to_string(),
        }
    }

    pub async fn add_file(&self, file_path: &Path) -> String {
        let mut reader = std::fs::File::open(file_path).unwrap();
        let mut content = Vec::<u8>::new();
        reader.read_to_end(&mut content).unwrap();

        let file_name = file_path.file_name().unwrap().to_str().unwrap().to_string();
        let part = reqwest::multipart::Part::stream(content).file_name(file_name);
        let form = multipart::Form::new().part("file", part);

        let client = reqwestclient::new();
        let resp = client
            .post(self.api_url.to_owned() + "add")
            .multipart(form)
            .send()
            .await
            .unwrap()
            .json::<IpfsResponse>()
            .await
            .unwrap();

        println!(
            "Name = {} \n Hash = {} \n Size = {} \n",
            resp.name, resp.hash, resp.size
        );

        resp.hash
    }

    pub async fn cat_file(&self, cid: &str) -> Response<Body> {
        let https = HttpsConnector::new();
        let client = hyperclient::builder().build::<_, hyper::Body>(https);
        let url = self.gateway_url.to_owned() + cid;
        let parsed = url.parse().unwrap();
        let res = client.get(parsed).await.unwrap();
        println!("Response Status = {} \n", res.status());
        res
    }
}

/* ------------------ TETS ----------------- */

#[cfg(test)]
mod tests {
    use futures::StreamExt;
    use std::path::Path;

    use super::*;
    const FILEPATH: &'static str = "./credentials/keys/";
    /* HTTPS */
    #[tokio::test]
    async fn upload_file_http() {
        let ternoa_ipfs =
            TernoaIpfsApi::new(&IPFS_API_URL.to_string(), &IPFS_GATEWAY_URL.to_string());
        let full_path = FILEPATH.to_string() + "passwordx.txt";
        let path = Path::new(&full_path);

        ternoa_ipfs.add_file(path).await;
    }

    #[tokio::test]
    async fn download_file_http() {
        //let CID = "QmTcs4gtZ8QfotzH82AnLE84FVdK75uNGWBBKMniw68AG3";
        let cid = "QmS6yiJ9epgShMS8r4ZggZWsgxRkghM5883g77DtHhh7B8";
        let ternoa_ipfs = TernoaIpfsApi::new(
            &(IPFS_GATEWAY_URL.to_string()),
            &IPFS_GATEWAY_URL.to_string(),
        );

        let mut res = ternoa_ipfs.cat_file(cid).await;

        let mut data = Vec::<u8>::with_capacity(2000);
        while let Some(chunk) = res.body_mut().next().await {
            data.extend(&chunk.unwrap());
        }
        //let parsed: char = serde_json::from_slice(&data).unwrap();
        println!("response = {}", String::from_utf8(data).unwrap());
    }
}
