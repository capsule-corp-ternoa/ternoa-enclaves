pub const VERSION: &str = "0.4.3";
pub const ATTESTATION_SERVER_URL: &str = "https://51.222.44.147:9100/attest";
//pub const ATTESTATION_SERVER_URL = "https://dev-c1n1.ternoa.network:9100";

// ---------- SYNC
pub const RETRY_COUNT: u8 = 5;
pub const RETRY_DELAY: u8 = 6;
pub const _MAX_STREAM_SIZE: usize = 1000 * 3 * 1024; // 3KB is the size of keyshare, 1000 is maximum number of extrinsics in block

// ---------- HTTP SERVER
pub const SEALPATH: &str = "/nft/";
pub const SYNC_STATE_FILE: &str = "/nft/sync.state";
pub const ENCLAVE_ACCOUNT_FILE: &str = "/nft/enclave_account.key";
pub const CONTENT_LENGTH_LIMIT: usize = 400 * 1024 * 1024; // 400MB for 6 millions of keyshares

// ----------- VERIFY
pub const MAX_VALIDATION_PERIOD: u32 = 20;
pub const MAX_BLOCK_VARIATION: u32 = 2;
