pub const VERSION: &str = env!("CARGO_PKG_VERSION");
pub const ATTESTATION_SERVER_URL: &str = if cfg!(any(feature = "alphanet", features = "betanet")) {
	// PRODUCTION-KEY when binary is built by github
	"https://alphanet-attestation.ternoa.network/attest"
} else if cfg!(feature = "mainnet") {
	// PRODUCTION-KEY when binary is built by github
	"https://mainnet-attestation.ternoa.network/attest"
} else {
	// DEVELOPMENT-KEY when binary is built locally
	"https://dev-attestation.ternoa.network/attest"
};

pub const SENTRY_URL: &str = "https://089e5c79239442bfb6af6e5d7676644c@error.ternoa.dev/22";

// ---------- SYNC
pub const RETRY_COUNT: u8 = 5;
pub const RETRY_DELAY: u8 = 6;
pub const _MAX_STREAM_SIZE: usize = 1000 * 3 * 1024; // 3KB is the size of keyshare, 1000 is maximum number of extrinsics in block

// ---------- HTTP SERVER
pub const SEALPATH: &str = "/nft";
pub const SYNC_STATE_FILE: &str = "/nft/sync.state";
pub const ENCLAVE_ACCOUNT_FILE: &str = "/nft/enclave_account.key";
pub const CONTENT_LENGTH_LIMIT: usize = 400 * 1024 * 1024; // 400MB for 6 millions of keyshares

// ----------- VERIFY
pub const MAX_VALIDATION_PERIOD: u32 = 20;
pub const MAX_BLOCK_VARIATION: u32 = 2;
pub const MAX_KEYSHARE_SIZE: u16 = 3000;
pub const MIN_KEYSHARE_SIZE: u16 = 16;

// ----------- CHAIN's GENESIS HASH
pub const MAINNET_GENESIS_HASH: &str =
	"6859c81ca95ef624c9dfe4dc6e3381c33e5d6509e35e147092bfbc780f777c4e";
pub const ALPHANET_GENESIS_HASH: &str =
	"535f8421af34dfbb87736b3b2231ddb3c598b0b2cd73a4c5e93b13bf6e65f4c0";
