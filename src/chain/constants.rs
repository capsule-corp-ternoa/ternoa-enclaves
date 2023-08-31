pub const VERSION: &str = "0.4.3";
pub const ATTESTATION_SERVER_URL: &str = if cfg!(any(feature = "release-build")) {
	// PRODUCTION-KEY when binary is built by github
	"https://dev-c1n3.ternoa.network:9200/attest"
} else {
	// DEVELOPMENT-KEY when binary is built locally
	"https://dev-c1n3.ternoa.network:9100/attest"
};

//pub const ATTESTATION_SERVER_URL = "https://dev-c1n1.ternoa.network:9100";

pub const GITHUB_SIGN_PUBLIC_KEY: &str = if cfg!(feature = "release-build") {
	"https://gist.githubusercontent.com/zorvan/9221744faa5b18d8e9918fc6d8014958/raw/b07e9954ce708e614b79314f1530566278575abf/cosign.pub"
} else {
	"https://gist.githubusercontent.com/zorvan/46b26ff51b27590683ddaf70c0ea9dac/raw/1f6d02e3232f556a31b1bfe4a6ba491e7d5b5ff7/cosign.pub"
};

pub const PRODUCTION_SIGN_PUBLIC_KEY: &str = "-----BEGIN PUBLIC KEY-----\n
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEP3rRdMrdqDujXJV30xjUh2WzWAe2\n
bHJqMbnlRocYFo07kCI2SW41AxEVumpcqGSI1cxjUeEdMGfxD/liGj6msQ==\n
-----END PUBLIC KEY-----";

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
