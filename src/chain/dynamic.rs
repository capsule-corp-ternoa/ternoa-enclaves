
pub enum CIType {
    Transaction,
    Storage,
    Constant,
}

pub enum ChainResult {
    TX(Result<subxt::ext::sp_core::H256, subxt::Error>),
    SC(Result<Value<subxt::ext::scale_value::scale::TypeId>, subxt::Error>),
}
pub struct ChainInteract {
    interaction_type: CIType,
    module: &'static str,
    call: &'static str,
    args: Vec<Value>,
}

impl ChainInteract {

    /// Creates a new ChainInteract
    /// # Arguments
    /// * `citype` - The type of chain interaction
    /// * `module` - The module to interact with
    /// * `call` - The call to make
    /// * `args` - The arguments to pass to the call
    /// # Returns
    /// * `ChainInteract` - The new ChainInteract
    pub fn new(citype: CIType, module: &'static str, call: &'static str, args: Vec<Value>) -> Self {
        ChainInteract {
            interaction_type: citype,
            module: module,
            call: call,
            args: args,
        }
    }

    /// Executes the chain interaction
    /// # Returns
    /// * `ChainResult` - The result of the chain interaction
    pub async fn exec(self) -> ChainResult {
        let api = get_chain_api(TERNOA_ALPHANET_RPC.into()).await;
        let signer = PairSigner::new(AccountKeyring::Alice.pair());
        let dest = AccountKeyring::Bob.to_account_id();

        match self.interaction_type {
            CIType::Transaction => {
                let tx = subxt::dynamic::tx(self.module, self.call, self.args);
                // submit the transaction with default params:
                let hash = api.tx().sign_and_submit_default(&tx, &signer).await;

                ChainResult::TX(hash)
            }

            CIType::Constant => {
                let constant_address = subxt::dynamic::constant(self.module, self.call);
                let result = api.constants().at(&constant_address);

                ChainResult::SC(result)
            }

            CIType::Storage => {
                let storage_address = subxt::dynamic::storage(self.module, self.call, self.args);

                let result = api.storage().fetch_or_default(&storage_address, None).await;

                ChainResult::SC(result)
            }
        }
    }
}

/// Gets the chain api
/// # Arguments
/// * `url` - The url of the chain
pub async fn dynamic_get_nft_data(nft_id: u32) -> Result<String, String> {
    let ci = ChainInteract::new(
        CIType::Storage,
        "nft",
        "nfts",
        vec![Value::from_bytes(nft_id.to_be_bytes())],
    );
    match ci.exec().await {
        ChainResult::SC(result) => {
            match result {
                Ok(res) => Ok(res),
                Err(err) => Err(format!("Failed to get NFT data: {}", err)),
            }
        },
        ChainResult::TX(_) => Err("Storage cannot return a transaction".to_string()),
    }
}


    /* ---------------- Sample Dynamic Calls ----------------*/
    /// Sample dynamic calls
    async fn dynamic_tx() -> Result<(), Box<dyn std::error::Error>> {
        let api = get_chain_api(TERNOA_ALPHANET_RPC.into()).await?;

        let signer = PairSigner::new(AccountKeyring::Alice.pair());
        let dest = AccountKeyring::Bob.to_account_id();
        // Create a transaction to submit:
        let tx = subxt::dynamic::tx(
            "Balances",
            "transfer",
            vec![
                // A value representing a MultiAddress<AccountId32, _>. We want the "Id" variant, and that
                // will ultimately contain the bytes for our destination address (there is a new type wrapping
                // the address, but our encoding will happily ignore such things and do it's best to line up what
                // we provide with what it needs).
                Value::unnamed_variant("Id", [Value::from_bytes(&dest)]),
                // A value representing the amount we'd like to transfer.
                Value::u128(123_456_789_012_345),
            ],
        );

        // submit the transaction with default params:
        let hash = api
            .tx()
            .sign_and_submit_default(&tx, &signer)
            .await?;
        info!("Balance transfer extrinsic submitted: {}", hash);

        Ok(())
    }


async fn dynamic_constant() -> Result<(), Box<dyn std::error::Error>> {
    let api = get_chain_api(TERNOA_ALPHANET_RPC.into()).await;
    let constant_address = subxt::dynamic::constant("nft", "ExistentialDeposit");
    let existential_deposit = api.constants().at(&constant_address)?;
    info!("Existential Deposit: {}", existential_deposit);

    Ok(())
}

async fn dynamic_storage() -> Result<(), Box<dyn std::error::Error>> {
    let api = get_chain_api(TERNOA_ALPHANET_RPC.into()).await;

    // sample: fetch an account details
    let dest = AccountKeyring::Bob.to_account_id();
    let storage_address = subxt::dynamic::storage(
        "System",
        "Account",
        vec![
            Value::from_bytes(&dest),
        ],
    );
    let account = api
        .storage()
        .fetch_or_default(&storage_address, None)
        .await?;
    info!("Bob's account details: {}", account);

    // sample: storage iteration - fetch all accounts
    let storage_address = subxt::dynamic::storage_root("System", "Account");
    let mut iter = api.storage().iter(storage_address, 10, None).await?;
    let mut counter = 0;
    while let Some((key, account)) = iter.next().await? {
        info!("{}: {}", hex::encode(key), account);
        counter += 1;
        if counter > 10 {
            break;
        }
    }

    Ok(())
}
