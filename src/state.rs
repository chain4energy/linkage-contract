use cosmwasm_std::Addr;
use did_contract::state::Did;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
pub struct Nft {
    pub contract_address: Addr,
    pub token_id: String,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
pub struct NftLockEntry {
    pub sender: Addr,
    pub did: Did,
}