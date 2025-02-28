use cosmwasm_schema::cw_serde;
use cosmwasm_std::Addr;
// use schemars::JsonSchema;
// use serde::{Deserialize, Serialize};

// #[cw_serde]
// pub struct MessageResponse {
//     pub msg: String,
// }

// #[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
#[cw_serde]
pub struct NftLockEntryResponse {
    pub contract_address: Addr,
    pub token_id: String,
    pub sender: Addr,
    pub did: String,
}
