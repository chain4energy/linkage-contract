use crate::error::ContractError;
use crate::responses::{MessageResponse, NftLockEntryResponse};
use cosmwasm_std::Order::Ascending;
use cosmwasm_std::{
    to_json_binary, to_json_string, Addr, Binary, Response, StdResult, SubMsg,
    SubMsgResult, WasmMsg,
};
use cw_storage_plus::{Item, Map};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use sylvia::ctx::{ExecCtx, InstantiateCtx, QueryCtx, ReplyCtx};
use sylvia::{contract, entry_points};

pub struct LinkageContract {
    pub(crate) authorized_contract: Item<Addr>,
    locked_nfts: Map<String, NftLockEntry>,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub struct TransferNftMsg {
    recipient: String,
    token_id: String,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub struct Cw721ExecuteMsg {
    transfer_nft: TransferNftMsg,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
pub struct NftLockEntry {
    sender: Addr,
    did: String,
}

#[entry_points]
#[contract]
#[sv::error(ContractError)]
#[sv::features(replies)]
impl LinkageContract {
    pub const fn new() -> Self {
        LinkageContract {
            authorized_contract: Item::new("authorized_contract"),
            locked_nfts: Map::new("locked_nfts"),
        }
    }

    #[sv::msg(instantiate)]
    pub fn instantiate(&self, ctx: InstantiateCtx, msg: Addr) -> StdResult<Response> {
        self.authorized_contract.save(ctx.deps.storage, &msg)?;
        Ok(Response::default())
    }

    #[sv::msg(query)]
    pub fn authorized_contract(&self, ctx: QueryCtx) -> Result<MessageResponse, ContractError> {
        let result = self.authorized_contract.load(ctx.deps.storage);
        match result {
            Ok(a) => Ok(MessageResponse { msg: a.to_string() }),
            Err(e) => Err(ContractError::LinkageContractError(e)),
        }
    }

    #[sv::msg(query)]
    pub fn count_locked_nfts(&self, ctx: QueryCtx) -> Result<MessageResponse, ContractError> {
        let count = self
            .locked_nfts
            .keys(ctx.deps.storage, None, None, Ascending)
            .count();
        Ok(MessageResponse {
            msg: count.to_string(),
        })
    }

    #[sv::msg(query)]
    pub fn get_locked_nft(
        &self,
        ctx: QueryCtx,
        token_id: String,
    ) -> Result<NftLockEntryResponse, ContractError> {
        let cloned_token_id = token_id.clone();
        let result = self.locked_nfts.load(ctx.deps.storage, token_id);
        match result {
            Ok(a) => Ok(NftLockEntryResponse {
                token_id: cloned_token_id,
                sender: a.sender,
                did: a.did,
            }),
            Err(e) => Err(ContractError::LinkageContractError(e)),
        }
    }

    #[sv::msg(exec)]
    pub fn receive_nft(
        &self,
        ctx: ExecCtx,
        sender: Addr,
        token_id: String,
        msg: Binary,
    ) -> Result<Response, ContractError> {
        let bytes = msg.to_vec();
        let did = String::from_utf8(bytes).unwrap();
        let auth_contract = self.authorized_contract.load(ctx.deps.storage);
        match auth_contract {
            Ok(v) => {
                // check if sender-contract is same as authorized contract
                let equal = ctx.info.sender.eq(&v);
                if !equal {
                    return Err(ContractError::UnauthorizedContractError);
                }

                // save NftLockEntry
                let entry: NftLockEntry = NftLockEntry { sender, did };
                let result = self.locked_nfts.save(ctx.deps.storage, token_id, &entry);
                match result {
                    Ok(_) => Ok(Response::default()),
                    Err(e) => Err(ContractError::LinkageContractError(e)),
                }
            }
            Err(e) => Err(ContractError::LinkageContractError(e)),
        }
    }

    #[sv::msg(exec)]
    pub fn unlock_nft(&self, ctx: ExecCtx, token_id: String) -> Result<Response, ContractError> {
        // find NFT
        let result = self.locked_nfts.load(ctx.deps.storage, token_id.clone());
        match result {
            Ok(a) => {
                // check if sender is same as sender in NftLockEntry
                let eq = ctx.info.sender.eq(&a.sender);
                if !eq {
                    return Err(ContractError::UnauthorizedContractError);
                }

                // if eq then remove and query cw721_base
                let exec_msg = Cw721ExecuteMsg {
                    transfer_nft: TransferNftMsg {
                        recipient: ctx.info.sender.into_string(),
                        token_id: token_id.clone(),
                    },
                };

                let auth_contract_address = self.authorized_contract.load(ctx.deps.storage)?;

                let msg = WasmMsg::Execute {
                    contract_addr: auth_contract_address.into_string(),
                    msg: to_json_binary(&exec_msg)?,
                    funds: vec![],
                };

                let sub_msg = SubMsg::reply_on_error(msg, 1u64);

                self.locked_nfts.remove(ctx.deps.storage, token_id);
                Ok(Response::new().add_submessage(sub_msg))
            }
            Err(e) => Err(ContractError::LinkageContractError(e)),
        }
    }

    #[sv::msg(reply)]
    fn reply(
        &self,
        _ctx: ReplyCtx,
        result: SubMsgResult,
        #[sv::payload(raw)] payload: Binary,
    ) -> Result<Response, ContractError> {
        let response = to_json_string(&result)?;
        Ok(Response::new()
            .add_attribute("action", "Cw721base error response")
            .add_attribute("result", response)
            .add_attribute("payload", String::from_utf8(payload.to_vec()).unwrap()))
    }
}

#[cfg(test)]
mod tests {
    use crate::contract::sv::mt::{CodeId, LinkageContractProxy};
    use crate::responses::NftLockEntryResponse;
    use cosmwasm_std::{to_json_binary, Binary, Empty, Response, StdResult};
    use cw721::{Cw721ExecuteMsg, Cw721QueryMsg};
    use cw_multi_test::{Contract, ContractWrapper, Executor, IntoAddr};
    use sylvia::multitest::App;

    #[test]
    fn instantiate_and_get_authorized_contract() {
        let app = App::default();
        let code_id = CodeId::store_code(&app);

        let owner = "owner".into_addr();

        let auth_address = "cw721_address".into_addr();

        let contract = code_id
            .instantiate(auth_address.clone())
            .call(&owner)
            .unwrap();

        let result = contract.authorized_contract();
        assert!(result.is_ok(), "Expected Ok, but go an Err");
        assert_eq!(auth_address.to_string(), result.unwrap().msg)
    }

    #[test]
    fn receive_nft_and_get_locked_nfts() {
        let app = App::default();
        let code_id = CodeId::store_code(&app);
        let owner = "owner".into_addr();
        let auth_address = "cw721_address".into_addr();
        let contract = code_id
            .instantiate(auth_address.clone())
            .call(&owner)
            .unwrap();

        let sender = "sender_address".into_addr();
        let token_id = String::from("token_id");
        let msg = Binary::new("did:address".as_bytes().to_vec());

        let result = contract
            .receive_nft(sender.clone(), token_id.clone(), msg.clone())
            .call(&auth_address);
        assert!(result.is_ok(), "Expected Ok, but got Err");

        let result = contract.count_locked_nfts();
        assert!(result.is_ok(), "Expected Ok, but got Err");
        assert_eq!("1", result.unwrap().msg);

        let unauth_address = "unauth_address".into_addr();

        let result = contract
            .receive_nft(sender.clone(), token_id.clone(), msg.clone())
            .call(&unauth_address);
        assert!(result.is_err(), "Expected Err, but got Ok");

        let result = contract.count_locked_nfts();
        assert!(result.is_ok(), "Expected Ok, but got Err");
        assert_eq!("1", result.unwrap().msg);
    }

    #[test]
    fn receive_nft_and_get_locked_nft() {
        let app = App::default();
        let code_id = CodeId::store_code(&app);
        let owner = "owner".into_addr();
        let auth_address = "cw721_address".into_addr();
        let contract = code_id
            .instantiate(auth_address.clone())
            .call(&owner)
            .unwrap();

        let sender = "sender_address".into_addr();
        let token_id = String::from("token_id");
        let msg = Binary::new("did:address".as_bytes().to_vec());

        let result = contract.get_locked_nft(token_id.clone());
        assert!(result.is_err(), "Expected Err, but got Ok");

        let result = contract
            .receive_nft(sender.clone(), token_id.clone(), msg.clone())
            .call(&auth_address);
        assert!(result.is_ok(), "Expected Ok, but got Err");

        let expected_nft = NftLockEntryResponse {
            token_id: token_id.clone(),
            sender: sender.clone(),
            did: String::from_utf8(msg.to_vec()).unwrap(),
        };

        let result = contract.get_locked_nft(token_id);
        assert!(result.is_ok(), "Expected Ok, but got Err");
        assert_eq!(expected_nft, result.unwrap());
    }

    #[test]
    fn unlock_nft() {
        let app = App::default();
        let linkage_code_id = CodeId::store_code(&app);
        let cw721_base_code_id = app.app_mut().store_code(cw721_base_contract_mock());

        let owner_address = "owner".into_addr();

        let sender = "sender_address".into_addr();
        let token_id = String::from("token_id");
        let msg = Binary::new("did:address".as_bytes().to_vec());

        let cw721_base_contract = app.app_mut().instantiate_contract(
            cw721_base_code_id,
            owner_address.clone(),
            &msg,
            &[],
            "label",
            None,
        );

        let cw721_base_contract_addr = cw721_base_contract.unwrap();

        let linkage_contract = linkage_code_id
            .instantiate(cw721_base_contract_addr.clone())
            .call(&owner_address)
            .unwrap();

        let result = linkage_contract
            .receive_nft(sender.clone(), token_id.clone(), msg.clone())
            .call(&cw721_base_contract_addr);
        assert!(result.is_ok(), "Expected Ok, but got Err");

        let result = linkage_contract.unlock_nft(token_id.clone()).call(&sender);
        assert!(result.is_ok(), "Expected Ok, but got Err");
    }

    pub fn cw721_base_contract_mock() -> Box<dyn Contract<Empty>> {
        let contract = ContractWrapper::new(
            |_deps, _, _info, _msg: Cw721ExecuteMsg| -> StdResult<Response> {
                Ok(Response::default())
            },
            |_deps, _, _info, _msg: String| -> StdResult<Response> {
                Ok(Response::default())
            },
            |_, _, _msg: Cw721QueryMsg| -> StdResult<Binary> {
                let data = "test";
                Ok(to_json_binary(data)?)
            }
        );
        Box::new(contract)
    }
}
