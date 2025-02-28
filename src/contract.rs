use crate::error::ContractError;
use crate::responses::{NftLockEntryResponse};
use crate::state::{NftLockEntry, Nft};
use cosmwasm_std::Order::Ascending;
use cosmwasm_std::{to_json_binary, to_json_string, Addr, Api, Binary, Deps, Event, Order, Response, StdResult, Storage, SubMsg, SubMsgResult, WasmMsg};
use cw_storage_plus::{Item, Map};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use sylvia::ctx::{ExecCtx, InstantiateCtx, QueryCtx, ReplyCtx};
use sylvia::{contract, entry_points};

pub struct LinkageContract {
    pub admins: Item<Vec<Addr>>, // Think if can be did_contract controller, but what if did contract does not exist, can it be admined then? will error break contract?
    pub authorized_nft_contracts: Item<Vec<Addr>>,
    pub locked_nfts: Map<(Addr, String), NftLockEntry>,
    pub nfts_by_owner: Map<Addr, Vec<Nft>>,
    pub nfts_by_did: Map<String, Vec<Nft>>,
}


#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)] 
#[serde(rename_all = "snake_case")]
pub struct TransferNftMsg { // TODO use nft contract api
    recipient: String,
    token_id: String,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub struct Cw721ExecuteMsg { // TODO use nft contract api
    transfer_nft: TransferNftMsg,
}



#[entry_points]
#[contract]
#[sv::error(ContractError)]
#[sv::features(replies)]
impl LinkageContract {
    pub const fn new() -> Self {
        LinkageContract {
            admins: Item::new("admins"),
            authorized_nft_contracts: Item::new("authorized_nft_contracts"),
            locked_nfts: Map::new("locked_nfts"),
            nfts_by_did: Map::new("nfts_by_did"),
            nfts_by_owner: Map::new("nfts_by_owner"),
        }
    }

    #[sv::msg(instantiate)]
    pub fn instantiate(&self, ctx: InstantiateCtx, admins: Vec<Addr>, authorized_nft_contracts: Vec<Addr>) -> Result<Response, ContractError> {
        self.save_admins(ctx.deps.storage, &admins)?;
        self.save_authorized_nft_contracts(ctx.deps.storage, &authorized_nft_contracts)?;
        Ok(Response::default())
    }

    // ---- Admins ------

    #[sv::msg(exec)]
    pub fn add_admin(&self, ctx: ExecCtx, new_admin: String) -> Result<Response, ContractError> {
        self.authorize_admin(ctx.deps.as_ref(), &ctx.info.sender)?;

        let new_admin = self.ensure_valid_admin(ctx.deps.api, new_admin)?;
        
        let mut admins: Vec<Addr> = self.admins.load(ctx.deps.storage)?;
        self.ensure_unique_admins(&admins, &new_admin)?;

        admins.push(new_admin.clone());
        self.save_admins(ctx.deps.storage, &admins)?;

        let event = Event::new("add_admin")
            .add_attribute("executor", ctx.info.sender.to_string())
            .add_attribute("new_admin", new_admin.to_string());

        Ok(Response::new()
            .add_attribute("action", "add_admin")
            .add_attribute("new_admin", new_admin.to_string())
            .add_event(event))
    }


    #[sv::msg(exec)]
    pub fn remove_admin(&self, ctx: ExecCtx, admin_to_remove: String) -> Result<Response, ContractError> {
        self.authorize_admin(ctx.deps.as_ref(), &ctx.info.sender)?;

        let admin = self.ensure_valid_admin(ctx.deps.api, admin_to_remove)?;

        let mut admins = self.admins.load(ctx.deps.storage)?;

        if let Some(pos) = admins.iter().position(|x| x == &admin) {
            admins.remove(pos);
            self.save_admins(ctx.deps.storage, &admins)?;

            let event = Event::new("remove_admin")
            .add_attribute("executor", ctx.info.sender.to_string())
            .add_attribute("removed_admin", admin.to_string());

            Ok(Response::new()
                .add_attribute("action", "remove_admin")
                .add_attribute("removed_admin", admin.to_string())
                .add_event(event))
        } else {
            Err(ContractError::AdminNotFound())
        }
    }

    #[sv::msg(query)]
    pub fn get_admins(&self, ctx: QueryCtx) -> Result<Vec<Addr>, ContractError> {
        let result = self.admins.load(ctx.deps.storage)?;
        Ok(result)
    }

    // ---- Authorized NFT Contracts ------

    #[sv::msg(exec)]
    pub fn add_authorized_nft_contract(&self, ctx: ExecCtx, nft_contract_address: Addr) -> Result<Response, ContractError> {
        self.authorize_admin(ctx.deps.as_ref(), &ctx.info.sender)?;

        self.ensure_valid_contract_addr(ctx.deps.api, &nft_contract_address)?;
        
        let mut authorized_nft_contracts: Vec<Addr> = self.authorized_nft_contracts.load(ctx.deps.storage)?;
        self.ensure_unique_nft_contract_addr(&authorized_nft_contracts, &nft_contract_address)?;

        authorized_nft_contracts.push(nft_contract_address.clone());
        self.save_admins(ctx.deps.storage, &authorized_nft_contracts)?;

        let event = Event::new("add_authorized_nft_contract")
            .add_attribute("executor", ctx.info.sender.to_string())
            .add_attribute("new_authorized_nft_contract", nft_contract_address.to_string());

        Ok(Response::new()
            .add_attribute("action", "add_authorized_nft_contract")
            .add_attribute("new_authorized_nft_contract", nft_contract_address.to_string())
            .add_event(event))
    }


    #[sv::msg(exec)]
    pub fn remove_authorized_nft_contract(&self, ctx: ExecCtx, nft_contract_address: Addr) -> Result<Response, ContractError> {
        self.authorize_admin(ctx.deps.as_ref(), &ctx.info.sender)?;

        self.ensure_valid_contract_addr(ctx.deps.api, &nft_contract_address)?;

        let mut authorized_nft_contracts = self.authorized_nft_contracts.load(ctx.deps.storage)?;

        if let Some(pos) = authorized_nft_contracts.iter().position(|x| x == &nft_contract_address) {
            authorized_nft_contracts.remove(pos);
            self.save_admins(ctx.deps.storage, &authorized_nft_contracts)?;

            let event = Event::new("remove_authorized_nft_contract")
            .add_attribute("executor", ctx.info.sender.to_string())
            .add_attribute("removed_authorized_nft_contract", nft_contract_address.to_string());

            Ok(Response::new()
                .add_attribute("action", "remove_authorized_nft_contract")
                .add_attribute("removed_authorized_nft_contract", nft_contract_address.to_string())
                .add_event(event))
        } else {
            Err(ContractError::AdminNotFound())
        }
    }

    #[sv::msg(query)]
    pub fn get_authorized_nft_contracts(&self, ctx: QueryCtx) -> Result<Vec<Addr>, ContractError> {
        let result = self.authorized_nft_contracts.load(ctx.deps.storage)?;
        Ok(result)
    }

    // ---- NFT Locking ------

    #[sv::msg(exec)]
    pub fn receive_nft(
        &self,
        ctx: ExecCtx,
        sender: Addr,
        token_id: String,
        msg: Binary,
    ) -> Result<Response, ContractError> {
        let did = self.ensure_valid_did(msg)?;
        self.authorize_contract(ctx.deps.as_ref(), &ctx.info.sender)?;

        // let key: Nft = Nft { 
        //     contract_address: ctx.info.sender.clone(), 
        //     token_id: token_id.clone(),
        // };
        let entry: NftLockEntry = NftLockEntry { 
            sender: sender.clone(), 
            did: did.clone(),
        };
        self.save_nft_linkage(ctx.deps.storage, ctx.info.sender.clone(), token_id.clone(), &entry)?;

        let event = Event::new("receive_nft")
            .add_attribute("executor", ctx.info.sender.to_string())
            .add_attribute("sender", sender.as_str())
            .add_attribute("token_id", token_id.clone())
            .add_attribute("did", did.clone());

        Ok(Response::new()
            .add_attribute("action", "receive_nft")
            .add_attribute("sender", sender.as_str())
            .add_attribute("token_id", token_id)
            .add_attribute("did", did)
            .add_event(event))
    }

    #[sv::msg(exec)]
    pub fn unlock_nft(&self, ctx: ExecCtx, contract_address: Addr, token_id: String) -> Result<Response, ContractError> {
        // find NFT
        let result = self.locked_nfts.load(ctx.deps.storage, (contract_address.clone(), token_id.clone()));
        match result {
            Ok(nft) => {
                self.authorize_contract(ctx.deps.as_ref(), &contract_address)?; // TODO is it really required?
                if !self.is_admin(ctx.deps.as_ref(), &ctx.info.sender)? {
                    self.authorize_sender(&ctx.info.sender, &nft)?
                }

                self.remove_nft_linkage(ctx.deps.storage, contract_address.clone(), token_id.clone(), &nft)?;

                let exec_msg = Cw721ExecuteMsg {
                    transfer_nft: TransferNftMsg {
                        recipient: ctx.info.sender.to_string(),
                        token_id: token_id.clone(),
                    },
                };

                let msg = WasmMsg::Execute {
                    contract_addr: contract_address.to_string(),
                    msg: to_json_binary(&exec_msg)?,
                    funds: vec![],
                };

                let sub_msg = SubMsg::reply_on_error(msg, 1u64);

                let event = Event::new("unlock_nft")
                .add_attribute("executor", ctx.info.sender.as_str())
                .add_attribute("contract_address", contract_address.as_str())
                .add_attribute("token_id", token_id.clone())
                .add_attribute("did", nft.did.clone());
    
            Ok(Response::new()
                .add_attribute("action", "unlock_nft")
                .add_attribute("contract_address", contract_address.as_str())
                .add_attribute("token_id", token_id.clone())
                .add_attribute("did", nft.did.clone())
                .add_event(event)
                .add_submessage(sub_msg))
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

    // ------------ NFT Queries ------------


    // #[sv::msg(query)]
    // pub fn authorized_contract(&self, ctx: QueryCtx) -> Result<MessageResponse, ContractError> {
    //     let result = self.authorized_contract.load(ctx.deps.storage);
    //     match result {
    //         Ok(a) => Ok(MessageResponse { msg: a.to_string() }),
    //         Err(e) => Err(ContractError::LinkageContractError(e)),
    //     }
    // }

    // #[sv::msg(query)]
    // pub fn count_locked_nfts(&self, ctx: QueryCtx) -> Result<MessageResponse, ContractError> {
    //     let count = self
    //         .locked_nfts
    //         .keys(ctx.deps.storage, None, None, Ascending)
    //         .count();
    //     Ok(MessageResponse {
    //         msg: count.to_string(),
    //     })
    // }

    #[sv::msg(query)]
    pub fn get_locked_nft(
        &self,
        ctx: QueryCtx,
        contract_address: Addr,
        token_id: String,
    ) -> Result<NftLockEntryResponse, ContractError> {
        let cloned_token_id = token_id.clone();
        let result = self.locked_nfts.load(ctx.deps.storage, (contract_address.clone(), token_id.clone()));
        match result {
            Ok(a) => Ok(NftLockEntryResponse {
                contract_address,
                token_id: cloned_token_id,
                sender: a.sender,
                did: a.did,
            }),
            Err(e) => Err(ContractError::LinkageContractError(e)),
        }
    }

    // TODO: test
    #[sv::msg(query)]
    pub fn get_locked_nfts_by_did(&self, ctx: QueryCtx, did: String) -> Result<Vec<NftLockEntryResponse>, ContractError> {
        let nfts_by_did = self.nfts_by_did.load(ctx.deps.storage, did.clone())?;
        let mut result: Vec<NftLockEntryResponse> = vec![];

        for nft in nfts_by_did.iter() {
            let entry = self.locked_nfts.load(ctx.deps.storage, (nft.contract_address.clone(), nft.token_id.clone()))?;
            let nft: NftLockEntryResponse = NftLockEntryResponse {
                contract_address: nft.contract_address.clone(),
                token_id: nft.token_id.clone(),
                sender: entry.sender.clone(),
                did: entry.did.clone(),
            };
            result.push(nft);
        }

        Ok(result)
    }

    // TODO: test
    #[sv::msg(query)]
    pub fn get_locked_nfts_by_owner(&self, ctx: QueryCtx, owner: Addr) -> Result<Vec<NftLockEntryResponse>, ContractError> {
        let nfts_by_owner = self.nfts_by_owner.load(ctx.deps.storage, owner.clone())?;
        let mut result: Vec<NftLockEntryResponse> = vec![];

        for nft in nfts_by_owner.iter() {
            let entry = self.locked_nfts.load(ctx.deps.storage, (nft.contract_address.clone(), nft.token_id.clone()))?;
            let nft: NftLockEntryResponse = NftLockEntryResponse {
                contract_address: nft.contract_address.clone(),
                token_id: nft.token_id.clone(),
                sender: entry.sender.clone(),
                did: entry.did.clone(),
            };
            result.push(nft);
        }

        Ok(result)
    }

   

    // ------------------------------- 

    fn save_admins(&self, storage: &mut dyn Storage, admins: &Vec<Addr>) ->  Result<(), ContractError> {
        let result = self.admins.save(storage, admins);
        match result {
            Ok(_) => Ok(()),
            Err(e) => Err(ContractError::LinkageContractError(e)) //  TODO specific error
        }
    }

    fn save_authorized_nft_contracts(&self, storage: &mut dyn Storage, authorized_nft_contracts: &Vec<Addr>) ->  Result<(), ContractError> {
        let result = self.authorized_nft_contracts.save(storage, authorized_nft_contracts);
        match result {
            Ok(_) => Ok(()),
            Err(e) => Err(ContractError::LinkageContractError(e)) //  TODO specific error
        }
    }

    fn save_nft_linkage(&self, storage: &mut dyn Storage, contract_addr: Addr, token_id: String, entry: &NftLockEntry) ->  Result<(), ContractError> {
        if self.locked_nfts.has(storage, (contract_addr.clone(), token_id.clone())) {
            return Err(ContractError::AlreadyExists); //  TODO specific error
        }
        
        let result = self.locked_nfts.save(storage, (contract_addr.clone(), token_id.clone()), entry);
        if let Err(e) = result {
            return Err(ContractError::LinkageContractError(e)); //  TODO specific error
        }
        let nft = Nft {
            contract_address: contract_addr.clone(),
            token_id: token_id.clone(),
        };

        // TODO add some addioinal checking for nft duplication ?????
        let result = self.nfts_by_owner.may_load(storage, entry.sender.clone());
        match result {
            Ok(result) => {
                let nfts_vec = match result {
                    Some(mut nfts) => {
                        nfts.push(nft.clone());
                        nfts
                    },
                    None => {
                        vec![nft.clone()]
                    }
                };
                let result = self.nfts_by_owner.save(storage, entry.sender.clone(), &nfts_vec);
                if let Err(e) = result {
                    return Err(ContractError::LinkageContractError(e)); //  TODO specific error
                }
            },
            Err(e) => return Err(ContractError::LinkageContractError(e)) //  TODO specific error
        }

        // TODO add some addioinal checking for nft duplication ?????
        let result = self.nfts_by_did.may_load(storage, entry.did.clone());
        match result {
            Ok(result) => {
                let nfts_vec = match result {
                    Some(mut nfts) => {
                        nfts.push(nft.clone());
                        nfts
                    },
                    None => {
                        vec![nft.clone()]
                    }
                };
                let result = self.nfts_by_did.save(storage, entry.did.clone(), &nfts_vec);
                if let Err(e) = result {
                    return Err(ContractError::LinkageContractError(e)); //  TODO specific error
                }
            },
            Err(e) => return Err(ContractError::LinkageContractError(e)) //  TODO specific error
        }

        Ok(())


    }


    fn remove_nft_linkage(&self, storage: &mut dyn Storage, contract_addr: Addr, token_id: String, entry: &NftLockEntry) ->  Result<(), ContractError> {

        let result = self.nfts_by_owner.may_load(storage, entry.sender.clone());
        match result {
            Ok(result) => {
                let nfts_vec = match result {
                    Some(mut nfts) => {
                        let pos = nfts.iter().position(|x| x.token_id.eq(&token_id) && x.contract_address.eq(&contract_addr));
                        match pos {
                            Some(pos) =>  nfts.remove(pos),
                            None => return Err(ContractError::NotFound) //  TODO specific error
                        };
                        nfts
                    },
                    None => {
                        return Err(ContractError::NotFound); //  TODO specific error
                    }
                };
                if nfts_vec.is_empty() {
                    self.nfts_by_owner.remove(storage, entry.sender.clone());
                } else {
                    let result = self.nfts_by_owner.save(storage, entry.sender.clone(), &nfts_vec);
                    if let Err(e) = result {
                        return Err(ContractError::LinkageContractError(e)); //  TODO specific error
                    }
                }
            },
            Err(e) => return Err(ContractError::LinkageContractError(e)) //  TODO specific error
        }

        let result = self.nfts_by_did.may_load(storage, entry.did.clone());
        match result {
            Ok(result) => {
                let nfts_vec = match result {
                    Some(mut nfts) => {
                        let pos = nfts.iter().position(|x| x.token_id.eq(&token_id) && x.contract_address.eq(&contract_addr));
                        match pos {
                            Some(pos) =>  nfts.remove(pos),
                            None => return Err(ContractError::NotFound) //  TODO specific error
                        };
                        nfts
                    },
                    None => {
                        return Err(ContractError::NotFound); //  TODO specific error
                    }
                };
                if nfts_vec.is_empty() {
                    self.nfts_by_did.remove(storage, entry.did.clone());
                } else {
                    let result = self.nfts_by_did.save(storage, entry.did.clone(), &nfts_vec);
                    if let Err(e) = result {
                        return Err(ContractError::LinkageContractError(e)); //  TODO specific error
                    }
                }
            },
            Err(e) => return Err(ContractError::LinkageContractError(e)) //  TODO specific error
        }

        self.locked_nfts.remove(storage, (contract_addr.clone(), token_id.clone()));

        Ok(())


    }

    fn is_admin(&self, deps: Deps, sender: &Addr) -> Result<bool, ContractError> {
        let admins = self.admins.may_load(deps.storage); // TODO handle error
        match admins {
            Ok(admins) => {
                if let Some(admin_list) = admins {
                    // Check if the sender is one of the admins
                    Ok(admin_list.contains(sender))
                } else {
                    Ok(false)
                }
            },
            Err(e) => Err(ContractError::LinkageContractError(e)) //  TODO specific error
        }
    }

    fn authorize_admin(&self, deps: Deps, sender: &Addr) -> Result<(), ContractError> {
        if !self.is_admin(deps, sender)? {
            return Err(ContractError::Unauthorized());
        }
        Ok(())
    }

    fn is_authorized_contract(&self, deps: Deps, contract: &Addr) -> Result<bool, ContractError> {
        let authorized_nft_contracts = self.authorized_nft_contracts.may_load(deps.storage); // TODO handle error
        match authorized_nft_contracts {
            Ok(admins) => {
                if let Some(admin_list) = admins {
                    // Check if the sender is one of the admins
                    Ok(admin_list.contains(contract))
                } else {
                    Ok(false)
                }
            },
            Err(e) => Err(ContractError::LinkageContractError(e)) //  TODO specific error
        }
    }

    fn is_sender(&self, sender: &Addr, nft: &NftLockEntry) -> bool {
        sender.eq(&nft.sender)
    }

    fn authorize_sender(&self, sender: &Addr, nft: &NftLockEntry) -> Result<(), ContractError> {
        if !self.is_sender(sender, nft) {
            return Err(ContractError::Unauthorized());
        }
        Ok(())
    }

    fn authorize_contract(&self, deps: Deps, contract: &Addr) -> Result<(), ContractError> {
        if !self.is_authorized_contract(deps, contract)? {
            return Err(ContractError::UnauthorizedContractError);
        }
        Ok(())
    }

    

    fn ensure_valid_admin(&self, api: &dyn Api, admin: String) -> Result<Addr, ContractError> {
        let addr = api.addr_validate(&admin)?;
        Ok(addr)
    }

    fn ensure_unique_admins(&self, admins: &Vec<Addr>, new_admin: &Addr) -> Result<(), ContractError> {
        if admins.contains(new_admin) {
            Err(ContractError::AdminAlreadyExists())
        } else {
            Ok (())
        }
    }

    fn ensure_valid_contract_addr(&self, api: &dyn Api, contract_addr: &Addr) -> Result<Addr, ContractError> {
        let addr = api.addr_validate(contract_addr.as_str())?;
        Ok(addr)
    }

    fn ensure_unique_nft_contract_addr(&self, ntf_contract_addrs: &Vec<Addr>, contract_addr: &Addr) -> Result<(), ContractError> {
        if ntf_contract_addrs.contains(contract_addr) {
            Err(ContractError::NftContractAlreadyExists())
        } else {
            Ok (())
        }
    }

    fn ensure_valid_did(&self, msg: Binary) -> Result<String, ContractError> {
        let bytes = msg.to_vec();
        let did_result = String::from_utf8(bytes);

        match did_result {
            Ok(did) => {
                Ok(did)
            },
            Err(e) => Err(ContractError::DidInvalid(e))
        }

    }
}

#[cfg(test)]
mod tests {
    use crate::contract::sv::mt::{CodeId, LinkageContractProxy};
    use crate::error::ContractError;
    use crate::responses::NftLockEntryResponse;
    use cosmwasm_std::{to_json_binary, Binary, Empty, Response, StdResult};
    use cw721::{Cw721ExecuteMsg, Cw721QueryMsg};
    use cw_multi_test::{Contract, ContractWrapper, Executor, IntoAddr};
    use sylvia::multitest::App;

    #[test]
    fn instantiate_and_get_authorized_contract() {
        let app = App::default();
        let code_id = CodeId::store_code(&app);

        let admin = "admin".into_addr();

        let owner = "owner".into_addr();

        let auth_address = "cw721_address".into_addr();

        let contract = code_id
            .instantiate(vec![admin.clone()], vec![auth_address.clone()])
            .call(&owner)
            .unwrap();

        let result = contract.get_authorized_nft_contracts();
        assert!(result.is_ok(), "Expected Ok, but go an Err");
        let result = result.unwrap();
        assert_eq!(result.len(), 1);

        assert_eq!(auth_address, result[0]);


        let result = contract.get_admins();
        assert!(result.is_ok(), "Expected Ok, but go an Err");
        let result = result.unwrap();
        assert_eq!(result.len(), 1);

        assert_eq!(admin, result[0])
    }

    #[test]
    fn receive_nft_and_get_locked_nfts() {
        let app = App::default();
        let code_id = CodeId::store_code(&app);
        let admin = "admin".into_addr();

        let owner = "owner".into_addr();
        let auth_address = "cw721_address".into_addr();
        let contract = code_id
            .instantiate(vec![admin.clone()], vec![auth_address.clone()])
            .call(&owner)
            .unwrap();

        let sender = "sender_address".into_addr();
        let token_id = String::from("token_id");
        let token_id_2 = String::from("token_id_2");
        let did = "did:address";
        let msg = Binary::new(did.as_bytes().to_vec());

        let result = contract.get_locked_nft(auth_address.clone(), token_id.clone());
        assert!(result.is_err(), "Expected Err, but got Ok");

        let result = contract
            .receive_nft(sender.clone(), token_id.clone(), msg.clone())
            .call(&auth_address);
        assert!(result.is_ok(), "Expected Ok, but got Err");

        let result = contract.get_locked_nft(auth_address.clone(), token_id.clone());
        assert!(result.is_ok(), "Expected Ok, but got Err");
        let expcted_nft = NftLockEntryResponse{
            contract_address: auth_address.clone(),
            token_id: token_id.clone(),
            sender: sender.clone(),
            did: String::from_utf8(msg.to_vec()).unwrap(),
        };
        assert_eq!(expcted_nft.clone(), result.unwrap());

        let result = contract.get_locked_nfts_by_did(did.to_string());
        assert!(result.is_ok(), "Expected Ok, but go an Err");
        let result = result.unwrap();
        assert_eq!(result.len(), 1);

        assert_eq!(expcted_nft.clone(), result[0]);

        let result = contract.get_locked_nfts_by_owner(sender.clone());
        assert!(result.is_ok(), "Expected Ok, but go an Err");
        let result = result.unwrap();
        assert_eq!(result.len(), 1);

        assert_eq!(expcted_nft.clone(), result[0]);


        let unauth_address = "unauth_address".into_addr();

        let result = contract
            .receive_nft(sender.clone(), token_id_2.clone(), msg.clone())
            .call(&unauth_address);
        assert!(result.is_err(), "Expected Err, but got Ok");

        assert_eq!(result.unwrap_err(), ContractError::UnauthorizedContractError);

        let result = contract.get_locked_nft(unauth_address, token_id_2.clone());
        assert!(result.is_err(), "Expected Err, but got Ok");

        let result = contract.get_locked_nft(auth_address.clone(), token_id_2.clone());
        assert!(result.is_err(), "Expected Err, but got Ok");

        let result = contract
            .receive_nft(sender.clone(), token_id_2.clone(), msg.clone())
            .call(&auth_address);
        assert!(result.is_ok(), "Expected Ok, but got Err");

        let result = contract.get_locked_nft(auth_address.clone(), token_id_2.clone());
        assert!(result.is_ok(), "Expected Ok, but got Err");
        let expcted_nft_2 = NftLockEntryResponse{
            contract_address: auth_address.clone(),
            token_id: token_id_2.clone(),
            sender: sender.clone(),
            did: String::from_utf8(msg.to_vec()).unwrap(),
        };
        assert_eq!(expcted_nft_2.clone(), result.unwrap());

        let result = contract.get_locked_nfts_by_did(did.to_string());
        assert!(result.is_ok(), "Expected Ok, but go an Err");
        let result = result.unwrap();
        assert_eq!(result.len(), 2);

        assert_eq!(expcted_nft.clone(), result[0]);
        assert_eq!(expcted_nft_2.clone(), result[1]);

        let result = contract.get_locked_nfts_by_owner(sender.clone());
        assert!(result.is_ok(), "Expected Ok, but go an Err");
        let result = result.unwrap();
        assert_eq!(result.len(), 2);

        assert_eq!(expcted_nft.clone(), result[0]);
        assert_eq!(expcted_nft_2.clone(), result[1]);

    }

    #[test]
    fn unlock_nfts() {
        let app = App::default();
        let linkage_code_id = CodeId::store_code(&app);
        let cw721_base_code_id = app.app_mut().store_code(cw721_base_contract_mock());
        let admin = "admin".into_addr();
        let owner = "owner".into_addr();
        // let auth_address = "cw721_address".into_addr();
        let sender = "sender_address".into_addr();
        let token_id = String::from("token_id");
        let token_id_2 = String::from("token_id_2");
        let did = "did:address";
        let msg = Binary::new(did.as_bytes().to_vec());

        let cw721_base_contract = app.app_mut().instantiate_contract(
                    cw721_base_code_id,
                    owner.clone(),
                    &msg,
                    &[],
                    "label",
                    None,
                );

        let cw721_base_contract_addr = cw721_base_contract.unwrap();


        let linkage_contract = linkage_code_id
            .instantiate(vec![admin.clone()], vec![cw721_base_contract_addr.clone()])
            .call(&owner)
            .unwrap();

        let result = linkage_contract
            .receive_nft(sender.clone(), token_id.clone(), msg.clone())
            .call(&cw721_base_contract_addr);
        assert!(result.is_ok(), "Expected Ok, but got Err");

        let result = linkage_contract
            .receive_nft(sender.clone(), token_id_2.clone(), msg.clone())
            .call(&cw721_base_contract_addr);
        assert!(result.is_ok(), "Expected Ok, but got Err");

        let result = linkage_contract.unlock_nft(cw721_base_contract_addr.clone(), token_id.clone()).call(&sender);
        assert!(result.is_ok(), "Expected Ok, but got Err");
        
        let result = linkage_contract.get_locked_nft(cw721_base_contract_addr.clone(), token_id.clone());
        assert!(result.is_err(), "Expected Err, but got Ok");

        let result = linkage_contract.get_locked_nft(cw721_base_contract_addr.clone(), token_id_2.clone());
        assert!(result.is_ok(), "Expected Ok, but got Err");
        let expcted_nft_2 = NftLockEntryResponse{
            contract_address: cw721_base_contract_addr.clone(),
            token_id: token_id_2.clone(),
            sender: sender.clone(),
            did: String::from_utf8(msg.to_vec()).unwrap(),
        };
        assert_eq!(expcted_nft_2.clone(), result.unwrap());

        let result = linkage_contract.get_locked_nfts_by_did(did.to_string());
        assert!(result.is_ok(), "Expected Ok, but go an Err");
        let result = result.unwrap();
        assert_eq!(result.len(), 1);

        assert_eq!(expcted_nft_2.clone(), result[0]);
        // assert_eq!(expcted_nft_2.clone(), result[1]);

        let result = linkage_contract.get_locked_nfts_by_owner(sender.clone());
        assert!(result.is_ok(), "Expected Ok, but go an Err");
        let result = result.unwrap();
        assert_eq!(result.len(), 1);

        assert_eq!(expcted_nft_2.clone(), result[0]);
        // assert_eq!(expcted_nft_2.clone(), result[1]);

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
