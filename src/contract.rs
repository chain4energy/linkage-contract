use std::collections::HashSet;

use crate::error::ContractError;
use crate::responses::NftLockEntryResponse;
use crate::state::{Nft, NftLockEntry};
use cosmwasm_std::{
    to_json_binary, to_json_string, Addr, Api, Binary, Deps, Event, Response, Storage,
    SubMsgResult, WasmMsg,
};
use cw_storage_plus::{Item, Map};
use did_contract::state::Did;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use sylvia::ctx::{ExecCtx, InstantiateCtx, QueryCtx, ReplyCtx};
use sylvia::{contract, entry_points};

pub struct LinkageContract {
    pub admins: Item<Vec<Addr>>, // Think if can be did_contract controller, but what if did contract does not exist, can it be admined then? will error break contract?
    pub authorized_nft_contracts: Item<Vec<Addr>>,
    pub locked_nfts: Map<(Addr, String), NftLockEntry>,
    pub nfts_by_owner: Map<Addr, Vec<Nft>>,
    pub nfts_by_did: Map<Did, Vec<Nft>>,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub struct TransferNftMsg {
    // TODO use nft contract api
    recipient: String,
    token_id: String,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub struct Cw721ExecuteMsg {
    // TODO use nft contract api
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
    pub fn instantiate(
        &self,
        ctx: InstantiateCtx,
        admins: Vec<Addr>,
        authorized_nft_contracts: Vec<Addr>,
    ) -> Result<Response, ContractError> {
        self.ensure_one_admin(&admins)?;
        self.ensure_admin_not_duplicated(&admins)?;
        self.ensure_authorized_contract_not_duplicated(&authorized_nft_contracts)?;
        for admin in &admins {
            self.ensure_valid_admin(ctx.deps.api, &admin.to_string())?;
        }
        for contract in &authorized_nft_contracts {
            self.ensure_valid_contract_addr(ctx.deps.api, &contract)?;
        }
        self.save_admins(ctx.deps.storage, &admins)?;
        self.save_authorized_nft_contracts(ctx.deps.storage, &authorized_nft_contracts)?;
        Ok(Response::default())
    }

    // ---- Admins ------

    #[sv::msg(exec)]
    pub fn add_admin(&self, ctx: ExecCtx, new_admin: String) -> Result<Response, ContractError> {
        self.authorize_admin(ctx.deps.as_ref(), &ctx.info.sender)?;

        let new_admin = self.ensure_valid_admin(ctx.deps.api, &new_admin)?;

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
    pub fn remove_admin(
        &self,
        ctx: ExecCtx,
        admin_to_remove: String,
    ) -> Result<Response, ContractError> {
        self.authorize_admin(ctx.deps.as_ref(), &ctx.info.sender)?;

        let admin = self.ensure_valid_admin(ctx.deps.api, &admin_to_remove)?;

        let mut admins = self.admins.load(ctx.deps.storage)?;

        if let Some(pos) = admins.iter().position(|x| x == &admin) {
            admins.remove(pos);
            self.ensure_one_admin(&admins)?;
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
    pub fn add_authorized_nft_contract(
        &self,
        ctx: ExecCtx,
        nft_contract_address: Addr,
    ) -> Result<Response, ContractError> {
        self.authorize_admin(ctx.deps.as_ref(), &ctx.info.sender)?;

        self.ensure_valid_contract_addr(ctx.deps.api, &nft_contract_address)?;

        let mut authorized_nft_contracts: Vec<Addr> =
            self.authorized_nft_contracts.load(ctx.deps.storage)?;
        self.ensure_unique_nft_contract_addr(&authorized_nft_contracts, &nft_contract_address)?;

        authorized_nft_contracts.push(nft_contract_address.clone());
        self.save_authorized_nft_contracts(ctx.deps.storage, &authorized_nft_contracts)?;

        let event = Event::new("add_authorized_nft_contract")
            .add_attribute("executor", ctx.info.sender.to_string())
            .add_attribute(
                "new_authorized_nft_contract",
                nft_contract_address.to_string(),
            );

        Ok(Response::new()
            .add_attribute("action", "add_authorized_nft_contract")
            .add_attribute(
                "new_authorized_nft_contract",
                nft_contract_address.to_string(),
            )
            .add_event(event))
    }

    #[sv::msg(exec)]
    pub fn remove_authorized_nft_contract(
        &self,
        ctx: ExecCtx,
        nft_contract_address: Addr,
    ) -> Result<Response, ContractError> {
        self.authorize_admin(ctx.deps.as_ref(), &ctx.info.sender)?;

        self.ensure_valid_contract_addr(ctx.deps.api, &nft_contract_address)?;

        let mut authorized_nft_contracts = self.authorized_nft_contracts.load(ctx.deps.storage)?;

        if let Some(pos) = authorized_nft_contracts
            .iter()
            .position(|x| x == &nft_contract_address)
        {
            authorized_nft_contracts.remove(pos);
            self.save_authorized_nft_contracts(ctx.deps.storage, &authorized_nft_contracts)?;
        } else {
            return Err(ContractError::NftContractNotFound());
        }

        let event = Event::new("remove_authorized_nft_contract")
            .add_attribute("executor", ctx.info.sender.to_string())
            .add_attribute(
                "removed_authorized_nft_contract",
                nft_contract_address.to_string(),
            );

        Ok(Response::new()
            .add_attribute("action", "remove_authorized_nft_contract")
            .add_attribute(
                "removed_authorized_nft_contract",
                nft_contract_address.to_string(),
            )
            .add_event(event))
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
        let did = self.ensure_valid_did_msg(msg)?;
        self.ensure_valid_contract_addr(ctx.deps.api, &ctx.info.sender)?;
        self.ensure_token_id(&token_id)?;
        self.authorize_contract(ctx.deps.as_ref(), &ctx.info.sender)?;
        // let key: Nft = Nft {
        //     contract_address: ctx.info.sender.clone(),
        //     token_id: token_id.clone(),
        // };
        let entry: NftLockEntry = NftLockEntry {
            sender: sender.clone(),
            did: did.clone(),
        };
        self.save_nft_linkage(
            ctx.deps.storage,
            ctx.info.sender.clone(),
            token_id.clone(),
            &entry,
        )?;

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
    pub fn unlock_nft(
        &self,
        ctx: ExecCtx,
        contract_address: Addr,
        token_id: String,
    ) -> Result<Response, ContractError> {
        self.ensure_valid_contract_addr(ctx.deps.api, &contract_address)?;
        self.ensure_token_id(&token_id)?;
        self.authorize_contract(ctx.deps.as_ref(), &contract_address)?;
        // find NFT
        let result = self
            .locked_nfts
            .may_load(
                ctx.deps.storage,
                (contract_address.clone(), token_id.clone()),
            )
            .map_err(|e| {
                ContractError::StorageError(
                    format!("Loading nft: {}:{}", contract_address, token_id),
                    e,
                )
            })?;
        if result.is_none() {
            return Err(ContractError::NotFound(format!(
                "NFT not found: {}:{}",
                contract_address, token_id
            )));
        }
        let nft = result.unwrap();
        self.authorize_admin_or_sender(ctx.deps.as_ref(), &ctx.info.sender, &nft)?;

        // match result {
        //     Ok(nft) => {

        // if !self.is_admin(ctx.deps.as_ref(), &ctx.info.sender)? {
        //     self.authorize_sender(&ctx.info.sender, &nft)?
        // }

        self.remove_nft_linkage(
            ctx.deps.storage,
            contract_address.clone(),
            token_id.clone(),
            &nft,
        )?;

        // let exec_msg = cw721::Cw721ExecuteMsg::TransferNft { recipient: ctx.info.sender.to_string(), token_id: token_id.clone() };

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

        // let sub_msg = SubMsg::reply_on_error(msg, 1u64);

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
            .add_message(msg))
        // .add_submessage(sub_msg))
        //     }
        //     Err(e) => Err(ContractError::LinkageContractError(e)),
        // }
    }

    // ------------ NFT Queries ------------

    #[sv::msg(query)]
    pub fn get_locked_nft(
        &self,
        ctx: QueryCtx,
        contract_address: Addr,
        token_id: String,
    ) -> Result<NftLockEntryResponse, ContractError> {
        self.ensure_valid_contract_addr(ctx.deps.api, &contract_address)?;
        self.ensure_token_id(&token_id)?;
        let result = self
            .locked_nfts
            .may_load(
                ctx.deps.storage,
                (contract_address.clone(), token_id.clone()),
            )
            .map_err(|e| {
                ContractError::StorageError(
                    format!("Loading nft: {}:{}", contract_address, token_id),
                    e,
                )
            })?;
        if result.is_none() {
            return Err(ContractError::NotFound(format!(
                "NFT not found: {}:{}",
                contract_address, token_id
            )));
        }
        let nft = result.unwrap();
        Ok(NftLockEntryResponse {
            contract_address,
            token_id: token_id.clone(),
            sender: nft.sender,
            did: nft.did,
        })

        // match result {
        //     Ok(a) => Ok(NftLockEntryResponse {
        //         contract_address,
        //         token_id: cloned_token_id,
        //         sender: a.sender,
        //         did: a.did,
        //     }),
        //     Err(e) => Err(ContractError::LinkageContractError(e)),
        // }
    }

    #[sv::msg(query)]
    pub fn get_locked_nfts_by_did(
        &self,
        ctx: QueryCtx,
        did: Did,
    ) -> Result<Vec<NftLockEntryResponse>, ContractError> {
        self.ensure_valid_did(&did)?;
        let nfts_by_did = self.nfts_by_did.may_load(ctx.deps.storage, did.clone())?;
        if nfts_by_did.is_none() {
            return Ok(vec![]);
        }
        let mut result: Vec<NftLockEntryResponse> = vec![];

        for nft in nfts_by_did.unwrap().iter() {
            let entry = self.locked_nfts.may_load(
                ctx.deps.storage,
                (nft.contract_address.clone(), nft.token_id.clone()),
            )?;
            if entry.is_none() {
                continue;
            }
            let entry = entry.unwrap();
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

    #[sv::msg(query)]
    pub fn get_locked_nfts_by_owner(
        &self,
        ctx: QueryCtx,
        owner: Addr,
    ) -> Result<Vec<NftLockEntryResponse>, ContractError> {
        self.ensure_valid_address(ctx.deps.api, &owner)?;
        let nfts_by_owner = self
            .nfts_by_owner
            .may_load(ctx.deps.storage, owner.clone())?;
        if nfts_by_owner.is_none() {
            return Ok(vec![]);
        }
        let mut result: Vec<NftLockEntryResponse> = vec![];

        for nft in nfts_by_owner.unwrap().iter() {
            let entry = self.locked_nfts.may_load(
                ctx.deps.storage,
                (nft.contract_address.clone(), nft.token_id.clone()),
            )?;
            if entry.is_none() {
                continue;
            }
            let entry = entry.unwrap();
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

    fn save_admins(
        &self,
        storage: &mut dyn Storage,
        admins: &Vec<Addr>,
    ) -> Result<(), ContractError> {
        self.admins
            .save(storage, admins)
            .map_err(|e| ContractError::StorageError("admins".to_string(), e))
    }

    fn save_authorized_nft_contracts(
        &self,
        storage: &mut dyn Storage,
        authorized_nft_contracts: &Vec<Addr>,
    ) -> Result<(), ContractError> {
        self.authorized_nft_contracts
            .save(storage, authorized_nft_contracts)
            .map_err(|e| ContractError::StorageError("authorized nft contracts".to_string(), e))
    }

    fn save_nft_linkage(
        &self,
        storage: &mut dyn Storage,
        contract_addr: Addr,
        token_id: String,
        entry: &NftLockEntry,
    ) -> Result<(), ContractError> {
        if self
            .locked_nfts
            .has(storage, (contract_addr.clone(), token_id.clone()))
        {
            return Err(ContractError::AlreadyExists(format!(
                "NFT already locked: {}:{}",
                contract_addr, token_id
            )));
        }

        self.locked_nfts
            .save(storage, (contract_addr.clone(), token_id.clone()), entry)
            .map_err(|e| {
                ContractError::StorageError(format!("Save NFT: {}:{}", contract_addr, token_id), e)
            })?;

        let nft = Nft {
            contract_address: contract_addr.clone(),
            token_id: token_id.clone(),
        };

        let result = self
            .nfts_by_owner
            .may_load(storage, entry.sender.clone())
            .map_err(|e| {
                ContractError::StorageError(
                    format!("Load NFT by owner for: {}:{}", contract_addr, token_id),
                    e,
                )
            })?;

        let nfts_vec = LinkageContract::add_nft_to_list(
            result,
            &nft,
            &contract_addr,
            &token_id,
            "NFT by owner",
        )?;

        // let nfts_vec = match result {
        //     Some(mut nfts) => {
        //         if nfts.contains(&nft.clone()) {
        //             return Err(ContractError::AlreadyExists(format!(
        //                 "NFT already exists on NFT by owner list: {}:{}",
        //                 contract_addr, token_id
        //             )));
        //         }
        //         nfts.push(nft.clone());
        //         nfts
        //     }
        //     None => {
        //         vec![nft.clone()]
        //     }
        // };

        self.nfts_by_owner
            .save(storage, entry.sender.clone(), &nfts_vec)
            .map_err(|e| {
                ContractError::StorageError(
                    format!("Save NFT by owner: {}:{}", contract_addr, token_id),
                    e,
                )
            })?;

        let result = self
            .nfts_by_did
            .may_load(storage, entry.did.clone())
            .map_err(|e| {
                ContractError::StorageError(
                    format!("Load NFT by did for: {}:{}", contract_addr, token_id),
                    e,
                )
            })?;

        let nfts_vec = LinkageContract::add_nft_to_list(
            result,
            &nft,
            &contract_addr,
            &token_id,
            "NFT by did",
        )?;

        self.nfts_by_did
            .save(storage, entry.did.clone(), &nfts_vec)
            .map_err(|e| {
                ContractError::StorageError(
                    format!("Save NFT by did: {}:{}", contract_addr, token_id),
                    e,
                )
            })?;
        Ok(())
    }

    fn add_nft_to_list(
        result: Option<Vec<Nft>>,
        nft: &Nft,
        contract_addr: &Addr,
        token_id: &String,
        list_name: &str,
    ) -> Result<Vec<Nft>, ContractError> {
        let nfts_vec = match result {
            Some(mut nfts) => {
                if nfts.contains(&nft.clone()) {
                    return Err(ContractError::AlreadyExists(format!(
                        "NFT already exists on {} list: {}:{}",
                        list_name, contract_addr, token_id
                    )));
                }
                nfts.push(nft.clone());
                nfts
            }
            None => {
                vec![nft.clone()]
            }
        };
        Ok(nfts_vec)
    }

    fn remove_nft_from_list(
        result: Option<Vec<Nft>>,
        contract_addr: &Addr,
        token_id: &String,
        list_name: &str,
    ) -> Result<Vec<Nft>, ContractError> {
        let nfts_vec = match result {
            Some(mut nfts) => {
                let pos = nfts
                    .iter()
                    .position(|x| x.token_id.eq(token_id) && x.contract_address.eq(&contract_addr));
                match pos {
                    Some(pos) => nfts.remove(pos),
                    None => {
                        return Err(ContractError::NotFound(format!(
                            "NFT not found: {}:{}",
                            contract_addr, token_id
                        )))
                    }
                };
                nfts
            }
            None => {
                return Err(ContractError::NotFound(format!(
                    "{} not found: {}:{}",
                    list_name, contract_addr, token_id
                )));
            }
        };
        Ok(nfts_vec)
    }

    fn remove_nft_linkage(
        &self,
        storage: &mut dyn Storage,
        contract_addr: Addr,
        token_id: String,
        entry: &NftLockEntry,
    ) -> Result<(), ContractError> {
        let result = self
            .nfts_by_owner
            .may_load(storage, entry.sender.clone())
            .map_err(|e| {
                ContractError::StorageError(
                    format!(
                        "Load NFT by owner: {}:{}",
                        contract_addr.clone(),
                        token_id.clone()
                    ),
                    e,
                )
            })?;

        let nfts_vec = LinkageContract::remove_nft_from_list(
            result,
            &contract_addr,
            &token_id,
            "NFTs by owner",
        )?;
        // match result {
        //     Ok(result) => {
        // let nfts_vec = match result {
        //     Some(mut nfts) => {
        //         let pos = nfts.iter().position(|x| {
        //             x.token_id.eq(&token_id) && x.contract_address.eq(&contract_addr)
        //         });
        //         match pos {
        //             Some(pos) => nfts.remove(pos),
        //             None => {
        //                 return Err(ContractError::NotFound(format!(
        //                     "NFT not found: {}:{}",
        //                     contract_addr, token_id
        //                 )))
        //             }
        //         };
        //         nfts
        //     }
        //     None => {
        //         return Err(ContractError::NotFound(format!(
        //             "NFTs by owner not found: {}:{}",
        //             contract_addr, token_id
        //         )));
        //     }
        // };
        if nfts_vec.is_empty() {
            self.nfts_by_owner.remove(storage, entry.sender.clone());
        } else {
            self.nfts_by_owner
                .save(storage, entry.sender.clone(), &nfts_vec)
                .map_err(|e| {
                    ContractError::StorageError(
                        format!(
                            "Save NFT by owner: {}:{}",
                            contract_addr.clone(),
                            token_id.clone()
                        ),
                        e,
                    )
                })?;
        }
        let result = self
            .nfts_by_did
            .may_load(storage, entry.did.clone())
            .map_err(|e| {
                ContractError::StorageError(
                    format!(
                        "Load NFT by did: {}:{}",
                        contract_addr.clone(),
                        token_id.clone()
                    ),
                    e,
                )
            })?;

        let nfts_vec = LinkageContract::remove_nft_from_list(
            result,
            &contract_addr,
            &token_id,
            "NFTs by did",
        )?;
        if nfts_vec.is_empty() {
            self.nfts_by_did.remove(storage, entry.did.clone());
        } else {
            self.nfts_by_did
                .save(storage, entry.did.clone(), &nfts_vec)
                .map_err(|e| {
                    ContractError::StorageError(
                        format!(
                            "Save NFT by did: {}:{}",
                            contract_addr.clone(),
                            token_id.clone()
                        ),
                        e,
                    )
                })?;
        }

        self.locked_nfts
            .remove(storage, (contract_addr.clone(), token_id.clone()));

        Ok(())
    }

    fn is_admin(&self, deps: Deps, sender: &Addr) -> Result<bool, ContractError> {
        let admins = self.admins.may_load(deps.storage);
        match admins {
            Ok(admins) => {
                if let Some(admin_list) = admins {
                    // Check if the sender is one of the admins
                    Ok(admin_list.contains(sender))
                } else {
                    Ok(false)
                }
            }
            Err(e) => Err(ContractError::LinkageContractError(e)), //  TODO specific error
        }
    }

    fn authorize_admin(&self, deps: Deps, sender: &Addr) -> Result<(), ContractError> {
        if !self.is_admin(deps, sender)? {
            return Err(ContractError::Unauthorized(
                "Sender is not an admin".to_string(),
            ));
        }
        Ok(())
    }

    fn is_authorized_contract(&self, deps: Deps, contract: &Addr) -> Result<bool, ContractError> {
        let authorized_nft_contracts = self.authorized_nft_contracts.may_load(deps.storage);
        match authorized_nft_contracts {
            Ok(admins) => {
                if let Some(admin_list) = admins {
                    // Check if the sender is one of the admins
                    Ok(admin_list.contains(contract))
                } else {
                    Ok(false)
                }
            }
            Err(e) => Err(ContractError::LinkageContractError(e)), //  TODO specific error
        }
    }

    fn is_sender(&self, sender: &Addr, nft: &NftLockEntry) -> bool {
        sender.eq(&nft.sender)
    }

    fn authorize_admin_or_sender(
        &self,
        deps: Deps,
        sender: &Addr,
        nft: &NftLockEntry,
    ) -> Result<(), ContractError> {
        if !self.is_admin(deps, sender)? {
            self.authorize_sender(sender, &nft)?
        }
        Ok(())
    }

    fn authorize_sender(&self, sender: &Addr, nft: &NftLockEntry) -> Result<(), ContractError> {
        if !self.is_sender(sender, nft) {
            return Err(ContractError::Unauthorized(
                "Sender is not the owner of the NFT".to_string(),
            ));
        }
        Ok(())
    }

    fn authorize_contract(&self, deps: Deps, contract: &Addr) -> Result<(), ContractError> {
        if !self.is_authorized_contract(deps, contract)? {
            return Err(ContractError::Unauthorized(
                "Contract is not authorized".to_string(),
            ));
        }
        Ok(())
    }

    fn ensure_valid_admin(&self, api: &dyn Api, admin: &str) -> Result<Addr, ContractError> {
        api.addr_validate(admin)
            .map_err(|e| ContractError::InvalidAdminAddress(e))
    }

    fn ensure_valid_address(&self, api: &dyn Api, admin: &Addr) -> Result<Addr, ContractError> {
        api.addr_validate(admin.as_str())
            .map_err(|e| ContractError::InvalidAddress(e))
    }

    fn ensure_unique_admins(
        &self,
        admins: &Vec<Addr>,
        new_admin: &Addr,
    ) -> Result<(), ContractError> {
        if admins.contains(new_admin) {
            Err(ContractError::AdminAlreadyExists())
        } else {
            Ok(())
        }
    }

    fn ensure_valid_contract_addr(
        &self,
        api: &dyn Api,
        contract_addr: &Addr,
    ) -> Result<Addr, ContractError> {
        api.addr_validate(contract_addr.as_str())
            .map_err(|e| ContractError::InvalidContractAddress(e))
    }

    fn ensure_unique_nft_contract_addr(
        &self,
        ntf_contract_addrs: &Vec<Addr>,
        contract_addr: &Addr,
    ) -> Result<(), ContractError> {
        if ntf_contract_addrs.contains(contract_addr) {
            Err(ContractError::NftContractAlreadyExists())
        } else {
            Ok(())
        }
    }

    fn ensure_valid_did_msg(&self, msg: Binary) -> Result<Did, ContractError> {
        let bytes = msg.to_vec();
        let did = String::from_utf8(bytes).map_err(|e| ContractError::DidMsgInvalid(e))?;
        let did = Did::from(&did);
        self.ensure_valid_did(&did)?;
        Ok(did)
    }

    fn ensure_valid_did(&self, did: &Did) -> Result<(), ContractError> {
        did.ensure_valid()
            .map_err(|e| ContractError::DidInvalid(e))?;
        Ok(())
    }

    fn ensure_one_admin(&self, admins: &Vec<Addr>) -> Result<(), ContractError> {
        if admins.is_empty() {
            return Err(ContractError::NoAdmin);
        }
        Ok(())
    }

    fn ensure_token_id(&self, token_id: &str) -> Result<(), ContractError> {
        if token_id.is_empty() {
            return Err(ContractError::NoTokenId);
        }
        Ok(())
    }

    fn ensure_admin_not_duplicated(&self, admins: &Vec<Addr>) -> Result<(), ContractError> {
        let mut seen = HashSet::new();
        for admin in admins {
            if !seen.insert(admin.to_string()) {
                return Err(ContractError::DuplicatedAdmin(admin.to_string()));
            }
        }
        Ok(())
    }

    fn ensure_authorized_contract_not_duplicated(
        &self,
        contracts: &Vec<Addr>,
    ) -> Result<(), ContractError> {
        let mut seen = HashSet::new();
        for contact in contracts {
            if !seen.insert(contact.to_string()) {
                return Err(ContractError::DuplicatedContract(contact.to_string()));
            }
        }
        Ok(())
    }
}
