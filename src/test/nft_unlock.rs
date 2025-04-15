use crate::contract::sv::mt::{CodeId, LinkageContractProxy};
use crate::responses::NftLockEntryResponse;
use cosmwasm_std::{to_json_binary, Addr, Binary, Empty, Response, StdResult};
use cw721::{Cw721ExecuteMsg, Cw721QueryMsg};
use cw_multi_test::{Contract, ContractWrapper, Executor, IntoAddr};
use did_contract::state::{Did, DID_PREFIX};
use sylvia::multitest::App;

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
    let did = format!("{}address", DID_PREFIX);
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

    let result = linkage_contract
        .unlock_nft(cw721_base_contract_addr.clone(), token_id.clone())
        .call(&sender);
    assert!(result.is_ok(), "Expected Ok, but got Err");

    let result =
        linkage_contract.get_locked_nft(cw721_base_contract_addr.clone(), token_id.clone());
    assert!(result.is_err(), "Expected Err, but got Ok");

    let result =
        linkage_contract.get_locked_nft(cw721_base_contract_addr.clone(), token_id_2.clone());
    assert!(result.is_ok(), "Expected Ok, but got Err");
    let expcted_nft_2 = NftLockEntryResponse {
        contract_address: cw721_base_contract_addr.clone(),
        token_id: token_id_2.clone(),
        sender: sender.clone(),
        did: Did::new(&String::from_utf8(msg.to_vec()).unwrap()),
    };
    assert_eq!(expcted_nft_2.clone(), result.unwrap());

    let result = linkage_contract.get_locked_nfts_by_did(Did::new(&did));
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

#[test]
fn test_unlock_nft_success() {
    let app = App::default();
    let linkage_code_id = CodeId::store_code(&app);
    let cw721_mock = cw721_base_contract_mock();
    let cw721_base_code_id = app.app_mut().store_code(cw721_mock);
    let admin = "admin".into_addr();
    let owner = "owner".into_addr();
    // let auth_address = "cw721_address".into_addr();
    let sender = "sender_address".into_addr();
    let token_id = "token_id".to_string();
    // let token_id_2 = String::from("token_id_2");
    let did = format!("{}address", DID_PREFIX);
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


    // let app = App::default();
    // let code_id = CodeId::store_code(&app);
    // let admin = "admin".into_addr();
    // let sender = "sender_address".into_addr();
    // let token_id = "token_id".to_string();
    // let did = format!("{}did", DID_PREFIX);
    // let msg = Binary::from(did.as_bytes());
    // let auth_address = "auth_contract".into_addr();

    let contract = linkage_code_id
        .instantiate(vec![admin.clone()], vec![cw721_base_contract_addr.clone()])
        .call(&admin)
        .unwrap();

    // Lock the NFT
    let result = contract
        .receive_nft(sender.clone(), token_id.clone(), msg.clone())
        .call(&cw721_base_contract_addr);
    assert!(result.is_ok(), "Expected Ok, but got Err");

    // Unlock the NFT
    let result = contract
        .unlock_nft(cw721_base_contract_addr.clone(), token_id.clone())
        .call(&sender);
    assert!(result.is_ok(), "Expected Ok, but got Err");

    let res = result.unwrap();

    assert_eq!(res.events.len(), 4);
    // Verify event attributes
    assert_eq!(res.events[0].ty, "execute");
    assert_eq!(res.events[0].attributes[0].key, "_contract_address");
    assert_eq!(res.events[0].attributes[0].value, "cosmwasm14hj2tavq8fpesdwxxcu44rty3hh90vhujrvcmstl4zr3txmfvw9s8jef58");
    assert_eq!(res.events[0].attributes.len(), 1);

    assert_eq!(res.events[1].ty, "wasm");
    assert_eq!(res.events[1].attributes[0].key, "_contract_address");
    assert_eq!(res.events[1].attributes[0].value, "cosmwasm14hj2tavq8fpesdwxxcu44rty3hh90vhujrvcmstl4zr3txmfvw9s8jef58");
    assert_eq!(res.events[1].attributes[1].key, "action");
    assert_eq!(res.events[1].attributes[1].value, "unlock_nft");
    assert_eq!(res.events[1].attributes[2].key, "contract_address");
    assert_eq!(res.events[1].attributes[2].value, cw721_base_contract_addr.to_string());
//  assert_eq!(res.events[1].attributes[2].key, "sender");
//  assert_eq!(res.events[1].attributes[2].value, sender.to_string());
    assert_eq!(res.events[1].attributes[3].key, "token_id");
    assert_eq!(res.events[1].attributes[3].value, token_id);
    assert_eq!(res.events[1].attributes[4].key, "did");
    assert_eq!(res.events[1].attributes[4].value, did);
    assert_eq!(res.events[1].attributes.len(), 5);
    
    assert_eq!(res.events[2].ty, "wasm-unlock_nft");
    assert_eq!(res.events[2].attributes[0].key, "_contract_address");
    assert_eq!(res.events[2].attributes[0].value, "cosmwasm14hj2tavq8fpesdwxxcu44rty3hh90vhujrvcmstl4zr3txmfvw9s8jef58");
    assert_eq!(res.events[2].attributes[1].key, "executor");
    assert_eq!(res.events[2].attributes[1].value, sender.to_string());
    assert_eq!(res.events[1].attributes[2].key, "contract_address");
    assert_eq!(res.events[1].attributes[2].value, cw721_base_contract_addr.to_string());
    assert_eq!(res.events[2].attributes[3].key, "token_id");
    assert_eq!(res.events[2].attributes[3].value, token_id);
    assert_eq!(res.events[2].attributes[4].key, "did");
    assert_eq!(res.events[2].attributes[4].value, did);
    assert_eq!(res.events[2].attributes.len(), 5);

    assert_eq!(res.events[3].ty, "execute");
    assert_eq!(res.events[3].attributes[0].key, "_contract_address");
    assert_eq!(res.events[3].attributes[0].value,  cw721_base_contract_addr.to_string());

    assert_eq!(res.events[3].attributes.len(), 1);

    // Verify the NFT is no longer locked
    let result = contract.get_locked_nft(cw721_base_contract_addr.clone(), token_id.clone());
    assert!(result.is_err(), "Expected Err, but got Ok");
    assert_eq!(
        result.unwrap_err().to_string(),
        "Generic error: Querier contract error: Not found: NFT not found: cosmwasm1uzyszmsnca8euusre35wuqj4el3hyj8jty84kwln7du5stwwxyns2z5hxp:token_id"
    );
}

#[test]
fn test_unlock_nft_by_admin() {
    let app = App::default();
    let linkage_code_id = CodeId::store_code(&app);
    let cw721_base_code_id = app.app_mut().store_code(cw721_base_contract_mock());
    let admin = "admin".into_addr();
    let sender = "sender_address".into_addr();
    let token_id = "token_id".to_string();
    let did = format!("{}address", DID_PREFIX);
    let msg = Binary::new(did.as_bytes().to_vec());

    let cw721_base_contract = app.app_mut().instantiate_contract(
        cw721_base_code_id,
        admin.clone(),
        &msg,
        &[],
        "label",
        None,
    );

    let cw721_base_contract_addr = cw721_base_contract.unwrap();

    let contract = linkage_code_id
        .instantiate(vec![admin.clone()], vec![cw721_base_contract_addr.clone()])
        .call(&admin)
        .unwrap();

    // Lock the NFT
    let result = contract
        .receive_nft(sender.clone(), token_id.clone(), msg.clone())
        .call(&cw721_base_contract_addr);
    assert!(result.is_ok(), "Expected Ok, but got Err");

    // Unlock the NFT by admin
    let result = contract
        .unlock_nft(cw721_base_contract_addr.clone(), token_id.clone())
        .call(&admin);
    assert!(result.is_ok(), "Expected Ok, but got Err");

    // Verify the NFT is no longer locked
    let result = contract.get_locked_nft(cw721_base_contract_addr.clone(), token_id.clone());
    assert!(result.is_err(), "Expected Err, but got Ok");
}

#[test]
fn test_unlock_nft_unauthorized() {
    let app = App::default();
    let linkage_code_id = CodeId::store_code(&app);
    let cw721_base_code_id = app.app_mut().store_code(cw721_base_contract_mock());
    let admin = "admin".into_addr();
    let sender = "sender_address".into_addr();
    let unauthorized_user = "unauthorized_user".into_addr();
    let token_id = "token_id".to_string();
    let did = format!("{}address", DID_PREFIX);
    let msg = Binary::new(did.as_bytes().to_vec());

    let cw721_base_contract = app.app_mut().instantiate_contract(
        cw721_base_code_id,
        admin.clone(),
        &msg,
        &[],
        "label",
        None,
    );

    let cw721_base_contract_addr = cw721_base_contract.unwrap();

    let contract = linkage_code_id
        .instantiate(vec![admin.clone()], vec![cw721_base_contract_addr.clone()])
        .call(&admin)
        .unwrap();

    // Lock the NFT
    let result = contract
        .receive_nft(sender.clone(), token_id.clone(), msg.clone())
        .call(&cw721_base_contract_addr);
    assert!(result.is_ok(), "Expected Ok, but got Err");

    // Attempt to unlock the NFT by an unauthorized user
    let result = contract
        .unlock_nft(cw721_base_contract_addr.clone(), token_id.clone())
        .call(&unauthorized_user);
    assert!(result.is_err(), "Expected Err, but got Ok");
    assert_eq!(
        result.unwrap_err().to_string(),
        "Unauthorized: Sender is not the owner of the NFT"
    );
}

#[test]
fn test_unlock_non_existent_nft() {
    let app = App::default();
    let linkage_code_id = CodeId::store_code(&app);
    let cw721_base_code_id = app.app_mut().store_code(cw721_base_contract_mock());
    let admin = "admin".into_addr();
    let sender = "sender_address".into_addr();
    let token_id = "non_existent_token_id".to_string();

    let cw721_base_contract = app.app_mut().instantiate_contract(
        cw721_base_code_id,
        admin.clone(),
        &Binary::default(),
        &[],
        "label",
        None,
    );

    let cw721_base_contract_addr = cw721_base_contract.unwrap();

    let contract = linkage_code_id
        .instantiate(vec![admin.clone()], vec![cw721_base_contract_addr.clone()])
        .call(&admin)
        .unwrap();

    // Attempt to unlock a non-existent NFT
    let result = contract
        .unlock_nft(cw721_base_contract_addr.clone(), token_id.clone())
        .call(&sender);
    assert!(result.is_err(), "Expected Err, but got Ok");
    assert_eq!(
        result.unwrap_err().to_string(),
        format!(
            "Not found: NFT not found: {}:{}",
            cw721_base_contract_addr, token_id
        )
    );
}

#[test]
fn test_unlock_nft_invalid_contract_address() {
    let app = App::default();
    let linkage_code_id = CodeId::store_code(&app);
    let cw721_base_code_id = app.app_mut().store_code(cw721_base_contract_mock());
    let admin = "admin".into_addr();
    let sender = "sender_address".into_addr();
    let token_id = "token_id".to_string();
    let invalid_address = Addr::unchecked("invalid_contract");
    let did = format!("{}address", DID_PREFIX);
    let msg = Binary::new(did.as_bytes().to_vec());

    let cw721_base_contract = app.app_mut().instantiate_contract(
        cw721_base_code_id,
        admin.clone(),
        &Binary::default(),
        &[],
        "label",
        None,
    );

    let cw721_base_contract_addr = cw721_base_contract.unwrap();

    let contract = linkage_code_id
        .instantiate(vec![admin.clone()], vec![cw721_base_contract_addr.clone()])
        .call(&admin)
        .unwrap();

    // Lock the NFT
    let result = contract
        .receive_nft(sender.clone(), token_id.clone(), msg)
        .call(&cw721_base_contract_addr);
    assert!(result.is_ok(), "Expected Ok, but got Err");

    // Attempt to unlock the NFT with an invalid contract address
    let result = contract
        .unlock_nft(invalid_address.clone(), token_id.clone())
        .call(&sender);
    assert!(result.is_err(), "Expected Err, but got Ok");
    assert_eq!(
        result.unwrap_err().to_string(),
         "Invalid contract address: Generic error: Error decoding bech32"
    );
}


#[test]
fn test_unlock_nft_invalid_contract_address_unauthorized() {
    let app = App::default();
    let linkage_code_id = CodeId::store_code(&app);
    let cw721_base_code_id = app.app_mut().store_code(cw721_base_contract_mock());
    let admin = "admin".into_addr();
    let sender = "sender_address".into_addr();
    let token_id = "token_id".to_string();
    let invalid_address = "invalid_contract".into_addr();
    let did = format!("{}address", DID_PREFIX);
    let msg = Binary::new(did.as_bytes().to_vec());

    let cw721_base_contract = app.app_mut().instantiate_contract(
        cw721_base_code_id,
        admin.clone(),
        &Binary::default(),
        &[],
        "label",
        None,
    );

    let cw721_base_contract_addr = cw721_base_contract.unwrap();

    let contract = linkage_code_id
        .instantiate(vec![admin.clone()], vec![cw721_base_contract_addr.clone()])
        .call(&admin)
        .unwrap();

    // Lock the NFT
    let result = contract
        .receive_nft(sender.clone(), token_id.clone(), msg)
        .call(&cw721_base_contract_addr);
    assert!(result.is_ok(), "Expected Ok, but got Err");

    // Attempt to unlock the NFT with an invalid contract address
    let result = contract
        .unlock_nft(invalid_address.clone(), token_id.clone())
        .call(&sender);
    assert!(result.is_err(), "Expected Err, but got Ok");
    assert_eq!(
        result.unwrap_err().to_string(),
         "Unauthorized: Contract is not authorized"
    );
}

#[test]
fn test_unlock_nft_incorrect_sender() {
    let app = App::default();
    let linkage_code_id = CodeId::store_code(&app);
    let cw721_base_code_id = app.app_mut().store_code(cw721_base_contract_mock());
    let admin = "admin".into_addr();
    let sender = "sender_address".into_addr();
    let incorrect_sender = "incorrect_sender".into_addr();
    let token_id = "token_id".to_string();
    let did = format!("{}address", DID_PREFIX);
    let msg = Binary::new(did.as_bytes().to_vec());

    let cw721_base_contract = app.app_mut().instantiate_contract(
        cw721_base_code_id,
        admin.clone(),
        &msg,
        &[],
        "label",
        None,
    );

    let cw721_base_contract_addr = cw721_base_contract.unwrap();

    let contract = linkage_code_id
        .instantiate(vec![admin.clone()], vec![cw721_base_contract_addr.clone()])
        .call(&admin)
        .unwrap();

    // Lock the NFT
    let result = contract
        .receive_nft(sender.clone(), token_id.clone(), msg.clone())
        .call(&cw721_base_contract_addr);
    assert!(result.is_ok(), "Expected Ok, but got Err");

    // Attempt to unlock the NFT with an incorrect sender
    let result = contract
        .unlock_nft(cw721_base_contract_addr.clone(), token_id.clone())
        .call(&incorrect_sender);
    assert!(result.is_err(), "Expected Err, but got Ok");
    assert_eq!(
        result.unwrap_err().to_string(),
        "Unauthorized: Sender is not the owner of the NFT"
    );
}

#[test]
fn test_unlock_nft_empty_token_id() {
    let app = App::default();
    let linkage_code_id = CodeId::store_code(&app);
    let cw721_base_code_id = app.app_mut().store_code(cw721_base_contract_mock());
    let admin = "admin".into_addr();
    let sender = "sender_address".into_addr();
    let token_id = "".to_string(); // Empty token ID
    let did = format!("{}address", DID_PREFIX);
    let msg = Binary::new(did.as_bytes().to_vec());

    let cw721_base_contract = app.app_mut().instantiate_contract(
        cw721_base_code_id,
        admin.clone(),
        &msg,
        &[],
        "label",
        None,
    );

    let cw721_base_contract_addr = cw721_base_contract.unwrap();

    let contract = linkage_code_id
        .instantiate(vec![admin.clone()], vec![cw721_base_contract_addr.clone()])
        .call(&admin)
        .unwrap();

    // Attempt to unlock the NFT with an empty token ID
    let result = contract
        .unlock_nft(cw721_base_contract_addr.clone(), token_id.clone())
        .call(&sender);
    assert!(result.is_err(), "Expected Err, but got Ok");
    assert_eq!(
        result.unwrap_err().to_string(),
        "Token id is required"
    );
}

#[test]
fn test_unlock_nft_empty_contract_address() {
    let app = App::default();
    let linkage_code_id = CodeId::store_code(&app);
    let cw721_base_code_id = app.app_mut().store_code(cw721_base_contract_mock());
    let admin = "admin".into_addr();
    let sender = "sender_address".into_addr();
    let token_id = "token_id".to_string();
    let empty_address = Addr::unchecked(""); // Empty contract address
    let did = format!("{}address", DID_PREFIX);
    let msg = Binary::new(did.as_bytes().to_vec());

    let cw721_base_contract = app.app_mut().instantiate_contract(
        cw721_base_code_id,
        admin.clone(),
        &msg,
        &[],
        "label",
        None,
    );

    let cw721_base_contract_addr = cw721_base_contract.unwrap();

    let contract = linkage_code_id
        .instantiate(vec![admin.clone()], vec![cw721_base_contract_addr.clone()])
        .call(&admin)
        .unwrap();

    // Attempt to unlock the NFT with an empty contract address
    let result = contract
        .unlock_nft(empty_address.clone(), token_id.clone())
        .call(&sender);
    assert!(result.is_err(), "Expected Err, but got Ok");
    assert_eq!(
        result.unwrap_err().to_string(),
        "Invalid contract address: Generic error: Error decoding bech32"
    );
}

#[test]
fn test_unlock_nft_after_relocking() {
    let app = App::default();
    let linkage_code_id = CodeId::store_code(&app);
    let cw721_base_code_id = app.app_mut().store_code(cw721_base_contract_mock());
    let admin = "admin".into_addr();
    let sender = "sender_address".into_addr();
    let token_id = "token_id".to_string();
    let did = format!("{}address", DID_PREFIX);
    let msg = Binary::new(did.as_bytes().to_vec());

    let cw721_base_contract = app.app_mut().instantiate_contract(
        cw721_base_code_id,
        admin.clone(),
        &msg,
        &[],
        "label",
        None,
    );

    let cw721_base_contract_addr = cw721_base_contract.unwrap();

    let contract = linkage_code_id
        .instantiate(vec![admin.clone()], vec![cw721_base_contract_addr.clone()])
        .call(&admin)
        .unwrap();

    // Lock the NFT
    let result = contract
        .receive_nft(sender.clone(), token_id.clone(), msg.clone())
        .call(&cw721_base_contract_addr);
    assert!(result.is_ok(), "Expected Ok, but got Err");

    // Unlock the NFT
    let result = contract
        .unlock_nft(cw721_base_contract_addr.clone(), token_id.clone())
        .call(&sender);
    assert!(result.is_ok(), "Expected Ok, but got Err");

    // Re-lock the NFT
    let result = contract
        .receive_nft(sender.clone(), token_id.clone(), msg.clone())
        .call(&cw721_base_contract_addr);
    assert!(result.is_ok(), "Expected Ok, but got Err");

    // Unlock the NFT again
    let result = contract
        .unlock_nft(cw721_base_contract_addr.clone(), token_id.clone())
        .call(&sender);
    assert!(result.is_ok(), "Expected Ok, but got Err");
}

#[test]
fn test_unlock_nft_multiple_admins() {
    let app = App::default();
    let linkage_code_id = CodeId::store_code(&app);
    let cw721_base_code_id = app.app_mut().store_code(cw721_base_contract_mock());
    let admin1 = "admin1".into_addr();
    let admin2 = "admin2".into_addr();
    let sender = "sender_address".into_addr();
    let token_id = "token_id".to_string();
    let did = format!("{}address", DID_PREFIX);
    let msg = Binary::new(did.as_bytes().to_vec());

    let cw721_base_contract = app.app_mut().instantiate_contract(
        cw721_base_code_id,
        admin1.clone(),
        &msg,
        &[],
        "label",
        None,
    );

    let cw721_base_contract_addr = cw721_base_contract.unwrap();

    let contract = linkage_code_id
        .instantiate(vec![admin1.clone(), admin2.clone()], vec![cw721_base_contract_addr.clone()])
        .call(&admin1)
        .unwrap();

    // Lock the NFT
    let result = contract
        .receive_nft(sender.clone(), token_id.clone(), msg.clone())
        .call(&cw721_base_contract_addr);
    assert!(result.is_ok(), "Expected Ok, but got Err");

    // Unlock the NFT by the second admin
    let result = contract
        .unlock_nft(cw721_base_contract_addr.clone(), token_id.clone())
        .call(&admin2);
    assert!(result.is_ok(), "Expected Ok, but got Err");
}

#[test]
fn test_unlock_one_nft_when_multiple_locked() {
    let app = App::default();
    let linkage_code_id = CodeId::store_code(&app);
    let cw721_base_code_id = app.app_mut().store_code(cw721_base_contract_mock());
    let admin = "admin".into_addr();
    let sender = "sender_address".into_addr();
    let token_id_1 = "token_id_1".to_string();
    let token_id_2 = "token_id_2".to_string();
    let did1 = format!("{}address", DID_PREFIX);
    let msg1 = Binary::new(did1.as_bytes().to_vec());

    let did2 = format!("{}address", DID_PREFIX);
    let msg2 = Binary::new(did2.as_bytes().to_vec());

    let cw721_base_contract = app.app_mut().instantiate_contract(
        cw721_base_code_id,
        admin.clone(),
        &msg1,
        &[],
        "label",
        None,
    );

    let cw721_base_contract_addr = cw721_base_contract.unwrap();

    let contract = linkage_code_id
        .instantiate(vec![admin.clone()], vec![cw721_base_contract_addr.clone()])
        .call(&admin)
        .unwrap();

    // Lock two NFTs
    let result = contract
        .receive_nft(sender.clone(), token_id_1.clone(), msg1.clone())
        .call(&cw721_base_contract_addr);
    assert!(result.is_ok(), "Expected Ok, but got Err");

    let result = contract
        .receive_nft(sender.clone(), token_id_2.clone(), msg2.clone())
        .call(&cw721_base_contract_addr);
    assert!(result.is_ok(), "Expected Ok, but got Err");

    // Unlock the first NFT
    let result = contract
        .unlock_nft(cw721_base_contract_addr.clone(), token_id_1.clone())
        .call(&sender);
    assert!(result.is_ok(), "Expected Ok, but got Err");

    // Verify the first NFT is no longer locked
    let result = contract.get_locked_nft(cw721_base_contract_addr.clone(), token_id_1.clone());
    assert!(result.is_err(), "Expected Err, but got Ok");
    assert_eq!(
        result.unwrap_err().to_string(),
        format!(
            "Generic error: Querier contract error: Not found: NFT not found: {}:{}",
            cw721_base_contract_addr, token_id_1
        )
    );

    // Verify the second NFT is still locked
    let result = contract.get_locked_nft(cw721_base_contract_addr.clone(), token_id_2.clone());
    assert!(result.is_ok(), "Expected Ok, but got Err");
    let locked_nft = result.unwrap();
    assert_eq!(locked_nft.token_id, token_id_2);
    assert_eq!(locked_nft.sender, sender);
    assert_eq!(locked_nft.did, Did::new(&did1));
}

#[test]
fn test_unlock_nfts_same_owner_same_did() {
    let app = App::default();
    let linkage_code_id = CodeId::store_code(&app);
    let cw721_base_code_id = app.app_mut().store_code(cw721_base_contract_mock());
    let admin = "admin".into_addr();
    let sender = "sender_address".into_addr();
    let token_id_1 = "token_id_1".to_string();
    let token_id_2 = "token_id_2".to_string();
    let did = format!("{}address", DID_PREFIX);
    let msg = Binary::new(did.as_bytes().to_vec());

    let cw721_base_contract = app.app_mut().instantiate_contract(
        cw721_base_code_id,
        admin.clone(),
        &msg,
        &[],
        "label",
        None,
    );

    let cw721_base_contract_addr = cw721_base_contract.unwrap();

    let contract = linkage_code_id
        .instantiate(vec![admin.clone()], vec![cw721_base_contract_addr.clone()])
        .call(&admin)
        .unwrap();

    // Lock two NFTs with the same owner and DID
    let result = contract
        .receive_nft(sender.clone(), token_id_1.clone(), msg.clone())
        .call(&cw721_base_contract_addr);
    assert!(result.is_ok(), "Expected Ok, but got Err");

    let result = contract
        .receive_nft(sender.clone(), token_id_2.clone(), msg.clone())
        .call(&cw721_base_contract_addr);
    assert!(result.is_ok(), "Expected Ok, but got Err");

    // Unlock the first NFT
    let result = contract
        .unlock_nft(cw721_base_contract_addr.clone(), token_id_1.clone())
        .call(&sender);
    assert!(result.is_ok(), "Expected Ok, but got Err");

    // Verify the first NFT is no longer locked
    let result = contract.get_locked_nft(cw721_base_contract_addr.clone(), token_id_1.clone());
    assert!(result.is_err(), "Expected Err, but got Ok");

    // Verify the second NFT is still locked
    let result = contract.get_locked_nft(cw721_base_contract_addr.clone(), token_id_2.clone());
    assert!(result.is_ok(), "Expected Ok, but got Err");
    let locked_nft = result.unwrap();
    assert_eq!(locked_nft.token_id, token_id_2);
    assert_eq!(locked_nft.sender, sender);
    assert_eq!(locked_nft.did, Did::new(&did));
}

#[test]
fn test_unlock_nfts_same_owner_different_dids() {
    let app = App::default();
    let linkage_code_id = CodeId::store_code(&app);
    let cw721_base_code_id = app.app_mut().store_code(cw721_base_contract_mock());
    let admin = "admin".into_addr();
    let sender = "sender_address".into_addr();
    let token_id_1 = "token_id_1".to_string();
    let token_id_2 = "token_id_2".to_string();
    let did_1 = format!("{}did1", DID_PREFIX);
    let did_2 = format!("{}did2", DID_PREFIX);
    let msg_1 = Binary::new(did_1.as_bytes().to_vec());
    let msg_2 = Binary::new(did_2.as_bytes().to_vec());

    let cw721_base_contract = app.app_mut().instantiate_contract(
        cw721_base_code_id,
        admin.clone(),
        &msg_1,
        &[],
        "label",
        None,
    );

    let cw721_base_contract_addr = cw721_base_contract.unwrap();

    let contract = linkage_code_id
        .instantiate(vec![admin.clone()], vec![cw721_base_contract_addr.clone()])
        .call(&admin)
        .unwrap();

    // Lock two NFTs with the same owner but different DIDs
    let result = contract
        .receive_nft(sender.clone(), token_id_1.clone(), msg_1.clone())
        .call(&cw721_base_contract_addr);
    assert!(result.is_ok(), "Expected Ok, but got Err");

    let result = contract
        .receive_nft(sender.clone(), token_id_2.clone(), msg_2.clone())
        .call(&cw721_base_contract_addr);
    assert!(result.is_ok(), "Expected Ok, but got Err");

    // Unlock the first NFT
    let result = contract
        .unlock_nft(cw721_base_contract_addr.clone(), token_id_1.clone())
        .call(&sender);
    assert!(result.is_ok(), "Expected Ok, but got Err");

    // Verify the first NFT is no longer locked
    let result = contract.get_locked_nft(cw721_base_contract_addr.clone(), token_id_1.clone());
    assert!(result.is_err(), "Expected Err, but got Ok");

    // Verify the second NFT is still locked
    let result = contract.get_locked_nft(cw721_base_contract_addr.clone(), token_id_2.clone());
    assert!(result.is_ok(), "Expected Ok, but got Err");
    let locked_nft = result.unwrap();
    assert_eq!(locked_nft.token_id, token_id_2);
    assert_eq!(locked_nft.sender, sender);
    assert_eq!(locked_nft.did, Did::new(&did_2));
}

#[test]
fn test_unlock_nfts_different_owners_same_did() {
    let app = App::default();
    let linkage_code_id = CodeId::store_code(&app);
    let cw721_base_code_id = app.app_mut().store_code(cw721_base_contract_mock());
    let admin = "admin".into_addr();
    let sender_1 = "sender_1".into_addr();
    let sender_2 = "sender_2".into_addr();
    let token_id_1 = "token_id_1".to_string();
    let token_id_2 = "token_id_2".to_string();
    let did = format!("{}address", DID_PREFIX);
    let msg = Binary::new(did.as_bytes().to_vec());

    let cw721_base_contract = app.app_mut().instantiate_contract(
        cw721_base_code_id,
        admin.clone(),
        &msg,
        &[],
        "label",
        None,
    );

    let cw721_base_contract_addr = cw721_base_contract.unwrap();

    let contract = linkage_code_id
        .instantiate(vec![admin.clone()], vec![cw721_base_contract_addr.clone()])
        .call(&admin)
        .unwrap();

    // Lock two NFTs with different owners but the same DID
    let result = contract
        .receive_nft(sender_1.clone(), token_id_1.clone(), msg.clone())
        .call(&cw721_base_contract_addr);
    assert!(result.is_ok(), "Expected Ok, but got Err");

    let result = contract
        .receive_nft(sender_2.clone(), token_id_2.clone(), msg.clone())
        .call(&cw721_base_contract_addr);
    assert!(result.is_ok(), "Expected Ok, but got Err");

    // Unlock the first NFT
    let result = contract
        .unlock_nft(cw721_base_contract_addr.clone(), token_id_1.clone())
        .call(&sender_1);
    assert!(result.is_ok(), "Expected Ok, but got Err");

    // Verify the first NFT is no longer locked
    let result = contract.get_locked_nft(cw721_base_contract_addr.clone(), token_id_1.clone());
    assert!(result.is_err(), "Expected Err, but got Ok");

    // Verify the second NFT is still locked
    let result = contract.get_locked_nft(cw721_base_contract_addr.clone(), token_id_2.clone());
    assert!(result.is_ok(), "Expected Ok, but got Err");
    let locked_nft = result.unwrap();
    assert_eq!(locked_nft.token_id, token_id_2);
    assert_eq!(locked_nft.sender, sender_2);
    assert_eq!(locked_nft.did, Did::new(&did));
}

pub fn cw721_base_contract_mock() -> Box<dyn Contract<Empty>> {
    let contract = ContractWrapper::new(
        |_deps, _, _info, _msg: Cw721ExecuteMsg| -> StdResult<Response> { Ok(Response::default()) },
        |_deps, _, _info, _msg: String| -> StdResult<Response> { Ok(Response::default()) },
        |_, _, _msg: Cw721QueryMsg| -> StdResult<Binary> {
            let data = "test";
            Ok(to_json_binary(data)?)
        },
    );
    Box::new(contract)
}
