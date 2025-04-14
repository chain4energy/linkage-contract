use crate::contract::sv::mt::{CodeId, LinkageContractProxy};
use crate::error::ContractError;
use crate::responses::NftLockEntryResponse;
use cosmwasm_std::{to_json_binary, Addr, Binary, Empty, Response, StdResult};
use cw721::{Cw721ExecuteMsg, Cw721QueryMsg};
use cw_multi_test::{Contract, ContractWrapper, Executor, IntoAddr};
use did_contract::state::Did;
use sylvia::multitest::App;

#[test]
fn test_add_authorized_nft_contract() {
    let app = App::default();
    let code_id = CodeId::store_code(&app);

    let owner = "owner".into_addr();
    let auth_address = "cw721_address".into_addr();
    let contract = code_id
        .instantiate(vec![owner.clone()], vec![auth_address.clone()])
        .call(&owner)
        .unwrap();

    let new_nft_contract = "new_nft_contract".into_addr();

    // Successfully add a new authorized NFT contract
    let res = contract
        .add_authorized_nft_contract(new_nft_contract.clone())
        .call(&owner);
    assert!(res.is_ok(), "Expected Ok, but got an Err");

    let res = res.unwrap();
    assert_eq!(res.events[0].ty, "execute");
    assert_eq!(res.events[0].attributes[0].key, "_contract_address");
    assert_eq!(
        res.events[0].attributes[0].value,
        contract.contract_addr.to_string()
    );

    assert_eq!(res.events[1].ty, "wasm");
    assert_eq!(res.events[1].attributes[0].key, "_contract_address");
    assert_eq!(
        res.events[1].attributes[0].value,
        contract.contract_addr.to_string()
    );
    assert_eq!(res.events[1].attributes[1].key, "action");
    assert_eq!(
        res.events[1].attributes[1].value,
        "add_authorized_nft_contract"
    );
    assert_eq!(
        res.events[1].attributes[2].key,
        "new_authorized_nft_contract"
    );
    assert_eq!(
        res.events[1].attributes[2].value,
        new_nft_contract.to_string()
    );

    assert_eq!(res.events[2].ty, "wasm-add_authorized_nft_contract");
    assert_eq!(res.events[2].attributes[0].key, "_contract_address");
    assert_eq!(
        res.events[2].attributes[0].value,
        contract.contract_addr.to_string()
    );
    assert_eq!(res.events[2].attributes[1].key, "executor");
    assert_eq!(res.events[2].attributes[1].value, owner.to_string());
    assert_eq!(
        res.events[2].attributes[2].key,
        "new_authorized_nft_contract"
    );
    assert_eq!(
        res.events[2].attributes[2].value,
        new_nft_contract.to_string()
    );

    // Ensure it was added correctly
    let result = contract.get_authorized_nft_contracts();
    assert!(result.is_ok(), "Expected Ok, but got an Err");
    let authorized_contracts = result.unwrap();
    assert_eq!(authorized_contracts.len(), 2);
    assert!(authorized_contracts.contains(&new_nft_contract));

    // Try adding the same contract again (should fail)
    let res = contract
        .add_authorized_nft_contract(new_nft_contract.clone())
        .call(&owner);
    assert!(res.is_err(), "Expected Err, but got Ok");
    assert_eq!(
        "NFT contract already exists",
        res.err().unwrap().to_string()
    );

    // Unauthorized user should not be able to add a contract
    let unauthorized_user = "unauthorized_user".into_addr();
    let another_nft_contract = "another_nft_contract".into_addr();
    let res = contract
        .add_authorized_nft_contract(another_nft_contract.clone())
        .call(&unauthorized_user);
    assert!(res.is_err(), "Expected Err, but got Ok");
    assert_eq!("Unauthorized", res.err().unwrap().to_string());
}

#[test]
fn test_add_authorized_nft_contract_duplicate() {
    let app = App::default();
    let code_id = CodeId::store_code(&app);

    let owner = "owner".into_addr();
    let auth_address = "cw721_address".into_addr();
    let contract = code_id
        .instantiate(vec![owner.clone()], vec![auth_address.clone()])
        .call(&owner)
        .unwrap();

    let new_nft_contract = "new_nft_contract".into_addr();

    // Add the contract once
    contract
        .add_authorized_nft_contract(new_nft_contract.clone())
        .call(&owner)
        .expect("Failed to add contract");

    // Attempt to add the same contract again
    let res = contract
        .add_authorized_nft_contract(new_nft_contract.clone())
        .call(&owner);
    assert!(res.is_err(), "Expected Err, but got Ok");
    assert_eq!(
        res.err().unwrap().to_string(),
        "NFT contract already exists",
        "Expected 'NFT contract already exists' error"
    );
}

#[test]
fn test_add_authorized_nft_contract_invalid_address() {
    let app = App::default();
    let code_id = CodeId::store_code(&app);

    let owner = "owner".into_addr();
    let auth_address = "cw721_address".into_addr();
    let contract = code_id
        .instantiate(vec![owner.clone()], vec![auth_address.clone()])
        .call(&owner)
        .unwrap();

    // Attempt to add an invalid contract address
    let invalid_address = "invalid_address".to_string();
    let invalid_address = Addr::unchecked(invalid_address.clone());
    let res = contract
        .add_authorized_nft_contract(invalid_address)
        .call(&owner);
    assert!(res.is_err(), "Expected Err, but got Ok");
    assert_eq!(
        res.err().unwrap().to_string(),
        "Invalid contract address: Generic error: Error decoding bech32",
        "Expected 'Invalid contract address' error"
    );
}

#[test]
fn test_add_authorized_nft_contract_empty_address() {
    let app = App::default();
    let code_id = CodeId::store_code(&app);

    let owner = "owner".into_addr();
    let auth_address = "cw721_address".into_addr();
    let contract = code_id
        .instantiate(vec![owner.clone()], vec![auth_address.clone()])
        .call(&owner)
        .unwrap();

    // Attempt to add an invalid contract address
    let invalid_address = "".to_string();
    let invalid_address = Addr::unchecked(invalid_address.clone());
    let res = contract
        .add_authorized_nft_contract(invalid_address)
        .call(&owner);
    assert!(res.is_err(), "Expected Err, but got Ok");
    assert_eq!(
        res.err().unwrap().to_string(),
        "Invalid contract address: Generic error: Error decoding bech32",
        "Expected 'Invalid contract address' error"
    );
}

#[test]
fn test_add_authorized_nft_contract_unauthorized() {
    let app = App::default();
    let code_id = CodeId::store_code(&app);

    let owner = "owner".into_addr();
    let auth_address = "cw721_address".into_addr();
    let contract = code_id
        .instantiate(vec![owner.clone()], vec![auth_address.clone()])
        .call(&owner)
        .unwrap();

    let unauthorized_user = "unauthorized_user".into_addr();
    let new_nft_contract = "new_nft_contract".into_addr();

    // Attempt to add a contract as an unauthorized user
    let res = contract
        .add_authorized_nft_contract(new_nft_contract.clone())
        .call(&unauthorized_user);
    assert!(res.is_err(), "Expected Err, but got Ok");
    assert_eq!(
        res.err().unwrap().to_string(),
        "Unauthorized",
        "Expected 'Unauthorized' error"
    );
}

#[test]
fn test_remove_authorized_nft_contract() {
    let app = App::default();
    let code_id = CodeId::store_code(&app);

    let owner = "owner".into_addr();
    let auth_address = "cw721_address".into_addr();
    let contract = code_id
        .instantiate(vec![owner.clone()], vec![auth_address.clone()])
        .call(&owner)
        .unwrap();

    // Remove existing authorized contract
    let res = contract
        .remove_authorized_nft_contract(auth_address.clone())
        .call(&owner);
    assert!(res.is_ok(), "Expected Ok, but got an Err");

    // Verify emitted events
    let res = res.unwrap();
    assert_eq!(res.events[0].ty, "execute");
    assert_eq!(res.events[1].ty, "wasm");
    assert_eq!(res.events[1].attributes[1].key, "action");
    assert_eq!(
        res.events[1].attributes[1].value,
        "remove_authorized_nft_contract"
    );
    assert_eq!(
        res.events[1].attributes[2].key,
        "removed_authorized_nft_contract"
    );
    assert_eq!(res.events[1].attributes[2].value, auth_address.to_string());

    // Ensure contract was removed
    let result = contract.get_authorized_nft_contracts();
    assert!(result.is_ok(), "Expected Ok, but got an Err");
    let authorized_contracts = result.unwrap();
    assert!(!authorized_contracts.contains(&auth_address));

    // Try removing a non-existing contract (should fail)
    let res = contract
        .remove_authorized_nft_contract(auth_address.clone())
        .call(&owner);
    assert!(res.is_err(), "Expected Err, but got Ok");
    assert_eq!("NFT contract not found", res.err().unwrap().to_string());

    // Unauthorized user should not be able to remove a contract
    let unauthorized_user = "unauthorized_user".into_addr();
    let res = contract
        .remove_authorized_nft_contract(auth_address.clone())
        .call(&unauthorized_user);
    assert!(res.is_err(), "Expected Err, but got Ok");
    assert_eq!("Unauthorized", res.err().unwrap().to_string());
}

#[test]
fn test_remove_authorized_nft_contract_non_existent() {
    let app = App::default();
    let code_id = CodeId::store_code(&app);

    let owner = "owner".into_addr();
    let auth_address = "cw721_address".into_addr();
    let contract = code_id
        .instantiate(vec![owner.clone()], vec![auth_address.clone()])
        .call(&owner)
        .unwrap();

    let non_existent_contract = "non_existent_contract".into_addr();

    // Attempt to remove a non-existent contract
    let res = contract
        .remove_authorized_nft_contract(non_existent_contract.clone())
        .call(&owner);
    assert!(res.is_err(), "Expected Err, but got Ok");
    assert_eq!(
        res.err().unwrap().to_string(),
        "NFT contract not found",
        "Expected 'NFT contract not found' error"
    );
}

#[test]
fn test_remove_authorized_nft_contract_unauthorized() {
    let app = App::default();
    let code_id = CodeId::store_code(&app);

    let owner = "owner".into_addr();
    let auth_address = "cw721_address".into_addr();
    let contract = code_id
        .instantiate(vec![owner.clone()], vec![auth_address.clone()])
        .call(&owner)
        .unwrap();

    let unauthorized_user = "unauthorized_user".into_addr();

    // Attempt to remove a contract as an unauthorized user
    let res = contract
        .remove_authorized_nft_contract(auth_address.clone())
        .call(&unauthorized_user);
    assert!(res.is_err(), "Expected Err, but got Ok");
    assert_eq!(
        res.err().unwrap().to_string(),
        "Unauthorized",
        "Expected 'Unauthorized' error"
    );
}

#[test]
fn test_remove_last_authorized_nft_contract() {
    let app = App::default();
    let code_id = CodeId::store_code(&app);

    let owner = "owner".into_addr();
    let auth_address = "cw721_address".into_addr();
    let contract = code_id
        .instantiate(vec![owner.clone()], vec![auth_address.clone()])
        .call(&owner)
        .unwrap();

    // Remove the last authorized contract
    let res = contract
        .remove_authorized_nft_contract(auth_address.clone())
        .call(&owner);
    assert!(res.is_ok(), "Expected Ok, but got an Err");

    // Ensure no contracts remain
    let result = contract.get_authorized_nft_contracts();
    assert!(result.is_ok(), "Expected Ok, but got an Err");
    let authorized_contracts = result.unwrap();
    assert!(authorized_contracts.is_empty());
}

#[test]
fn test_remove_authorized_nft_contract_empty_address() {
    let app = App::default();
    let code_id = CodeId::store_code(&app);

    let owner = "owner".into_addr();
    let auth_address = "cw721_address".into_addr();
    let contract = code_id
        .instantiate(vec![owner.clone()], vec![auth_address.clone()])
        .call(&owner)
        .unwrap();

    // Attempt to remove an empty contract address
    let empty_address = "".to_string();
    let empty_address = Addr::unchecked(empty_address.clone());
    let res = contract
        .remove_authorized_nft_contract(empty_address)
        .call(&owner);
    assert!(res.is_err(), "Expected Err, but got Ok");
    assert_eq!(
        res.err().unwrap().to_string(),
        "Invalid contract address: Generic error: Error decoding bech32",
        "Expected 'Invalid contract address' error"
    );
}

#[test]
fn test_remove_authorized_nft_contract_invalid_address() {
    let app = App::default();
    let code_id = CodeId::store_code(&app);

    let owner = "owner".into_addr();
    let auth_address = "cw721_address".into_addr();
    let contract = code_id
        .instantiate(vec![owner.clone()], vec![auth_address.clone()])
        .call(&owner)
        .unwrap();

    // Attempt to remove an empty contract address
    let empty_address = "invalid_address".to_string();
    let empty_address = Addr::unchecked(empty_address.clone());
    let res = contract
        .remove_authorized_nft_contract(empty_address)
        .call(&owner);
    assert!(res.is_err(), "Expected Err, but got Ok");
    assert_eq!(
        res.err().unwrap().to_string(),
        "Invalid contract address: Generic error: Error decoding bech32",
        "Expected 'Invalid contract address' error"
    );
}

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
