
use crate::contract::sv::mt::{CodeId, LinkageContractProxy};
use cosmwasm_std::{Addr, Binary};
use cw_multi_test::{Executor, IntoAddr};
use sylvia::multitest::App;
use did_contract::state::{Did, DID_PREFIX};
use crate::test::nft_unlock::cw721_base_contract_mock;

#[test]
fn test_get_locked_nft_success() {
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

    // Retrieve the locked NFT
    let result = contract.get_locked_nft(cw721_base_contract_addr.clone(), token_id.clone());
    assert!(result.is_ok(), "Expected Ok, but got Err");
    let locked_nft = result.unwrap();

    // Verify the locked NFT details
    assert_eq!(locked_nft.contract_address, cw721_base_contract_addr);
    assert_eq!(locked_nft.token_id, token_id);
    assert_eq!(locked_nft.sender, sender);
    assert_eq!(locked_nft.did, Did::new(&did));
}

#[test]
fn test_get_locked_nft_non_existent() {
    let app = App::default();
    let linkage_code_id = CodeId::store_code(&app);
    let cw721_base_code_id = app.app_mut().store_code(cw721_base_contract_mock());
    let admin = "admin".into_addr();
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

    // Attempt to retrieve a non-existent NFT
    let result = contract.get_locked_nft(cw721_base_contract_addr.clone(), token_id.clone());
    assert!(result.is_err(), "Expected Err, but got Ok");
    assert_eq!(
        result.unwrap_err().to_string(),
        format!(
            "Generic error: Querier contract error: Not found: NFT not found: {}:{}",
            cw721_base_contract_addr, token_id
        )
    );
}

#[test]
fn test_get_locked_nft_invalid_contract_address() {
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
        .receive_nft(sender.clone(), token_id.clone(), msg)
        .call(&cw721_base_contract_addr);
    assert!(result.is_ok(), "Expected Ok, but got Err");

    // Attempt to retrieve the NFT with an invalid contract address
    let result = contract.get_locked_nft(invalid_address.clone(), token_id.clone());
    assert!(result.is_err(), "Expected Err, but got Ok");
    assert_eq!(
        result.unwrap_err().to_string(),
        "Generic error: Querier contract error: Invalid contract address: Generic error: Error decoding bech32",
    );
}

#[test]
fn test_get_locked_nft_invalid_token_id() {
    let app = App::default();
    let linkage_code_id = CodeId::store_code(&app);
    let cw721_base_code_id = app.app_mut().store_code(cw721_base_contract_mock());
    let admin = "admin".into_addr();
    let token_id = "".to_string();
    // let invalid_address = Addr::from("invalid_contract");
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

    // // Lock the NFT
    // let result = contract
    //     .receive_nft(sender.clone(), token_id.clone(), msg)
    //     .call(&cw721_base_contract_addr);
    // assert!(result.is_ok(), "Expected Ok, but got Err");

    // Attempt to retrieve the NFT with an invalid contract address
    let result = contract.get_locked_nft(cw721_base_contract_addr.clone(), token_id.clone());
    assert!(result.is_err(), "Expected Err, but got Ok");
    assert_eq!(
        result.unwrap_err().to_string(),
        "Generic error: Querier contract error: Token id is required",
    );
}

#[test]
fn test_get_locked_nft_after_unlocking() {
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

    // Attempt to retrieve the NFT after unlocking
    let result = contract.get_locked_nft(cw721_base_contract_addr.clone(), token_id.clone());
    assert!(result.is_err(), "Expected Err, but got Ok");
    assert_eq!(
        result.unwrap_err().to_string(),
        format!(
            "Generic error: Querier contract error: Not found: NFT not found: {}:{}",
            cw721_base_contract_addr, token_id
        )
    );
}