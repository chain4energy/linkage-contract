
use crate::contract::sv::mt::{CodeId, LinkageContractProxy};
use cosmwasm_std:: Binary;
use cw_multi_test::{Executor, IntoAddr};
use did_contract::state::{Did, DID_PREFIX};
use sylvia::multitest::App;
use crate::test::nft_unlock::cw721_base_contract_mock;

#[test]
fn test_get_locked_nfts_by_did_success() {
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

    // Lock two NFTs with the same DID
    let result = contract
        .receive_nft(sender.clone(), token_id_1.clone(), msg.clone())
        .call(&cw721_base_contract_addr);
    assert!(result.is_ok(), "Expected Ok, but got Err");

    let result = contract
        .receive_nft(sender.clone(), token_id_2.clone(), msg.clone())
        .call(&cw721_base_contract_addr);
    assert!(result.is_ok(), "Expected Ok, but got Err");

    // Retrieve NFTs by DID
    let result = contract.get_locked_nfts_by_did(Did::new(&did));
    assert!(result.is_ok(), "Expected Ok, but got Err");
    let locked_nfts = result.unwrap();

    // Verify the retrieved NFTs
    assert_eq!(locked_nfts.len(), 2);
    assert!(locked_nfts.iter().any(|nft| nft.token_id == token_id_1));
    assert!(locked_nfts.iter().any(|nft| nft.token_id == token_id_2));
}

#[test]
fn test_get_locked_nfts_by_did_none_exist() {
    let app = App::default();
    let linkage_code_id = CodeId::store_code(&app);
    let cw721_base_code_id = app.app_mut().store_code(cw721_base_contract_mock());
    let admin = "admin".into_addr();
    let did = format!("{}nonexistent", DID_PREFIX);

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

    // Query a DID with no associated NFTs
    let result = contract.get_locked_nfts_by_did(Did::new(&did));
    assert!(result.is_ok(), "Expected Ok, but got Err");
    let locked_nfts = result.unwrap();

    // Verify the result is empty
    assert!(locked_nfts.is_empty(), "Expected no NFTs, but found some");
}

#[test]
fn test_get_locked_nfts_by_did_after_unlocking() {
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

    // Query the DID
    let result = contract.get_locked_nfts_by_did(Did::new(&did));
    assert!(result.is_ok(), "Expected Ok, but got Err");
    let locked_nfts = result.unwrap();

    // Verify the result is empty
    assert!(locked_nfts.is_empty(), "Expected no NFTs, but found some");
}

#[test]
fn test_get_locked_nfts_by_did_multiple_owners() {
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

    // Lock two NFTs with the same DID but different owners
    let result = contract
        .receive_nft(sender_1.clone(), token_id_1.clone(), msg.clone())
        .call(&cw721_base_contract_addr);
    assert!(result.is_ok(), "Expected Ok, but got Err");

    let result = contract
        .receive_nft(sender_2.clone(), token_id_2.clone(), msg.clone())
        .call(&cw721_base_contract_addr);
    assert!(result.is_ok(), "Expected Ok, but got Err");

    // Retrieve NFTs by DID
    let result = contract.get_locked_nfts_by_did(Did::new(&did));
    assert!(result.is_ok(), "Expected Ok, but got Err");
    let locked_nfts = result.unwrap();

    // Verify the retrieved NFTs
    assert_eq!(locked_nfts.len(), 2);
    assert!(locked_nfts.iter().any(|nft| nft.token_id == token_id_1 && nft.sender == sender_1));
    assert!(locked_nfts.iter().any(|nft| nft.token_id == token_id_2 && nft.sender == sender_2));
}

#[test]
fn test_get_locked_nfts_by_did_invalid_did() {
    let app = App::default();
    let linkage_code_id = CodeId::store_code(&app);
    let cw721_base_code_id = app.app_mut().store_code(cw721_base_contract_mock());
    let admin = "admin".into_addr();
    let invalid_did = "invalid_did_format"; // Invalid DID format

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

    // Attempt to query NFTs with an invalid DID
    let result = contract.get_locked_nfts_by_did(Did::from(invalid_did));
    assert!(result.is_err(), "Expected Err, but got Ok");
    assert_eq!(
        result.unwrap_err().to_string(),
        "Generic error: Querier contract error: Did invalid: Did format error: invalid_did_format"
    );
}