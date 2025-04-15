
use crate::contract::sv::mt::{CodeId, LinkageContractProxy};
use cosmwasm_std::{Addr, Binary};
use cw_multi_test::{Executor, IntoAddr};
use sylvia::multitest::App;
use did_contract::state::{Did, DID_PREFIX};
use crate::test::nft_unlock::cw721_base_contract_mock;

#[test]
fn test_get_locked_nfts_by_owner_success() {
    let app = App::default();
    let linkage_code_id = CodeId::store_code(&app);
    let cw721_base_code_id = app.app_mut().store_code(cw721_base_contract_mock());
    let admin = "admin".into_addr();
    let owner = "owner_address".into_addr();
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

    // Lock two NFTs with the same owner
    let result = contract
        .receive_nft(owner.clone(), token_id_1.clone(), msg.clone())
        .call(&cw721_base_contract_addr);
    assert!(result.is_ok(), "Expected Ok, but got Err");

    let result = contract
        .receive_nft(owner.clone(), token_id_2.clone(), msg.clone())
        .call(&cw721_base_contract_addr);
    assert!(result.is_ok(), "Expected Ok, but got Err");

    // Retrieve NFTs by owner
    let result = contract.get_locked_nfts_by_owner(owner.clone());
    assert!(result.is_ok(), "Expected Ok, but got Err");
    let locked_nfts = result.unwrap();

    // Verify the retrieved NFTs
    assert_eq!(locked_nfts.len(), 2);
    assert!(locked_nfts.iter().any(|nft| nft.token_id == token_id_1));
    assert!(locked_nfts.iter().any(|nft| nft.token_id == token_id_2));
}

#[test]
fn test_get_locked_nfts_by_owner_none_exist() {
    let app = App::default();
    let linkage_code_id = CodeId::store_code(&app);
    let cw721_base_code_id = app.app_mut().store_code(cw721_base_contract_mock());
    let admin = "admin".into_addr();
    let owner = "nonexistent_owner".into_addr();

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

    // Query an owner with no associated NFTs
    let result = contract.get_locked_nfts_by_owner(owner.clone());
    assert!(result.is_ok(), "Expected Ok, but got Err");
    let locked_nfts = result.unwrap();

    // Verify the result is empty
    assert!(locked_nfts.is_empty(), "Expected no NFTs, but found some");
}

#[test]
fn test_get_locked_nfts_by_owner_after_unlocking() {
    let app = App::default();
    let linkage_code_id = CodeId::store_code(&app);
    let cw721_base_code_id = app.app_mut().store_code(cw721_base_contract_mock());
    let admin = "admin".into_addr();
    let owner = "owner_address".into_addr();
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
        .receive_nft(owner.clone(), token_id.clone(), msg.clone())
        .call(&cw721_base_contract_addr);
    assert!(result.is_ok(), "Expected Ok, but got Err");

    // Unlock the NFT
    let result = contract
        .unlock_nft(cw721_base_contract_addr.clone(), token_id.clone())
        .call(&owner);
    assert!(result.is_ok(), "Expected Ok, but got Err");

    // Query the owner
    let result = contract.get_locked_nfts_by_owner(owner.clone());
    assert!(result.is_ok(), "Expected Ok, but got Err");
    let locked_nfts = result.unwrap();

    // Verify the result is empty
    assert!(locked_nfts.is_empty(), "Expected no NFTs, but found some");
}

#[test]
fn test_get_locked_nfts_by_owner_multiple_dids() {
    let app = App::default();
    let linkage_code_id = CodeId::store_code(&app);
    let cw721_base_code_id = app.app_mut().store_code(cw721_base_contract_mock());
    let admin = "admin".into_addr();
    let owner = "owner_address".into_addr();
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
        .receive_nft(owner.clone(), token_id_1.clone(), msg_1.clone())
        .call(&cw721_base_contract_addr);
    assert!(result.is_ok(), "Expected Ok, but got Err");

    let result = contract
        .receive_nft(owner.clone(), token_id_2.clone(), msg_2.clone())
        .call(&cw721_base_contract_addr);
    assert!(result.is_ok(), "Expected Ok, but got Err");

    // Retrieve NFTs by owner
    let result = contract.get_locked_nfts_by_owner(owner.clone());
    assert!(result.is_ok(), "Expected Ok, but got Err");
    let locked_nfts = result.unwrap();

    // Verify the retrieved NFTs
    assert_eq!(locked_nfts.len(), 2);
    assert!(locked_nfts.iter().any(|nft| nft.token_id == token_id_1 && nft.did == Did::new(&did_1)));
    assert!(locked_nfts.iter().any(|nft| nft.token_id == token_id_2 && nft.did == Did::new(&did_2)));
}

#[test]
fn test_get_locked_nfts_by_owner_invalid_owner() {
    let app = App::default();
    let linkage_code_id = CodeId::store_code(&app);
    let cw721_base_code_id = app.app_mut().store_code(cw721_base_contract_mock());
    let admin = "admin".into_addr();
    let invalid_owner = Addr::unchecked("invalid_owner_address"); // Invalid owner address

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

    // Attempt to query NFTs with an invalid owner address
    let result = contract.get_locked_nfts_by_owner(invalid_owner.clone());
    assert!(result.is_err(), "Expected Err, but got Ok");
    assert_eq!(
        result.unwrap_err().to_string(),
        "Generic error: Querier contract error: Invalid address: Generic error: Error decoding bech32"
    );
}

#[test]
fn test_get_locked_nfts_by_owner_multiple_owners() {
    let app = App::default();
    let linkage_code_id = CodeId::store_code(&app);
    let cw721_base_code_id = app.app_mut().store_code(cw721_base_contract_mock());
    let admin = "admin".into_addr();
    let owner_1 = "owner_1".into_addr();
    let owner_2 = "owner_2".into_addr();
    let token_id_1 = "token_id_1".to_string();
    let token_id_2 = "token_id_2".to_string();
    let token_id_3 = "token_id_3".to_string();
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

    // Lock two NFTs for owner_1
    let result = contract
        .receive_nft(owner_1.clone(), token_id_1.clone(), msg_1.clone())
        .call(&cw721_base_contract_addr);
    assert!(result.is_ok(), "Expected Ok, but got Err");

    let result = contract
        .receive_nft(owner_1.clone(), token_id_2.clone(), msg_2.clone())
        .call(&cw721_base_contract_addr);
    assert!(result.is_ok(), "Expected Ok, but got Err");

    // Lock one NFT for owner_2
    let result = contract
        .receive_nft(owner_2.clone(), token_id_3.clone(), msg_1.clone())
        .call(&cw721_base_contract_addr);
    assert!(result.is_ok(), "Expected Ok, but got Err");

    // Retrieve NFTs for owner_1
    let result = contract.get_locked_nfts_by_owner(owner_1.clone());
    assert!(result.is_ok(), "Expected Ok, but got Err");
    let locked_nfts = result.unwrap();

    // Verify the retrieved NFTs for owner_1
    assert_eq!(locked_nfts.len(), 2);
    assert!(locked_nfts.iter().any(|nft| nft.token_id == token_id_1 && nft.did == Did::new(&did_1)));
    assert!(locked_nfts.iter().any(|nft| nft.token_id == token_id_2 && nft.did == Did::new(&did_2)));

    // Retrieve NFTs for owner_2
    let result = contract.get_locked_nfts_by_owner(owner_2.clone());
    assert!(result.is_ok(), "Expected Ok, but got Err");
    let locked_nfts = result.unwrap();

    // Verify the retrieved NFTs for owner_2
    assert_eq!(locked_nfts.len(), 1);
    assert!(locked_nfts.iter().any(|nft| nft.token_id == token_id_3 && nft.did == Did::new(&did_1)));
}