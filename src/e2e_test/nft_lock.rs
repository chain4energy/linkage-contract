
use cosmwasm_std::{to_base64, Addr};

use cw721_base::{ExecuteMsg, QueryMsg};
use did_contract::state::{Did, DID_PREFIX};

use serde_json::json;
use serial_test::serial;
use e2e_test_suite::teardown_suite;

use crate::e2e_test::tests::{create_key_and_address, init_suite, CW721_BASE_CONTRACT_NAME, LINKAGE_CONTRACT_NAME};
use crate::responses::NftLockEntryResponse;


#[test]
#[serial]
fn test_full_linkage_process() {
    init_suite();
    println!("RUN full_linkage_process");

    let context: std::sync::RwLockReadGuard<'_, e2e_test_suite::TestSuiteContextInternal> = e2e_test_suite::get_context();

    let cw721_base_contract_address = context.get_contracts_info().get(CW721_BASE_CONTRACT_NAME).expect("no cw721_base contract info").contract_address.clone();
    let linkage_contract_address = context.get_contracts_info().get(LINKAGE_CONTRACT_NAME).expect("no linkage contract info").contract_address.clone();
    let (contract_admin_key, contract_admin_address) = create_key_and_address();
    let token_id = "C4E1".to_string();

    // let did = "did_1233";
    let did = format!("{}address", DID_PREFIX);

    let base64_encoded = to_base64(did.clone());
    println!("Base64 Encoded: {}", base64_encoded);
    // let did_binary = cosmwasm_std::Binary::from_base64(&base64_encoded).expect("Base64 decode failed");
    // println!("Binary: {:?}", did_binary);


    // ------ Mint NFT in cw721_base contract

    let exec_msg: ExecuteMsg<(), ()> = cw721_base::msg::ExecuteMsg::Mint { token_id: token_id.clone(), owner: contract_admin_address.clone(), extension: (), token_uri: None };
    let msg = json!(exec_msg).to_string();
    let result = context.get_chain_client().tx.wasm().execute_contract_msg(&contract_admin_key, &cw721_base_contract_address.clone(), &msg, vec![]);
    assert!(result.is_ok(), "Expected OK, but go an Err");


    // ------ Check owner of NFT in cw721_base contract

    let exec_msg: QueryMsg<()> = cw721_base::msg::QueryMsg::OwnerOf { token_id: token_id.clone(), include_expired: None };
    let msg = json!(exec_msg).to_string();

    let result = context.get_chain_client().query.wasm().contract(&cw721_base_contract_address.clone(), &msg);

    assert!(result.is_ok(), "Expected OK, but go an Err");
    let result = result.unwrap();
    let resp = String::from_utf8(result.clone().data).expect("Invalid UTF-8 sequence");
    println!("Cw721 owner of resp: {resp}");

    let owner_of: cw721::OwnerOfResponse = serde_json::from_slice(&result.data).expect("Get owner of response deserialization error");
    let expected_owner_of = cw721::OwnerOfResponse {
        approvals: vec![],
        owner: contract_admin_address.clone()
    };

    assert_eq!(expected_owner_of, owner_of);


    // ------ Send NFT from cw721 to linkage   

    // TODO: check coswasm_std binary type conflict between linkage and cw721_base
    let msg = format!(r#"{{"send_nft":{{"contract":"{}", "token_id":"{}", "msg":"{}"}}}}"#, linkage_contract_address.clone(), token_id.clone(), base64_encoded.to_string());
    // let exec_msg: ExecuteMsg<(), ()> = cw721_base::msg::ExecuteMsg::SendNft { contract: linkage_contract_address.clone(), token_id: token_id.clone(), msg: did_binary };
    let result = context.get_chain_client().tx.wasm().execute_contract_msg(&contract_admin_key, &cw721_base_contract_address.clone(), &msg, vec![]);
    assert!(result.is_ok(), "Expected OK, but go an Err");
    let result = result.unwrap();
    let resp = String::from_utf8(result.clone().data).expect("Invalid UTF-8 sequence");
    println!("Send NFT resp: {resp}");


    // ------ Check owner after transfering NFT to linkage
    
    let exec_msg: QueryMsg<()> = cw721_base::msg::QueryMsg::OwnerOf { token_id: token_id.clone(), include_expired: None };
    let msg = json!(exec_msg).to_string();

    let result = context.get_chain_client().query.wasm().contract(&cw721_base_contract_address.clone(), &msg);

    assert!(result.is_ok(), "Expected OK, but go an Err");
    let result = result.unwrap();
    let resp = String::from_utf8(result.clone().data).expect("Invalid UTF-8 sequence");
    println!("Cw721 owner of resp: {resp}");

    let owner_of: cw721::OwnerOfResponse = serde_json::from_slice(&result.data).expect("Get owner of response deserialization error");
    let expected_owner_of = cw721::OwnerOfResponse {
        approvals: vec![],
        owner: linkage_contract_address.clone()
    };

    assert_eq!(expected_owner_of, owner_of);


    // ------ Get authorized contracts

    let query_msg = super::super::contract::sv::QueryMsg::GetAuthorizedNftContracts {  };

    let msg = json!(query_msg).to_string();
    let result = context.get_chain_client().query.wasm().contract(&linkage_contract_address.clone(), &msg);
    assert!(result.is_ok(), "Expected OK, but got an Err");

    let result = result.unwrap();
    let resp = String::from_utf8(result.clone().data).expect("Invalid UTF-8 sequence");
    println!("Authorized contracts: {resp}");
    let authorized_contracts: Vec<Addr> = serde_json::from_slice(&result.data).expect("Get Authorized Contracts response deserialization error");
    let expected_authorized_contracts = vec![Addr::unchecked(cw721_base_contract_address.clone())];

    assert_eq!(expected_authorized_contracts.clone(), authorized_contracts);


    // ------ Get locked NFT by token_id

    let query_msg = super::super::contract::sv::QueryMsg::GetLockedNft { contract_address: Addr::unchecked(cw721_base_contract_address.clone()), token_id: token_id.clone() };
    let msg = json!(query_msg).to_string();
    let result = context.get_chain_client().query.wasm().contract(&linkage_contract_address.clone(), &msg);
    assert!(result.is_ok(), "Expected OK, but got an Err");

    let result = result.unwrap();
    let resp = String::from_utf8(result.clone().data).expect("Invalid UTF-8 sequence");
    println!("NftLockEntry: {resp}");
    let nft_lock_entry: NftLockEntryResponse = serde_json::from_slice(&result.data).expect("Get NftLockedEntry response deserialization error");
    let expected_nft_lock_entry = NftLockEntryResponse{ 
        did: Did::new(&did.clone()),
        sender: Addr::unchecked(contract_admin_address.clone()),
        contract_address: Addr::unchecked(cw721_base_contract_address.clone()),
        token_id: token_id.clone()
    };

    assert_eq!(expected_nft_lock_entry.clone(), nft_lock_entry);


    // ------ Get locked NFTs by DID

    let query_msg = super::super::contract::sv::QueryMsg::GetLockedNftsByDid { did: Did::new(&did.clone()) };
    let msg = json!(query_msg).to_string();
    let result = context.get_chain_client().query.wasm().contract(&linkage_contract_address.clone(), &msg);
    assert!(result.is_ok(), "Expected OK, but got an Err");

    let result = result.unwrap();
    let resp = String::from_utf8(result.clone().data).expect("Invalid UTF-8 sequence");
    println!("NftLockEntry: {resp}");
    let nft_lock_entry: Vec<NftLockEntryResponse> = serde_json::from_slice(&result.data).expect("Get NftLockedEntry response deserialization error");
    let expected_nft_lock_entry = vec![NftLockEntryResponse{ 
        did: Did::new(&did.clone()),
        sender: Addr::unchecked(contract_admin_address.clone()),
        contract_address: Addr::unchecked(cw721_base_contract_address.clone()),
        token_id: token_id.clone()
    }];

    assert_eq!(expected_nft_lock_entry.clone(), nft_lock_entry);


    // ------ Get locked NFTs by owner

    let query_msg = super::super::contract::sv::QueryMsg::GetLockedNftsByOwner { owner: Addr::unchecked(contract_admin_address.clone()) };
    let msg = json!(query_msg).to_string();
    let result = context.get_chain_client().query.wasm().contract(&linkage_contract_address.clone(), &msg);
    assert!(result.is_ok(), "Expected OK, but got an Err");

    let result = result.unwrap();
    let resp = String::from_utf8(result.clone().data).expect("Invalid UTF-8 sequence");
    println!("NftLockEntry: {resp}");
    let nft_lock_entry: Vec<NftLockEntryResponse> = serde_json::from_slice(&result.data).expect("Get NftLockedEntry response deserialization error");
    let expected_nft_lock_entry = vec![NftLockEntryResponse{ 
        did: Did::new(&did.clone()),
        sender: Addr::unchecked(contract_admin_address.clone()),
        contract_address: Addr::unchecked(cw721_base_contract_address.clone()),
        token_id: token_id.clone()
    }];

    assert_eq!(expected_nft_lock_entry.clone(), nft_lock_entry);

    
    // ------ Unlock NFT
    
    let query_msg = format!(r#"{{"unlock_nft":{{"contract_address":"{}", "token_id":"{}"}}}}"#, cw721_base_contract_address.clone(), token_id.clone());
    let result = context.get_chain_client().tx.wasm().execute_contract_msg(&contract_admin_key, &linkage_contract_address.clone(), &query_msg, vec![]);
    assert!(result.is_ok(), "Expected OK, but go an Err");
    
    // ------ Last NFT owner check in cw721_base contract

    let exec_msg: QueryMsg<()> = cw721_base::msg::QueryMsg::OwnerOf { token_id: token_id.clone(), include_expired: None };
    let msg = json!(exec_msg).to_string();
   
    let result = context.get_chain_client().query.wasm().contract(&cw721_base_contract_address.clone(), &msg);
   
    assert!(result.is_ok(), "Expected OK, but go an Err");
    let result = result.unwrap();
    let resp = String::from_utf8(result.clone().data).expect("Invalid UTF-8 sequence");
    println!("Cw721 owner of resp: {resp}");
   
    let owner_of: cw721::OwnerOfResponse = serde_json::from_slice(&result.data).expect("Get owner of response deserialization error");
    let expected_owner_of = cw721::OwnerOfResponse {
        approvals: vec![],
        owner: contract_admin_address.clone()
    };
   
    assert_eq!(expected_owner_of, owner_of);
    teardown_suite();

}
