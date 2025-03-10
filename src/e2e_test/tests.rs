
use std::collections::HashMap;

use cosmrs::{crypto::secp256k1::SigningKey, proto::cosmos::bank::v1beta1::QueryBalanceResponse};
use cosmwasm_std::{to_base64, Addr, Binary, Coin, Decimal};
use cw721::{Cw721, Cw721ExecuteMsg, Cw721Query, Cw721QueryMsg};
use cw721_base::{ExecuteMsg, QueryMsg};
use serde_json::json;
use serial_test::serial;
use e2e_test_suite::{derive_private_key_from_mnemonic, error::CosmError, ContractInit, ADDR_PREFIX};

use crate::{responses::NftLockEntryResponse, state::NftLockEntry};


const CONTRACT_CREATOR_MNEMONIC: &str = "harbor flee number sibling doll recycle brisk mask blanket orphan initial maze race flash limb sound wing ramp proud battle feature ceiling feel miss";
const HD_PATH: &str = "m/44'/118'/0'/0/0";

const LINKAGE_CONTRACT_NAME: &str = "linkage";
const LINKAGE_CONTRACT_PATH: &str = "./target/wasm32-unknown-unknown/release/linkage_contract.wasm";

const CW721_BASE_CONTRACT_NAME: &str = "cw721_base";
// const CW721_BASE_CONTRACT_PATH: &str = "./../../external/cw-nfts/target/wasm32-unknown-unknown/release/cw721_base.wasm";
const CW721_BASE_CONTRACT_PATH: &str = "./../../external/cw-nfts/artifacts/cw721_base.wasm";




#[test]
#[serial]
fn test_add_admin() {
    init_suite();

    println!("RUN test_add_admin");
    let context = e2e_test_suite::get_context();
    
    let (key, address) = create_key_and_address();

    let wrong_admin_key = derive_private_key_from_mnemonic("dinosaur sound goddess cradle brush you mammal prize little bike surround actor frost edit off debris print correct knee photo fluid game mad same",    HD_PATH).expect("create key error");

    let escrow_contract_address = context.get_contracts_info().get(LINKAGE_CONTRACT_NAME).expect("no contract info").contract_address.clone();

    // ---- wrong admin

    let add_admin_msg = super::super::contract::sv::ExecMsg::AddAdmin { new_admin: "c4e13pq6693n69hfznt33u8d6zkszpy5nq4ucj0f5s".to_string() };
    
    let msg = json!(add_admin_msg).to_string();
    println!("Message: {msg}");

    let result = context.get_chain_client().tx.wasm().execute_contract_msg(&wrong_admin_key, &escrow_contract_address, &msg, vec![]);
    let err = result.err().unwrap();
    if let CosmError::TxBroadcastError(_, tx_result, _, _) = err {
        assert_eq!("failed to execute message; message index: 0: Unauthorized: execute wasm contract failed" , tx_result.log);

    } else {
        panic!("not TxBroadcastError");
    }
    // assert_eq!("Tx Bradcast Error", result.err().unwrap().to_string());
    // --- success
    let add_admin_msg = super::super::contract::sv::ExecMsg::AddAdmin { new_admin: "c4e13pq6693n69hfznt33u8d6zkszpy5nq4ucj0f5s".to_string() };
    
    let msg = json!(add_admin_msg).to_string();
    println!("Message: {msg}");

    let result = context.get_chain_client().tx.wasm().execute_contract_msg(&key, &escrow_contract_address, &msg, vec![]);
    assert!(result.is_ok(), "Expected Ok, but got an Err");

}

#[test]
#[serial]
fn test_full_linkage_process() {
    init_suite();
    println!("RUN full_linkage_process");

    let context = e2e_test_suite::get_context();

    let cw721_base_contract_address = context.get_contracts_info().get(CW721_BASE_CONTRACT_NAME).expect("no cw721_base contract info").contract_address.clone();
    let linkage_contract_address = context.get_contracts_info().get(LINKAGE_CONTRACT_NAME).expect("no linkage contract info").contract_address.clone();
    let (contract_admin_key, contract_admin_address) = create_key_and_address();
    let token_id = "C4E1".to_string();

    let did = "did_1233";
    let base64_encoded = to_base64(did);
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
        did: "did_1233".to_string(),
        sender: Addr::unchecked(contract_admin_address.clone()),
        contract_address: Addr::unchecked(cw721_base_contract_address.clone()),
        token_id: token_id.clone()
    };

    assert_eq!(expected_nft_lock_entry.clone(), nft_lock_entry);


    // ------ Get locked NFTs by DID

    let query_msg = super::super::contract::sv::QueryMsg::GetLockedNftsByDid { did: "did_1233".to_string() };
    let msg = json!(query_msg).to_string();
    let result = context.get_chain_client().query.wasm().contract(&linkage_contract_address.clone(), &msg);
    assert!(result.is_ok(), "Expected OK, but got an Err");

    let result = result.unwrap();
    let resp = String::from_utf8(result.clone().data).expect("Invalid UTF-8 sequence");
    println!("NftLockEntry: {resp}");
    let nft_lock_entry: Vec<NftLockEntryResponse> = serde_json::from_slice(&result.data).expect("Get NftLockedEntry response deserialization error");
    let expected_nft_lock_entry = vec![NftLockEntryResponse{ 
        did: "did_1233".to_string(),
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
        did: "did_1233".to_string(),
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


}

#[test]
#[serial]
fn my_test_2() {
    init_suite();
    println!("RUN TEST 2")
}

#[test]
#[serial]
fn my_test_3() {
    init_suite();
    // setup_context();
    println!("RUN TEST 3");
}

#[test]
fn my_test_4() {

    println!(r#"{{"admins": ["{}"], "did_contract": "{}"}}"#, 34, "DDDDDDDD");
}

fn init_suite() {
    let (owner_key, owner_addr) = create_key_and_address();

    let mut contracts: HashMap<String, ContractInit> = HashMap::new();
    // contracts.insert(LINKAGE_CONTRACT_NAME.into(), ContractInit { contract_path: LINKAGE_CONTRACT_PATH.to_string(), json_ncoded_init_args: format!(r#"{{"admins": ["{}"], "authorized_nft_contracts": ["{}"]}}"#, &owner_addr, &owner_addr), label: "linkage_contract".to_string() });
    contracts.insert(CW721_BASE_CONTRACT_NAME.into(), ContractInit { contract_path: CW721_BASE_CONTRACT_PATH.to_string(), json_ncoded_init_args: format!(r#"{{"name":"{}", "symbol":"{}"}}"#, "C4E_NFT_COLLECTION", "C4E"), label: "cw721_contract".to_string() });

    e2e_test_suite::init_suite(CONTRACT_CREATOR_MNEMONIC, HD_PATH, &contracts, "c4e-chain-linkage:v1.4.4", "linkage-contract", "linkage");

    let cw721_base_contract_address: String;
    {
        let context = e2e_test_suite::get_context();
        cw721_base_contract_address = context.get_contracts_info().get(CW721_BASE_CONTRACT_NAME).expect("no cw721-base contract info").contract_address.clone();
    }

    e2e_test_suite::add_contract(CONTRACT_CREATOR_MNEMONIC, HD_PATH, LINKAGE_CONTRACT_NAME, 
        ContractInit {
            contract_path: LINKAGE_CONTRACT_PATH.to_string(), 
            json_ncoded_init_args: format!(r#"{{"admins": ["{}"], "authorized_nft_contracts": ["{}"]}}"#, &owner_addr, cw721_base_contract_address), 
            label: "linkage_contract".to_string()
        }
    );
    // let context: std::sync::RwLockReadGuard<'_, e2e_test_suite::TestSuiteContextInternal> = e2e_test_suite::get_context();
}

fn create_key_and_address() -> (SigningKey, String){
    create_key_and_address_from_mnemonic(CONTRACT_CREATOR_MNEMONIC)
}

fn create_key_and_address_from_mnemonic(mnemonic: &str) -> (SigningKey, String){
    let key = derive_private_key_from_mnemonic(mnemonic,    HD_PATH).expect("create key error");
    let address = key.public_key().account_id(ADDR_PREFIX).expect("cannot create address").to_string();
    (key, address)
}
