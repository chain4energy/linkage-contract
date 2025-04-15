
use std::{thread::sleep, time::Duration};
use cosmwasm_std::Addr;
use serde_json::json;
use serial_test::serial;
use e2e_test_suite::{derive_private_key_from_mnemonic, error::CosmError, teardown_suite};

use crate::e2e_test::tests::{init_suite, create_key_and_address, LINKAGE_CONTRACT_NAME, HD_PATH};


#[test]
#[serial]
fn test_add_admin_success() {
    init_suite();

    println!("RUN test_add_admin");
    let context = e2e_test_suite::get_context();
    
    let (key, owner) = create_key_and_address();

    // let wrong_admin_key = derive_private_key_from_mnemonic("dinosaur sound goddess cradle brush you mammal prize little bike surround actor frost edit off debris print correct knee photo fluid game mad same",    HD_PATH).expect("create key error");

    let linkage_contract_address = context.get_contracts_info().get(LINKAGE_CONTRACT_NAME).expect("no contract info").contract_address.clone();

    // --- success
    let add_admin_msg = super::super::contract::sv::ExecMsg::AddAdmin { new_admin: "c4e13pq6693n69hfznt33u8d6zkszpy5nq4ucj0f5s".to_string() };
    
    let add_admin_msg = json!(add_admin_msg).to_string();
    println!("Message: {add_admin_msg}");

    let result = context.get_chain_client().tx.wasm().execute_contract_msg(&key, &linkage_contract_address, &add_admin_msg, vec![]);
    assert!(result.is_ok(), "Expected Ok, but got an Err");

    sleep(Duration::from_secs(5));

    let get_admin_msg = super::super::contract::sv::QueryMsg::GetAdmins{};
    
    let get_admin_msg = json!(get_admin_msg).to_string();
    println!("Message: {get_admin_msg}");

    let result = context.get_chain_client().query.wasm().contract(&linkage_contract_address, &get_admin_msg);
    assert!(result.is_ok(), "Expected Ok, but got an Err");

    teardown_suite();

    // json deserialize
    let result: Vec<Addr> = serde_json::from_slice(&result.unwrap().data).unwrap();
    assert_eq!(result.len(), 2);
    assert_eq!(result[0].to_string(), owner);
    assert_eq!(result[1].to_string(), "c4e13pq6693n69hfznt33u8d6zkszpy5nq4ucj0f5s".to_string());

    
}


#[test]
#[serial]
fn test_add_admin_unauthorized() {
    init_suite();

    println!("RUN test_add_admin");
    let context = e2e_test_suite::get_context();
    
    let (_key, owner) = create_key_and_address();

    let wrong_admin_key = derive_private_key_from_mnemonic("dinosaur sound goddess cradle brush you mammal prize little bike surround actor frost edit off debris print correct knee photo fluid game mad same",    HD_PATH).expect("create key error");

    let linkage_contract_address = context.get_contracts_info().get(LINKAGE_CONTRACT_NAME).expect("no contract info").contract_address.clone();

    // ---- wrong admin

    let add_admin_msg = super::super::contract::sv::ExecMsg::AddAdmin { new_admin: "c4e13pq6693n69hfznt33u8d6zkszpy5nq4ucj0f5s".to_string() };
    
    let msg = json!(add_admin_msg).to_string();
    println!("Message: {msg}");

    let result = context.get_chain_client().tx.wasm().execute_contract_msg(&wrong_admin_key, &linkage_contract_address, &msg, vec![]);
    let err = result.err().unwrap();
    if let CosmError::TxBroadcastError(_, tx_result, _, _) = err {
        assert_eq!("failed to execute message; message index: 0: Unauthorized: Sender is not an admin: execute wasm contract failed" , tx_result.log);

    } else {
        panic!("not TxBroadcastError");
    }

    sleep(Duration::from_secs(5));

    let get_admin_msg = super::super::contract::sv::QueryMsg::GetAdmins{};
    
    let get_admin_msg = json!(get_admin_msg).to_string();
    println!("Message: {get_admin_msg}");

    let result = context.get_chain_client().query.wasm().contract(&linkage_contract_address, &get_admin_msg);
    assert!(result.is_ok(), "Expected Ok, but got an Err");

    teardown_suite();

    // json deserialize
    let result: Vec<Addr> = serde_json::from_slice(&result.unwrap().data).unwrap();
    assert_eq!(result.len(), 1);
    assert_eq!(result[0].to_string(), owner);
    // assert_eq!(result[1].to_string(), "c4e13pq6693n69hfznt33u8d6zkszpy5nq4ucj0f5s".to_string());
}