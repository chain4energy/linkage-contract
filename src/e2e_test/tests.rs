
use std::collections::HashMap;

use cosmrs::crypto::secp256k1::SigningKey;
use e2e_test_suite::{derive_private_key_from_mnemonic, ContractInit, ADDR_PREFIX};



const CONTRACT_CREATOR_MNEMONIC: &str = "harbor flee number sibling doll recycle brisk mask blanket orphan initial maze race flash limb sound wing ramp proud battle feature ceiling feel miss";
pub const HD_PATH: &str = "m/44'/118'/0'/0/0";

pub const LINKAGE_CONTRACT_NAME: &str = "linkage";
const LINKAGE_CONTRACT_PATH: &str = "./target/wasm32-unknown-unknown/release/linkage_contract.wasm";

pub const CW721_BASE_CONTRACT_NAME: &str = "cw721_base";
const CW721_BASE_CONTRACT_PATH: &str = "./src/e2e_test/resources/cw721_base.wasm";

const CW721_TEST_CONTRACT_PATH: &str = "./src/e2e_test/resources/cw721_test_contract.wasm";

pub fn init_suite() {
    init_suite_with_cw721_contract(CW721_BASE_CONTRACT_PATH, format!(r#"{{"name":"{}", "symbol":"{}"}}"#, "C4E_NFT_COLLECTION", "C4E").as_str());
}

pub fn init_suite_cw721_expiration() {
    init_suite_with_cw721_contract(CW721_TEST_CONTRACT_PATH, format!(r#"{{"expiration_seconds": {}, "name":"{}", "symbol":"{}"}}"#, 20, "C4E_NFT_COLLECTION", "C4E").as_str());
}

pub fn init_suite_with_cw721_contract(path: &str, init_args: &str) {
    let (_owner_key, owner_addr) = create_key_and_address();

    let mut contracts: HashMap<String, ContractInit> = HashMap::new();
    // contracts.insert(LINKAGE_CONTRACT_NAME.into(), ContractInit { contract_path: LINKAGE_CONTRACT_PATH.to_string(), json_ncoded_init_args: format!(r#"{{"admins": ["{}"], "authorized_nft_contracts": ["{}"]}}"#, &owner_addr, &owner_addr), label: "linkage_contract".to_string() });
    contracts.insert(CW721_BASE_CONTRACT_NAME.into(), ContractInit { contract_path: path.to_string(), json_ncoded_init_args: init_args.to_string(), label: "cw721_contract".to_string() });
    
    e2e_test_suite::init_suite(CONTRACT_CREATOR_MNEMONIC, HD_PATH, &contracts, "c4e-chain-linkage:v1.4.4", "linkage-contract", "linkage", "chain-node-linkage");

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


pub fn create_key_and_address() -> (SigningKey, String){
    create_key_and_address_from_mnemonic(CONTRACT_CREATOR_MNEMONIC)
}

pub fn create_key_and_address_from_mnemonic(mnemonic: &str) -> (SigningKey, String){
    let key = derive_private_key_from_mnemonic(mnemonic,    HD_PATH).expect("create key error");
    let address = key.public_key().account_id(ADDR_PREFIX).expect("cannot create address").to_string();
    (key, address)
}
