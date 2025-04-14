use crate::contract::sv::mt::{CodeId, LinkageContractProxy};
use crate::error::ContractError;
use crate::responses::NftLockEntryResponse;
use cosmwasm_std::{to_json_binary, Addr, Binary, Empty, Response, StdResult};
use cw721::{Cw721ExecuteMsg, Cw721QueryMsg};
use cw_multi_test::{Contract, ContractWrapper, Executor, IntoAddr};
use did_contract::state::{Did, DID_PREFIX};
use sylvia::multitest::App;

#[test]
fn receive_nft_and_get_locked_nfts() {
    let app = App::default();
    let code_id = CodeId::store_code(&app);
    let admin = "admin".into_addr();

    let owner = "owner".into_addr();
    let auth_address = "cw721_address".into_addr();
    let contract = code_id
        .instantiate(vec![admin.clone()], vec![auth_address.clone()])
        .call(&owner)
        .unwrap();

    let sender = "sender_address".into_addr();
    let token_id = String::from("token_id");
    let token_id_2 = String::from("token_id_2");
    let did = format!("{}address", DID_PREFIX);
    let msg = Binary::new(did.as_bytes().to_vec());

    let result = contract.get_locked_nft(auth_address.clone(), token_id.clone());
    assert!(result.is_err(), "Expected Err, but got Ok");
    // assert_eq!(
    //     result.unwrap_err(),
    //     ContractError::UnauthorizedContractError
    // );

    let result = contract
        .receive_nft(sender.clone(), token_id.clone(), msg.clone())
        .call(&auth_address);
    // assert_eq!(
    //     result.unwrap_err(),
    //     ContractError::DidInvalid(())
    // );
    assert!(result.is_ok(), "Expected Ok, but got Err");

    let result = contract.get_locked_nft(auth_address.clone(), token_id.clone());
    assert!(result.is_ok(), "Expected Ok, but got Err");
    let expcted_nft = NftLockEntryResponse {
        contract_address: auth_address.clone(),
        token_id: token_id.clone(),
        sender: sender.clone(),
        did: Did::new(&String::from_utf8(msg.to_vec()).unwrap()),
    };
    assert_eq!(expcted_nft.clone(), result.unwrap());

    let result = contract.get_locked_nfts_by_did(Did::new(&did));
    assert!(result.is_ok(), "Expected Ok, but go an Err");
    let result = result.unwrap();
    assert_eq!(result.len(), 1);

    assert_eq!(expcted_nft.clone(), result[0]);

    let result = contract.get_locked_nfts_by_owner(sender.clone());
    assert!(result.is_ok(), "Expected Ok, but go an Err");
    let result = result.unwrap();
    assert_eq!(result.len(), 1);

    assert_eq!(expcted_nft.clone(), result[0]);

    let unauth_address = "unauth_address".into_addr();

    let result = contract
        .receive_nft(sender.clone(), token_id_2.clone(), msg.clone())
        .call(&unauth_address);
    assert!(result.is_err(), "Expected Err, but got Ok");

    assert_eq!(
        result.unwrap_err(),
        ContractError::UnauthorizedContractError
    );

    let result = contract.get_locked_nft(unauth_address, token_id_2.clone());
    assert!(result.is_err(), "Expected Err, but got Ok");

    let result = contract.get_locked_nft(auth_address.clone(), token_id_2.clone());
    assert!(result.is_err(), "Expected Err, but got Ok");

    let result = contract
        .receive_nft(sender.clone(), token_id_2.clone(), msg.clone())
        .call(&auth_address);
    assert!(result.is_ok(), "Expected Ok, but got Err");

    let result = contract.get_locked_nft(auth_address.clone(), token_id_2.clone());
    assert!(result.is_ok(), "Expected Ok, but got Err");
    let expcted_nft_2 = NftLockEntryResponse {
        contract_address: auth_address.clone(),
        token_id: token_id_2.clone(),
        sender: sender.clone(),
        did: Did::new(&String::from_utf8(msg.to_vec()).unwrap()),
    };
    assert_eq!(expcted_nft_2.clone(), result.unwrap());

    let result = contract.get_locked_nfts_by_did(Did::new(&did));
    assert!(result.is_ok(), "Expected Ok, but go an Err");
    let result = result.unwrap();
    assert_eq!(result.len(), 2);

    assert_eq!(expcted_nft.clone(), result[0]);
    assert_eq!(expcted_nft_2.clone(), result[1]);

    let result = contract.get_locked_nfts_by_owner(sender.clone());
    assert!(result.is_ok(), "Expected Ok, but go an Err");
    let result = result.unwrap();
    assert_eq!(result.len(), 2);

    assert_eq!(expcted_nft.clone(), result[0]);
    assert_eq!(expcted_nft_2.clone(), result[1]);
}

#[test]
fn test_receive_nft_success() {
    let app = App::default();
    let code_id = CodeId::store_code(&app);
    let admin = "admin".into_addr();
    let sender = "sender_address".into_addr();
    let token_id = "token_id".to_string();
    let did = format!("{}address", DID_PREFIX);
    let msg = Binary::from(did.as_bytes());

    let auth_address = "auth_contract".into_addr();
    let contract = code_id
        .instantiate(vec![admin.clone()], vec![auth_address.clone()])
        .call(&admin)
        .unwrap();

    let result = contract
        .receive_nft(sender.clone(), token_id.clone(), msg.clone())
        .call(&auth_address);

    assert!(result.is_ok(), "Expected Ok, but got Err");
    let res = result.unwrap();

    assert_eq!(res.events.len(), 3);

    // Verify event attributes
    assert_eq!(res.events[0].ty, "execute");
    assert_eq!(res.events[0].attributes[0].key, "_contract_address");
    assert_eq!(res.events[0].attributes[0].value, "cosmwasm1mzdhwvvh22wrt07w59wxyd58822qavwkx5lcej7aqfkpqqlhaqfsgn6fq2");
    assert_eq!(res.events[0].attributes.len(), 1);
 
    assert_eq!(res.events[1].ty, "wasm");
    assert_eq!(res.events[1].attributes[0].key, "_contract_address");
    assert_eq!(res.events[1].attributes[0].value, "cosmwasm1mzdhwvvh22wrt07w59wxyd58822qavwkx5lcej7aqfkpqqlhaqfsgn6fq2");
    assert_eq!(res.events[1].attributes[1].key, "action");
    assert_eq!(res.events[1].attributes[1].value, "receive_nft");
    assert_eq!(res.events[1].attributes[2].key, "sender");
    assert_eq!(res.events[1].attributes[2].value, sender.to_string());
    assert_eq!(res.events[1].attributes[3].key, "token_id");
    assert_eq!(res.events[1].attributes[3].value, token_id);
    assert_eq!(res.events[1].attributes[4].key, "did");
    assert_eq!(res.events[1].attributes[4].value, did);
    assert_eq!(res.events[1].attributes.len(), 5);
    
    assert_eq!(res.events[2].ty, "wasm-receive_nft");
    assert_eq!(res.events[2].attributes[0].key, "_contract_address");
    assert_eq!(res.events[2].attributes[0].value, "cosmwasm1mzdhwvvh22wrt07w59wxyd58822qavwkx5lcej7aqfkpqqlhaqfsgn6fq2");
    assert_eq!(res.events[2].attributes[1].key, "executor");
    assert_eq!(res.events[2].attributes[1].value, "cosmwasm1dfannzw0pjczc5wlth2zek3lzdwvxmrh9uvpmw40jgakkds2sm4qle8aws");
    assert_eq!(res.events[2].attributes[2].key, "sender");
    assert_eq!(res.events[2].attributes[2].value, sender.to_string());

    assert_eq!(res.events[2].attributes[3].key, "token_id");
    assert_eq!(res.events[2].attributes[3].value, token_id);
    assert_eq!(res.events[2].attributes[4].key, "did");
    assert_eq!(res.events[2].attributes[4].value, did);
    assert_eq!(res.events[2].attributes.len(), 5);

}

#[test]
fn test_receive_nft_unauthorized_contract() {
    let app = App::default();
    let code_id = CodeId::store_code(&app);
    let admin = "admin".into_addr();
    let sender = "sender_address".into_addr();
    let token_id = "token_id".to_string();
    let did = format!("{}address", DID_PREFIX);
    let msg = Binary::from(did.as_bytes());

    let auth_address = "auth_contract".into_addr();
    let unauthorized_address = "unauth_contract".into_addr();
    let contract = code_id
        .instantiate(vec![admin.clone()], vec![auth_address.clone()])
        .call(&admin)
        .unwrap();

    let result = contract
        .receive_nft(sender.clone(), token_id.clone(), msg.clone())
        .call(&unauthorized_address);

    assert!(result.is_err(), "Expected Err, but got Ok");
    assert_eq!(
        result.unwrap_err(),
        ContractError::UnauthorizedContractError
    );
}

#[test]
fn test_receive_nft_invalid_did() {
    let app = App::default();
    let code_id = CodeId::store_code(&app);
    let admin = "admin".into_addr();
    let sender = "sender_address".into_addr();
    let token_id = "token_id".to_string();
    let invalid_did = "invalid_did";
    let msg = Binary::from(invalid_did.as_bytes());

    let auth_address = "auth_contract".into_addr();
    let contract = code_id
        .instantiate(vec![admin.clone()], vec![auth_address.clone()])
        .call(&admin)
        .unwrap();

    let result = contract
        .receive_nft(sender.clone(), token_id.clone(), msg.clone())
        .call(&auth_address);

    assert!(result.is_err(), "Expected Err, but got Ok");
    assert_eq!(
        result.unwrap_err(),
        ContractError::DidInvalid(did_contract::error::ContractError::DidFormatError())
    );
}

#[test]
fn test_receive_nft_duplicate_token_id() {
    let app = App::default();
    let code_id = CodeId::store_code(&app);
    let admin = "admin".into_addr();
    let sender = "sender_address".into_addr();
    let token_id = "token_id".to_string();
    let did = format!("{}address", DID_PREFIX);
    let msg = Binary::from(did.as_bytes());

    let auth_address = "auth_contract".into_addr();
    let contract = code_id
        .instantiate(vec![admin.clone()], vec![auth_address.clone()])
        .call(&admin)
        .unwrap();

    // First call should succeed
    let result = contract
        .receive_nft(sender.clone(), token_id.clone(), msg.clone())
        .call(&auth_address);
    assert!(result.is_ok(), "Expected Ok, but got Err");

    // Second call with the same token ID should fail
    let result = contract
        .receive_nft(sender.clone(), token_id.clone(), msg.clone())
        .call(&auth_address);
    assert!(result.is_err(), "Expected Err, but got Ok");
    assert_eq!(
        result.unwrap_err(),
        ContractError::AlreadyExists(format!(
            "NFT already locked: {}:{}",
            auth_address, token_id
        ))
    );
}

#[test]
fn test_receive_nft_empty_token_id() {
    let app = App::default();
    let code_id = CodeId::store_code(&app);
    let admin = "admin".into_addr();
    let sender = "sender_address".into_addr();
    let token_id = "".to_string();
    let did = format!("{}address", DID_PREFIX);
    let msg = Binary::from(did.as_bytes());

    let auth_address = "auth_contract".into_addr();
    let contract = code_id
        .instantiate(vec![admin.clone()], vec![auth_address.clone()])
        .call(&admin)
        .unwrap();

    let result = contract
        .receive_nft(sender.clone(), token_id.clone(), msg.clone())
        .call(&auth_address);

    assert!(result.is_err(), "Expected Err, but got Ok");
    assert_eq!(result.unwrap_err(), ContractError::NoTokenId);
}

#[test]
fn test_receive_nft_invalid_contract_address() {
    let app = App::default();
    let code_id = CodeId::store_code(&app);
    let admin = "admin".into_addr();
    let sender = "sender_address".into_addr();
    let token_id = "token_id".to_string();
    let did = format!("{}address", DID_PREFIX);
    let msg = Binary::from(did.as_bytes());

    let invalid_address = Addr::unchecked("invalid_address");
    let contract = code_id
        .instantiate(vec![admin.clone()], vec![invalid_address.clone()])
        .call(&admin)
        .unwrap();

    let result = contract
        .receive_nft(sender.clone(), token_id.clone(), msg.clone())
        .call(&invalid_address);

    assert!(result.is_err(), "Expected Err, but got Ok");
    assert_eq!(
        result.err().unwrap().to_string(),
        "Invalid contract address: Generic error: Error decoding bech32",
        "Expected 'Invalid address' error"
    );
    // assert_eq!(
    //     result.unwrap_err(),
    //     ContractError::InvalidContractAddress()
    // );
}

#[test]
fn test_receive_multiple_nfts_for_one_owner() {
    let app = App::default();
    let code_id = CodeId::store_code(&app);
    let admin = "admin".into_addr();
    let owner1 = "owner_address_1".into_addr(); // Single owner
    let owner2 = "owner_address_2".into_addr(); // Single owner

    let auth_address = "auth_contract".into_addr();
    let contract = code_id
        .instantiate(vec![admin.clone()], vec![auth_address.clone()])
        .call(&admin)
        .unwrap();

    // Define multiple token IDs with different DIDs
    let token_ids = vec!["token_id_1".to_string(), "token_id_2".to_string(), "token_id_3".to_string()];
    let dids = vec![
        format!("{}did1", DID_PREFIX),
        format!("{}did2", DID_PREFIX),
        format!("{}did3", DID_PREFIX),
    ];

    // Receive multiple NFTs for the same owner
    for (token_id, did) in token_ids.iter().zip(dids.iter()) {
        let msg = Binary::from(did.as_bytes());
        let result = contract
            .receive_nft(owner1.clone(), token_id.clone(), msg.clone())
            .call(&auth_address);
        assert!(result.is_ok(), "Expected Ok, but got Err for token_id: {}", token_id);
    }

    let token_ids_other_owner = vec!["token_id_101".to_string(), "token_id_102".to_string(), "token_id_103".to_string()];
    let dids_other_owner = vec![
        format!("{}did101", DID_PREFIX),
        format!("{}did102", DID_PREFIX),
        format!("{}did103", DID_PREFIX),
    ];

    for (token_id, did) in token_ids_other_owner.iter().zip(dids_other_owner.iter()) {
        let msg = Binary::from(did.as_bytes());
        let result = contract
            .receive_nft(owner2.clone(), token_id.clone(), msg.clone())
            .call(&auth_address);
        assert!(result.is_ok(), "Expected Ok, but got Err for token_id: {}", token_id);
    }

    // Verify that all NFTs are linked to the owner
    let result = contract.get_locked_nfts_by_owner(owner1.clone());
    assert!(result.is_ok(), "Expected Ok, but got Err");
    let locked_nfts = result.unwrap();
    assert_eq!(locked_nfts.len(), token_ids.len(), "Expected {} NFTs, but got {}", token_ids.len(), locked_nfts.len());

    for (i, nft) in locked_nfts.iter().enumerate() {
        assert_eq!(nft.contract_address, auth_address);
        assert_eq!(nft.token_id, token_ids[i]);
        assert_eq!(nft.sender, owner1);
        assert_eq!(nft.did, Did::new(&dids[i]));
    }

    let result = contract.get_locked_nfts_by_owner(owner2.clone());
    assert!(result.is_ok(), "Expected Ok, but got Err");
    let locked_nfts = result.unwrap();
    assert_eq!(locked_nfts.len(), token_ids_other_owner.len(), "Expected {} NFTs, but got {}", token_ids_other_owner.len(), locked_nfts.len());

    for (i, nft) in locked_nfts.iter().enumerate() {
        assert_eq!(nft.contract_address, auth_address);
        assert_eq!(nft.token_id, token_ids_other_owner[i]);
        assert_eq!(nft.sender, owner2);
        assert_eq!(nft.did, Did::new(&dids_other_owner[i]));
    }

    // Verify unrelated owner gets no NFTs
    let unrelated_owner = "unrelated_owner".into_addr();
    let result = contract.get_locked_nfts_by_owner(unrelated_owner);
    assert!(result.is_ok(), "Expected Ok, but got Err for unrelated owner");
    let locked_nfts = result.unwrap();
    assert_eq!(locked_nfts.len(), 0, "Expected 0 NFTs, but got {}", locked_nfts.len());
}


#[test]
fn test_receive_multiple_nfts_for_one_did() {
    let app = App::default();
    let code_id = CodeId::store_code(&app);
    let admin = "admin".into_addr();
    let auth_address = "auth_contract".into_addr();
    let contract = code_id
        .instantiate(vec![admin.clone()], vec![auth_address.clone()])
        .call(&admin)
        .unwrap();

    // Define multiple token IDs with different owners but the same DID
    let token_ids = vec!["token_id_1".to_string(), "token_id_2".to_string(), "token_id_3".to_string()];
    let owners = vec![
        "owner_1".into_addr(),
        "owner_2".into_addr(),
        "owner_3".into_addr(),
    ];
    let did1 = format!("{}shared_did", DID_PREFIX); // Single DID
    let msg = Binary::from(did1.as_bytes());

    // Receive multiple NFTs for the same DID
    for (token_id, owner) in token_ids.iter().zip(owners.iter()) {
        let result = contract
            .receive_nft(owner.clone(), token_id.clone(), msg.clone())
            .call(&auth_address);
        assert!(result.is_ok(), "Expected Ok, but got Err for token_id: {}", token_id);
    }



    let token_ids_did2 = vec!["token_id_101".to_string(), "token_id_102".to_string(), "token_id_103".to_string()];
    let did2 = format!("{}shared_did2", DID_PREFIX); // Single DID
    let msg = Binary::from(did2.as_bytes());

    // Receive multiple NFTs for the same DID
    for (token_id, owner) in token_ids_did2.iter().zip(owners.iter()) {
        let result = contract
            .receive_nft(owner.clone(), token_id.clone(), msg.clone())
            .call(&auth_address);
        assert!(result.is_ok(), "Expected Ok, but got Err for token_id: {}", token_id);
    }

    // Verify that all NFTs are linked to the DID
    let result = contract.get_locked_nfts_by_did(Did::new(&did1));
    assert!(result.is_ok(), "Expected Ok, but got Err");
    let locked_nfts = result.unwrap();
    assert_eq!(locked_nfts.len(), token_ids.len(), "Expected {} NFTs, but got {}", token_ids.len(), locked_nfts.len());

    for (i, nft) in locked_nfts.iter().enumerate() {
        assert_eq!(nft.contract_address, auth_address);
        assert_eq!(nft.token_id, token_ids[i]);
        assert_eq!(nft.sender, owners[i]);
        assert_eq!(nft.did, Did::new(&did1));
    }


    let result = contract.get_locked_nfts_by_did(Did::new(&did2));
    assert!(result.is_ok(), "Expected Ok, but got Err");
    let locked_nfts = result.unwrap();
    assert_eq!(locked_nfts.len(), token_ids_did2.len(), "Expected {} NFTs, but got {}", token_ids_did2.len(), locked_nfts.len());

    for (i, nft) in locked_nfts.iter().enumerate() {
        assert_eq!(nft.contract_address, auth_address);
        assert_eq!(nft.token_id, token_ids_did2[i]);
        assert_eq!(nft.sender, owners[i]);
        assert_eq!(nft.did, Did::new(&did2));
    }

    // Verify unrelated DID gets no NFTs
    let unrelated_did = format!("{}unrelated_did", DID_PREFIX);
    let result = contract.get_locked_nfts_by_did(Did::new(&unrelated_did));
    assert!(result.is_ok(), "Expected Ok, but got Err for unrelated DID");
    let locked_nfts = result.unwrap();
    assert_eq!(locked_nfts.len(), 0, "Expected 0 NFTs, but got {}", locked_nfts.len());
}