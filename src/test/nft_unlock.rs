use crate::contract::sv::mt::{CodeId, LinkageContractProxy};
use crate::error::ContractError;
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
