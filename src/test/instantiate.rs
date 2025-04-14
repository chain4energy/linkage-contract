
use crate::contract::sv::mt::{CodeId, LinkageContractProxy};
use crate::error::ContractError;
use crate::responses::NftLockEntryResponse;
use cosmwasm_std::{to_json_binary, Addr, Binary, Empty, Response, StdResult};
use cw721::{Cw721ExecuteMsg, Cw721QueryMsg};
use cw_multi_test::{Contract, ContractWrapper, Executor, IntoAddr};
use did_contract::state::Did;
use sylvia::multitest::App;

#[test]
fn test_instantiate_success() {
    let app = App::default();
    let code_id = CodeId::store_code(&app);

    let admin1 = "admin1".into_addr();
    let admin2 = "admin2".into_addr();
    let nft_contract1 = "nft_contract1".into_addr();
    let nft_contract2 = "nft_contract2".into_addr();

    let contract = code_id
        .instantiate(
            vec![admin1.clone(), admin2.clone()],
            vec![nft_contract1.clone(), nft_contract2.clone()],
        )
        .call(&admin1)
        .expect("instantiate should succeed");

    let admins = contract.get_admins().expect("get_admins failed");
    assert_eq!(admins.len(), 2);
    assert!(admins.contains(&admin1));
    assert!(admins.contains(&admin2));

    let nft_contracts = contract
        .get_authorized_nft_contracts()
        .expect("get_authorized_nft_contracts failed");
    assert_eq!(nft_contracts.len(), 2);
    assert!(nft_contracts.contains(&nft_contract1));
    assert!(nft_contracts.contains(&nft_contract2));
}

#[test]
fn test_instantiate_no_admins_should_fail() {
    let app = App::default();
    let code_id = CodeId::store_code(&app);

    let nft_contract = "nft_contract".into_addr();

    let contract_result = code_id
        .instantiate(vec![], vec![nft_contract.clone()])
        .call(&nft_contract);
    assert!(contract_result.is_err());
    assert_eq!(
        contract_result.unwrap_err().to_string(),
        "At least one contract admin is required"
    );
}

#[test]
fn test_instantiate_with_empty_authorized_nft_contracts() {
    let app = App::default();
    let code_id = CodeId::store_code(&app);

    let admin = "admin".into_addr();

    let contract = code_id
        .instantiate(vec![admin.clone()], vec![])
        .call(&admin)
        .expect("instantiate should succeed even without NFT contracts");

    let admins = contract.get_admins().expect("get_admins failed");
    assert_eq!(admins.len(), 1);
    assert_eq!(admins[0], admin);

    let nft_contracts = contract
        .get_authorized_nft_contracts()
        .expect("get_authorized_nft_contracts failed");
    assert_eq!(nft_contracts.len(), 0);
}
