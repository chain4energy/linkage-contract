
use crate::contract::sv::mt::{CodeId, LinkageContractProxy};
use cw_multi_test::IntoAddr;
use sylvia::multitest::App;

#[test]
fn test_add_admin() {
    let app = App::default();
    let code_id = CodeId::store_code(&app);

    let owner = "owner".into_addr();

    let auth_address = "cw721_address".into_addr();

    let contract = code_id
        .instantiate(vec![owner.clone()], vec![auth_address.clone()])
        .call(&owner)
        .unwrap();

    let admin1 = "admin1".into_addr();

    let res = contract
        .add_admin(admin1.to_string())
        .call(&owner)
        .expect("error adding admin");

    assert_eq!(res.events[0].ty, "execute");
    assert_eq!(res.events[0].attributes[0].key, "_contract_address");
    assert_eq!(
        res.events[0].attributes[0].value,
        contract.contract_addr.to_string()
    );

    assert_eq!(res.events[1].ty, "wasm");
    assert_eq!(res.events[1].attributes[0].key, "_contract_address");
    assert_eq!(
        res.events[1].attributes[0].value,
        contract.contract_addr.to_string()
    );
    assert_eq!(res.events[1].attributes[1].key, "action");
    assert_eq!(res.events[1].attributes[1].value, "add_admin");
    assert_eq!(res.events[1].attributes[2].key, "new_admin");
    assert_eq!(res.events[1].attributes[2].value, admin1.to_string());

    assert_eq!(res.events[2].ty, "wasm-add_admin");
    assert_eq!(res.events[2].attributes[0].key, "_contract_address");
    assert_eq!(
        res.events[2].attributes[0].value,
        contract.contract_addr.to_string()
    );
    assert_eq!(res.events[2].attributes[1].key, "executor");
    assert_eq!(res.events[2].attributes[1].value, owner.to_string());
    assert_eq!(res.events[2].attributes[2].key, "new_admin");
    assert_eq!(res.events[2].attributes[2].value, admin1.to_string());

    let non_admin1 = "non_admin".into_addr();
    let admin2 = "admin2".into_addr();
    let res = contract.add_admin(admin2.to_string()).call(&non_admin1);

    assert!(res.is_err(), "Expected Err, but got an Ok");
    assert_eq!("Unauthorized: Sender is not an admin", res.err().unwrap().to_string());

    let admin3 = "admin3".into_addr();

    contract
        .add_admin(admin3.to_string())
        .call(&owner)
        .expect("error adding admin3");

    let admin4 = "admin4".into_addr();

    contract
        .add_admin(admin4.to_string())
        .call(&admin1)
        .expect("error adding admin3");
}

#[test]
fn test_add_invalid_admin() {
    let app = App::default();
    let code_id = CodeId::store_code(&app);

    let owner = "owner".into_addr();
    let auth_address = "cw721_address".into_addr();

    let contract = code_id
        .instantiate(vec![owner.clone()], vec![auth_address.clone()])
        .call(&owner)
        .unwrap();

    // Attempt to add an invalid admin (e.g., an empty string)
    let invalid_admin = "";
    let res = contract.add_admin(invalid_admin.to_string()).call(&owner);

    // Ensure the operation fails
    assert!(res.is_err(), "Expected Err, but got Ok");
    assert_eq!(
        res.err().unwrap().to_string(),
        "Invalid admin address: Generic error: Error decoding bech32",
        "Expected 'Invalid address' error"
    );

    // Attempt to add an invalid admin (e.g., a malformed address)
    let malformed_admin = "invalid_address";
    let res = contract.add_admin(malformed_admin.to_string()).call(&owner);

    // Ensure the operation fails
    assert!(res.is_err(), "Expected Err, but got Ok");
    assert_eq!(
        res.err().unwrap().to_string(),
        "Invalid admin address: Generic error: Error decoding bech32",
        "Expected 'Invalid address' error"
    );
}

#[test]
fn test_add_duplicate_admin() {
    let app = App::default();
    let code_id = CodeId::store_code(&app);

    let owner = "owner".into_addr();
    let auth_address = "cw721_address".into_addr();

    let contract = code_id
        .instantiate(vec![owner.clone()], vec![auth_address.clone()])
        .call(&owner)
        .unwrap();

    let admin1 = "admin1".into_addr();

    // Add the first admin successfully
    contract
        .add_admin(admin1.to_string())
        .call(&owner)
        .expect("error adding admin1");

    // Attempt to add the same admin again
    let res = contract.add_admin(admin1.to_string()).call(&owner);

    // Ensure the operation fails
    assert!(res.is_err(), "Expected Err, but got Ok");
    assert_eq!(
        res.err().unwrap().to_string(),
        "Admin already exists",
        "Expected 'Admin already exists' error"
    );
}

#[test]
fn test_remove_admin() {
    let app = App::default();
    let code_id = CodeId::store_code(&app);

    let owner = "owner".into_addr();

    let auth_address = "cw721_address".into_addr();

    let contract = code_id
        .instantiate(vec![owner.clone()], vec![auth_address.clone()])
        .call(&owner)
        .unwrap();
    let admin1 = "admin1".into_addr();

    // First, add an admin to remove later
    contract
        .add_admin(admin1.to_string())
        .call(&owner)
        .expect("error adding admin1");

    // Remove the admin
    let res = contract
        .remove_admin(admin1.to_string())
        .call(&owner)
        .expect("error removing admin");

    // Validate the response attributes and events
    assert_eq!(res.events[0].ty, "execute");
    assert_eq!(res.events[0].attributes[0].key, "_contract_address");
    assert_eq!(
        res.events[0].attributes[0].value,
        contract.contract_addr.to_string()
    );

    assert_eq!(res.events[1].ty, "wasm");
    assert_eq!(res.events[1].attributes[0].key, "_contract_address");
    assert_eq!(
        res.events[1].attributes[0].value,
        contract.contract_addr.to_string()
    );
    assert_eq!(res.events[1].attributes[1].key, "action");
    assert_eq!(res.events[1].attributes[1].value, "remove_admin");
    assert_eq!(res.events[1].attributes[2].key, "removed_admin");
    assert_eq!(res.events[1].attributes[2].value, admin1.to_string());

    // Test removing a non-existing admin
    let non_admin = "non_admin".into_addr();
    let res = contract.remove_admin(non_admin.to_string()).call(&owner);

    assert!(res.is_err(), "Expected Err, but got an Ok");
    assert_eq!("Admin not found", res.err().unwrap().to_string());

    // Test unauthorized removal attempt
    let unauthorized_user = "unauthorized".into_addr();
    let another_admin = "admin2".into_addr();

    // Add a second admin to test unauthorized removal
    contract
        .add_admin(another_admin.to_string())
        .call(&owner)
        .expect("error adding admin2");

    let res = contract
        .remove_admin(another_admin.to_string())
        .call(&unauthorized_user);

    assert!(res.is_err(), "Expected Err, but got an Ok");
    assert_eq!("Unauthorized: Sender is not an admin", res.err().unwrap().to_string());
}

#[test]
fn test_cannot_remove_last_admin() {
    let app = App::default();
    let code_id = CodeId::store_code(&app);

    let only_admin = "only_admin".into_addr();
    let auth_address = "cw721_address".into_addr();

    let contract = code_id
        .instantiate(vec![only_admin.clone()], vec![auth_address.clone()])
        .call(&only_admin)
        .unwrap();

    let res = contract
        .remove_admin(only_admin.to_string())
        .call(&only_admin);

    assert!(res.is_err(), "Expected error when removing last admin");
    assert_eq!(
        "At least one contract admin is required",
        res.err().unwrap().to_string()
    );
}

#[test]
fn test_remove_same_admin_twice() {
    let app = App::default();
    let code_id = CodeId::store_code(&app);

    let admin = "admin".into_addr();
    let auth_address = "cw721_address".into_addr();

    let contract = code_id
        .instantiate(vec![admin.clone()], vec![auth_address.clone()])
        .call(&admin)
        .unwrap();

    let admin_to_remove = "admin2".into_addr();
    contract
        .add_admin(admin_to_remove.to_string())
        .call(&admin)
        .expect("failed to add admin");

    // First removal should succeed
    contract
        .remove_admin(admin_to_remove.to_string())
        .call(&admin)
        .expect("first removal failed");

    // Second removal should fail
    let result = contract
        .remove_admin(admin_to_remove.to_string())
        .call(&admin);

    assert!(result.is_err(), "Expected error on second removal");
    assert_eq!("Admin not found", result.unwrap_err().to_string());
}

#[test]
fn test_get_admins() {
    let app = App::default();
    let code_id = CodeId::store_code(&app);

    let owner = "owner".into_addr();
    let admin1 = "admin1".into_addr();
    let admin2 = "admin2".into_addr();

    let auth_address = "cw721_address".into_addr();

    // Instantiate contract with an initial admin
    let contract = code_id
        .instantiate(vec![admin1.clone()], vec![auth_address.clone()])
        .call(&owner)
        .unwrap();

    // Check initial admins
    let result = contract.get_admins();
    assert!(result.is_ok(), "Expected Ok, but got an Err");
    let admins = result.unwrap();
    assert_eq!(admins.len(), 1);
    assert_eq!(admins[0], admin1);

    // Add a second admin
    contract
        .add_admin(admin2.to_string())
        .call(&admin1)
        .expect("error adding admin");

    let result = contract.get_admins();
    assert!(result.is_ok(), "Expected Ok, but got an Err");
    let admins = result.unwrap();
    assert_eq!(admins.len(), 2);
    assert!(admins.contains(&admin1));
    assert!(admins.contains(&admin2));

    // Remove the first admin
    contract
        .remove_admin(admin1.to_string())
        .call(&admin1)
        .expect("error removing admin");

    let result = contract.get_admins();
    assert!(result.is_ok(), "Expected Ok, but got an Err");
    let admins = result.unwrap();
    assert_eq!(admins.len(), 1);
    assert!(admins.contains(&admin2));
    assert!(!admins.contains(&admin1));
}
