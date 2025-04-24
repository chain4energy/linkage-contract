use std::string::FromUtf8Error;

use cosmwasm_std::StdError;
use thiserror::Error;

#[derive(Error, Debug, PartialEq)]
pub enum ContractError {
    #[error("{0}")]
    Std(#[from] StdError),

    #[error("Linkage contract error: {0}")]
    LinkageContractError(StdError),

    // #[error("Load nfts by owner error: {0}: {1}")]
    // LoadNftsByOwnerError(String, StdError),

    #[error("Storage error: {0}: {1}")]
    StorageError(String, StdError),

    #[error("Invalid admin address: {0}")]
    InvalidAdminAddress(StdError),

    #[error("Invalid address: {0}")]
    InvalidAddress(StdError),

    #[error("Duplicated admin: {0}")]
    DuplicatedAdmin(String),

    #[error("Duplicated contract: {0}")]
    DuplicatedContract(String),

    #[error("Invalid contract address: {0}")]
    InvalidContractAddress(StdError),

    #[error("Not found: {0}")]
    NotFound(String),

    #[error("Unauthorized: {0}")]
    Unauthorized(String),

    #[error("Invalid input: {0}")]
    InvalidInput(String),

    // #[error("Unauthorized contract error")]
    // UnauthorizedContractError,

    #[error("Not found error")]
    NotFoundContractError,

    #[error("Admin not found")]
    AdminNotFound(),

    #[error("Admin already exists")]
    AdminAlreadyExists(),

    #[error("NFT contract not found")]
    NftContractNotFound(),

    #[error("NFT contract already exists")]
    NftContractAlreadyExists(),

    #[error("Did Invalid: {0}")]
    DidMsgInvalid(FromUtf8Error),

    #[error("AlreadyExists: {0}")]
    AlreadyExists(String),

    #[error("At least one contract admin is required")]
    NoAdmin,

    #[error("Token id is required")]
    NoTokenId,

    #[error("Did invalid: {0}")]
    DidInvalid(did_contract::error::ContractError),
}