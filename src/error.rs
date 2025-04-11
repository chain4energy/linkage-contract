use std::string::FromUtf8Error;

use cosmwasm_std::StdError;
use thiserror::Error;

#[derive(Error, Debug, PartialEq)]
pub enum ContractError {
    #[error("{0}")]
    Std(#[from] StdError),

    #[error("Linkage contract error: {0}")]
    LinkageContractError(StdError),

    #[error("Storage error: {0}: {1}")]
    StorageError(String, StdError),

    #[error("Invalid admin address: {0}")]
    InvalidAdminAddress(StdError),

    #[error("Invalid conract address: {0}")]
    InvalidContractAddress(StdError),

    #[error("Not found")]
    NotFound,

    #[error("Unauthorized")]
    Unauthorized(),

    #[error("Unauthorized contract error")]
    UnauthorizedContractError,

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

    #[error("Did Invalid")]
    DidInvalid(FromUtf8Error),

    #[error("AlreadyExists: {0}")]
    AlreadyExists(String),

    #[error("At least one contract admin is required")]
    NoAdmin,
}