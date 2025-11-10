# API Specification

## Overview

This document provides the complete API specification for the Linkage Contract, including all message types, query operations, and response formats.

---

## Instantiate Message

### InstantiateMsg

Initializes the contract with admins and authorized NFT contracts.

```rust
pub struct InstantiateMsg {
    pub admins: Vec<Addr>,
    pub authorized_nft_contracts: Vec<Addr>,
}
```

#### Parameters

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `admins` | `Vec<Addr>` | ✅ | List of admin addresses (minimum 1) |
| `authorized_nft_contracts` | `Vec<Addr>` | ✅ | List of authorized NFT contracts (can be empty) |

#### Validation

- ✅ At least one admin required
- ✅ No duplicate admins
- ✅ No duplicate NFT contracts
- ✅ All addresses must be valid bech32 format

#### Example (JSON)

```json
{
  "admins": [
    "c4e1admin1address...",
    "c4e1admin2address..."
  ],
  "authorized_nft_contracts": [
    "c4e1nftcontract1...",
    "c4e1nftcontract2..."
  ]
}
```

#### Errors

| Error | Condition |
|-------|-----------|
| `NoAdmin` | Admin list is empty |
| `DuplicatedAdmin` | Duplicate admin in list |
| `DuplicatedContract` | Duplicate contract in list |
| `InvalidAdminAddress` | Invalid bech32 address format |
| `InvalidContractAddress` | Invalid contract address format |

---

## Execute Messages

### AddAdmin

Adds a new administrator to the contract.

**Authorization**: Admin only

```rust
pub fn add_admin(new_admin: String) -> Result<Response, ContractError>
```

#### Parameters

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `new_admin` | `String` | ✅ | Address of new admin |

#### Example (JSON)

```json
{
  "add_admin": {
    "new_admin": "c4e1newadminaddress..."
  }
}
```

#### Response

Standard CosmWasm Response with event:

```json
{
  "events": [
    {
      "type": "wasm-add_admin",
      "attributes": [
        {"key": "executor", "value": "c4e1calleraddress..."},
        {"key": "new_admin", "value": "c4e1newadminaddress..."}
      ]
    }
  ]
}
```

#### Errors

| Error | Condition |
|-------|-----------|
| `Unauthorized` | Caller is not an admin |
| `InvalidAdminAddress` | Invalid address format |
| `AdminAlreadyExists` | Admin already in list |

---

### RemoveAdmin

Removes an existing administrator.

**Authorization**: Admin only

```rust
pub fn remove_admin(admin_to_remove: String) -> Result<Response, ContractError>
```

#### Parameters

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `admin_to_remove` | `String` | ✅ | Address of admin to remove |

#### Example (JSON)

```json
{
  "remove_admin": {
    "admin_to_remove": "c4e1adminaddress..."
  }
}
```

#### Response

```json
{
  "events": [
    {
      "type": "wasm-remove_admin",
      "attributes": [
        {"key": "executor", "value": "c4e1calleraddress..."},
        {"key": "removed_admin", "value": "c4e1adminaddress..."}
      ]
    }
  ]
}
```

#### Errors

| Error | Condition |
|-------|-----------|
| `Unauthorized` | Caller is not an admin |
| `InvalidAdminAddress` | Invalid address format |
| `AdminNotFound` | Admin not in list |
| `NoAdmin` | Would remove last admin |

---

### AddAuthorizedNftContract

Authorizes an NFT contract to lock NFTs.

**Authorization**: Admin only

```rust
pub fn add_authorized_nft_contract(nft_contract_address: Addr) -> Result<Response, ContractError>
```

#### Parameters

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `nft_contract_address` | `Addr` | ✅ | NFT contract address |

#### Example (JSON)

```json
{
  "add_authorized_nft_contract": {
    "nft_contract_address": "c4e1nftcontract..."
  }
}
```

#### Response

```json
{
  "events": [
    {
      "type": "wasm-add_authorized_nft_contract",
      "attributes": [
        {"key": "executor", "value": "c4e1adminaddress..."},
        {"key": "new_authorized_nft_contract", "value": "c4e1nftcontract..."}
      ]
    }
  ]
}
```

#### Errors

| Error | Condition |
|-------|-----------|
| `Unauthorized` | Caller is not an admin |
| `InvalidContractAddress` | Invalid address format |
| `NftContractAlreadyExists` | Contract already authorized |

---

### RemoveAuthorizedNftContract

Removes authorization for an NFT contract.

**Authorization**: Admin only

```rust
pub fn remove_authorized_nft_contract(nft_contract_address: Addr) -> Result<Response, ContractError>
```

#### Parameters

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `nft_contract_address` | `Addr` | ✅ | NFT contract address |

#### Example (JSON)

```json
{
  "remove_authorized_nft_contract": {
    "nft_contract_address": "c4e1nftcontract..."
  }
}
```

#### Response

```json
{
  "events": [
    {
      "type": "wasm-remove_authorized_nft_contract",
      "attributes": [
        {"key": "executor", "value": "c4e1adminaddress..."},
        {"key": "removed_authorized_nft_contract", "value": "c4e1nftcontract..."}
      ]
    }
  ]
}
```

#### Errors

| Error | Condition |
|-------|-----------|
| `Unauthorized` | Caller is not an admin |
| `InvalidContractAddress` | Invalid address format |
| `NftContractNotFound` | Contract not in authorized list |

---

### ReceiveNft

Receives and locks an NFT from a CW721 contract.

**Authorization**: Authorized NFT contract only (called by CW721 contract)

```rust
pub fn receive_nft(
    sender: Addr,
    token_id: String,
    msg: Binary,
) -> Result<Response, ContractError>
```

#### Parameters

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `sender` | `Addr` | ✅ | Original owner of the NFT |
| `token_id` | `String` | ✅ | NFT token ID |
| `msg` | `Binary` | ✅ | DID encoded as binary (UTF-8) |

#### Integration Pattern

This function is called by a CW721 contract when a user executes:

```json
{
  "send_nft": {
    "contract": "linkage_contract_address",
    "token_id": "my_token_123",
    "msg": "<base64_encoded_DID>"
  }
}
```

#### DID Format

The `msg` field must contain a valid DID in UTF-8 encoding:
- Format: `did:c4e:<identifier>`
- Example: `did:c4e:alice123`

#### Example (Direct Call - Not Typical)

```json
{
  "receive_nft": {
    "sender": "c4e1owneraddress...",
    "token_id": "token_123",
    "msg": "ZGlkOmM0ZTphbGljZTEyMw=="
  }
}
```

#### Response

```json
{
  "events": [
    {
      "type": "wasm-receive_nft",
      "attributes": [
        {"key": "executor", "value": "c4e1nftcontract..."},
        {"key": "sender", "value": "c4e1owneraddress..."},
        {"key": "token_id", "value": "token_123"},
        {"key": "did", "value": "did:c4e:alice123"}
      ]
    }
  ]
}
```

#### Errors

| Error | Condition |
|-------|-----------|
| `Unauthorized` | Calling contract not authorized |
| `InvalidContractAddress` | Invalid contract address |
| `NoTokenId` | Token ID is empty |
| `DidMsgInvalid` | DID message cannot be decoded |
| `DidInvalid` | DID format is invalid |
| `AlreadyExists` | NFT already locked |

---

### UnlockNft

Unlocks an NFT and transfers it back to the caller.

**Authorization**: Admin or NFT owner

```rust
pub fn unlock_nft(
    contract_address: Addr,
    token_id: String,
) -> Result<Response, ContractError>
```

#### Parameters

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `contract_address` | `Addr` | ✅ | NFT contract address |
| `token_id` | `String` | ✅ | NFT token ID |

#### Example (JSON)

```json
{
  "unlock_nft": {
    "contract_address": "c4e1nftcontract...",
    "token_id": "token_123"
  }
}
```

#### Response

```json
{
  "events": [
    {
      "type": "wasm-unlock_nft",
      "attributes": [
        {"key": "executor", "value": "c4e1calleraddress..."},
        {"key": "contract_address", "value": "c4e1nftcontract..."},
        {"key": "token_id", "value": "token_123"},
        {"key": "did", "value": "did:c4e:alice123"}
      ]
    }
  ],
  "messages": [
    {
      "msg": {
        "wasm": {
          "execute": {
            "contract_addr": "c4e1nftcontract...",
            "msg": {
              "transfer_nft": {
                "recipient": "c4e1calleraddress...",
                "token_id": "token_123"
              }
            },
            "funds": []
          }
        }
      }
    }
  ]
}
```

#### Behavior

1. Validates authorization (admin or owner)
2. Removes NFT from all storage indexes
3. Executes CW721 `transfer_nft` to caller
4. Emits unlock event

#### Errors

| Error | Condition |
|-------|-----------|
| `Unauthorized` | Caller is neither admin nor owner |
| `InvalidContractAddress` | Invalid contract address |
| `NoTokenId` | Token ID is empty |
| `NotFound` | NFT not locked |

---

## Query Messages

All queries are read-only and do not require authorization.

### GetAdmins

Returns the list of contract administrators.

```rust
pub fn get_admins() -> Result<Vec<Addr>, ContractError>
```

#### Example (JSON)

```json
{
  "get_admins": {}
}
```

#### Response

```json
[
  "c4e1admin1address...",
  "c4e1admin2address..."
]
```

---

### GetAuthorizedNftContracts

Returns the list of authorized NFT contracts.

```rust
pub fn get_authorized_nft_contracts() -> Result<Vec<Addr>, ContractError>
```

#### Example (JSON)

```json
{
  "get_authorized_nft_contracts": {}
}
```

#### Response

```json
[
  "c4e1nftcontract1...",
  "c4e1nftcontract2..."
]
```

---

### GetLockedNft

Retrieves information about a specific locked NFT.

```rust
pub fn get_locked_nft(
    contract_address: Addr,
    token_id: String,
) -> Result<NftLockEntryResponse, ContractError>
```

#### Parameters

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `contract_address` | `Addr` | ✅ | NFT contract address |
| `token_id` | `String` | ✅ | NFT token ID |

#### Example (JSON)

```json
{
  "get_locked_nft": {
    "contract_address": "c4e1nftcontract...",
    "token_id": "token_123"
  }
}
```

#### Response

```json
{
  "contract_address": "c4e1nftcontract...",
  "token_id": "token_123",
  "sender": "c4e1owneraddress...",
  "did": "did:c4e:alice123"
}
```

#### Errors

| Error | Condition |
|-------|-----------|
| `InvalidContractAddress` | Invalid contract address |
| `NoTokenId` | Token ID is empty |
| `NotFound` | NFT not locked |

---

### GetLockedNftsByDid

Retrieves all NFTs linked to a specific DID.

```rust
pub fn get_locked_nfts_by_did(
    did: Did,
) -> Result<Vec<NftLockEntryResponse>, ContractError>
```

#### Parameters

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `did` | `Did` (String) | ✅ | Decentralized Identifier |

#### Example (JSON)

```json
{
  "get_locked_nfts_by_did": {
    "did": "did:c4e:alice123"
  }
}
```

#### Response

```json
[
  {
    "contract_address": "c4e1nftcontract1...",
    "token_id": "token_123",
    "sender": "c4e1owneraddress1...",
    "did": "did:c4e:alice123"
  },
  {
    "contract_address": "c4e1nftcontract2...",
    "token_id": "token_456",
    "sender": "c4e1owneraddress2...",
    "did": "did:c4e:alice123"
  }
]
```

#### Behavior

- Returns empty array `[]` if no NFTs linked to DID
- Filters out any inconsistent entries

#### Errors

| Error | Condition |
|-------|-----------|
| `DidInvalid` | Invalid DID format |

---

### GetLockedNftsByOwner

Retrieves all NFTs locked by a specific owner.

```rust
pub fn get_locked_nfts_by_owner(
    owner: Addr,
) -> Result<Vec<NftLockEntryResponse>, ContractError>
```

#### Parameters

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `owner` | `Addr` | ✅ | Owner address |

#### Example (JSON)

```json
{
  "get_locked_nfts_by_owner": {
    "owner": "c4e1owneraddress..."
  }
}
```

#### Response

```json
[
  {
    "contract_address": "c4e1nftcontract1...",
    "token_id": "token_123",
    "sender": "c4e1owneraddress...",
    "did": "did:c4e:alice123"
  },
  {
    "contract_address": "c4e1nftcontract1...",
    "token_id": "token_789",
    "sender": "c4e1owneraddress...",
    "did": "did:c4e:bob456"
  }
]
```

#### Behavior

- Returns empty array `[]` if owner has no locked NFTs
- Filters out any inconsistent entries

#### Errors

| Error | Condition |
|-------|-----------|
| `InvalidAddress` | Invalid owner address |

---

## Response Types

### NftLockEntryResponse

Complete information about a locked NFT.

```rust
pub struct NftLockEntryResponse {
    pub contract_address: Addr,  // NFT contract address
    pub token_id: String,        // NFT token ID
    pub sender: Addr,            // Original owner
    pub did: Did,                // Associated DID
}
```

#### JSON Schema

```json
{
  "type": "object",
  "required": ["contract_address", "token_id", "sender", "did"],
  "properties": {
    "contract_address": {"type": "string"},
    "token_id": {"type": "string"},
    "sender": {"type": "string"},
    "did": {"type": "string"}
  }
}
```

---

## Events

All state-changing operations emit events for audit and monitoring.

### Event Format

```rust
Event {
    type: String,
    attributes: Vec<Attribute>
}
```

### Event Types

#### add_admin

Emitted when a new admin is added.

```json
{
  "type": "wasm-add_admin",
  "attributes": [
    {"key": "_contract_address", "value": "<contract_address>"},
    {"key": "executor", "value": "<admin_who_added>"},
    {"key": "new_admin", "value": "<new_admin_address>"}
  ]
}
```

#### remove_admin

Emitted when an admin is removed.

```json
{
  "type": "wasm-remove_admin",
  "attributes": [
    {"key": "_contract_address", "value": "<contract_address>"},
    {"key": "executor", "value": "<admin_who_removed>"},
    {"key": "removed_admin", "value": "<removed_admin_address>"}
  ]
}
```

#### add_authorized_nft_contract

Emitted when an NFT contract is authorized.

```json
{
  "type": "wasm-add_authorized_nft_contract",
  "attributes": [
    {"key": "_contract_address", "value": "<contract_address>"},
    {"key": "executor", "value": "<admin_address>"},
    {"key": "new_authorized_nft_contract", "value": "<nft_contract_address>"}
  ]
}
```

#### remove_authorized_nft_contract

Emitted when an NFT contract authorization is revoked.

```json
{
  "type": "wasm-remove_authorized_nft_contract",
  "attributes": [
    {"key": "_contract_address", "value": "<contract_address>"},
    {"key": "executor", "value": "<admin_address>"},
    {"key": "removed_authorized_nft_contract", "value": "<nft_contract_address>"}
  ]
}
```

#### receive_nft

Emitted when an NFT is locked.

```json
{
  "type": "wasm-receive_nft",
  "attributes": [
    {"key": "_contract_address", "value": "<contract_address>"},
    {"key": "executor", "value": "<nft_contract_address>"},
    {"key": "sender", "value": "<nft_owner_address>"},
    {"key": "token_id", "value": "<token_id>"},
    {"key": "did", "value": "<did_string>"}
  ]
}
```

#### unlock_nft

Emitted when an NFT is unlocked.

```json
{
  "type": "wasm-unlock_nft",
  "attributes": [
    {"key": "_contract_address", "value": "<contract_address>"},
    {"key": "executor", "value": "<caller_address>"},
    {"key": "contract_address", "value": "<nft_contract_address>"},
    {"key": "token_id", "value": "<token_id>"},
    {"key": "did", "value": "<associated_did>"}
  ]
}
```

---

## Error Codes

### ContractError Enum

Complete list of error types:

```rust
pub enum ContractError {
    Std(StdError),
    StorageError(String, StdError),
    InvalidAdminAddress(StdError),
    InvalidAddress(StdError),
    InvalidContractAddress(StdError),
    DuplicatedAdmin(String),
    DuplicatedContract(String),
    NotFound(String),
    Unauthorized(String),
    InvalidInput(String),
    NotFoundContractError,
    AdminNotFound(),
    AdminAlreadyExists(),
    NftContractNotFound(),
    NftContractAlreadyExists(),
    DidMsgInvalid(FromUtf8Error),
    DidInvalid(did_contract::error::ContractError),
    AlreadyExists(String),
    NoAdmin,
    NoTokenId,
}
```

### Error Messages

| Error Code | Message Format | HTTP Status |
|------------|----------------|-------------|
| `Std` | Standard CosmWasm error | 500 |
| `StorageError` | "Storage error: {context}: {error}" | 500 |
| `InvalidAdminAddress` | "Invalid admin address: {error}" | 400 |
| `InvalidAddress` | "Invalid address: {error}" | 400 |
| `InvalidContractAddress` | "Invalid contract address: {error}" | 400 |
| `DuplicatedAdmin` | "Duplicated admin: {address}" | 400 |
| `DuplicatedContract` | "Duplicated contract: {address}" | 400 |
| `NotFound` | "Not found: {description}" | 404 |
| `Unauthorized` | "Unauthorized: {reason}" | 403 |
| `AdminNotFound` | "Admin not found" | 404 |
| `AdminAlreadyExists` | "Admin already exists" | 400 |
| `NftContractNotFound` | "NFT contract not found" | 404 |
| `NftContractAlreadyExists` | "NFT contract already exists" | 400 |
| `DidMsgInvalid` | "Did Invalid: {error}" | 400 |
| `DidInvalid` | "Did invalid: {error}" | 400 |
| `AlreadyExists` | "AlreadyExists: {description}" | 409 |
| `NoAdmin` | "At least one contract admin is required" | 400 |
| `NoTokenId` | "Token id is required" | 400 |

---

## Gas Estimates

Estimated gas costs for operations (approximate):

| Operation | Gas Cost | Notes |
|-----------|----------|-------|
| Instantiate | ~150k | Initial setup |
| Add Admin | ~80k | Simple list append |
| Remove Admin | ~80k | List removal |
| Authorize Contract | ~80k | Simple list append |
| Deauthorize Contract | ~80k | List removal |
| Lock NFT | ~200k | Triple index update |
| Unlock NFT | ~250k | Triple index update + transfer |
| Get Admins | ~10k | Simple read |
| Get Authorized Contracts | ~10k | Simple read |
| Get Locked NFT | ~20k | Single lookup |
| Get NFTs by Owner | ~30k + n*10k | Index read + n lookups |
| Get NFTs by DID | ~30k + n*10k | Index read + n lookups |

*Note: Gas costs vary based on network conditions and data size*

---

**Document Version**: 1.0  
**Last Updated**: November 10, 2025  
**Contract Version**: 0.1.0
