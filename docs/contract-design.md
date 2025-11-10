# Linkage Contract - Design Document

## Overview

The **Linkage Contract** is a CosmWasm smart contract that provides a secure mechanism to lock NFTs (CW721 tokens) and link them to Decentralized Identifiers (DIDs). It serves as a bridge between digital identity and digital assets on the Chain4Energy (C4E) blockchain.

## Purpose

This contract enables:
- **NFT Custody**: Secure locking of CW721-compliant NFTs
- **Identity Linkage**: Association of locked NFTs with DIDs
- **Access Control**: Role-based permissions for admin and owner operations
- **Query System**: Efficient lookups by owner, DID, or specific NFT

## Use Cases

1. **Identity Verification**: Prove identity ownership through NFT possession
2. **Credential Systems**: Use NFTs as credentials linked to DIDs
3. **Asset Custody**: Secure NFT storage with identity verification
4. **Reputation Systems**: Link reputation NFTs to decentralized identities
5. **Governance**: NFT-based voting rights tied to identities

## Architecture

### Technology Stack

- **Framework**: Sylvia v1.3.5 (CosmWasm framework)
- **CosmWasm**: v2.2.2
- **Storage**: cw-storage-plus v2.0.0
- **DID Integration**: did-contract v0.1.0
- **Testing**: cw-multi-test v2.3.3

### Contract Structure

```rust
pub struct LinkageContract {
    pub admins: Item<Vec<Addr>>,
    pub authorized_nft_contracts: Item<Vec<Addr>>,
    pub locked_nfts: Map<(Addr, String), NftLockEntry>,
    pub nfts_by_owner: Map<Addr, Vec<Nft>>,
    pub nfts_by_did: Map<Did, Vec<Nft>>,
}
```

## State Design

### Storage Strategy: Triple-Index Pattern

The contract uses three separate storage structures for locked NFTs:

#### 1. Primary Storage: `locked_nfts`
- **Type**: `Map<(Addr, String), NftLockEntry>`
- **Key**: (contract_address, token_id)
- **Value**: NftLockEntry { sender, did }
- **Purpose**: Primary storage with O(1) lookup by NFT identifier

#### 2. Owner Index: `nfts_by_owner`
- **Type**: `Map<Addr, Vec<Nft>>`
- **Key**: Owner address
- **Value**: List of NFTs owned
- **Purpose**: Efficient owner-based queries

#### 3. DID Index: `nfts_by_did`
- **Type**: `Map<Did, Vec<Nft>>`
- **Key**: DID string
- **Value**: List of NFTs linked to DID
- **Purpose**: Efficient DID-based queries

### Design Rationale

**Advantages**:
- O(1) query performance for all access patterns
- No full table scans required
- Optimized for read-heavy workloads
- Supports multiple query dimensions

**Trade-offs**:
- 3x storage overhead
- More complex update logic
- Must maintain consistency across all indexes

**Decision**: The use case prioritizes query performance over storage costs, making this the optimal choice for identity verification systems.

## Data Structures

### Nft
```rust
pub struct Nft {
    pub contract_address: Addr,  // NFT contract address
    pub token_id: String,        // Unique token identifier
}
```

### NftLockEntry
```rust
pub struct NftLockEntry {
    pub sender: Addr,  // Original owner
    pub did: Did,      // Associated DID
}
```

### NftLockEntryResponse
```rust
pub struct NftLockEntryResponse {
    pub contract_address: Addr,
    pub token_id: String,
    pub sender: Addr,
    pub did: Did,
}
```

## Access Control

### Three-Tier Authorization Model

#### 1. Admin Level
**Capabilities**:
- Add/remove admins
- Add/remove authorized NFT contracts
- Unlock any NFT (emergency access)

**Validation**: `authorize_admin(deps, sender)`

#### 2. Owner Level
**Capabilities**:
- Unlock their own NFTs

**Validation**: `authorize_sender(sender, nft)`

#### 3. Contract Level
**Capabilities**:
- Lock NFTs (via receive_nft)

**Validation**: `authorize_contract(deps, contract)`

### Authorization Matrix

| Operation | Admin | Owner | Auth Contract | Public |
|-----------|-------|-------|---------------|--------|
| Add Admin | ✅ | ❌ | ❌ | ❌ |
| Remove Admin | ✅ | ❌ | ❌ | ❌ |
| Authorize Contract | ✅ | ❌ | ❌ | ❌ |
| Deauthorize Contract | ✅ | ❌ | ❌ | ❌ |
| Lock NFT | ❌ | ❌ | ✅ | ❌ |
| Unlock Own NFT | ✅ | ✅ | ❌ | ❌ |
| Unlock Any NFT | ✅ | ❌ | ❌ | ❌ |
| Query Operations | ✅ | ✅ | ✅ | ✅ |

## State Transitions

### NFT Lifecycle

```
┌─────────────┐
│  Unlocked   │  (In user wallet)
│ (External)  │
└──────┬──────┘
       │
       │ send_nft(linkage_contract, token_id, DID)
       │
       ▼
┌─────────────┐
│   Locked    │  (In linkage contract)
│  (Internal) │
└──────┬──────┘
       │
       │ unlock_nft(contract_address, token_id)
       │
       ▼
┌─────────────┐
│  Unlocked   │  (Returned to caller)
│ (External)  │
└─────────────┘
```

### Storage Operations

#### Lock Operation
1. Validate authorization (contract must be authorized)
2. Validate DID format
3. Check NFT not already locked
4. Store in `locked_nfts[contract_addr, token_id] = {sender, did}`
5. Append to `nfts_by_owner[sender]`
6. Append to `nfts_by_did[did]`
7. Emit `receive_nft` event

#### Unlock Operation
1. Validate authorization (admin or owner)
2. Load NFT entry from `locked_nfts`
3. Remove from `locked_nfts[contract_addr, token_id]`
4. Remove from `nfts_by_owner[sender]`
5. Remove from `nfts_by_did[did]`
6. Execute transfer back to caller
7. Emit `unlock_nft` event

## Integration Flow

### NFT Locking Flow

```
┌─────────┐
│  User   │
└────┬────┘
     │
     │ 1. Call send_nft on CW721 contract
     │    - contract: linkage_contract_address
     │    - token_id: "my_token"
     │    - msg: DID (as binary)
     │
     ▼
┌────────────────┐
│ CW721 Contract │
└────┬───────────┘
     │
     │ 2. Transfer NFT ownership to linkage_contract
     │ 3. Call receive_nft(sender, token_id, msg)
     │
     ▼
┌──────────────────┐
│ Linkage Contract │
└────┬─────────────┘
     │
     │ 4. Validate and store linkage
     │ 5. Update all indexes
     │ 6. Emit event
     │
     ▼
   [Done]
```

### NFT Unlocking Flow

```
┌──────────────┐
│ Owner/Admin  │
└────┬─────────┘
     │
     │ 1. Call unlock_nft
     │    - contract_address
     │    - token_id
     │
     ▼
┌──────────────────┐
│ Linkage Contract │
└────┬─────────────┘
     │
     │ 2. Validate authorization
     │ 3. Remove from all indexes
     │ 4. Execute WasmMsg::Execute
     │    - transfer_nft to caller
     │
     ▼
┌────────────────┐
│ CW721 Contract │
└────┬───────────┘
     │
     │ 5. Transfer NFT to caller
     │
     ▼
┌──────────────┐
│ Owner/Admin  │ Receives NFT
└──────────────┘
```

## Validation Strategy

### Multi-Layer Validation

#### Address Validation
```rust
fn ensure_valid_admin(&self, api: &dyn Api, admin: &str) -> Result<Addr, ContractError>
```
- Validates bech32 format
- Checks checksum
- Verifies chain prefix

#### DID Validation
```rust
fn ensure_valid_did(&self, did: &Did) -> Result<(), ContractError>
```
- Validates DID format (prefix + identifier)
- Uses did-contract validation logic
- Ensures proper structure

#### Business Logic Validation
- At least one admin required
- No duplicate admins
- No duplicate authorized contracts
- Token ID not empty
- NFT not already locked
- Contract authorized before locking

## Security Considerations

### Attack Surface

1. **Unauthorized Access**
   - Mitigation: Strict authorization checks at every entry point
   - Whitelist-based contract authorization

2. **Storage Manipulation**
   - Mitigation: Private state variables, atomic transactions
   - Consistency checks across all indexes

3. **Reentrancy**
   - Mitigation: State updated before external calls
   - CosmWasm's message queue prevents classic reentrancy

4. **Integer Overflow**
   - Mitigation: Rust's built-in overflow checks
   - No user-controlled arithmetic

5. **Address Validation**
   - Mitigation: All addresses validated via `addr_validate()`
   - Invalid addresses rejected before processing

### Security Best Practices

✅ Input validation on all entry points  
✅ Authorization checks before state changes  
✅ Comprehensive error handling  
✅ Event emission for audit trail  
✅ No unsafe code usage  
✅ Duplicate prevention  
✅ Atomic state updates  
✅ Address format validation  
✅ DID format validation  
✅ Storage cleanup to prevent bloat  

## Performance Analysis

### Query Complexity

| Operation | Time Complexity | Storage Reads |
|-----------|----------------|---------------|
| get_locked_nft | O(1) | 1 |
| get_locked_nfts_by_owner | O(1) + O(n) | 1 + n |
| get_locked_nfts_by_did | O(1) + O(n) | 1 + n |
| get_admins | O(1) | 1 |
| get_authorized_nft_contracts | O(1) | 1 |

*n = number of NFTs for owner/DID*

### Write Complexity

| Operation | Time Complexity | Storage Writes |
|-----------|----------------|----------------|
| lock_nft | O(1) | 3 |
| unlock_nft | O(n) | 3 |
| add_admin | O(1) | 1 |
| remove_admin | O(n) | 1 |

*n = number of admins or NFTs*

### Gas Optimization

**Implemented Optimizations**:
- Early validation returns
- Minimal cloning operations
- Storage cleanup (remove empty lists)
- Efficient iteration patterns
- Batch storage updates

**Estimated Gas Costs**:
- Lock NFT: ~200k gas
- Unlock NFT: ~250k gas
- Add Admin: ~80k gas
- Query: ~10-50k gas

## Error Handling

### Error Types

All errors use `thiserror` for clean error definitions:

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
    DidMsgInvalid(FromUtf8Error),
    DidInvalid(did_contract::error::ContractError),
    AlreadyExists(String),
    AdminNotFound(),
    AdminAlreadyExists(),
    NftContractNotFound(),
    NftContractAlreadyExists(),
    NoAdmin,
    NoTokenId,
    // ... others
}
```

### Error Strategy

1. **Fail-Fast**: Validate all inputs before state changes
2. **Descriptive Messages**: Include context in error messages
3. **Type Safety**: Strongly typed error variants
4. **Propagation**: Use `?` operator for clean error propagation
5. **Atomic Operations**: All-or-nothing state updates

## Testing Strategy

### Test Coverage

The contract includes comprehensive tests across multiple modules:

1. **instantiate.rs**: Contract initialization
   - Valid instantiation
   - Edge cases (no admins, duplicates)
   - Invalid addresses

2. **admin.rs**: Admin management
   - Adding/removing admins
   - Authorization checks

3. **authorized_nft.rs**: NFT contract authorization
   - Adding/removing authorized contracts

4. **nft_lock.rs**: NFT locking
   - Basic locking
   - Multiple NFTs per owner/DID
   - Validation failures

5. **nft_unlock.rs**: NFT unlocking
   - Owner unlocking
   - Admin unlocking
   - Unauthorized attempts
   - Complex scenarios

6. **Query tests**: All query operations

### Test Approach

- **Unit Tests**: Individual function testing
- **Integration Tests**: Full workflow testing with cw-multi-test
- **Edge Cases**: Empty values, duplicates, invalid inputs
- **Authorization**: Permission boundary testing
- **Storage Consistency**: Index integrity validation

## Deployment Considerations

### Prerequisites

- Rust toolchain with wasm32-unknown-unknown target
- Docker for optimization
- CosmWasm-check for validation
- Access to C4E chain node

### Build Process

```bash
# Development build
cargo wasm

# Optimized production build
make optimize  # Uses cosmwasm/optimizer:0.16.1
```

### Deployment Steps

1. **Store Code**: Upload optimized WASM to chain
2. **Get Code ID**: Query for stored code ID
3. **Instantiate**: Deploy with initial admin(s)
4. **Configure**: Add authorized NFT contracts
5. **Verify**: Query contract state

### Configuration

**Instantiation Parameters**:
- `admins`: List of admin addresses (minimum 1)
- `authorized_nft_contracts`: Initial NFT contract whitelist (can be empty)

## Future Enhancements

### Potential Features

1. **Pagination**: For large NFT collections
2. **Batch Operations**: Lock/unlock multiple NFTs
3. **Time Locks**: Expiration-based unlocking
4. **Metadata**: Additional data per lock
5. **Delegation**: Owner can delegate unlock rights
6. **Events**: More granular event types
7. **Migration**: Contract upgrade support

### Scalability Considerations

- **Storage Growth**: Linear with number of locked NFTs
- **Query Performance**: Maintained through indexing
- **State Size**: Consider pagination for very large collections
- **Gas Optimization**: Batch operations for efficiency

## Dependencies

### Core Dependencies

```toml
cosmwasm-std = "=2.2.2"
serde = "1.0.210"
cw-storage-plus = "2.0.0"
cosmwasm-schema = "2.2.2"
schemars = "0.8.21"
sylvia = "1.3.5"
thiserror = "2.0.12"
did-contract = { git = "...", tag = "v0.1.0" }
```

### Development Dependencies

```toml
cw-multi-test = "2.3.3"
sylvia = { version = "1.3.5", features = ["mt"] }
serde_json = "1.0.128"
serial_test = "3.1"
cosmrs = "0.22"
cw721-base = "0.18.0"
cw721 = "0.18.0"
regex = "1.11.1"
```

## Maintenance Guidelines

### Code Quality

- Run `cargo clippy -- -D warnings` before commits
- Ensure `cargo fmt` formatting
- Maintain test coverage >80%
- Update documentation with code changes
- Review security implications of changes

### Version Management

- Follow semantic versioning
- Document breaking changes
- Provide migration paths
- Test upgrade scenarios

---

**Document Version**: 1.0  
**Last Updated**: November 10, 2025  
**Contract Version**: 0.1.0
