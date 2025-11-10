# Linkage Contract

A CosmWasm smart contract for linking NFTs (CW721 tokens) to Decentralized Identifiers (DIDs) on the Chain4Energy (C4E) blockchain.

## Overview

The Linkage Contract provides a secure mechanism to lock NFTs and associate them with DIDs, creating a bridge between digital identity and digital assets. This enables use cases such as identity verification, credential systems, and reputation management.

## Features

- **🔒 NFT Locking**: Secure custody of CW721-compliant NFTs
- **🆔 DID Integration**: Link NFTs to Decentralized Identifiers
- **👥 Multi-Admin Support**: Role-based access control with multiple administrators
- **✅ Authorization System**: Whitelist-based NFT contract authorization
- **🔍 Flexible Queries**: Search by owner, DID, or specific NFT
- **🔓 Controlled Unlocking**: Owner or admin-controlled NFT release with automatic transfer

## Quick Start

### Prerequisites

- Rust 1.70+
- `wasm32-unknown-unknown` target
- Docker (for optimization)

### Installation

```bash
# Clone the repository
git clone https://github.com/chain4energy/linkage-contract
cd linkage-contract

# Add WASM target
rustup target add wasm32-unknown-unknown
```

### Build

```bash
# Development build
cargo wasm

# Production build (optimized)
make optimize
```

### Test

```bash
# Run all tests
cargo test

# Run specific test module
cargo test --test nft_lock

# With output
cargo test -- --nocapture
```

## Documentation

Comprehensive documentation is available in the `docs/` directory:

- **[Contract Design](docs/contract-design.md)**: Architecture and design decisions
- **[API Specification](docs/api-specification.md)**: Complete API reference with examples
- **[Deployment Guide](docs/deployment-guide.md)**: Step-by-step deployment instructions

## Usage Examples

### Lock an NFT

```bash
# User sends NFT from CW721 contract
c4ed tx wasm execute <nft_contract> '{
  "send_nft": {
    "contract": "<linkage_contract_address>",
    "token_id": "my_token_123",
    "msg": "'$(echo -n "did:c4e:alice" | base64)'"
  }
}' --from user_wallet
```

### Query Locked NFTs by DID

```bash
c4ed query wasm contract-state smart <linkage_contract> '{
  "get_locked_nfts_by_did": {
    "did": "did:c4e:alice"
  }
}'
```

### Unlock an NFT

```bash
c4ed tx wasm execute <linkage_contract> '{
  "unlock_nft": {
    "contract_address": "<nft_contract>",
    "token_id": "my_token_123"
  }
}' --from owner_wallet
```

## Architecture

### Storage Structure

The contract uses a triple-index storage pattern for optimal query performance:

- **Primary Storage**: Direct NFT lookup by (contract_address, token_id)
- **Owner Index**: Efficient queries for NFTs by owner address
- **DID Index**: Efficient queries for NFTs by DID

### Authorization Model

Three-tier authorization system:
1. **Admin**: Full contract control, can unlock any NFT
2. **Owner**: Can unlock their own NFTs
3. **Authorized Contract**: Can lock NFTs via receive_nft

## Project Structure

```
linkage-contract/
├── docs/                    # Documentation
│   ├── contract-design.md
│   ├── api-specification.md
│   └── deployment-guide.md
├── src/
│   ├── contract.rs         # Main contract logic (Sylvia framework)
│   ├── state.rs            # State structures
│   ├── error.rs            # Error definitions
│   ├── responses.rs        # Response types
│   ├── lib.rs              # Library exports
│   └── test/               # Comprehensive test suite
├── Cargo.toml              # Dependencies
├── Makefile                # Build and deployment tasks
└── README.md               # This file
```

## Technology Stack

- **Framework**: Sylvia 1.3.5 (CosmWasm framework)
- **CosmWasm**: 2.2.2
- **Storage**: cw-storage-plus 2.0.0
- **DID Integration**: did-contract 0.1.0
- **Testing**: cw-multi-test 2.3.3

## Development

### Running Tests

```bash
# All tests
cargo test

# Specific test file
cargo test --test nft_lock

# Integration tests
cargo test --features library

# With coverage
cargo tarpaulin --out Html
```

### Code Quality

```bash
# Linting
cargo clippy -- -D warnings

# Formatting
cargo fmt

# Security audit
cargo audit
```

### Local Chain Testing

```bash
# Start local C4E chain
make build-c4e-chain-docker
make prepare_chain
make run_chain

# Stop chain
make stop_chain
```

## Deployment

### Testnet Deployment

```bash
# 1. Build optimized WASM
make optimize

# 2. Store code
c4ed tx wasm store artifacts/linkage_contract.wasm --from admin

# 3. Instantiate
c4ed tx wasm instantiate <code_id> '{
  "admins": ["c4e1admin..."],
  "authorized_nft_contracts": []
}' --from admin --label "linkage-contract"
```

See [Deployment Guide](docs/deployment-guide.md) for detailed instructions.

## Contributing

Contributions are welcome! Please:

1. Fork the repository
2. Create a feature branch
3. Add tests for new functionality
4. Ensure all tests pass
5. Run `cargo fmt` and `cargo clippy`
6. Submit a pull request

## Security

### Reporting Vulnerabilities

Please report security vulnerabilities to: [security contact]

### Security Features

- ✅ Input validation on all entry points
- ✅ Authorization checks before state changes
- ✅ Address format validation
- ✅ DID format validation
- ✅ Duplicate prevention
- ✅ Atomic state updates
- ✅ Comprehensive error handling

## License

This project is licensed under the Apache License 2.0 - see the [LICENSE](LICENSE) file for details.

Copyright 2025 Chain4Energy

## Contact

- **Project**: Chain4Energy Linkage Contract
- **Repository**: https://github.com/chain4energy/linkage-contract
- **Documentation**: [Link to online docs]

## Acknowledgments

Built with:
- [CosmWasm](https://cosmwasm.com/)
- [Sylvia Framework](https://github.com/CosmWasm/sylvia)
- [Chain4Energy](https://c4e.io/)