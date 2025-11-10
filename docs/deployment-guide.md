# Deployment Guide

## Overview

This guide provides step-by-step instructions for building, testing, and deploying the Linkage Contract to a CosmWasm-enabled blockchain.

---

## Prerequisites

### Required Tools

1. **Rust Toolchain**
   ```bash
   # Install Rust (if not already installed)
   curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
   
   # Add wasm32 target
   rustup target add wasm32-unknown-unknown
   ```

2. **Docker**
   ```bash
   # Required for WASM optimization
   # Install from: https://docs.docker.com/get-docker/
   ```

3. **C4E Chain CLI** (or compatible CosmWasm chain)
   ```bash
   # Install c4ed CLI tool
   # Refer to Chain4Energy documentation
   ```

4. **Development Tools**
   ```bash
   # Optional but recommended
   cargo install cargo-audit
   cargo install cosmwasm-check
   ```

### Environment Setup

Create environment configuration:

```bash
# Copy example environment file
cp config/.env.example config/.env

# Edit with your values
nano config/.env
```

Example `.env` file:
```bash
CHAIN_ID="babajaga-1"
NODE_URL="https://rpc-testnet.c4e.io:443"
ADMIN_WALLET="admin_key_name"
GAS_PRICES="0.025uc4e"
GAS_ADJUSTMENT="1.3"
```

⚠️ **Security Note**: Never commit `.env` files to version control!

---

## Building the Contract

### Development Build

For local testing and development:

```bash
# Standard build
cargo build

# WASM build (unoptimized)
cargo wasm

# Or using Makefile
make build
```

Output: `target/wasm32-unknown-unknown/release/linkage_contract.wasm`

### Production Build (Optimized)

For deployment to mainnet or testnet:

```bash
# Using Docker optimizer
make optimize
```

This uses the `cosmwasm/optimizer:0.16.1` Docker image to create an optimized WASM binary.

**Important Notes**:
- ⚠️ For deterministic builds (production), use Intel processors only (not Apple M1/M2)
- The optimizer reduces binary size and gas costs significantly
- Output located in: `artifacts/linkage_contract.wasm`
- Checksums stored in: `artifacts/checksums.txt`

#### Manual Optimization

```bash
docker run --rm -it --entrypoint sh \
  -v "$(pwd)":/code \
  --mount type=volume,source="linkage_contract_cache",target=/target \
  --mount type=volume,source=registry_cache,target=/usr/local/cargo/registry \
  cosmwasm/optimizer:0.16.1 \
  -c "apk add --no-cache git && optimize.sh /code && chown -R $(id -u):$(id -g) /code/artifacts"
```

### Verify Contract

```bash
# Check WASM binary validity
cosmwasm-check artifacts/linkage_contract.wasm

# Or using Makefile
make check-contract
```

Expected output:
```
Available capabilities: {"cosmwasm_1_1", "cosmwasm_1_2", "cosmwasm_1_3", "iterator", "staking", "stargate"}
```

---

## Testing

### Unit Tests

Run all unit tests:

```bash
# Run tests
cargo test

# With output
cargo test -- --nocapture

# Specific test module
cargo test --test nft_lock

# Specific test function
cargo test test_receive_nft_success
```

### Integration Tests

The project uses `cw-multi-test` for integration testing:

```bash
# Build tests
make build_tests

# Run integration tests
cargo test --features library
```

### Code Quality Checks

```bash
# Linting
cargo clippy -- -D warnings

# Formatting check
cargo fmt --check

# Format code
cargo fmt

# Security audit
cargo audit
```

### Coverage Report (Optional)

```bash
# Install tarpaulin
cargo install cargo-tarpaulin

# Generate coverage
cargo tarpaulin --out Html --output-dir coverage
```

---

## Local Testing Environment

### Setup Local Chain

The project includes Docker configuration for local C4E chain testing:

```bash
# Build local chain Docker image
make build-c4e-chain-docker

# Prepare chain configuration
make prepare_chain

# Run local 4-node chain
make run_chain
```

The local chain will expose RPC on:
- Node 1: http://localhost:31657
- Node 2-4: Internal network only

### Stop Local Chain

```bash
# Stop and clean up
make stop_chain

# Clean chain data
make clean_prepare_chain
```

---

## Deployment Process

### Step 1: Store Contract Code

Upload the optimized WASM binary to the blockchain:

```bash
# Store code
c4ed tx wasm store artifacts/linkage_contract.wasm \
  --from $ADMIN_WALLET \
  --gas auto \
  --gas-adjustment 1.3 \
  --gas-prices 0.025uc4e \
  --chain-id $CHAIN_ID \
  --node $NODE_URL \
  --broadcast-mode block \
  -y

# Alternative: using script
./scripts/deploy_contract.sh store
```

**Expected Output**:
```json
{
  "code_id": 42,
  "txhash": "ABC123...",
  ...
}
```

Note the `code_id` for the next step.

### Step 2: Query Code Info

Verify the stored code:

```bash
# Get code info
c4ed query wasm code-info <code_id> --node $NODE_URL

# List all codes
c4ed query wasm list-code --node $NODE_URL
```

### Step 3: Instantiate Contract

Create an instance of the contract:

```bash
# Prepare instantiate message
INIT_MSG='{
  "admins": ["c4e1admin1address...", "c4e1admin2address..."],
  "authorized_nft_contracts": ["c4e1nftcontract1..."]
}'

# Instantiate
c4ed tx wasm instantiate <code_id> "$INIT_MSG" \
  --from $ADMIN_WALLET \
  --label "linkage-contract-v0.1.0" \
  --admin <admin_address> \
  --gas auto \
  --gas-adjustment 1.3 \
  --gas-prices 0.025uc4e \
  --chain-id $CHAIN_ID \
  --node $NODE_URL \
  --broadcast-mode block \
  -y

# Alternative: using script
./scripts/deploy_contract.sh instantiate <code_id>
```

**Parameters**:
- `<code_id>`: Code ID from Step 1
- `--label`: Human-readable label for the instance
- `--admin`: Address that can migrate the contract (optional)

### Step 4: Get Contract Address

Query the instantiated contract address:

```bash
# List contracts by code
c4ed query wasm list-contract-by-code <code_id> --node $NODE_URL

# Or from transaction hash
c4ed query tx <tx_hash> --node $NODE_URL | jq -r '.logs[0].events[] | select(.type=="instantiate") | .attributes[] | select(.key=="_contract_address") | .value'
```

Save the contract address for future interactions.

### Step 5: Verify Deployment

Query the contract to verify successful deployment:

```bash
# Get admins
c4ed query wasm contract-state smart <contract_address> \
  '{"get_admins":{}}' \
  --node $NODE_URL

# Get authorized contracts
c4ed query wasm contract-state smart <contract_address> \
  '{"get_authorized_nft_contracts":{}}' \
  --node $NODE_URL
```

---

## Post-Deployment Configuration

### Add Additional Admins

```bash
ADD_ADMIN_MSG='{
  "add_admin": {
    "new_admin": "c4e1newadminaddress..."
  }
}'

c4ed tx wasm execute <contract_address> "$ADD_ADMIN_MSG" \
  --from $ADMIN_WALLET \
  --gas auto \
  --gas-adjustment 1.3 \
  --gas-prices 0.025uc4e \
  --chain-id $CHAIN_ID \
  --node $NODE_URL \
  -y
```

### Authorize NFT Contracts

```bash
AUTH_CONTRACT_MSG='{
  "add_authorized_nft_contract": {
    "nft_contract_address": "c4e1nftcontractaddress..."
  }
}'

c4ed tx wasm execute <contract_address> "$AUTH_CONTRACT_MSG" \
  --from $ADMIN_WALLET \
  --gas auto \
  --gas-adjustment 1.3 \
  --gas-prices 0.025uc4e \
  --chain-id $CHAIN_ID \
  --node $NODE_URL \
  -y
```

---

## Testing Deployed Contract

### Lock an NFT

```bash
# From NFT contract perspective
SEND_NFT_MSG='{
  "send_nft": {
    "contract": "<linkage_contract_address>",
    "token_id": "token_123",
    "msg": "'$(echo -n "did:c4e:alice123" | base64)'"
  }
}'

c4ed tx wasm execute <nft_contract_address> "$SEND_NFT_MSG" \
  --from $USER_WALLET \
  --gas auto \
  --gas-adjustment 1.3 \
  --gas-prices 0.025uc4e \
  --chain-id $CHAIN_ID \
  --node $NODE_URL \
  -y
```

### Query Locked NFT

```bash
# Query specific NFT
QUERY_NFT='{
  "get_locked_nft": {
    "contract_address": "<nft_contract_address>",
    "token_id": "token_123"
  }
}'

c4ed query wasm contract-state smart <contract_address> "$QUERY_NFT" --node $NODE_URL

# Query by owner
QUERY_OWNER='{
  "get_locked_nfts_by_owner": {
    "owner": "<owner_address>"
  }
}'

c4ed query wasm contract-state smart <contract_address> "$QUERY_OWNER" --node $NODE_URL

# Query by DID
QUERY_DID='{
  "get_locked_nfts_by_did": {
    "did": "did:c4e:alice123"
  }
}'

c4ed query wasm contract-state smart <contract_address> "$QUERY_DID" --node $NODE_URL
```

### Unlock NFT

```bash
UNLOCK_MSG='{
  "unlock_nft": {
    "contract_address": "<nft_contract_address>",
    "token_id": "token_123"
  }
}'

c4ed tx wasm execute <contract_address> "$UNLOCK_MSG" \
  --from $OWNER_WALLET \
  --gas auto \
  --gas-adjustment 1.3 \
  --gas-prices 0.025uc4e \
  --chain-id $CHAIN_ID \
  --node $NODE_URL \
  -y
```

---

## Contract Migration

### Prepare New Version

1. Update contract code
2. Increment version in `Cargo.toml`
3. Run full test suite
4. Build optimized WASM
5. Audit changes (if production)

### Migration Process

```bash
# 1. Store new code
c4ed tx wasm store artifacts/linkage_contract.wasm \
  --from $ADMIN_WALLET \
  --gas auto \
  --gas-adjustment 1.3 \
  --gas-prices 0.025uc4e \
  --chain-id $CHAIN_ID \
  --node $NODE_URL \
  -y

# 2. Migrate contract (if admin set during instantiation)
MIGRATE_MSG='{}'  # Empty for this contract

c4ed tx wasm migrate <contract_address> <new_code_id> "$MIGRATE_MSG" \
  --from $ADMIN_WALLET \
  --gas auto \
  --gas-adjustment 1.3 \
  --gas-prices 0.025uc4e \
  --chain-id $CHAIN_ID \
  --node $NODE_URL \
  -y
```

**Note**: This contract currently doesn't implement migrate functionality. For upgrades, deploy a new instance and migrate state manually.

---

## Monitoring & Maintenance

### Query Contract State

```bash
# Get contract info
c4ed query wasm contract <contract_address> --node $NODE_URL

# Get contract history
c4ed query wasm contract-history <contract_address> --node $NODE_URL

# Get all contract state (raw)
c4ed query wasm contract-state all <contract_address> --node $NODE_URL
```

### Monitor Events

```bash
# Query transactions for contract
c4ed query txs --events "wasm._contract_address=<contract_address>" --node $NODE_URL

# Filter by event type
c4ed query txs --events "wasm.action=receive_nft" --node $NODE_URL
```

### Performance Metrics

Monitor these metrics:
- Number of locked NFTs
- Number of unique owners
- Number of unique DIDs
- Admin count
- Authorized contract count
- Average gas usage per operation

---

## Troubleshooting

### Build Issues

**Problem**: WASM target not found
```bash
rustup target add wasm32-unknown-unknown
```

**Problem**: Optimizer fails
```bash
# Clean Docker volumes
docker volume rm linkage_contract_cache
docker volume rm registry_cache

# Retry optimization
make optimize
```

### Deployment Issues

**Problem**: "Insufficient fees"
```bash
# Increase gas prices
--gas-prices 0.05uc4e
```

**Problem**: "Out of gas"
```bash
# Increase gas adjustment
--gas-adjustment 1.5
```

**Problem**: "Contract address already exists"
- Use different label or
- Check if contract already instantiated

### Runtime Issues

**Problem**: "Unauthorized" error
- Verify caller is admin (for admin operations)
- Verify caller is owner (for unlock operations)
- Verify contract is authorized (for receive_nft)

**Problem**: "NFT not found"
- Verify NFT is actually locked
- Check contract address and token_id are correct
- Query contract state to confirm

**Problem**: "DID invalid"
- Verify DID format: `did:c4e:<identifier>`
- Check DID encoding (must be UTF-8 in binary)

---

## Security Checklist

Before deploying to production:

- [ ] Full test suite passes
- [ ] Code reviewed by multiple developers
- [ ] Security audit completed (for production)
- [ ] Optimized build generated on Intel processor
- [ ] WASM binary verified with cosmwasm-check
- [ ] Admin keys secured (hardware wallet recommended)
- [ ] Backup of private keys stored securely
- [ ] Deployment tested on testnet
- [ ] Gas costs estimated and acceptable
- [ ] Monitoring system in place
- [ ] Emergency procedures documented
- [ ] Rollback plan prepared

---

## Deployment Checklist

- [ ] Prerequisites installed
- [ ] Environment configured
- [ ] Contract built and optimized
- [ ] Tests passing (100% success rate)
- [ ] Code stored on chain
- [ ] Code ID recorded
- [ ] Contract instantiated
- [ ] Contract address recorded
- [ ] Initial configuration complete
- [ ] Admin wallet secured
- [ ] Test transactions successful
- [ ] Monitoring configured
- [ ] Documentation updated

---

## Network Configurations

### C4E Testnet

```bash
CHAIN_ID="babajaga-1"
NODE_URL="https://rpc-testnet.c4e.io:443"
GAS_PRICES="0.025uc4e"
```

### C4E Mainnet

```bash
CHAIN_ID="perun-1"
NODE_URL="https://rpc.c4e.io:443"
GAS_PRICES="0.025uc4e"
```

### Local Development

```bash
CHAIN_ID="c4e-local"
NODE_URL="http://localhost:31657"
GAS_PRICES="0.025uc4e"
```

---

## Scripts Reference

### Available Make Targets

```bash
make build              # Standard cargo build
make build_tests        # Build test suite
make optimize           # Optimize WASM for production
make check-contract     # Verify WASM binary
make clean              # Clean build artifacts
make expand             # Expand macros for debugging

# Local chain management
make build-c4e-chain-docker  # Build chain Docker image
make prepare_chain           # Prepare chain config
make run_chain               # Start local chain
make stop_chain              # Stop local chain
make clean_prepare_chain     # Clean chain data

# Dependencies
make update_cargo_dependencies  # Update Cargo.lock
```

### Deployment Scripts

Create `scripts/deploy_contract.sh`:

```bash
#!/bin/bash
set -e

COMMAND=$1
CODE_ID=$2

case $COMMAND in
  store)
    c4ed tx wasm store artifacts/linkage_contract.wasm \
      --from $ADMIN_WALLET \
      --gas auto \
      --gas-adjustment 1.3 \
      --gas-prices 0.025uc4e \
      --chain-id $CHAIN_ID \
      --node $NODE_URL \
      --broadcast-mode block \
      -y
    ;;
  instantiate)
    INIT_MSG='{"admins":["'$ADMIN_ADDRESS'"],"authorized_nft_contracts":[]}'
    c4ed tx wasm instantiate $CODE_ID "$INIT_MSG" \
      --from $ADMIN_WALLET \
      --label "linkage-contract" \
      --admin $ADMIN_ADDRESS \
      --gas auto \
      --gas-adjustment 1.3 \
      --gas-prices 0.025uc4e \
      --chain-id $CHAIN_ID \
      --node $NODE_URL \
      --broadcast-mode block \
      -y
    ;;
  *)
    echo "Usage: $0 {store|instantiate} [code_id]"
    exit 1
    ;;
esac
```

Make executable:
```bash
chmod +x scripts/deploy_contract.sh
```

---

## Best Practices

### Development
- Always test locally before deploying to testnet
- Use feature flags for optional functionality
- Keep dependencies up to date
- Run security audits regularly
- Document all changes

### Deployment
- Deploy to testnet first
- Use deterministic builds (Intel processor)
- Verify checksums match
- Keep detailed deployment logs
- Monitor gas costs

### Operations
- Use hardware wallets for admin keys
- Implement multi-sig for critical operations
- Monitor contract events regularly
- Have rollback procedures ready
- Document all admin actions

---

**Document Version**: 1.0  
**Last Updated**: November 10, 2025  
**Contract Version**: 0.1.0
