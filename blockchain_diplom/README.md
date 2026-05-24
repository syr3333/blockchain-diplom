# Anonymous Fact Verification System

Universal Zero-Knowledge proof system for anonymous fact verification. Prove any fact about yourself (age, income, qualification, citizenship) without revealing personal data.

**Stack:** Go · Noir · Barretenberg · Hardhat · Solidity · Docker

---

## Quick Start (Docker)

### Prerequisites
- [Docker Desktop](https://www.docker.com/products/docker-desktop/) installed and running
- [Go](https://go.dev/dl/) 1.24+
- [Node.js](https://nodejs.org/) 22+ for manual Hardhat usage
- [Noir](https://noir-lang.org/) + [Barretenberg](https://github.com/AztecProtocol/barretenberg)

### Step 0: Install Noir & Barretenberg

```bash
# Noir (ZK circuit compiler)
curl -L https://raw.githubusercontent.com/noir-lang/noirup/refs/heads/main/install | bash
source ~/.zshrc && noirup

# Barretenberg (proving backend)
curl -L https://raw.githubusercontent.com/AztecProtocol/aztec-packages/master/barretenberg/bbup/install | bash
source ~/.zshrc && bbup

# Verify
nargo --version   # Expected: 1.0.0-beta.19
bb --version      # Expected: 4.0.0-nightly.*
```

### Step 1: Generate test data and ZK proof

```bash
# Generate test credentials (EdDSA keypair, signed credential, Merkle tree)
cd cli
go mod tidy
cd testdata && go run generate.go
cd ../..

# Compile ZK circuit
cd circuits/age_over_18_v1
nargo compile
nargo execute

# Generate EVM-compatible proof
mkdir -p target_evm
bb write_vk -b ./target/age_over_18_v1.json -o ./target_evm -t evm
bb prove -b ./target/age_over_18_v1.json -w ./target/age_over_18_v1.gz \
  -o ./target_evm/proof -k ./target_evm/vk -t evm
cd ../..
```

### Step 2: Start all services in Docker

```bash
docker compose up --build -d
```

Three services will start:

| Service | Port | Description |
|---------|------|-------------|
| **hardhat** | 8545 | Local Ethereum blockchain |
| **deployer** | — | Deploys contracts + submits proof (one-shot, exits after) |
| **verifier** | 8080 | Verifier web UI + backend with on-chain lookup |

Wait ~60 seconds, then check logs:

```bash
docker compose logs deployer
```

You should see:

```
deployer-1  | Proof submitted! TX: 0x...
deployer-1  | Subject tag: 0x03d6...
deployer-1  | === Deploy complete ===
```

### Step 3: Verify the fact

Open **http://localhost:8080** in your browser.

The form has 3 fields. **Verifier ID Hash** is pre-filled. Enter:

| Field | Value |
|-------|-------|
| **Subject Tag** | `0x03d637250e8c93e4f7789c830d1347ccc13e323e511e5bc4e51f26f44c39cbc9` |
| **Fact Type Hash** | `0x02cee4c0520193097ae2ed7cb1b1dad60aff4aeab979c2a1ef513d9f43333332` |

Click **Lookup Fact On-Chain** → **FACT FOUND**.

The verifier confirmed the fact exists on-chain without ever seeing the birth date.

You can also verify via curl:

```bash
curl -s "http://localhost:8080/api/lookup?\
verifier_id_hash=0x2222222222222222222222222222222222222222222222222222222222222222&\
subject_tag=0x03d637250e8c93e4f7789c830d1347ccc13e323e511e5bc4e51f26f44c39cbc9&\
fact_type_hash=0x02cee4c0520193097ae2ed7cb1b1dad60aff4aeab979c2a1ef513d9f43333332" | python3 -m json.tool
```

Expected: `"exists": true`

### Step 4: Stop

```bash
docker compose down -v
```

---

## How It Works

```
Issuer                     Holder                      Blockchain              Verifier
┌────────────────┐         ┌─────────────────┐         ┌─────────────────┐     ┌─────────────────┐
│ Verify real     │─cred──>│ Generate ZK      │─tx────>│ HonkVerifier    │     │ Receive          │
│ documents       │        │ proof (Noir+BB)  │        │ checks proof    │     │ subject_tag      │
│ Sign with EdDSA │        │                  │        │                 │     │                  │
└────────────────┘         │ Private:         │        │ FactRegistry    │     │ Query blockchain │
                           │  birth_date      │        │ stores fact     │────>│ by fact_key      │
                           │  holder_secret   │        │ checks fact_key │     │                  │
                           │  issuer_identity │        └─────────────────┘     │ FACT FOUND /     │
                           │                  │                                │ NOT FOUND        │
                           │ Public:          │                                └─────────────────┘
                           │  verifier_id_hash│
                           │  subject_tag     │
                           │  fact_type_hash  │
                           │  cutoff_date     │
                           └─────────────────┘
```

### Privacy guarantees

- **Zero-knowledge**: verifier never sees birth date, passport, or any personal data
- **Unlinkability**: each verifier gets a unique pseudonym (`subject_tag = Poseidon(holder_secret, verifier_id_hash)`) — cannot track user across services
- **Replay protection**: `factKey = keccak256(verifier_id_hash || subject_tag || fact_type_hash)` prevents submitting the same verified fact twice
- **Issuer privacy**: verifier doesn't learn which specific issuer signed the credential; issuer policy root is fixed inside the circuit instead of returned as a public input
- **Issuer trust**: the circuit accepts only issuers included in the embedded trusted Merkle policy root
- **On-chain minimal data**: blockchain stores only the lookup result; no credential, issuer key, schema hash, policy root, or public nullifier is stored
- **Relayer privacy**: the transaction sender pays gas but is not stored in the verified fact, event payload, API response, or UI

See [`docs/public_inputs_privacy.md`](docs/public_inputs_privacy.md) for the public input audit and issuer-linkability notes.

### ZK circuit checks (4 assertions)

1. **Predicate**: `birth_date_days <= cutoff_date_days` (age check)
2. **EdDSA signature**: credential and Holder binding are authentically signed by a trusted issuer
3. **Merkle inclusion**: issuer's public key is in the trusted policy tree (depth 16)
4. **subject_tag**: correctly derived from holder_secret + verifier_id

### Circuit input groups

`age_over_18_v1` groups Noir inputs by purpose instead of exposing one long argument list:

| Group | Visibility | Purpose |
|-------|------------|---------|
| `credential` | private | Birth date claim and Holder secret bound to the signed credential |
| `issuer` | private | Issuer public key, EdDSA signature parts, and Merkle path proving the issuer is trusted |
| `context` | public | Minimal values checked by the verifier contract: verifier id, fact type, subject tag, and age cutoff |

---

## Manual Setup (without Docker)

### Step 1: Generate test data
```bash
cd cli && go mod tidy
cd testdata && go run generate.go && cd ../..
```

### Step 2: Compile circuit & generate proof
```bash
cd circuits/age_over_18_v1
nargo compile && nargo execute
mkdir -p target_evm
bb write_vk -b ./target/age_over_18_v1.json -o ./target_evm -t evm
bb prove -b ./target/age_over_18_v1.json -w ./target/age_over_18_v1.gz \
  -o ./target_evm/proof -k ./target_evm/vk -t evm
bb write_solidity_verifier -k ./target_evm/vk \
  -o ../../blockchain/contracts/NoirVerifier.sol -t evm
cd ../..
```

### Step 3: Start blockchain & deploy contracts
```bash
cd blockchain && npm install

# Terminal 1: start local node
npm run node

# Terminal 2: deploy contracts + submit test proof
npm run deploy:seed
```

### Step 4: Start Verifier
```bash
cd site/backend
FACT_REGISTRY_ADDRESS=<address from deploy output> \
VERIFIER_ID_HASH=0x2222222222222222222222222222222222222222222222222222222222222222 \
ETHEREUM_RPC_URL=http://127.0.0.1:8545 \
go run main.go verifier.go
```

Open **http://localhost:8080** and lookup the fact.

### Step 5: CLI usage
```bash
cd cli && go build -o zk-verify ./cmd/main.go

cat > .env <<'EOF'
CREDENTIALS_FILE=testdata/credential.json
REQUEST_FILE=testdata/verification_request.json
POLICY_FILE=testdata/issuer_policy.json
HOLDER_SECRET=0x00deadbeef00000000000000000000000000000000000000000000000000001
NOIR_CIRCUIT_DIR=../circuits/age_over_18_v1
ETHEREUM_RPC_URL=http://127.0.0.1:8545
FACT_REGISTRY_ADDRESS=<address from deploy output>
RELAYER_PRIVATE_KEY=<local dev account private key>
CHAIN_ID=31337
EOF

./zk-verify import-credential --file testdata/credential.json

# Alternative issuer example: bank/KYC provider in a shared two-issuer policy
CREDENTIALS_FILE=testdata/credential_bank.json \
REQUEST_FILE=testdata/verification_request_multi_issuer.json \
POLICY_FILE=testdata/issuer_policy_multi.json \
./zk-verify prove

./zk-verify lookup-fact \
  --verifier-id-hash 0x2222222222222222222222222222222222222222222222222222222222222222 \
  --subject-tag 0x03d637250e8c93e4f7789c830d1347ccc13e323e511e5bc4e51f26f44c39cbc9 \
  --fact-type-hash 0x02cee4c0520193097ae2ed7cb1b1dad60aff4aeab979c2a1ef513d9f43333332
```

---

## Project Structure

```
anonymous-fact-verification/
├── circuits/age_over_18_v1/      Noir ZK circuit
│   ├── src/main.nr               Circuit logic (5 checks)
│   └── Nargo.toml                Dependencies (poseidon, eddsa)
├── blockchain/                   Hardhat + Solidity
│   ├── contracts/
│   │   ├── FactRegistry.sol      Verified fact storage + proof verification
│   │   └── NoirVerifier.sol      Auto-generated UltraHonk verifier (DO NOT EDIT)
│   ├── scripts/
│   │   ├── deploy-and-seed.ts    Deploy all contracts + submit test proof
│   │   └── test-e2e.ts           On-chain E2E test
│   └── Dockerfile
├── cli/                          Go CLI (Holder application)
│   ├── cmd/main.go               Subcommands: prove, submit-fact, lookup-fact
│   ├── internal/
│   │   ├── blockchain/           On-chain read/write (ethclient)
│   │   ├── prover/               Proof generation (nargo + bb)
│   │   ├── policy/               Poseidon Merkle tree (depth 16)
│   │   ├── creds/                Credential model
│   │   └── request/              Verification request model
│   └── testdata/                 Generated credentials, requests, and issuer policies
├── site/                         Verifier web application
│   ├── backend/                  Go HTTP server (on-chain fact lookup)
│   ├── frontend/                 HTML/JS/CSS
│   └── Dockerfile
├── docs/                         Public-input and privacy notes
├── docker-compose.yml            Run everything with one command
```

## Cryptography

| Primitive | Formula |
|-----------|---------|
| **subject_tag** | `Poseidon(holder_secret, verifier_id_hash)` |
| **holder_binding** | `Poseidon(holder_secret, schema_hash)` |
| **signed_claim** | `Poseidon(birth_date_days, holder_binding)` |
| **credential_hash** | `Poseidon(issuer_pubkey_x, issuer_pubkey_y, signed_claim, schema_hash)` |
| **fact_key** | `keccak256(verifier_id_hash || subject_tag || fact_type_hash)` |
| **merkle_leaf** | `Poseidon(issuer_pubkey_x, issuer_pubkey_y)` |

| Component | Details |
|-----------|---------|
| Hash function | Poseidon BN254 x5 (`go-iden3-crypto` = `noir-lang/poseidon` v0.2.6) |
| Signature | EdDSA on BabyJubJub (`go-iden3-crypto/babyjub` = `noir-lang/eddsa` v0.1.3) |
| Merkle tree | Depth 16, Poseidon hash, max 65536 issuers |
| Proving system | UltraHonk (Barretenberg), proof size ~9 KB |
| On-chain verification | Auto-generated Solidity verifier (HonkVerifier) |

## License

MIT
