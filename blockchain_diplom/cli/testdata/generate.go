//go:build ignore
// +build ignore

// generate.go - creates real test data with EdDSA keys and valid Merkle tree
package main

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"os"

	"github.com/iden3/go-iden3-crypto/babyjub"
	"github.com/iden3/go-iden3-crypto/poseidon"
)

const sampleIssuerPrivateKeyHex = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
const sampleBankIssuerPrivateKeyHex = "1f1e1d1c1b1a191817161514131211100f0e0d0c0b0a09080706050403020100"
const registrySaltHex = "4444444444444444444444444444444444444444444444444444444444444444"

func main() {
	// 1. Build a deterministic issuer EdDSA keypair for reproducible fixtures.
	issuerPrivKey := fixedIssuerPrivateKey()
	issuerPubKey := issuerPrivKey.Public()
	fmt.Printf("Issuer pubkey X: %s\n", issuerPubKey.X.String())
	fmt.Printf("Issuer pubkey Y: %s\n", issuerPubKey.Y.String())

	// 2. Create credential data
	birthDateDays := big.NewInt(11323) // ~2001-01-01
	bnPrime, _ := new(big.Int).SetString("21888242871839275222246405745257275088548364400416034343698204186575808495617", 10)
	schemaHash := new(big.Int).Mod(hexToBig("0x1111111111111111111111111111111111111111111111111111111111111111"), bnPrime)
	holderSecret := hexToBig("0x00deadbeef00000000000000000000000000000000000000000000000000001")
	holderBinding, _ := poseidon.Hash([]*big.Int{holderSecret, schemaHash})
	signedClaim, _ := poseidon.Hash([]*big.Int{birthDateDays, holderBinding})

	// 3. Compute credential hash = Poseidon(pubkey_x, pubkey_y, signed_claim, schema_hash)
	credHash, _ := poseidon.Hash([]*big.Int{issuerPubKey.X, issuerPubKey.Y, signedClaim, schemaHash})
	fmt.Printf("Credential hash: %s\n", credHash.String())

	// 4. Sign credential hash with EdDSA
	sig := issuerPrivKey.SignPoseidon(credHash)
	fmt.Printf("Sig R8.X: %s\n", sig.R8.X.String())
	fmt.Printf("Sig R8.Y: %s\n", sig.R8.Y.String())
	fmt.Printf("Sig S: %s\n", sig.S.String())

	// Verify signature locally
	ok := issuerPubKey.VerifyPoseidon(credHash, sig)
	fmt.Printf("Signature valid: %v\n", ok)
	if !ok {
		fmt.Println("ERROR: signature verification failed!")
		os.Exit(1)
	}

	// 5. Build Merkle tree with this issuer
	// leaf = Poseidon(pubkey_x, pubkey_y)
	leaf, _ := poseidon.Hash([]*big.Int{issuerPubKey.X, issuerPubKey.Y})
	fmt.Printf("Leaf: 0x%064x\n", leaf)

	// Build tree depth=16 with 1 real leaf + padding zeros
	const depth = 16
	const maxLeaves = 1 << depth
	leaves := make([]*big.Int, maxLeaves)
	leaves[0] = leaf
	for i := 1; i < maxLeaves; i++ {
		leaves[i] = big.NewInt(0)
	}

	levels := make([][]*big.Int, depth+1)
	levels[0] = leaves
	for d := 0; d < depth; d++ {
		prev := levels[d]
		next := make([]*big.Int, len(prev)/2)
		for i := 0; i < len(next); i++ {
			h, _ := poseidon.Hash([]*big.Int{prev[2*i], prev[2*i+1]})
			next[i] = h
		}
		levels[d+1] = next
	}
	root := levels[depth][0]
	fmt.Printf("Merkle root: 0x%064x\n", root)

	// Get merkle path for leaf 0
	merklePath := make([]string, depth)
	merkleIndexBits := make([]int, depth)
	idx := 0
	for d := 0; d < depth; d++ {
		if idx%2 == 0 {
			merklePath[d] = levels[d][idx+1].String()
			merkleIndexBits[d] = 0
		} else {
			merklePath[d] = levels[d][idx-1].String()
			merkleIndexBits[d] = 1
		}
		idx /= 2
	}

	// 6. Compute subject_tag
	verifierIDHash := new(big.Int).Mod(hexToBig("0x2222222222222222222222222222222222222222222222222222222222222222"), bnPrime)
	factTypeHash := new(big.Int).Mod(hexToBig("0x3333333333333333333333333333333333333333333333333333333333333333"), bnPrime)

	subjectTag, _ := poseidon.Hash([]*big.Int{holderSecret, verifierIDHash})

	fmt.Printf("Subject tag: 0x%064x\n", subjectTag)

	cutoffDateDays := uint64(13879) // ~2008-01-01 (18 years before ~2026)

	// 7. Write credential.json
	credential := map[string]interface{}{
		"version":       "1.0",
		"credential_id": "urn:uuid:test-cred-001",
		"type":          []string{"VerifiableCredential", "AgeCredential"},
		"issuer": map[string]string{
			"did":      "did:web:gov.example.ru",
			"kid":      "zk-key-1",
			"pubkey_x": fmt.Sprintf("0x%064x", issuerPubKey.X),
			"pubkey_y": fmt.Sprintf("0x%064x", issuerPubKey.Y),
		},
		"subject": map[string]string{
			"did":                "did:key:holder-test-001",
			"binding_commitment": fmt.Sprintf("0x%064x", holderBinding),
		},
		"issuance_date":   "2026-03-01T09:00:00Z",
		"expiration_date": "2031-03-01T09:00:00Z",
		"schema_id":       "vc.age.v1",
		"schema_hash":     fmt.Sprintf("0x%064x", schemaHash),
		"claims": map[string]interface{}{
			"birth_date_days": 11323,
		},
		"revocation": map[string]interface{}{
			"status_list_id": "revocation-list-2026-03",
			"status_index":   481,
		},
		"signature": map[string]string{
			"alg": "eddsa-bn254-poseidon",
			"r8x": fmt.Sprintf("0x%064x", sig.R8.X),
			"r8y": fmt.Sprintf("0x%064x", sig.R8.Y),
			"s":   fmt.Sprintf("0x%064x", sig.S),
		},
	}
	must(writeJSON("credential.json", credential))

	// 8. Write issuer_policy.json
	issuerPolicy := map[string]interface{}{
		"version":   "1.0",
		"policy_id": "age-ru-2026-03",
		"hash_alg":  "poseidon",
		"depth":     depth,
		"root":      fmt.Sprintf("0x%064x", root),
		"issuers": []map[string]string{
			{
				"issuer_id":   "did:web:gov.example.ru",
				"pubkey_hash": fmt.Sprintf("0x%064x", leaf),
				"leaf":        fmt.Sprintf("0x%064x", leaf),
			},
		},
	}
	must(writeJSON("issuer_policy.json", issuerPolicy))

	// 9. Write verification_request.json
	request := map[string]interface{}{
		"version":          "1.0",
		"request_id":       "urn:uuid:req-test-001",
		"verifier_id":      "did:web:shop.example.com",
		"verifier_id_hash": fmt.Sprintf("0x%064x", verifierIDHash),
		"fact_type":        "age_over_18",
		"fact_type_hash":   fmt.Sprintf("0x%064x", factTypeHash),
		"purpose":          "age_check",
		"issued_at":        "2026-03-30T10:00:00Z",
		"expires_at":       "2027-03-30T10:05:00Z",
		"schema_id":        "vc.age.v1",
		"schema_hash":      fmt.Sprintf("0x%064x", schemaHash),
		"circuit_id":       "age_over_18_v1",
		"predicate": map[string]interface{}{
			"type":             "birth_date_lte_cutoff",
			"cutoff_date_days": cutoffDateDays,
		},
		"issuer_policy": map[string]interface{}{
			"root":           fmt.Sprintf("0x%064x", root),
			"snapshot_block": 0,
			"issuers": []map[string]string{
				{
					"issuer_id":   "did:web:gov.example.ru",
					"pubkey_hash": fmt.Sprintf("0x%064x", leaf),
					"leaf":        fmt.Sprintf("0x%064x", leaf),
				},
			},
		},
		"chain": map[string]interface{}{
			"chain_id":              31337,
			"fact_registry_address": "0x0000000000000000000000000000000000000000",
		},
		"response": map[string]string{
			"mode":         "https_post",
			"callback_url": "https://shop.example.com/api/zk/notify",
		},
	}
	must(writeJSON("verification_request.json", request))

	// 10. Additional example: a bank/KYC provider issues the same age fact.
	// It uses a shared two-issuer policy root, so the public root no longer
	// identifies the exact issuer by itself.
	bankIssuerPrivKey := fixedPrivateKey(sampleBankIssuerPrivateKeyHex)
	bankIssuerPubKey := bankIssuerPrivKey.Public()
	bankCredHash, _ := poseidon.Hash([]*big.Int{bankIssuerPubKey.X, bankIssuerPubKey.Y, signedClaim, schemaHash})
	bankSig := bankIssuerPrivKey.SignPoseidon(bankCredHash)
	bankOK := bankIssuerPubKey.VerifyPoseidon(bankCredHash, bankSig)
	fmt.Printf("Bank signature valid: %v\n", bankOK)
	if !bankOK {
		fmt.Println("ERROR: bank signature verification failed!")
		os.Exit(1)
	}

	bankLeaf, _ := poseidon.Hash([]*big.Int{bankIssuerPubKey.X, bankIssuerPubKey.Y})
	fmt.Printf("Bank leaf: 0x%064x\n", bankLeaf)

	multiLeaves := make([]*big.Int, maxLeaves)
	multiLeaves[0] = leaf
	multiLeaves[1] = bankLeaf
	for i := 2; i < maxLeaves; i++ {
		multiLeaves[i] = big.NewInt(0)
	}

	multiLevels := make([][]*big.Int, depth+1)
	multiLevels[0] = multiLeaves
	for d := 0; d < depth; d++ {
		prev := multiLevels[d]
		next := make([]*big.Int, len(prev)/2)
		for i := 0; i < len(next); i++ {
			h, _ := poseidon.Hash([]*big.Int{prev[2*i], prev[2*i+1]})
			next[i] = h
		}
		multiLevels[d+1] = next
	}
	multiRoot := multiLevels[depth][0]
	fmt.Printf("Multi-issuer Merkle root: 0x%064x\n", multiRoot)

	registrySalt := new(big.Int).Mod(hexToBig(registrySaltHex), bnPrime)
	registryCommitment, _ := poseidon.Hash([]*big.Int{multiRoot, registrySalt})
	contextHash, _ := poseidon.Hash([]*big.Int{
		verifierIDHash,
		factTypeHash,
		new(big.Int).SetUint64(cutoffDateDays),
		registryCommitment,
	})
	subjectTag, _ = poseidon.Hash([]*big.Int{holderSecret, contextHash})
	fmt.Printf("Registry commitment: 0x%064x\n", registryCommitment)
	fmt.Printf("Context hash: 0x%064x\n", contextHash)
	fmt.Printf("Context-scoped subject tag: 0x%064x\n", subjectTag)

	multiMerklePath := make([]string, depth)
	multiMerkleIndexBits := make([]int, depth)
	idx = 0
	for d := 0; d < depth; d++ {
		if idx%2 == 0 {
			multiMerklePath[d] = multiLevels[d][idx+1].String()
			multiMerkleIndexBits[d] = 0
		} else {
			multiMerklePath[d] = multiLevels[d][idx-1].String()
			multiMerkleIndexBits[d] = 1
		}
		idx /= 2
	}

	bankCredential := map[string]interface{}{
		"version":       "1.0",
		"credential_id": "urn:uuid:test-cred-bank-001",
		"type":          []string{"VerifiableCredential", "AgeOver18Credential", "KycAgeCredential"},
		"issuer": map[string]string{
			"did":      "did:web:bank.example.ru",
			"kid":      "zk-kyc-age-key-1",
			"pubkey_x": fmt.Sprintf("0x%064x", bankIssuerPubKey.X),
			"pubkey_y": fmt.Sprintf("0x%064x", bankIssuerPubKey.Y),
		},
		"subject": map[string]string{
			"did":                "did:key:holder-test-001",
			"binding_commitment": fmt.Sprintf("0x%064x", holderBinding),
		},
		"issuance_date":   "2026-03-02T09:00:00Z",
		"expiration_date": "2031-03-02T09:00:00Z",
		"schema_id":       "vc.age.v1",
		"schema_hash":     fmt.Sprintf("0x%064x", schemaHash),
		"claims": map[string]interface{}{
			"birth_date_days": birthDateDays.Uint64(),
		},
		"revocation": map[string]interface{}{
			"status_list_id": "bank-kyc-age-revocation-2026-03",
			"status_index":   915,
		},
		"signature": map[string]string{
			"alg": "eddsa-bn254-poseidon",
			"r8x": fmt.Sprintf("0x%064x", bankSig.R8.X),
			"r8y": fmt.Sprintf("0x%064x", bankSig.R8.Y),
			"s":   fmt.Sprintf("0x%064x", bankSig.S),
		},
	}
	must(writeJSON("credential_bank.json", bankCredential))

	multiIssuerEntries := []map[string]string{
		{
			"issuer_id":   "did:web:gov.example.ru",
			"pubkey_hash": fmt.Sprintf("0x%064x", leaf),
			"leaf":        fmt.Sprintf("0x%064x", leaf),
		},
		{
			"issuer_id":   "did:web:bank.example.ru",
			"pubkey_hash": fmt.Sprintf("0x%064x", bankLeaf),
			"leaf":        fmt.Sprintf("0x%064x", bankLeaf),
		},
	}

	multiIssuerPolicy := map[string]interface{}{
		"version":             "1.0",
		"policy_id":           "age-trusted-issuers-2026-03",
		"hash_alg":            "poseidon",
		"depth":               depth,
		"root":                fmt.Sprintf("0x%064x", multiRoot),
		"commitment_salt":     fmt.Sprintf("0x%064x", registrySalt),
		"registry_commitment": fmt.Sprintf("0x%064x", registryCommitment),
		"issuers":             multiIssuerEntries,
	}
	must(writeJSON("issuer_policy.json", multiIssuerPolicy))
	must(writeJSON("issuer_policy_multi.json", multiIssuerPolicy))

	multiIssuerRequest := map[string]interface{}{
		"version":          "1.0",
		"request_id":       "urn:uuid:req-test-bank-001",
		"verifier_id":      "did:web:shop.example.com",
		"verifier_id_hash": fmt.Sprintf("0x%064x", verifierIDHash),
		"fact_type":        "age_over_18",
		"fact_type_hash":   fmt.Sprintf("0x%064x", factTypeHash),
		"purpose":          "age_check",
		"issued_at":        "2026-03-30T10:00:00Z",
		"expires_at":       "2027-03-30T10:05:00Z",
		"schema_id":        "vc.age.v1",
		"schema_hash":      fmt.Sprintf("0x%064x", schemaHash),
		"circuit_id":       "age_over_18_v1",
		"predicate": map[string]interface{}{
			"type":             "birth_date_lte_cutoff",
			"cutoff_date_days": cutoffDateDays,
		},
		"issuer_policy": map[string]interface{}{
			"registry_commitment": fmt.Sprintf("0x%064x", registryCommitment),
			"snapshot_block":      0,
		},
		"chain": map[string]interface{}{
			"chain_id":              31337,
			"fact_registry_address": "0x0000000000000000000000000000000000000000",
		},
		"response": map[string]string{
			"mode":         "https_post",
			"callback_url": "https://shop.example.com/api/zk/notify",
		},
	}
	must(writeJSON("verification_request.json", multiIssuerRequest))
	must(writeJSON("verification_request_multi_issuer.json", multiIssuerRequest))

	// 11. Write Prover.toml directly for nargo test
	proverToml := fmt.Sprintf(`[credential]
birth_date_days = "%d"
holder_secret = "%s"

[issuer]
issuer_pubkey_x = "%s"
issuer_pubkey_y = "%s"
signature_r_x = "%s"
signature_r_y = "%s"
signature_s = "%s"
`, birthDateDays.Uint64(),
		holderSecret.String(),
		issuerPubKey.X.String(),
		issuerPubKey.Y.String(),
		sig.R8.X.String(),
		sig.R8.Y.String(),
		sig.S.String(),
	)

	proverToml += "issuer_policy_path = ["
	for i := 0; i < depth; i++ {
		proverToml += fmt.Sprintf(`"%s"`, multiMerklePath[i])
		if i < depth-1 {
			proverToml += ", "
		}
	}
	proverToml += "]\n"

	proverToml += "issuer_policy_path_indices = ["
	for i := 0; i < depth; i++ {
		proverToml += fmt.Sprintf(`"%d"`, multiMerkleIndexBits[i])
		if i < depth-1 {
			proverToml += ", "
		}
	}
	proverToml += "]\n"

	proverToml += fmt.Sprintf(`
[request]
verifier_id_hash = "%s"
fact_type_hash = "%s"
issuer_policy_root = "%s"
registry_salt = "%s"
cutoff_date_days = "%d"

[context]
context_hash = "%s"
registry_commitment = "%s"
subject_tag = "%s"
`,
		verifierIDHash.String(),
		factTypeHash.String(),
		multiRoot.String(),
		registrySalt.String(),
		cutoffDateDays,
		contextHash.String(),
		registryCommitment.String(),
		subjectTag.String(),
	)

	must(os.WriteFile("../../circuits/age_over_18_v1/Prover.toml", []byte(proverToml), 0644))
	fmt.Println("\nAll test data generated successfully!")
	fmt.Println("Files: credential.json, issuer_policy.json, verification_request.json")
	fmt.Println("Also: ../../circuits/age_over_18_v1/Prover.toml")
}

func fixedIssuerPrivateKey() babyjub.PrivateKey {
	return fixedPrivateKey(sampleIssuerPrivateKeyHex)
}

func fixedPrivateKey(keyHex string) babyjub.PrivateKey {
	raw, err := hex.DecodeString(keyHex)
	if err != nil {
		panic(err)
	}
	var key babyjub.PrivateKey
	copy(key[:], raw)
	return key
}

func hexToBig(h string) *big.Int {
	if len(h) >= 2 && h[:2] == "0x" {
		h = h[2:]
	}
	v := new(big.Int)
	v.SetString(h, 16)
	return v
}

func writeJSON(path string, data interface{}) error {
	b, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal %s: %w", path, err)
	}
	if err := os.WriteFile(path, b, 0644); err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	fmt.Printf("Written: %s\n", path)
	return nil
}

func must(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
