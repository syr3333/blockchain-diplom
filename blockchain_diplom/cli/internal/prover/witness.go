package prover

import (
	"fmt"
	"math/big"

	"github.com/iden3/go-iden3-crypto/poseidon"
)

// ComputeRegistryCommitment = Poseidon(issuer_policy_root, registry_salt)
func ComputeRegistryCommitment(policyRoot, registrySalt *big.Int) (*big.Int, error) {
	result, err := poseidon.Hash([]*big.Int{policyRoot, registrySalt})
	if err != nil {
		return nil, fmt.Errorf("compute registry_commitment: %w", err)
	}
	return result, nil
}

// ComputeContextHash = Poseidon(verifier_id_hash, fact_type_hash, cutoff_date_days, registry_commitment)
func ComputeContextHash(verifierIDHash, factTypeHash *big.Int, cutoffDateDays uint64, registryCommitment *big.Int) (*big.Int, error) {
	result, err := poseidon.Hash([]*big.Int{
		verifierIDHash,
		factTypeHash,
		new(big.Int).SetUint64(cutoffDateDays),
		registryCommitment,
	})
	if err != nil {
		return nil, fmt.Errorf("compute context_hash: %w", err)
	}
	return result, nil
}

// ComputeSubjectTag = Poseidon(holder_secret, context_hash)
func ComputeSubjectTag(holderSecret, contextHash *big.Int) (*big.Int, error) {
	result, err := poseidon.Hash([]*big.Int{holderSecret, contextHash})
	if err != nil {
		return nil, fmt.Errorf("compute subject_tag: %w", err)
	}
	return result, nil
}

// ComputeSubjectBinding = Poseidon(holder_secret, schema_hash)
func ComputeSubjectBinding(holderSecret, schemaHash *big.Int) (*big.Int, error) {
	result, err := poseidon.Hash([]*big.Int{holderSecret, schemaHash})
	if err != nil {
		return nil, fmt.Errorf("compute subject binding: %w", err)
	}
	return result, nil
}

// HexToField converts a hex string (0x...) to a big.Int field element
func HexToField(hex string) (*big.Int, error) {
	if len(hex) >= 2 && hex[:2] == "0x" {
		hex = hex[2:]
	}
	val := new(big.Int)
	_, ok := val.SetString(hex, 16)
	if !ok {
		return nil, fmt.Errorf("invalid hex: %s", hex)
	}
	return val, nil
}

// FieldToHex converts a big.Int to 0x-prefixed hex string (32 bytes padded)
func FieldToHex(val *big.Int) string {
	return fmt.Sprintf("0x%064x", val)
}
