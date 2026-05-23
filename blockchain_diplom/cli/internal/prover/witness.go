package prover

import (
	"fmt"
	"math/big"

	"github.com/iden3/go-iden3-crypto/poseidon"
)

// ComputeSubjectTag = Poseidon(holder_secret, verifier_id_hash)
func ComputeSubjectTag(holderSecret, verifierIDHash *big.Int) (*big.Int, error) {
	result, err := poseidon.Hash([]*big.Int{holderSecret, verifierIDHash})
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

// ComputeNullifier = Poseidon(holder_secret, verifier_id_hash, fact_type_hash, schema_hash)
func ComputeNullifier(holderSecret, verifierIDHash, factTypeHash, schemaHash *big.Int) (*big.Int, error) {
	result, err := poseidon.Hash([]*big.Int{holderSecret, verifierIDHash, factTypeHash, schemaHash})
	if err != nil {
		return nil, fmt.Errorf("compute nullifier: %w", err)
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
