package main

import (
	"context"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"
)

type FactResult struct {
	Exists           bool   `json:"exists"`
	VerifierIDHash   string `json:"verifier_id_hash,omitempty"`
	SubjectTag       string `json:"subject_tag,omitempty"`
	FactTypeHash     string `json:"fact_type_hash,omitempty"`
	IssuerPolicyRoot string `json:"issuer_policy_root,omitempty"`
	SchemaHash       string `json:"schema_hash,omitempty"`
	Nullifier        string `json:"nullifier,omitempty"`
	VerifiedAt       string `json:"verified_at,omitempty"`
	IsValid          bool   `json:"is_valid"`
	FactKey          string `json:"fact_key,omitempty"`
}

var factABI abi.ABI

func init() {
	const abiJSON = `[
		{
			"inputs": [
				{"name": "verifierIdHash", "type": "bytes32"},
				{"name": "subjectTag", "type": "bytes32"},
				{"name": "factTypeHash", "type": "bytes32"}
			],
			"name": "getFact",
			"outputs": [
				{
					"components": [
						{"name": "verifierIdHash", "type": "bytes32"},
						{"name": "subjectTag", "type": "bytes32"},
						{"name": "factTypeHash", "type": "bytes32"},
						{"name": "issuerPolicyRoot", "type": "bytes32"},
						{"name": "schemaHash", "type": "bytes32"},
						{"name": "nullifier", "type": "bytes32"},
						{"name": "verifiedAt", "type": "uint64"},
						{"name": "exists", "type": "bool"}
					],
					"name": "",
					"type": "tuple"
				}
			],
			"stateMutability": "view",
			"type": "function"
		}
	]`
	parsed, err := abi.JSON(strings.NewReader(abiJSON))
	if err != nil {
		panic("invalid FactRegistry ABI: " + err.Error())
	}
	factABI = parsed
}

func lookupFactOnChain(rpcURL, factRegistryAddr, verifierIDHashHex, subjectTagHex, factTypeHashHex string) (*FactResult, error) {
	client, err := ethclient.Dial(rpcURL)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to blockchain node")
	}
	defer client.Close()

	contractAddr := common.HexToAddress(factRegistryAddr)

	vid, err := hexToBytes32(verifierIDHashHex)
	if err != nil {
		return nil, fmt.Errorf("invalid verifier_id_hash format")
	}
	st, err := hexToBytes32(subjectTagHex)
	if err != nil {
		return nil, fmt.Errorf("invalid subject_tag format")
	}
	fth, err := hexToBytes32(factTypeHashHex)
	if err != nil {
		return nil, fmt.Errorf("invalid fact_type_hash format")
	}

	data, err := factABI.Pack("getFact", vid, st, fth)
	if err != nil {
		return nil, fmt.Errorf("internal encoding error")
	}

	result, err := client.CallContract(context.Background(), ethereum.CallMsg{
		To:   &contractAddr,
		Data: data,
	}, nil)
	if err != nil {
		return nil, fmt.Errorf("blockchain query failed")
	}

	out, err := factABI.Methods["getFact"].Outputs.Unpack(result)
	if err != nil {
		return nil, fmt.Errorf("failed to decode blockchain response")
	}

	raw := out[0]
	s, ok := raw.(struct {
		VerifierIdHash   [32]byte `json:"verifierIdHash"`
		SubjectTag       [32]byte `json:"subjectTag"`
		FactTypeHash     [32]byte `json:"factTypeHash"`
		IssuerPolicyRoot [32]byte `json:"issuerPolicyRoot"`
		SchemaHash       [32]byte `json:"schemaHash"`
		Nullifier        [32]byte `json:"nullifier"`
		VerifiedAt       uint64   `json:"verifiedAt"`
		Exists           bool     `json:"exists"`
	})
	if !ok {
		return nil, fmt.Errorf("unexpected blockchain response format")
	}

	if !s.Exists {
		return &FactResult{Exists: false, IsValid: false}, nil
	}

	// Compute fact_key = keccak256(abi.encodePacked(verifierIdHash, subjectTag, factTypeHash))
	packed := make([]byte, 96)
	copy(packed[0:32], s.VerifierIdHash[:])
	copy(packed[32:64], s.SubjectTag[:])
	copy(packed[64:96], s.FactTypeHash[:])
	factKey := crypto.Keccak256Hash(packed)

	res := &FactResult{
		Exists:           s.Exists,
		VerifierIDHash:   "0x" + hex.EncodeToString(s.VerifierIdHash[:]),
		SubjectTag:       "0x" + hex.EncodeToString(s.SubjectTag[:]),
		FactTypeHash:     "0x" + hex.EncodeToString(s.FactTypeHash[:]),
		IssuerPolicyRoot: "0x" + hex.EncodeToString(s.IssuerPolicyRoot[:]),
		SchemaHash:       "0x" + hex.EncodeToString(s.SchemaHash[:]),
		Nullifier:        "0x" + hex.EncodeToString(s.Nullifier[:]),
		IsValid:          s.Exists,
		FactKey:          factKey.Hex(),
	}

	res.VerifiedAt = time.Unix(int64(s.VerifiedAt), 0).UTC().Format(time.RFC3339)

	return res, nil
}

func hexToBytes32(h string) ([32]byte, error) {
	var result [32]byte
	h = strings.TrimPrefix(h, "0x")
	b, err := hex.DecodeString(h)
	if err != nil {
		return result, err
	}
	if len(b) > 32 {
		return result, fmt.Errorf("value exceeds 32 bytes")
	}
	copy(result[32-len(b):], b)
	return result, nil
}
