package blockchain

import (
	"context"
	"fmt"
	"strings"

	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"
)

type VerifiedFact struct {
	ContextHash [32]byte
	SubjectTag  [32]byte
	VerifiedAt  uint64
	Exists      bool
}

// LookupFact reads a VerifiedFact from FactRegistry by (contextHash, subjectTag).
func LookupFact(rpcURL, factRegistryAddr string, contextHash, subjectTag [32]byte) (*VerifiedFact, error) {
	client, err := ethclient.Dial(rpcURL)
	if err != nil {
		return nil, fmt.Errorf("connect to node: %w", err)
	}
	defer client.Close()

	contractAddr := common.HexToAddress(factRegistryAddr)
	data, err := factReaderABI.Pack("getFact", contextHash, subjectTag)
	if err != nil {
		return nil, fmt.Errorf("ABI pack getFact: %w", err)
	}

	result, err := client.CallContract(context.Background(), ethereum.CallMsg{
		To:   &contractAddr,
		Data: data,
	}, nil)
	if err != nil {
		return nil, fmt.Errorf("call getFact: %w", err)
	}

	outputs, err := factReaderABI.Unpack("getFact", result)
	if err != nil {
		return nil, fmt.Errorf("unpack getFact: %w", err)
	}

	if len(outputs) == 0 {
		return nil, fmt.Errorf("empty response from getFact")
	}

	decoded, ok := outputs[0].(struct {
		ContextHash [32]byte `json:"contextHash"`
		SubjectTag  [32]byte `json:"subjectTag"`
		VerifiedAt  uint64   `json:"verifiedAt"`
		Exists      bool     `json:"exists"`
	})
	if !ok {
		return nil, fmt.Errorf("unexpected getFact response type %T", outputs[0])
	}

	return &VerifiedFact{
		ContextHash: decoded.ContextHash,
		SubjectTag:  decoded.SubjectTag,
		VerifiedAt:  decoded.VerifiedAt,
		Exists:      decoded.Exists,
	}, nil
}

// IsFactValid checks if a fact exists.
func IsFactValid(rpcURL, factRegistryAddr string, contextHash, subjectTag [32]byte) (bool, error) {
	client, err := ethclient.Dial(rpcURL)
	if err != nil {
		return false, fmt.Errorf("connect to node: %w", err)
	}
	defer client.Close()

	contractAddr := common.HexToAddress(factRegistryAddr)

	data, err := factReaderABI.Pack("isFactValid", contextHash, subjectTag)
	if err != nil {
		return false, fmt.Errorf("ABI pack isFactValid: %w", err)
	}

	result, err := client.CallContract(context.Background(), ethereum.CallMsg{
		To:   &contractAddr,
		Data: data,
	}, nil)
	if err != nil {
		return false, fmt.Errorf("call isFactValid: %w", err)
	}

	outputs, err := factReaderABI.Unpack("isFactValid", result)
	if err != nil {
		return false, fmt.Errorf("unpack isFactValid: %w", err)
	}

	if len(outputs) > 0 {
		if val, ok := outputs[0].(bool); ok {
			return val, nil
		}
	}
	return false, nil
}

// ComputeFactKey computes keccak256(abi.encodePacked(contextHash, subjectTag)).
func ComputeFactKey(contextHash, subjectTag [32]byte) common.Hash {
	packed := make([]byte, 64)
	copy(packed[0:32], contextHash[:])
	copy(packed[32:64], subjectTag[:])
	return crypto.Keccak256Hash(packed)
}

var factReaderABI abi.ABI

func init() {
	const abiJSON = `[
		{
			"inputs": [
				{"name": "contextHash", "type": "bytes32"},
				{"name": "subjectTag", "type": "bytes32"}
			],
			"name": "getFact",
			"outputs": [
				{
					"components": [
						{"name": "contextHash", "type": "bytes32"},
						{"name": "subjectTag", "type": "bytes32"},
						{"name": "verifiedAt", "type": "uint64"},
						{"name": "exists", "type": "bool"}
					],
					"name": "",
					"type": "tuple"
				}
			],
			"stateMutability": "view",
			"type": "function"
		},
		{
			"inputs": [
				{"name": "contextHash", "type": "bytes32"},
				{"name": "subjectTag", "type": "bytes32"}
			],
			"name": "isFactValid",
			"outputs": [{"name": "", "type": "bool"}],
			"stateMutability": "view",
			"type": "function"
		}
	]`
	parsed, err := abi.JSON(strings.NewReader(abiJSON))
	if err != nil {
		panic("invalid FactRegistry reader ABI: " + err.Error())
	}
	factReaderABI = parsed
}
