package blockchain

import (
	"context"
	"crypto/ecdsa"
	"encoding/hex"
	"fmt"
	"math/big"
	"strings"

	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"
)

type SubmitConfig struct {
	RPCURL              string
	PrivateKey          string
	FactRegistryAddress string
	ChainID             *big.Int
}

type SubmitParams struct {
	Proof              []byte
	PublicInputs       [][32]byte
	ContextHash        [32]byte
	SubjectTag         [32]byte
	RegistryCommitment [32]byte
}

// SubmitFact sends the proof to FactRegistry.submitVerifiedFact
func SubmitFact(cfg SubmitConfig, params SubmitParams) (string, error) {
	ctx := context.Background()

	client, err := ethclient.Dial(cfg.RPCURL)
	if err != nil {
		return "", fmt.Errorf("connect to node: %w", err)
	}
	defer client.Close()

	privKeyHex := strings.TrimPrefix(cfg.PrivateKey, "0x")
	privateKey, err := crypto.HexToECDSA(privKeyHex)
	if err != nil {
		return "", fmt.Errorf("parse private key: %w", err)
	}

	publicKey := privateKey.Public().(*ecdsa.PublicKey)
	fromAddress := crypto.PubkeyToAddress(*publicKey)

	nonce, err := client.PendingNonceAt(ctx, fromAddress)
	if err != nil {
		return "", fmt.Errorf("get nonce: %w", err)
	}

	gasPrice, err := client.SuggestGasPrice(ctx)
	if err != nil {
		return "", fmt.Errorf("suggest gas price: %w", err)
	}

	contractAddr := common.HexToAddress(cfg.FactRegistryAddress)

	inputData, err := factSubmitABI.Pack("submitVerifiedFact",
		params.Proof,
		params.PublicInputs,
		params.ContextHash,
		params.SubjectTag,
		params.RegistryCommitment,
	)
	if err != nil {
		return "", fmt.Errorf("ABI encode: %w", err)
	}

	gasLimit, err := client.EstimateGas(ctx, ethereum.CallMsg{
		From:  fromAddress,
		To:    &contractAddr,
		Value: big.NewInt(0),
		Data:  inputData,
	})
	if err != nil {
		return "", fmt.Errorf("estimate gas: %w", err)
	}
	gasLimit += gasLimit / 5

	tx := types.NewTransaction(
		nonce,
		contractAddr,
		big.NewInt(0),
		gasLimit,
		gasPrice,
		inputData,
	)

	signedTx, err := types.SignTx(tx, types.NewEIP155Signer(cfg.ChainID), privateKey)
	if err != nil {
		return "", fmt.Errorf("sign tx: %w", err)
	}

	if err := client.SendTransaction(ctx, signedTx); err != nil {
		return "", fmt.Errorf("send tx: %w", err)
	}

	receipt, err := bind.WaitMined(ctx, client, signedTx)
	if err != nil {
		return "", fmt.Errorf("wait for tx mining: %w", err)
	}
	if receipt.Status != types.ReceiptStatusSuccessful {
		return "", fmt.Errorf("transaction reverted: %s", signedTx.Hash().Hex())
	}

	return signedTx.Hash().Hex(), nil
}

// HexToBytes32 converts a 0x-prefixed hex string to [32]byte
func HexToBytes32(h string) ([32]byte, error) {
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

var factSubmitABI abi.ABI

func init() {
	const abiJSON = `[{
		"inputs": [
			{"name": "proof", "type": "bytes"},
			{"name": "publicInputs", "type": "bytes32[]"},
			{"name": "contextHash", "type": "bytes32"},
			{"name": "subjectTag", "type": "bytes32"},
			{"name": "registryCommitment", "type": "bytes32"}
		],
		"name": "submitVerifiedFact",
		"outputs": [],
		"stateMutability": "nonpayable",
		"type": "function"
	}]`
	parsed, err := abi.JSON(strings.NewReader(abiJSON))
	if err != nil {
		panic("invalid FactRegistry submit ABI: " + err.Error())
	}
	factSubmitABI = parsed
}
