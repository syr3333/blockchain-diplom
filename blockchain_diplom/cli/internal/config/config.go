package config

import (
	"os"

	"github.com/joho/godotenv"
)

type Config struct {
	CredentialsFile     string
	RequestFile         string
	PolicyFile          string
	HolderSecret        string
	NoirCircuitDir      string
	NargoBin            string
	BbBin               string
	FactRegistryAddress string
	EthereumRPCURL      string
	RelayerPrivateKey   string
	ChainID             string
}

func LoadConfig() (*Config, error) {
	_ = godotenv.Load()

	cfg := &Config{
		CredentialsFile:     getEnv("CREDENTIALS_FILE", "testdata/credential.json"),
		RequestFile:         getEnv("REQUEST_FILE", "testdata/verification_request.json"),
		PolicyFile:          getEnv("POLICY_FILE", "testdata/issuer_policy.json"),
		HolderSecret:        getEnv("HOLDER_SECRET", ""),
		NoirCircuitDir:      getEnv("NOIR_CIRCUIT_DIR", "../circuits/age_over_18_v1"),
		NargoBin:            getEnv("NARGO_BIN", "nargo"),
		BbBin:               getEnv("BB_BIN", "bb"),
		FactRegistryAddress: getEnv("FACT_REGISTRY_ADDRESS", ""),
		EthereumRPCURL:      getEnv("ETHEREUM_RPC_URL", "http://127.0.0.1:8545"),
		RelayerPrivateKey:   getEnv("RELAYER_PRIVATE_KEY", getEnv("HOLDER_PRIVATE_KEY", "")),
		ChainID:             getEnv("CHAIN_ID", "31337"),
	}
	return cfg, nil
}

func getEnv(key, fallback string) string {
	if val := os.Getenv(key); val != "" {
		return val
	}
	return fallback
}
