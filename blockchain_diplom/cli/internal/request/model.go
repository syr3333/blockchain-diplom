package request

// VerificationRequest as per spec 7.1 - from Verifier to Holder
type VerificationRequest struct {
	Version        string          `json:"version"`
	RequestID      string          `json:"request_id"`
	VerifierID     string          `json:"verifier_id"`
	VerifierIDHash string          `json:"verifier_id_hash"`
	FactType       string          `json:"fact_type"`
	FactTypeHash   string          `json:"fact_type_hash"`
	Purpose        string          `json:"purpose"`
	IssuedAt       string          `json:"issued_at"`
	ExpiresAt      string          `json:"expires_at"`
	SchemaID       string          `json:"schema_id"`
	SchemaHash     string          `json:"schema_hash"`
	CircuitID      string          `json:"circuit_id"`
	Predicate      Predicate       `json:"predicate"`
	IssuerPolicy   IssuerPolicyRef `json:"issuer_policy"`
	Chain          ChainConfig     `json:"chain"`
	Response       ResponseConfig  `json:"response"`
}

type Predicate struct {
	Type           string `json:"type"`
	CutoffDateDays uint64 `json:"cutoff_date_days"`
}

type IssuerPolicyRef struct {
	Root               string        `json:"root,omitempty"`
	RegistryCommitment string        `json:"registry_commitment"`
	SnapshotBlock      uint64        `json:"snapshot_block"`
	Issuers            []IssuerEntry `json:"issuers,omitempty"`
}

type IssuerEntry struct {
	IssuerID   string `json:"issuer_id"`
	PubkeyHash string `json:"pubkey_hash"`
	Leaf       string `json:"leaf"`
}

type ChainConfig struct {
	ChainID             int    `json:"chain_id"`
	FactRegistryAddress string `json:"fact_registry_address"`
}

type ResponseConfig struct {
	Mode        string `json:"mode"`
	CallbackURL string `json:"callback_url"`
}
