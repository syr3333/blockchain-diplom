package result

// VerificationResult as per spec 7.7 - Verifier's final journal
type VerificationResult struct {
	Version          string       `json:"version"`
	RequestID        string       `json:"request_id"`
	ServiceID        string       `json:"service_id"`
	Verified         bool         `json:"verified"`
	VerificationMode string       `json:"verification_mode"`
	VerifiedAt       string       `json:"verified_at"`
	ProofContext     ProofContext `json:"proof_context"`
	Decision         Decision     `json:"decision"`
	Onchain          OnchainRef   `json:"onchain"`
}

type ProofContext struct {
	SubjectTag   string `json:"subject_tag"`
	FactTypeHash string `json:"fact_type_hash"`
	Nullifier    string `json:"nullifier"`
	PolicyRoot   string `json:"policy_root"`
}

type Decision struct {
	Type       string `json:"type"`
	Granted    bool   `json:"granted"`
	ReasonCode string `json:"reason_code"`
}

type OnchainRef struct {
	ChainID         int    `json:"chain_id"`
	ContractAddress string `json:"contract_address"`
	TxHash          string `json:"tx_hash"`
	FactKey         string `json:"fact_key"`
}
