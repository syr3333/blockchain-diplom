package policy

// IssuerPolicy as per spec 7.3
type IssuerPolicy struct {
	Version  string        `json:"version"`
	PolicyID string        `json:"policy_id"`
	HashAlg  string        `json:"hash_alg"`
	Depth    int           `json:"depth"`
	Root     string        `json:"root"`
	Issuers  []IssuerEntry `json:"issuers"`
}

type IssuerEntry struct {
	IssuerID   string `json:"issuer_id"`
	PubkeyHash string `json:"pubkey_hash"`
	Leaf       string `json:"leaf"`
}
