package creds

// Credential as per spec 7.2 - stored only by Holder
type Credential struct {
	Version        string         `json:"version"`
	CredentialID   string         `json:"credential_id"`
	Type           []string       `json:"type"`
	Issuer         IssuerRef      `json:"issuer"`
	Subject        SubjectRef     `json:"subject"`
	IssuanceDate   string         `json:"issuance_date"`
	ExpirationDate string         `json:"expiration_date"`
	SchemaID       string         `json:"schema_id"`
	SchemaHash     string         `json:"schema_hash"`
	Claims         Claims         `json:"claims"`
	Revocation     RevocationInfo `json:"revocation"`
	Signature      EdDSASignature `json:"signature"`
}

type IssuerRef struct {
	DID      string `json:"did"`
	KID      string `json:"kid"`
	PubkeyX  string `json:"pubkey_x,omitempty"`
	PubkeyY  string `json:"pubkey_y,omitempty"`
}

type SubjectRef struct {
	DID               string `json:"did"`
	BindingCommitment string `json:"binding_commitment"`
}

type Claims struct {
	BirthDateDays uint64 `json:"birth_date_days"`
}

type RevocationInfo struct {
	StatusListID string `json:"status_list_id"`
	StatusIndex  int    `json:"status_index"`
}

type EdDSASignature struct {
	Alg string `json:"alg"`
	R8X string `json:"r8x"`
	R8Y string `json:"r8y"`
	S   string `json:"s"`
}
