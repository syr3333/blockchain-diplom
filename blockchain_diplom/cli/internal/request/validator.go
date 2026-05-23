package request

import (
	"fmt"
	"strings"
	"time"
)

func (r *VerificationRequest) Validate() error {
	if r.RequestID == "" {
		return fmt.Errorf("request_id is required")
	}
	if r.VerifierIDHash == "" || !strings.HasPrefix(r.VerifierIDHash, "0x") {
		return fmt.Errorf("verifier_id_hash must be hex (0x...)")
	}
	if r.FactTypeHash == "" || !strings.HasPrefix(r.FactTypeHash, "0x") {
		return fmt.Errorf("fact_type_hash must be hex (0x...)")
	}
	if r.SchemaHash == "" || !strings.HasPrefix(r.SchemaHash, "0x") {
		return fmt.Errorf("schema_hash must be hex (0x...)")
	}
	if r.ExpiresAt != "" {
		expiry, err := time.Parse(time.RFC3339, r.ExpiresAt)
		if err != nil {
			return fmt.Errorf("invalid expires_at format: %w", err)
		}
		if time.Now().After(expiry) {
			return fmt.Errorf("request has expired")
		}
	}
	if r.IssuerPolicy.Root == "" {
		return fmt.Errorf("issuer_policy.root is required")
	}
	if r.Chain.FactRegistryAddress == "" {
		return fmt.Errorf("chain.fact_registry_address is required")
	}
	return nil
}
