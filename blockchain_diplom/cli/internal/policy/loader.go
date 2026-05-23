package policy

import (
	"encoding/json"
	"fmt"
	"os"
)

func LoadPolicy(path string) (*IssuerPolicy, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read policy file: %w", err)
	}
	var p IssuerPolicy
	if err := json.Unmarshal(data, &p); err != nil {
		return nil, fmt.Errorf("parse policy JSON: %w", err)
	}
	return &p, nil
}
