package creds

import (
	"encoding/json"
	"fmt"
	"os"
)

func LoadCredential(path string) (*Credential, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read credential file: %w", err)
	}
	var cred Credential
	if err := json.Unmarshal(data, &cred); err != nil {
		return nil, fmt.Errorf("parse credential JSON: %w", err)
	}
	return &cred, nil
}
