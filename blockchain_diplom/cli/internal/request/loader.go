package request

import (
	"encoding/json"
	"fmt"
	"os"
)

func LoadRequest(path string) (*VerificationRequest, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read request file: %w", err)
	}
	var req VerificationRequest
	if err := json.Unmarshal(data, &req); err != nil {
		return nil, fmt.Errorf("parse request JSON: %w", err)
	}
	return &req, nil
}
