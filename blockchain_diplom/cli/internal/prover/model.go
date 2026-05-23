package prover

// ProofPackage as per spec 7.5 - main output of Holder
type ProofPackage struct {
	Version           string   `json:"version"`
	RequestID         string   `json:"request_id"`
	CircuitID         string   `json:"circuit_id"`
	Backend           string   `json:"backend"`
	Proof             string   `json:"proof"`
	PublicInputs      []string `json:"public_inputs"`
	PublicInputLabels []string `json:"public_input_labels"`
	SubjectTag        string   `json:"subject_tag"`
	Nullifier         string   `json:"nullifier"`
	GeneratedAt       string   `json:"generated_at"`
}
