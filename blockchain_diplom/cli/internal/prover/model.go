package prover

// ProofPackage as per spec 7.5 - main output of Holder
type ProofPackage struct {
	Version           string   `json:"version,omitempty"`
	RequestID         string   `json:"request_id,omitempty"`
	CircuitID         string   `json:"circuit_id,omitempty"`
	Backend           string   `json:"backend,omitempty"`
	Proof             string   `json:"proof"`
	PublicInputs      []string `json:"public_inputs"`
	PublicInputLabels []string `json:"public_input_labels,omitempty"`
	SubjectTag        string   `json:"subject_tag,omitempty"`
	GeneratedAt       string   `json:"generated_at,omitempty"`
}
