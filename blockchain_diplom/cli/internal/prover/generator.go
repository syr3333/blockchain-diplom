package prover

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"diplom/cli/internal/creds"
	"diplom/cli/internal/policy"
	"diplom/cli/internal/request"
)

const ageSchemaHashHex = "0x1111111111111111111111111111111111111111111111111111111111111111"

// GenerateProof builds prover input, calls nargo execute + bb prove, returns ProofPackage
func GenerateProof(
	cfg ProverConfig,
	cred *creds.Credential,
	req *request.VerificationRequest,
	pol *policy.IssuerPolicy,
) (*ProofPackage, error) {
	circuitDir, err := filepath.Abs(cfg.CircuitDir)
	if err != nil {
		return nil, fmt.Errorf("resolve circuit dir: %w", err)
	}

	// 1. Parse issuer pubkey from credential
	issuerPubkeyX, err := HexToField(cred.Issuer.PubkeyX)
	if err != nil {
		return nil, fmt.Errorf("parse issuer.pubkey_x: %w", err)
	}
	issuerPubkeyY, err := HexToField(cred.Issuer.PubkeyY)
	if err != nil {
		return nil, fmt.Errorf("parse issuer.pubkey_y: %w", err)
	}

	// Find matching issuer in policy
	leafIndex := -1
	for i, iss := range pol.Issuers {
		if iss.IssuerID == cred.Issuer.DID {
			leafIndex = i
			break
		}
	}
	if leafIndex < 0 {
		return nil, fmt.Errorf("issuer %s not found in policy", cred.Issuer.DID)
	}

	// 2. Build Merkle tree and get path
	leaves := make([]*big.Int, len(pol.Issuers))
	for i, iss := range pol.Issuers {
		leaf, err := HexToField(iss.Leaf)
		if err != nil {
			return nil, fmt.Errorf("parse leaf %d: %w", i, err)
		}
		leaves[i] = leaf
	}

	levels, err := policy.BuildTree(leaves)
	if err != nil {
		return nil, fmt.Errorf("build merkle tree: %w", err)
	}
	merklePath, merkleIndexBits := policy.GetMerklePath(levels, leafIndex)

	// 3. Compute public pseudonym values and validate subject binding
	holderSecret, err := HexToField(cfg.HolderSecret)
	if err != nil {
		return nil, fmt.Errorf("parse holder_secret: %w", err)
	}
	verifierIDHash, err := HexToField(req.VerifierIDHash)
	if err != nil {
		return nil, fmt.Errorf("parse verifier_id_hash: %w", err)
	}
	factTypeHash, err := HexToField(req.FactTypeHash)
	if err != nil {
		return nil, fmt.Errorf("parse fact_type_hash: %w", err)
	}
	schemaHash, err := HexToField(req.SchemaHash)
	if err != nil {
		return nil, fmt.Errorf("parse schema_hash: %w", err)
	}
	if !strings.EqualFold(req.SchemaHash, ageSchemaHashHex) {
		return nil, fmt.Errorf("request schema_hash must match circuit schema %s", ageSchemaHashHex)
	}
	subjectBinding, err := ComputeSubjectBinding(holderSecret, schemaHash)
	if err != nil {
		return nil, err
	}
	expectedBinding, err := HexToField(cred.Subject.BindingCommitment)
	if err != nil {
		return nil, fmt.Errorf("parse subject.binding_commitment: %w", err)
	}
	if subjectBinding.Cmp(expectedBinding) != 0 {
		return nil, fmt.Errorf("credential subject binding does not match holder_secret")
	}

	subjectTag, err := ComputeSubjectTag(holderSecret, verifierIDHash)
	if err != nil {
		return nil, err
	}

	policyRoot, err := HexToField(pol.Root)
	if err != nil {
		return nil, fmt.Errorf("parse policy root: %w", err)
	}
	if pol.Root != req.IssuerPolicy.Root && !strings.EqualFold(pol.Root, req.IssuerPolicy.Root) {
		return nil, fmt.Errorf("request issuer_policy.root does not match policy file root")
	}

	// 4. Write Prover.toml for nargo
	proverToml, err := buildProverToml(
		cred.Claims.BirthDateDays,
		holderSecret,
		issuerPubkeyX, issuerPubkeyY,
		cred.Signature,
		merklePath, merkleIndexBits,
		verifierIDHash, factTypeHash,
		policyRoot,
		subjectTag,
		req.Predicate.CutoffDateDays,
	)
	if err != nil {
		return nil, err
	}

	tomlPath := filepath.Join(circuitDir, "Prover.toml")
	if err := os.WriteFile(tomlPath, []byte(proverToml), 0644); err != nil {
		return nil, fmt.Errorf("write Prover.toml: %w", err)
	}

	// 5. Compile the circuit and solve the witness.
	if err := runCommand(circuitDir, cfg.NargoBin, "compile"); err != nil {
		return nil, fmt.Errorf("nargo compile: %w", err)
	}
	if err := runCommand(circuitDir, cfg.NargoBin, "execute"); err != nil {
		return nil, fmt.Errorf("nargo execute: %w", err)
	}

	// 6. Generate an EVM-compatible proof for the Solidity verifier.
	acirPath := filepath.Join(circuitDir, "target", "age_over_18_v1.json")
	witnessPath := filepath.Join(circuitDir, "target", "age_over_18_v1.gz")
	targetEVMDir := filepath.Join(circuitDir, "target_evm")
	proofOutDir := filepath.Join(targetEVMDir, "proof")

	if err := os.MkdirAll(targetEVMDir, 0755); err != nil {
		return nil, fmt.Errorf("create target_evm: %w", err)
	}
	if err := runCommand(circuitDir, cfg.BbBin, "write_vk",
		"-b", acirPath,
		"-o", targetEVMDir,
		"-t", "evm",
	); err != nil {
		return nil, fmt.Errorf("bb write_vk: %w", err)
	}
	if err := runCommand(circuitDir, cfg.BbBin, "prove",
		"-b", acirPath,
		"-w", witnessPath,
		"-o", proofOutDir,
		"-k", filepath.Join(targetEVMDir, "vk"),
		"-t", "evm",
	); err != nil {
		return nil, fmt.Errorf("bb prove: %w", err)
	}

	// 7. Read proof
	proofBytes, err := os.ReadFile(filepath.Join(proofOutDir, "proof"))
	if err != nil {
		return nil, fmt.Errorf("read proof file: %w", err)
	}
	proofHex := "0x" + hex.EncodeToString(proofBytes)

	// 8. Build ProofPackage
	pkg := &ProofPackage{
		Version:   "1.0",
		RequestID: req.RequestID,
		CircuitID: "age_over_18_v1",
		Backend:   "noir-barretenberg",
		Proof:     proofHex,
		PublicInputs: []string{
			FieldToHex(verifierIDHash),
			FieldToHex(factTypeHash),
			FieldToHex(policyRoot),
			FieldToHex(subjectTag),
			fmt.Sprintf("0x%064x", new(big.Int).SetUint64(req.Predicate.CutoffDateDays)),
		},
		PublicInputLabels: []string{
			"verifier_id_hash",
			"fact_type_hash",
			"issuer_policy_root",
			"subject_tag",
			"cutoff_date_days",
		},
		SubjectTag:  FieldToHex(subjectTag),
		GeneratedAt: time.Now().UTC().Format(time.RFC3339),
	}

	return pkg, nil
}

type ProverConfig struct {
	CircuitDir   string
	NargoBin     string
	BbBin        string
	HolderSecret string
}

func buildProverToml(
	birthDateDays uint64,
	holderSecret *big.Int,
	issuerPubX, issuerPubY *big.Int,
	sig creds.EdDSASignature,
	merklePath []*big.Int, merkleIndexBits []int,
	verifierIDHash, factTypeHash *big.Int,
	policyRoot *big.Int,
	subjectTag *big.Int,
	cutoffDateDays uint64,
) (string, error) {
	sigRX, err := HexToField(sig.R8X)
	if err != nil {
		return "", fmt.Errorf("parse signature.r8x: %w", err)
	}
	sigRY, err := HexToField(sig.R8Y)
	if err != nil {
		return "", fmt.Errorf("parse signature.r8y: %w", err)
	}
	sigS, err := HexToField(sig.S)
	if err != nil {
		return "", fmt.Errorf("parse signature.s: %w", err)
	}

	toml := fmt.Sprintf(`[credential]
birth_date_days = "%d"
holder_secret = "%s"

[issuer]
issuer_pubkey_x = "%s"
issuer_pubkey_y = "%s"
signature_r_x = "%s"
signature_r_y = "%s"
signature_s = "%s"
`, birthDateDays,
		holderSecret.String(),
		issuerPubX.String(),
		issuerPubY.String(),
		sigRX.String(),
		sigRY.String(),
		sigS.String(),
	)

	toml += "issuer_policy_path = ["
	for i := 0; i < policy.TreeDepth; i++ {
		if i < len(merklePath) {
			toml += fmt.Sprintf(`"%s"`, merklePath[i].String())
		} else {
			toml += `"0"`
		}
		if i < policy.TreeDepth-1 {
			toml += ", "
		}
	}
	toml += "]\n"

	toml += "issuer_policy_path_indices = ["
	for i := 0; i < policy.TreeDepth; i++ {
		if i < len(merkleIndexBits) {
			toml += fmt.Sprintf(`"%d"`, merkleIndexBits[i])
		} else {
			toml += `"0"`
		}
		if i < policy.TreeDepth-1 {
			toml += ", "
		}
	}
	toml += "]\n"

	toml += fmt.Sprintf(`
[context]
verifier_id_hash = "%s"
fact_type_hash = "%s"
issuer_policy_root = "%s"
subject_tag = "%s"
cutoff_date_days = "%d"
`,
		verifierIDHash.String(),
		factTypeHash.String(),
		policyRoot.String(),
		subjectTag.String(),
		cutoffDateDays,
	)

	return toml, nil
}

func runCommand(dir, name string, args ...string) error {
	cmd := exec.Command(name, args...)
	cmd.Dir = dir
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

func SaveProofPackage(pkg *ProofPackage, path string) error {
	data, err := json.MarshalIndent(pkg, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal proof package: %w", err)
	}
	return os.WriteFile(path, data, 0644)
}
