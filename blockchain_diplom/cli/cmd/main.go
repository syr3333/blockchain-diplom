package main

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"os"
	"strings"
	"time"

	"diplom/cli/internal/blockchain"
	"diplom/cli/internal/config"
	"diplom/cli/internal/creds"
	"diplom/cli/internal/policy"
	"diplom/cli/internal/prover"
	"diplom/cli/internal/request"
	"diplom/cli/internal/result"

	"github.com/spf13/cobra"
)

func main() {
	rootCmd := &cobra.Command{
		Use:   "zk-verify",
		Short: "Anonymous fact verification CLI (Holder app)",
	}

	rootCmd.AddCommand(
		importCredentialCmd(),
		proveCmd(),
		submitFactCmd(),
		lookupFactCmd(),
		verifyServiceFlowCmd(),
	)

	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

func importCredentialCmd() *cobra.Command {
	var credPath, outPath string
	cmd := &cobra.Command{
		Use:   "import-credential",
		Short: "Import and validate a credential JSON file",
		RunE: func(cmd *cobra.Command, args []string) error {
			cred, err := creds.LoadCredential(credPath)
			if err != nil {
				return err
			}
			fmt.Printf("Credential imported: %s\n", cred.CredentialID)
			fmt.Printf("  Schema: %s (%s)\n", cred.SchemaID, cred.SchemaHash)
			fmt.Printf("  Issuer: %s\n", cred.Issuer.DID)
			fmt.Printf("  Claims: birth_date_days=%d\n", cred.Claims.BirthDateDays)
			fmt.Printf("  Signature alg: %s\n", cred.Signature.Alg)

			if outPath != "" {
				data, err := json.MarshalIndent(cred, "", "  ")
				if err != nil {
					return fmt.Errorf("marshal credential: %w", err)
				}
				return os.WriteFile(outPath, data, 0644)
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&credPath, "file", "testdata/credential.json", "Path to credential JSON")
	cmd.Flags().StringVar(&outPath, "out", "", "Save validated credential to path")
	return cmd
}

func proveCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "prove",
		Short: "Generate ZK proof from credential + request",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := config.LoadConfig()
			if err != nil {
				return err
			}

			cred, err := creds.LoadCredential(cfg.CredentialsFile)
			if err != nil {
				return fmt.Errorf("load credential: %w", err)
			}

			req, err := request.LoadRequest(cfg.RequestFile)
			if err != nil {
				return fmt.Errorf("load request: %w", err)
			}
			if err := req.Validate(); err != nil {
				return fmt.Errorf("validate request: %w", err)
			}

			pol, err := policy.LoadPolicy(cfg.PolicyFile)
			if err != nil {
				return fmt.Errorf("load policy: %w", err)
			}

			proverCfg := prover.ProverConfig{
				CircuitDir:   cfg.NoirCircuitDir,
				NargoBin:     cfg.NargoBin,
				BbBin:        cfg.BbBin,
				HolderSecret: cfg.HolderSecret,
			}

			pkg, err := prover.GenerateProof(proverCfg, cred, req, pol)
			if err != nil {
				return fmt.Errorf("generate proof: %w", err)
			}

			outPath := "proof_package.json"
			if err := prover.SaveProofPackage(pkg, outPath); err != nil {
				return fmt.Errorf("save proof: %w", err)
			}

			fmt.Printf("Proof generated successfully!\n")
			fmt.Printf("  Subject tag: %s\n", pkg.SubjectTag)
			fmt.Printf("  Saved to:    %s\n", outPath)
			return nil
		},
	}
	return cmd
}

func submitFactCmd() *cobra.Command {
	var proofPath string
	cmd := &cobra.Command{
		Use:   "submit-fact",
		Short: "Submit proof to FactRegistry on-chain",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := config.LoadConfig()
			if err != nil {
				return err
			}

			data, err := os.ReadFile(proofPath)
			if err != nil {
				return fmt.Errorf("read proof package: %w", err)
			}
			var pkg prover.ProofPackage
			if err := json.Unmarshal(data, &pkg); err != nil {
				return fmt.Errorf("parse proof package: %w", err)
			}

			proofBytes, err := hexDecode(pkg.Proof)
			if err != nil {
				return fmt.Errorf("parse proof hex: %w", err)
			}

			publicInputs := make([][32]byte, len(pkg.PublicInputs))
			for i, pi := range pkg.PublicInputs {
				publicInputs[i], err = blockchain.HexToBytes32(pi)
				if err != nil {
					return fmt.Errorf("parse public input %d: %w", i, err)
				}
			}
			if len(pkg.PublicInputs) != 5 {
				return fmt.Errorf("proof package has %d public inputs, want 5", len(pkg.PublicInputs))
			}

			verifierIDHash, err := blockchain.HexToBytes32(pkg.PublicInputs[0])
			if err != nil {
				return fmt.Errorf("parse verifier_id_hash: %w", err)
			}
			subjectTag, err := blockchain.HexToBytes32(pkg.SubjectTag)
			if err != nil {
				return fmt.Errorf("parse subject_tag: %w", err)
			}
			if !strings.EqualFold(pkg.SubjectTag, pkg.PublicInputs[3]) {
				return fmt.Errorf("subject_tag does not match public input 3")
			}
			factTypeHash, err := blockchain.HexToBytes32(pkg.PublicInputs[1])
			if err != nil {
				return fmt.Errorf("parse fact_type_hash: %w", err)
			}
			policyRoot, err := blockchain.HexToBytes32(pkg.PublicInputs[2])
			if err != nil {
				return fmt.Errorf("parse issuer_policy_root: %w", err)
			}

			chainID := new(big.Int)
			if _, ok := chainID.SetString(cfg.ChainID, 10); !ok {
				return fmt.Errorf("invalid CHAIN_ID: %s", cfg.ChainID)
			}

			txHash, err := blockchain.SubmitFact(
				blockchain.SubmitConfig{
					RPCURL:              cfg.EthereumRPCURL,
					PrivateKey:          cfg.RelayerPrivateKey,
					FactRegistryAddress: cfg.FactRegistryAddress,
					ChainID:             chainID,
				},
				blockchain.SubmitParams{
					Proof:            proofBytes,
					PublicInputs:     publicInputs,
					VerifierIDHash:   verifierIDHash,
					SubjectTag:       subjectTag,
					FactTypeHash:     factTypeHash,
					IssuerPolicyRoot: policyRoot,
				},
			)
			if err != nil {
				return fmt.Errorf("submit fact: %w", err)
			}

			fmt.Printf("Fact submitted! TX: %s\n", txHash)
			return nil
		},
	}
	cmd.Flags().StringVar(&proofPath, "proof", "proof_package.json", "Path to proof_package.json")
	return cmd
}

func lookupFactCmd() *cobra.Command {
	var subjectTagHex, factTypeHashHex, verifierIDHashHex string
	cmd := &cobra.Command{
		Use:   "lookup-fact",
		Short: "Look up a verified fact on-chain",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := config.LoadConfig()
			if err != nil {
				return err
			}

			verifierIDHash, err := blockchain.HexToBytes32(verifierIDHashHex)
			if err != nil {
				return fmt.Errorf("parse verifier_id_hash: %w", err)
			}
			subjectTag, err := blockchain.HexToBytes32(subjectTagHex)
			if err != nil {
				return fmt.Errorf("parse subject_tag: %w", err)
			}
			factTypeHash, err := blockchain.HexToBytes32(factTypeHashHex)
			if err != nil {
				return fmt.Errorf("parse fact_type_hash: %w", err)
			}

			fact, err := blockchain.LookupFact(
				cfg.EthereumRPCURL,
				cfg.FactRegistryAddress,
				verifierIDHash,
				subjectTag,
				factTypeHash,
			)
			if err != nil {
				return fmt.Errorf("lookup fact: %w", err)
			}

			if !fact.Exists {
				fmt.Println("Fact NOT found")
				return nil
			}

			fmt.Printf("Fact FOUND:\n")
			fmt.Printf("  Verified at: %s\n", time.Unix(int64(fact.VerifiedAt), 0))

			res := result.VerificationResult{
				Version:          "1.0",
				RequestID:        "",
				ServiceID:        verifierIDHashHex,
				Verified:         true,
				VerificationMode: "onchain_lookup",
				VerifiedAt:       time.Now().UTC().Format(time.RFC3339),
				ProofContext: result.ProofContext{
					SubjectTag:   subjectTagHex,
					FactTypeHash: factTypeHashHex,
				},
				Decision: result.Decision{
					Type:       "fact_verification",
					Granted:    true,
					ReasonCode: "FACT_FOUND_ONCHAIN",
				},
				Onchain: result.OnchainRef{
					ContractAddress: cfg.FactRegistryAddress,
					ChainID:         31337,
				},
			}

			data, err := json.MarshalIndent(res, "", "  ")
			if err != nil {
				return fmt.Errorf("marshal result: %w", err)
			}
			fmt.Println(string(data))
			return nil
		},
	}
	cmd.Flags().StringVar(&verifierIDHashHex, "verifier-id-hash", "", "Verifier ID hash (0x...)")
	cmd.Flags().StringVar(&subjectTagHex, "subject-tag", "", "Subject tag (0x...)")
	cmd.Flags().StringVar(&factTypeHashHex, "fact-type-hash", "", "Fact type hash (0x...)")
	cmd.MarkFlagRequired("subject-tag")
	cmd.MarkFlagRequired("fact-type-hash")
	cmd.MarkFlagRequired("verifier-id-hash")
	return cmd
}

func verifyServiceFlowCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "verify-service-flow",
		Short: "E2E: prove -> submit-fact -> lookup-fact",
		RunE: func(cmd *cobra.Command, args []string) error {
			fmt.Println("=== Step 1: Generate proof ===")
			if err := proveCmd().RunE(cmd, args); err != nil {
				return fmt.Errorf("prove failed: %w", err)
			}

			fmt.Println("\n=== Step 2: Submit fact ===")
			submitCmd := submitFactCmd()
			submitCmd.Flags().Set("proof", "proof_package.json")
			if err := submitCmd.RunE(cmd, args); err != nil {
				return fmt.Errorf("submit-fact failed: %w", err)
			}

			fmt.Println("\n=== Step 3: Lookup fact ===")
			data, err := os.ReadFile("proof_package.json")
			if err != nil {
				return fmt.Errorf("read proof_package.json: %w", err)
			}
			var pkg prover.ProofPackage
			if err := json.Unmarshal(data, &pkg); err != nil {
				return fmt.Errorf("parse proof_package.json: %w", err)
			}

			lookupCmd := lookupFactCmd()
			lookupCmd.Flags().Set("subject-tag", pkg.SubjectTag)
			lookupCmd.Flags().Set("fact-type-hash", pkg.PublicInputs[1])
			lookupCmd.Flags().Set("verifier-id-hash", pkg.PublicInputs[0])
			if err := lookupCmd.RunE(cmd, args); err != nil {
				return fmt.Errorf("lookup-fact failed: %w", err)
			}

			fmt.Println("\n=== E2E verification complete ===")
			return nil
		},
	}
	return cmd
}

func hexDecode(h string) ([]byte, error) {
	h = strings.TrimPrefix(h, "0x")
	return hex.DecodeString(h)
}
