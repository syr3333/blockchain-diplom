import { ethers } from "hardhat";
import * as fs from "fs";
import * as path from "path";

function assert(condition: unknown, message: string): asserts condition {
  if (!condition) {
    throw new Error(message);
  }
}

async function main() {
  const deployment = JSON.parse(fs.readFileSync("deployment.json", "utf8"));

  // Read proof and public_inputs from circuit output
  // Use EVM-targeted proof (correct size for Solidity verifier)
  const localProofDir = path.join(__dirname, "../../circuits/age_over_18_v1/target_evm/proof");
  const dockerProofDir = path.join(process.cwd(), "circuits/age_over_18_v1/target_evm/proof");
  const proofDir = fs.existsSync(localProofDir) ? localProofDir : dockerProofDir;
  const proofPath = path.join(proofDir, "proof");
  const publicInputsPath = path.join(proofDir, "public_inputs");

  const proofBytes = fs.readFileSync(proofPath);
  const publicInputsRaw = fs.readFileSync(publicInputsPath);

  // Parse public inputs (each is 32 bytes)
  const publicInputs: string[] = [];
  for (let i = 0; i < publicInputsRaw.length; i += 32) {
    const chunk = publicInputsRaw.subarray(i, i + 32);
    publicInputs.push("0x" + Buffer.from(chunk).toString("hex"));
  }
  console.log(`Proof size: ${proofBytes.length} bytes`);
  console.log(`Public inputs count: ${publicInputs.length}`);
  assert(publicInputs.length === 5, `expected 5 public inputs, got ${publicInputs.length}`);

  // 1. Test NoirVerifier.verify directly
  const verifierAddr = deployment.contracts.noirVerifier;
  const verifier = await ethers.getContractAt("HonkVerifier", verifierAddr);

  console.log("\n=== Step 1: Verify proof on-chain ===");
  const isValid = await verifier.verify(proofBytes, publicInputs);
  assert(isValid, "proof verification returned false");
  console.log("Proof valid:", isValid);

  // 2. Submit to FactRegistry
  console.log("\n=== Step 2: Submit fact to FactRegistry ===");
  const factRegistryAddr = deployment.contracts.factRegistry;
  const factRegistry = await ethers.getContractAt("FactRegistry", factRegistryAddr);

  // Use the public inputs as typed args.
  // The circuit public inputs order:
  // verifier_id_hash, fact_type_hash, issuer_policy_root, subject_tag, cutoff_date_days
  const offset = 0;
  const verifierIdHash = publicInputs[offset + 0];
  const factTypeHash = publicInputs[offset + 1];
  const issuerPolicyRoot = publicInputs[offset + 2];
  const subjectTag = publicInputs[offset + 3];

  const trustTx = await factRegistry.setIssuerPolicyRoot(issuerPolicyRoot, true);
  const trustReceipt = await trustTx.wait();
  assert(trustReceipt?.status === 1, "policy root trust transaction failed");
  console.log("Trusted issuer policy root:", issuerPolicyRoot);

  const existing = await factRegistry.getFact(verifierIdHash, subjectTag, factTypeHash);
  if (existing.exists) {
    console.log("Fact already exists, skipping first submit");
  } else {
    const tx = await factRegistry.submitVerifiedFact(
      proofBytes,
      publicInputs,
      verifierIdHash,
      subjectTag,
      factTypeHash,
      issuerPolicyRoot,
    );
    const receipt = await tx.wait();
    assert(receipt?.status === 1, "submit transaction failed");
    console.log("TX hash:", receipt?.hash);
  }

  // 3. Lookup fact
  console.log("\n=== Step 3: Lookup fact ===");
  const fact = await factRegistry.getFact(verifierIdHash, subjectTag, factTypeHash);
  assert(fact.exists, "fact was not stored");
  console.log("Fact exists:", fact.exists);
  console.log("  verifiedAt:", new Date(Number(fact.verifiedAt) * 1000).toISOString());

  // 4. Check isFactValid
  console.log("\n=== Step 4: Check isFactValid ===");
  const valid = await factRegistry.isFactValid(verifierIdHash, subjectTag, factTypeHash);
  assert(valid, "isFactValid returned false");
  console.log("Fact valid:", valid);

  // 5. Try duplicate fact key (should fail)
  console.log("\n=== Step 5: Try duplicate fact key (should revert) ===");
  try {
    await factRegistry.submitVerifiedFact(
      proofBytes,
      publicInputs,
      verifierIdHash,
      subjectTag,
      factTypeHash,
      issuerPolicyRoot,
    );
    throw new Error("duplicate submit unexpectedly succeeded");
  } catch (e: any) {
    assert(
      e.message?.includes("Fact already exists for this key"),
      `unexpected duplicate submit error: ${e.message?.substring(0, 200)}`,
    );
    console.log("Correctly reverted: YES - Fact already exists for this key");
  }

  console.log("\n=== E2E TEST COMPLETE ===");
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
