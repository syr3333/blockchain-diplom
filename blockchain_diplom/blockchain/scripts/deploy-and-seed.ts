import { ethers } from "hardhat";
import * as fs from "fs";
import * as path from "path";

async function main() {
  const [deployer] = await ethers.getSigners();
  console.log("Deploying with:", deployer.address);

  // 1. Deploy ZKTranscriptLib
  const ZKTranscriptLib = await ethers.getContractFactory("ZKTranscriptLib");
  const zkLib = await ZKTranscriptLib.deploy();
  await zkLib.waitForDeployment();
  const zkLibAddr = await zkLib.getAddress();
  console.log("ZKTranscriptLib:", zkLibAddr);

  // 2. Deploy HonkVerifier
  const Verifier = await ethers.getContractFactory("HonkVerifier", {
    libraries: { ZKTranscriptLib: zkLibAddr },
  });
  const verifier = await Verifier.deploy();
  await verifier.waitForDeployment();
  const verifierAddr = await verifier.getAddress();
  console.log("NoirVerifier:", verifierAddr);

  // 3. Deploy FactRegistry
  const FactRegistry = await ethers.getContractFactory("FactRegistry");
  const factReg = await FactRegistry.deploy(verifierAddr);
  await factReg.waitForDeployment();
  const factRegAddr = await factReg.getAddress();
  console.log("FactRegistry:", factRegAddr);

  // Save deployment
  const deployment = {
    deployer: deployer.address,
    timestamp: new Date().toISOString(),
    contracts: {
      zkTranscriptLib: zkLibAddr,
      noirVerifier: verifierAddr,
      factRegistry: factRegAddr,
    },
  };
  fs.writeFileSync("deployment.json", JSON.stringify(deployment, null, 2));

  // 5. Seed: submit test proof if proof files exist
  // In Docker, proof files are mounted to /app/proof_data/proof/ via volume
  // Locally, they're at ../../circuits/age_over_18_v1/target_evm/proof/
  const localDir = path.join(__dirname, "../../circuits/age_over_18_v1/target_evm/proof");
  const dockerDir = path.join(process.cwd(), "circuits/age_over_18_v1/target_evm/proof");
  const proofDir = fs.existsSync(localDir) ? localDir : dockerDir;
  const proofPath = path.join(proofDir, "proof");
  const piPath = path.join(proofDir, "public_inputs");

  if (fs.existsSync(proofPath) && fs.existsSync(piPath)) {
    console.log("\n--- Seeding: submitting test proof ---");
    const proofBytes = fs.readFileSync(proofPath);
    const piRaw = fs.readFileSync(piPath);

    const publicInputs: string[] = [];
    for (let i = 0; i < piRaw.length; i += 32) {
      publicInputs.push("0x" + Buffer.from(piRaw.subarray(i, i + 32)).toString("hex"));
    }
    if (publicInputs.length !== 7) {
      throw new Error(`expected 7 public inputs, got ${publicInputs.length}`);
    }

    const offset = publicInputs.length - 7;
    const verifierIdHash = publicInputs[offset + 0];
    const factTypeHash = publicInputs[offset + 1];
    const issuerPolicyRoot = publicInputs[offset + 2];
    const schemaHash = publicInputs[offset + 3];
    const subjectTag = publicInputs[offset + 4];
    const nullifier = publicInputs[offset + 5];

    const factRegistry = await ethers.getContractAt("FactRegistry", factRegAddr);
    await (await factRegistry.setIssuerPolicyRoot(issuerPolicyRoot, true)).wait();

    const tx = await factRegistry.submitVerifiedFact(
      proofBytes, publicInputs,
      verifierIdHash, subjectTag, factTypeHash,
      issuerPolicyRoot, schemaHash, nullifier,
    );
    const receipt = await tx.wait();
    if (receipt?.status !== 1) {
      throw new Error("proof submit transaction failed");
    }
    console.log("Proof submitted! TX:", receipt?.hash);
    console.log("Subject tag:", subjectTag);
    console.log("Fact type hash:", factTypeHash);
    console.log("Verifier ID hash:", verifierIdHash);
  } else {
    console.log("\nNo proof files found — skipping seed. Generate with:");
    console.log("  cd circuits/age_over_18_v1 && nargo execute && bb prove -t evm ...");
  }

  // Print .env for services
  console.log("\n=== Environment for Verifier backend ===");
  console.log(`FACT_REGISTRY_ADDRESS=${factRegAddr}`);
  console.log(`VERIFIER_ID_HASH=0x2222222222222222222222222222222222222222222222222222222222222222`);
}

main().catch((e) => { console.error(e); process.exitCode = 1; });
