import { ethers } from "hardhat";
import * as fs from "fs";

async function main() {
  const [deployer] = await ethers.getSigners();
  console.log("Deploying contracts with account:", deployer.address);
  console.log("Account balance:", (await deployer.provider.getBalance(deployer.address)).toString());

  // 1. Deploy ZKTranscriptLib library (required by HonkVerifier)
  const ZKTranscriptLib = await ethers.getContractFactory("ZKTranscriptLib");
  const zkTranscriptLib = await ZKTranscriptLib.deploy();
  await zkTranscriptLib.waitForDeployment();
  const zkTranscriptLibAddr = await zkTranscriptLib.getAddress();
  console.log("ZKTranscriptLib deployed to:", zkTranscriptLibAddr);

  // 2. Deploy HonkVerifier (NoirVerifier) linked to ZKTranscriptLib
  const NoirVerifier = await ethers.getContractFactory("HonkVerifier", {
    libraries: {
      ZKTranscriptLib: zkTranscriptLibAddr,
    },
  });
  const noirVerifier = await NoirVerifier.deploy();
  await noirVerifier.waitForDeployment();
  const noirVerifierAddr = await noirVerifier.getAddress();
  console.log("NoirVerifier (HonkVerifier) deployed to:", noirVerifierAddr);

  // 3. Deploy FactRegistry (needs NoirVerifier address)
  const FactRegistry = await ethers.getContractFactory("FactRegistry");
  const factRegistry = await FactRegistry.deploy(noirVerifierAddr);
  await factRegistry.waitForDeployment();
  const factRegistryAddr = await factRegistry.getAddress();
  console.log("FactRegistry deployed to:", factRegistryAddr);

  // Save deployment info
  const deployment = {
    network: (await ethers.provider.getNetwork()).name,
    deployer: deployer.address,
    timestamp: new Date().toISOString(),
    contracts: {
      zkTranscriptLib: zkTranscriptLibAddr,
      noirVerifier: noirVerifierAddr,
      factRegistry: factRegistryAddr,
    },
  };

  fs.writeFileSync("deployment.json", JSON.stringify(deployment, null, 2));
  console.log("\nDeployment info saved to deployment.json");
  console.log("\nAdd to CLI .env:");
  console.log(`FACT_REGISTRY_ADDRESS=${factRegistryAddr}`);
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
