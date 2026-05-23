// SPDX-License-Identifier: MIT
pragma solidity >=0.8.21;

interface INoirVerifier {
    function verify(bytes calldata proof, bytes32[] calldata publicInputs) external returns (bool);
}

contract FactRegistry {
    struct VerifiedFact {
        bytes32 verifierIdHash;
        bytes32 subjectTag;
        bytes32 factTypeHash;
        bytes32 issuerPolicyRoot;
        bytes32 schemaHash;
        bytes32 nullifier;
        uint64 verifiedAt;
        bool exists;
    }

    address public owner;
    INoirVerifier public noirVerifier;

    mapping(bytes32 => VerifiedFact) public facts;
    mapping(bytes32 => bool) public usedNullifiers;
    mapping(bytes32 => bool) public trustedPolicyRoots;

    event FactVerified(
        bytes32 indexed factKey,
        bytes32 indexed subjectTag,
        bytes32 verifierIdHash,
        bytes32 factTypeHash
    );

    event PolicyRootUpdated(bytes32 indexed issuerPolicyRoot, bool trusted);

    modifier onlyOwner() {
        require(msg.sender == owner, "Not owner");
        _;
    }

    constructor(address _noirVerifier) {
        require(_noirVerifier != address(0), "Invalid verifier address");
        owner = msg.sender;
        noirVerifier = INoirVerifier(_noirVerifier);
    }

    function setIssuerPolicyRoot(bytes32 issuerPolicyRoot, bool trusted) external onlyOwner {
        require(issuerPolicyRoot != bytes32(0), "Invalid policy root");
        trustedPolicyRoots[issuerPolicyRoot] = trusted;
        emit PolicyRootUpdated(issuerPolicyRoot, trusted);
    }

    function submitVerifiedFact(
        bytes calldata proof,
        bytes32[] calldata publicInputs,
        bytes32 verifierIdHash,
        bytes32 subjectTag,
        bytes32 factTypeHash,
        bytes32 issuerPolicyRoot,
        bytes32 schemaHash,
        bytes32 nullifier
    ) external {
        // 1. Bind stored values to the public inputs that will be verified by Noir.
        require(publicInputs.length == 7, "Invalid public inputs");
        require(publicInputs[0] == verifierIdHash, "verifierIdHash mismatch");
        require(publicInputs[1] == factTypeHash, "factTypeHash mismatch");
        require(publicInputs[2] == issuerPolicyRoot, "issuerPolicyRoot mismatch");
        require(publicInputs[3] == schemaHash, "schemaHash mismatch");
        require(publicInputs[4] == subjectTag, "subjectTag mismatch");
        require(publicInputs[5] == nullifier, "nullifier mismatch");

        // 2. Check issuer policy root is trusted by this registry.
        require(trustedPolicyRoots[issuerPolicyRoot], "Untrusted issuer policy root");

        // 3. Check nullifier not used
        require(!usedNullifiers[nullifier], "Nullifier already used");

        // 4. Compute fact key and check not already stored
        bytes32 factKey = keccak256(abi.encodePacked(verifierIdHash, subjectTag, factTypeHash));
        require(!facts[factKey].exists, "Fact already exists for this key");

        // 5. Verify the ZK proof.
        require(noirVerifier.verify(proof, publicInputs), "Proof verification failed");

        // 6. Store the verified fact
        facts[factKey] = VerifiedFact({
            verifierIdHash: verifierIdHash,
            subjectTag: subjectTag,
            factTypeHash: factTypeHash,
            issuerPolicyRoot: issuerPolicyRoot,
            schemaHash: schemaHash,
            nullifier: nullifier,
            verifiedAt: uint64(block.timestamp),
            exists: true
        });

        // 7. Mark nullifier as used
        usedNullifiers[nullifier] = true;

        // 8. Emit event
        emit FactVerified(factKey, subjectTag, verifierIdHash, factTypeHash);
    }

    function getFact(
        bytes32 verifierIdHash,
        bytes32 subjectTag,
        bytes32 factTypeHash
    ) external view returns (VerifiedFact memory) {
        bytes32 factKey = keccak256(abi.encodePacked(verifierIdHash, subjectTag, factTypeHash));
        return facts[factKey];
    }

    function isFactValid(
        bytes32 verifierIdHash,
        bytes32 subjectTag,
        bytes32 factTypeHash
    ) external view returns (bool) {
        bytes32 factKey = keccak256(abi.encodePacked(verifierIdHash, subjectTag, factTypeHash));
        VerifiedFact storage fact = facts[factKey];
        return fact.exists;
    }
}
