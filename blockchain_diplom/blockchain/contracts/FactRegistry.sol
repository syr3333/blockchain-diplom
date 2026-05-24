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
        uint64 verifiedAt;
        bool exists;
    }

    address public owner;
    INoirVerifier public noirVerifier;

    mapping(bytes32 => VerifiedFact) public facts;

    event FactVerified(
        bytes32 indexed factKey,
        bytes32 indexed subjectTag,
        bytes32 verifierIdHash,
        bytes32 factTypeHash
    );

    modifier onlyOwner() {
        require(msg.sender == owner, "Not owner");
        _;
    }

    constructor(address _noirVerifier) {
        require(_noirVerifier != address(0), "Invalid verifier address");
        owner = msg.sender;
        noirVerifier = INoirVerifier(_noirVerifier);
    }

    function submitVerifiedFact(
        bytes calldata proof,
        bytes32[] calldata publicInputs,
        bytes32 verifierIdHash,
        bytes32 subjectTag,
        bytes32 factTypeHash
    ) external {
        // 1. Bind stored values to the public inputs that will be verified by Noir.
        require(publicInputs.length == 4, "Invalid public inputs");
        require(publicInputs[0] == verifierIdHash, "verifierIdHash mismatch");
        require(publicInputs[1] == factTypeHash, "factTypeHash mismatch");
        require(publicInputs[2] == subjectTag, "subjectTag mismatch");

        // 2. Compute fact key and check not already stored.
        // This replaces public nullifier-based replay protection for this
        // registry: the same verifier/subject/fact tuple cannot be submitted twice.
        bytes32 factKey = keccak256(abi.encodePacked(verifierIdHash, subjectTag, factTypeHash));
        require(!facts[factKey].exists, "Fact already exists for this key");

        // 3. Verify the ZK proof.
        require(noirVerifier.verify(proof, publicInputs), "Proof verification failed");

        // 4. Store only lookup fields. Issuer policy root and schema hash are
        // fixed inside the circuit verification key, not exposed in public inputs.
        facts[factKey] = VerifiedFact({
            verifierIdHash: verifierIdHash,
            subjectTag: subjectTag,
            factTypeHash: factTypeHash,
            verifiedAt: uint64(block.timestamp),
            exists: true
        });

        // 5. Emit event
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
