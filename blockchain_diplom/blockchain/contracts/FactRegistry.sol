// SPDX-License-Identifier: MIT
pragma solidity >=0.8.21;

interface INoirVerifier {
    function verify(bytes calldata proof, bytes32[] calldata publicInputs) external returns (bool);
}

contract FactRegistry {
    struct VerifiedFact {
        bytes32 contextHash;
        bytes32 subjectTag;
        uint64 verifiedAt;
        bool exists;
    }

    address public owner;
    INoirVerifier public noirVerifier;

    mapping(bytes32 => VerifiedFact) public facts;
    mapping(bytes32 => bool) public trustedRegistryCommitments;

    event FactVerified(
        bytes32 indexed factKey,
        bytes32 indexed subjectTag,
        bytes32 contextHash
    );

    event RegistryCommitmentUpdated(bytes32 indexed registryCommitment, bool trusted);

    modifier onlyOwner() {
        require(msg.sender == owner, "Not owner");
        _;
    }

    constructor(address _noirVerifier) {
        require(_noirVerifier != address(0), "Invalid verifier address");
        owner = msg.sender;
        noirVerifier = INoirVerifier(_noirVerifier);
    }

    function setTrustedRegistryCommitment(bytes32 registryCommitment, bool trusted) external onlyOwner {
        require(registryCommitment != bytes32(0), "Invalid registry commitment");
        trustedRegistryCommitments[registryCommitment] = trusted;
        emit RegistryCommitmentUpdated(registryCommitment, trusted);
    }

    function submitVerifiedFact(
        bytes calldata proof,
        bytes32[] calldata publicInputs,
        bytes32 contextHash,
        bytes32 subjectTag,
        bytes32 registryCommitment
    ) external {
        // 1. Bind stored values to the public inputs that will be verified by Noir.
        require(publicInputs.length == 3, "Invalid public inputs");
        require(publicInputs[0] == contextHash, "contextHash mismatch");
        require(publicInputs[1] == registryCommitment, "registryCommitment mismatch");
        require(publicInputs[2] == subjectTag, "subjectTag mismatch");

        // 2. Check that the proof is bound to a trusted global registry commitment.
        require(trustedRegistryCommitments[registryCommitment], "Untrusted registry commitment");

        // 3. Compute fact key and check not already stored.
        // This replaces public nullifier-based replay protection for this
        // registry: the same context/subject tuple cannot be submitted twice.
        bytes32 factKey = keccak256(abi.encodePacked(contextHash, subjectTag));
        require(!facts[factKey].exists, "Fact already exists for this key");

        // 4. Verify the ZK proof.
        require(noirVerifier.verify(proof, publicInputs), "Proof verification failed");

        // 5. Store only lookup fields. The raw policy root is never submitted
        // to the contract; only the registry commitment is checked above.
        facts[factKey] = VerifiedFact({
            contextHash: contextHash,
            subjectTag: subjectTag,
            verifiedAt: uint64(block.timestamp),
            exists: true
        });

        // 6. Emit event
        emit FactVerified(factKey, subjectTag, contextHash);
    }

    function getFact(
        bytes32 contextHash,
        bytes32 subjectTag
    ) external view returns (VerifiedFact memory) {
        bytes32 factKey = keccak256(abi.encodePacked(contextHash, subjectTag));
        return facts[factKey];
    }

    function isFactValid(
        bytes32 contextHash,
        bytes32 subjectTag
    ) external view returns (bool) {
        bytes32 factKey = keccak256(abi.encodePacked(contextHash, subjectTag));
        VerifiedFact storage fact = facts[factKey];
        return fact.exists;
    }
}
