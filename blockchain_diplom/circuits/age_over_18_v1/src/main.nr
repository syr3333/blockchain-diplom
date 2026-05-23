// age_over_18_v1 - ZK circuit for anonymous age verification
//
// Proves: user is 18+ (birth_date_days <= cutoff_date_days)
// without revealing actual birth date.
//
// Also proves:
// - Credential signed by trusted Issuer (EdDSA BabyJubJub + Poseidon)
// - Issuer belongs to trusted set (Merkle inclusion, Poseidon, depth 16)
// - subject_tag and nullifier correctly derived
// - Holder secret is bound to the signed credential through a private commitment

use poseidon::poseidon::bn254::hash_2;
use poseidon::poseidon::bn254::hash_4;
use poseidon::poseidon::PoseidonHasher;
use eddsa::eddsa_verify;

// Merkle tree depth for issuer policy
global TREE_DEPTH: u32 = 16;

struct CredentialWitness {
    // Private claim from the credential. The verifier never sees this value.
    birth_date_days: Field,
    // Holder secret used to derive verifier-scoped identifiers.
    holder_secret: Field,
}

struct IssuerWitness {
    // Issuer public key is private to hide the exact issuer from the verifier.
    issuer_pubkey_x: Field,
    issuer_pubkey_y: Field,
    // EdDSA signature parts. R is a curve point, so Noir receives x/y separately.
    signature_r_x: Field,
    signature_r_y: Field,
    signature_s: Field,
    // Merkle inclusion proof for the issuer inside the trusted issuer policy.
    issuer_policy_path: [Field; TREE_DEPTH],
    issuer_policy_path_indices: [Field; TREE_DEPTH],
}

struct VerificationContext {
    // Public verifier/request context that the contract stores or checks.
    verifier_id_hash: Field,
    fact_type_hash: Field,
    issuer_policy_root: Field,
    schema_hash: Field,
    subject_tag: Field,
    nullifier: Field,
    cutoff_date_days: Field,
}

fn main(
    credential: CredentialWitness,
    issuer: IssuerWitness,
    context: pub VerificationContext,
) {
    // 1. Age predicate: birth_date_days <= cutoff_date_days
    let birth_days_u64 = credential.birth_date_days as u64;
    let cutoff_days_u64 = context.cutoff_date_days as u64;
    assert(birth_days_u64 <= cutoff_days_u64, "Age predicate failed: too young");

    // 2. EdDSA signature verification
    //    holder_binding = Poseidon2(holder_secret, schema_hash)
    //    signed_claim = Poseidon2(birth_date_days, holder_binding)
    //    credential_hash = Poseidon4(pubkey_x, pubkey_y, signed_claim, schema_hash)
    let holder_binding = hash_2([credential.holder_secret, context.schema_hash]);
    let signed_claim = hash_2([credential.birth_date_days, holder_binding]);
    let credential_hash = hash_4([
        issuer.issuer_pubkey_x,
        issuer.issuer_pubkey_y,
        signed_claim,
        context.schema_hash,
    ]);
    let sig_valid = eddsa_verify::<PoseidonHasher>(
        issuer.issuer_pubkey_x,
        issuer.issuer_pubkey_y,
        issuer.signature_s,
        issuer.signature_r_x,
        issuer.signature_r_y,
        credential_hash,
    );
    assert(sig_valid, "EdDSA signature verification failed");

    // 3. Merkle inclusion proof: issuer is in the trusted policy tree
    //    leaf = Poseidon2(issuer_pubkey_x, issuer_pubkey_y)
    let leaf = hash_2([issuer.issuer_pubkey_x, issuer.issuer_pubkey_y]);
    let computed_root = compute_merkle_root(
        leaf,
        issuer.issuer_policy_path,
        issuer.issuer_policy_path_indices,
    );
    assert(computed_root == context.issuer_policy_root, "Issuer not in policy tree");

    // 4. subject_tag = Poseidon2(holder_secret, verifier_id_hash)
    let computed_subject_tag = hash_2([credential.holder_secret, context.verifier_id_hash]);
    assert(computed_subject_tag == context.subject_tag, "subject_tag mismatch");

    // 5. nullifier = Poseidon4(holder_secret, verifier_id_hash, fact_type_hash, schema_hash)
    let computed_nullifier = hash_4([
        credential.holder_secret,
        context.verifier_id_hash,
        context.fact_type_hash,
        context.schema_hash,
    ]);
    assert(computed_nullifier == context.nullifier, "nullifier mismatch");
}

// Compute Merkle root from leaf, path siblings, and direction bits
fn compute_merkle_root(
    leaf: Field,
    path: [Field; TREE_DEPTH],
    index_bits: [Field; TREE_DEPTH],
) -> Field {
    let mut current = leaf;
    for i in 0..TREE_DEPTH {
        let bit = index_bits[i];
        // bit == 0: current is left child, sibling is right
        // bit == 1: current is right child, sibling is left
        let left = if bit == 0 { current } else { path[i] };
        let right = if bit == 0 { path[i] } else { current };
        current = hash_2([left, right]);
    }
    current
}
