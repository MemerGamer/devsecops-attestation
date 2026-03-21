# Architecture

## System Design

![Architecture diagram](./devsecops_attestation_architecture.svg)

```mermaid
flowchart TB
    subgraph CI["CI/CD Pipeline"]
        SAST["SAST scan"]
        SCA["SCA scan"]
        CFG["Config"]
        SEC["Secret scan"]
    end

    subgraph AT["Attestations"]
        A1["Attestation₁"]
        A2["Attestation₂"]
        A3["Attestation₃"]
        A4["Attestation₄"]
    end

    subgraph KS["Key Store"]
        K["Ed25519 key pair (per pipeline)"]
    end

    SAST -->|sign| A1
    SCA -->|sign| A2
    CFG -->|sign| A3
    SEC -->|sign| A4

    K -.->|signs| SAST
    K -.->|signs| SCA
    K -.->|signs| CFG
    K -.->|signs| SEC

    A1 --> PV["Policy Verifier (OPA + chain check)"]
    A2 --> PV
    A3 --> PV
    A4 --> PV
    PV --> DG["Deploy Gate"]
    DG --> OUT["ALLOW / BLOCK"]
```

> **Note:** Transparency log integration (Rekor/Sigstore) is a planned PhD-phase
> extension. The current implementation stores the attestation chain as a local JSON
> file uploaded as a GitHub Actions artifact.

Each attestation is an Ed25519-signed JSON envelope. Attestations are chained:
each one includes the SHA-256 digest of the previous, making insertion, deletion,
or reordering detectable.

## Data Flow

1. Each CI step (SAST, SCA, config scan) runs a security tool and writes a JSON result.
2. The `sign` binary wraps the result in a `types.Attestation`, signs it with Ed25519,
   links it to the previous attestation via SHA-256 digest, and appends it to
   `attestation-chain.json`.
3. The `gate evaluate` binary loads the chain, verifies all signatures and chain
   linkage, then evaluates the chain against a Rego policy via OPA.
4. If the policy allows, deployment proceeds. If blocked, the pipeline fails with reasons.

## Cryptographic Guarantees

- **Signature integrity**: each attestation's payload is signed with Ed25519 using the
  pipeline actor's private key. Tampering with any field invalidates the signature.
- **Chain integrity**: each attestation includes the SHA-256 digest of the previous
  attestation (including its signature), making insertion, deletion, or reordering
  detectable during chain verification.
- **Gate precondition**: the deployment gate always verifies the full chain before
  evaluating the policy. Policy evaluation on an unverified chain is a security defect.
