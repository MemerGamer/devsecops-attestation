# PhD Extension Path

The crypto core of this project is designed as the foundation for a PhD
focusing on the **network layer** of distributed attestation:

| This MSc | PhD Extension |
|---|---|
| Local key pair per pipeline actor | Distributed key generation (DKG) |
| Chain as an ordered slice | Chain as a distributed DAG |
| Threshold signing (in-process) | BFT threshold signing over a network |
| Single verifier | Gossip-based attestation propagation |
| OPA policy engine | Distributed policy consensus |

The `threshold.GossipProtocol` interface in `internal/threshold/threshold.go`
is intentionally left as a stub. It marks exactly where the network layer
will plug in during the PhD phase.
