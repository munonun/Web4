package proto

// ZKDLProof represents a serialized Schnorr NIZK proof.
type ZKDLProof struct {
	V string `json:"v"`
	R string `json:"r"`
}

// ZKLinearProof carries Pedersen commitments and per-row Schnorr proofs.
type ZKLinearProof struct {
	Commitments []string    `json:"commitments"`
	Proofs      []ZKDLProof `json:"proofs"`
}
