package linear

import (
	"encoding/base64"
	"fmt"

	"github.com/cloudflare/circl/zk/dl"

	"web4mvp/internal/proto"
	"web4mvp/internal/zk/pedersen"
)

// EncodeLinearProof serializes commitments and proofs into a JSON-friendly form.
func EncodeLinearProof(C []pedersen.Element, bundle *ProofBundle) (*proto.ZKLinearProof, error) {
	if bundle == nil || len(bundle.Proofs) == 0 {
		return nil, fmt.Errorf("empty proof bundle")
	}
	if len(C) == 0 {
		return nil, fmt.Errorf("empty commitments")
	}
	if len(bundle.Proofs) == 0 {
		return nil, fmt.Errorf("empty proofs")
	}
	commitments := make([]string, len(C))
	for i, c := range C {
		if c == nil {
			return nil, fmt.Errorf("nil commitment at %d", i)
		}
		b, err := c.MarshalBinaryCompress()
		if err != nil {
			return nil, fmt.Errorf("marshal commitment %d: %w", i, err)
		}
		commitments[i] = base64.StdEncoding.EncodeToString(b)
	}
	proofs := make([]proto.ZKDLProof, len(bundle.Proofs))
	for i, p := range bundle.Proofs {
		vb, err := p.V.MarshalBinaryCompress()
		if err != nil {
			return nil, fmt.Errorf("marshal proof V %d: %w", i, err)
		}
		rb, err := p.R.MarshalBinary()
		if err != nil {
			return nil, fmt.Errorf("marshal proof R %d: %w", i, err)
		}
		proofs[i] = proto.ZKDLProof{
			V: base64.StdEncoding.EncodeToString(vb),
			R: base64.StdEncoding.EncodeToString(rb),
		}
	}
	return &proto.ZKLinearProof{
		Commitments: commitments,
		Proofs:      proofs,
	}, nil
}

// DecodeLinearProof parses commitments and proofs from JSON-friendly form.
func DecodeLinearProof(z *proto.ZKLinearProof) ([]pedersen.Element, *ProofBundle, error) {
	if z == nil {
		return nil, nil, fmt.Errorf("missing proof")
	}
	if len(z.Commitments) == 0 || len(z.Proofs) == 0 {
		return nil, nil, fmt.Errorf("empty proof fields")
	}
	g := pedersen.Group()
	C := make([]pedersen.Element, len(z.Commitments))
	for i, enc := range z.Commitments {
		raw, err := base64.StdEncoding.DecodeString(enc)
		if err != nil {
			return nil, nil, fmt.Errorf("decode commitment %d: %w", i, err)
		}
		el := g.NewElement()
		if err := el.UnmarshalBinary(raw); err != nil {
			return nil, nil, fmt.Errorf("unmarshal commitment %d: %w", i, err)
		}
		C[i] = el
	}
	proofs := make([]proto.ZKDLProof, len(z.Proofs))
	copy(proofs, z.Proofs)
	bundle := &ProofBundle{Proofs: make([]dl.Proof, len(proofs))}
	for i, p := range proofs {
		vRaw, err := base64.StdEncoding.DecodeString(p.V)
		if err != nil {
			return nil, nil, fmt.Errorf("decode proof V %d: %w", i, err)
		}
		rRaw, err := base64.StdEncoding.DecodeString(p.R)
		if err != nil {
			return nil, nil, fmt.Errorf("decode proof R %d: %w", i, err)
		}
		v := g.NewElement()
		if err := v.UnmarshalBinary(vRaw); err != nil {
			return nil, nil, fmt.Errorf("unmarshal proof V %d: %w", i, err)
		}
		r := g.NewScalar()
		if err := r.UnmarshalBinary(rRaw); err != nil {
			return nil, nil, fmt.Errorf("unmarshal proof R %d: %w", i, err)
		}
		bundle.Proofs[i] = dl.Proof{V: v, R: r}
	}
	return C, bundle, nil
}
