package pedersen

import (
	"crypto/rand"
	"fmt"
	"sync"

	"github.com/cloudflare/circl/group"
)

type Scalar = group.Scalar
type Element = group.Element

const (
	pedersenDST = "web4/zk/pedersen"
)

var (
	gOnce sync.Once
	gElem Element
	hElem Element
	gErr  error
)

func Group() group.Group {
	return group.Ristretto255
}

func Generators() (Element, Element, error) {
	gOnce.Do(func() {
		g := Group().HashToElement([]byte("web4/zk/pedersen/g"), []byte(pedersenDST))
		h := Group().HashToElement([]byte("web4/zk/pedersen/h"), []byte(pedersenDST))
		if g.IsIdentity() {
			gErr = fmt.Errorf("pedersen g is identity")
			return
		}
		if h.IsIdentity() {
			gErr = fmt.Errorf("pedersen h is identity")
			return
		}
		if g.IsEqual(h) {
			gErr = fmt.Errorf("pedersen g == h")
			return
		}
		gElem = g
		hElem = h
	})
	if gErr != nil {
		return nil, nil, gErr
	}
	return gElem.Copy(), hElem.Copy(), nil
}

func CommitVector(x []Scalar, _ []byte) ([]Element, []Scalar, error) {
	if len(x) == 0 {
		return nil, nil, fmt.Errorf("empty vector")
	}
	g, h, err := Generators()
	if err != nil {
		return nil, nil, err
	}
	C := make([]Element, len(x))
	r := make([]Scalar, len(x))
	for i := range x {
		if x[i] == nil {
			return nil, nil, fmt.Errorf("nil scalar at %d", i)
		}
		if x[i].Group() != Group() {
			return nil, nil, fmt.Errorf("scalar group mismatch at %d", i)
		}
		r[i] = Group().RandomNonZeroScalar(rand.Reader)
		C[i] = commit(g, h, x[i], r[i])
	}
	return C, r, nil
}

func commit(g, h Element, x, r Scalar) Element {
	gx := Group().NewElement().Mul(g, x)
	hr := Group().NewElement().Mul(h, r)
	return Group().NewElement().Add(gx, hr)
}
