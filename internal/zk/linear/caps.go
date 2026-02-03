package linear

import (
	"os"
	"strconv"
	"strings"
)

const (
	defaultMaxProofs      = 32
	defaultMaxCommitments = 128
	defaultMaxRows        = 64
)

func maxProofs() int {
	return envCap("WEB4_ZK_MAX_PROOFS", defaultMaxProofs)
}

func maxCommitments() int {
	return envCap("WEB4_ZK_MAX_COMMITMENTS", defaultMaxCommitments)
}

func maxRows() int {
	return envCap("WEB4_ZK_MAX_ROWS", defaultMaxRows)
}

func envCap(key string, def int) int {
	raw := strings.TrimSpace(os.Getenv(key))
	if raw == "" {
		return def
	}
	v, err := strconv.Atoi(raw)
	if err != nil || v <= 0 {
		return def
	}
	return v
}
