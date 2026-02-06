package ch

import (
	"crypto/ecdsa"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum/crypto"
	"github.com/stretchr/testify/require"
)

func TestSignQuery(t *testing.T) {
	// 1. Generate a valid key
	privateKey, err := ecdsa.GenerateKey(crypto.S256(), rand.Reader)
	require.NoError(t, err)

	queryBody := "SELECT 1"
	queryID := "test-query-id"

	// 2. Sign
	token, err := SignQuery(privateKey, queryBody, queryID)
	require.NoError(t, err)
	require.NotEmpty(t, token)

	// 3. Verify JWS Structure (Header.Payload.Signature)
	parts := strings.Split(token, ".")
	require.Len(t, parts, 3)

	// 4. Verify Header
	headerJSON, err := base64.RawURLEncoding.DecodeString(parts[0])
	require.NoError(t, err)
	var header map[string]string
	err = json.Unmarshal(headerJSON, &header)
	require.NoError(t, err)
	require.Equal(t, "ES256K", header["alg"])
	require.Equal(t, "JWT", header["typ"])

	// 5. Verify Payload
	payloadJSON, err := base64.RawURLEncoding.DecodeString(parts[1])
	require.NoError(t, err)
	var payload JWSSignPayload
	err = json.Unmarshal(payloadJSON, &payload)
	require.NoError(t, err)

	require.Equal(t, queryID, payload.Qid)

	// Verify Address (sub) matches public key
	expectedAddr := crypto.PubkeyToAddress(privateKey.PublicKey).Hex()
	require.Equal(t, expectedAddr, payload.Sub)

	require.NotEmpty(t, payload.BodyHash)

	// 6. Verify Signature (Recover)
	// Reconstruct signing input
	signingInput := parts[0] + "." + parts[1]
	signingHash := crypto.Keccak256([]byte(signingInput))

	sigBytes, err := base64.RawURLEncoding.DecodeString(parts[2])
	require.NoError(t, err)

	// Ecrecover returns uncompressed public key bytes
	// crypto.SigToPub wraps Ecrecover
	recoveredPub, err := crypto.SigToPub(signingHash, sigBytes)
	require.NoError(t, err)

	recoveredAddr := crypto.PubkeyToAddress(*recoveredPub).Hex()
	require.Equal(t, expectedAddr, recoveredAddr)
}

func TestSignQuery_NilKey(t *testing.T) {
	_, err := SignQuery(nil, "SELECT 1", "qid")
	require.Error(t, err)
	require.Contains(t, err.Error(), "private key is nil")
}
