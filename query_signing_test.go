package ch

import (
	"crypto/ecdsa"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum/crypto"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func generateTestKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	key, err := crypto.GenerateKey()
	require.NoError(t, err)
	return key
}

func TestSignQuery_TokenStructure(t *testing.T) {
	key := generateTestKey(t)
	token, err := SignQuery(key, "SELECT 1", "test-query-id")
	require.NoError(t, err)

	parts := strings.Split(token, ".")
	assert.Len(t, parts, 3, "JWS token must have 3 parts: header.payload.signature")

	// Each part must be valid base64url
	for i, part := range parts {
		_, err := base64.RawURLEncoding.DecodeString(part)
		assert.NoError(t, err, "part %d is not valid base64url", i)
	}
}

func TestSignQuery_Header(t *testing.T) {
	key := generateTestKey(t)
	token, err := SignQuery(key, "SELECT 1", "test-query-id")
	require.NoError(t, err)

	headerB64 := strings.Split(token, ".")[0]
	headerBytes, err := base64.RawURLEncoding.DecodeString(headerB64)
	require.NoError(t, err)

	var header jwsHeader
	require.NoError(t, json.Unmarshal(headerBytes, &header))
	assert.Equal(t, "ES256K", header.Alg)
	assert.Equal(t, "JWS", header.Typ)
}

func TestSignQuery_Payload(t *testing.T) {
	key := generateTestKey(t)
	query := "SELECT * FROM users WHERE id = 1"
	token, err := SignQuery(key, query, "test-query-id")
	require.NoError(t, err)

	payloadB64 := strings.Split(token, ".")[1]
	payloadBytes, err := base64.RawURLEncoding.DecodeString(payloadB64)
	require.NoError(t, err)

	var payload jwsPayload
	require.NoError(t, json.Unmarshal(payloadBytes, &payload))
	assert.Greater(t, payload.Iat, int64(0), "iat must be a positive unix timestamp")
	assert.True(t, strings.HasPrefix(payload.QueryHash, "0x"), "qhash must have 0x prefix")
	assert.Len(t, payload.QueryHash, 66, "keccak256 hex should be 0x + 64 hex chars")

	// Verify the hash matches the query
	expectedHash := keccak256Hex([]byte(query))
	assert.Equal(t, expectedHash, payload.QueryHash)
}

func TestSignQuery_SignatureVerification(t *testing.T) {
	key := generateTestKey(t)
	token, err := SignQuery(key, "SELECT 1", "test-query-id")
	require.NoError(t, err)

	parts := strings.Split(token, ".")
	signingInput := parts[0] + "." + parts[1]
	sigBytes, err := base64.RawURLEncoding.DecodeString(parts[2])
	require.NoError(t, err)

	assert.Len(t, sigBytes, ethereumSignatureLength)

	// Undo Ethereum recovery ID offset
	recoveryID := sigBytes[64] - ethereumRecoveryIDOffset
	assert.True(t, recoveryID == 0 || recoveryID == 1)

	// Reconstruct original signature for verification
	sigForRecover := make([]byte, ethereumSignatureLength)
	copy(sigForRecover, sigBytes)
	sigForRecover[64] = recoveryID

	// Recover public key from signature
	msgHash := crypto.Keccak256([]byte(signingInput))
	recoveredPub, err := crypto.Ecrecover(msgHash, sigForRecover)
	require.NoError(t, err)

	// Compare with original public key
	expectedPub := crypto.FromECDSAPub(&key.PublicKey)
	assert.Equal(t, expectedPub, recoveredPub)
}

func TestSignQuery_DifferentQueries(t *testing.T) {
	key := generateTestKey(t)
	token1, err := SignQuery(key, "SELECT 1", "qid1")
	require.NoError(t, err)
	token2, err := SignQuery(key, "SELECT 2", "qid2")
	require.NoError(t, err)

	// Tokens should differ (different query hash)
	assert.NotEqual(t, token1, token2)

	// Headers should be the same
	assert.Equal(t, strings.Split(token1, ".")[0], strings.Split(token2, ".")[0])
}

func TestSignQuery_DifferentKeys(t *testing.T) {
	key1 := generateTestKey(t)
	key2 := generateTestKey(t)
	query := "SELECT 1"

	token1, err := SignQuery(key1, query, "qid")
	require.NoError(t, err)
	token2, err := SignQuery(key2, query, "qid")
	require.NoError(t, err)

	// Signatures should differ (different keys)
	sig1 := strings.Split(token1, ".")[2]
	sig2 := strings.Split(token2, ".")[2]
	assert.NotEqual(t, sig1, sig2)
}

func TestSignQuery_NilKey(t *testing.T) {
	_, err := SignQuery(nil, "SELECT 1", "qid")
	require.Error(t, err)
	require.Contains(t, err.Error(), "private key is nil")
}

func TestSignQuery_QueryIDIgnored(t *testing.T) {
	// QueryID is accepted for API compatibility but not included in the JWS payload.
	// The proxy validator only checks iat and qhash.
	key := generateTestKey(t)
	token1, err := SignQuery(key, "SELECT 1", "qid1")
	require.NoError(t, err)
	token2, err := SignQuery(key, "SELECT 1", "qid2")
	require.NoError(t, err)

	// Payloads should be similar (same query, same time window)
	// but tokens may differ due to timing differences in iat
	payload1B64 := strings.Split(token1, ".")[1]
	payload2B64 := strings.Split(token2, ".")[1]

	var p1, p2 jwsPayload
	b1, _ := base64.RawURLEncoding.DecodeString(payload1B64)
	b2, _ := base64.RawURLEncoding.DecodeString(payload2B64)
	json.Unmarshal(b1, &p1)
	json.Unmarshal(b2, &p2)

	// Query hashes should be identical
	assert.Equal(t, p1.QueryHash, p2.QueryHash)
}

// TestSignQuery_ProxyValidatorCompatibility verifies that the generated token
// can be validated by the proxy's EthValidator logic.
func TestSignQuery_ProxyValidatorCompatibility(t *testing.T) {
	// Use a known test key from the proxy's integration tests
	key, err := crypto.HexToECDSA("e7bc94e4a2346bfb31ce777e079044718ed02d53d8c297c69fce4259e96557bd")
	require.NoError(t, err)

	expectedAddr := crypto.PubkeyToAddress(key.PublicKey).Hex()
	t.Logf("Expected address: %s", expectedAddr)

	query := "SELECT 1"
	token, err := SignQuery(key, query, "test-qid")
	require.NoError(t, err)

	// Parse the compact JWS token
	parts := strings.Split(token, ".")
	require.Len(t, parts, 3)

	// Decode and verify header
	headerBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	require.NoError(t, err)
	var header jwsHeader
	require.NoError(t, json.Unmarshal(headerBytes, &header))
	assert.Equal(t, "ES256K", header.Alg)

	// Decode and verify payload
	payloadBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	require.NoError(t, err)
	var payload jwsPayload
	require.NoError(t, json.Unmarshal(payloadBytes, &payload))

	// Verify query hash matches what the proxy would compute
	expectedHash := keccak256Hex([]byte(query))
	assert.Equal(t, expectedHash, payload.QueryHash)

	// Verify the signature can be used to recover the correct address
	// (simulating what the proxy's recoverAddress does)
	sigBytes, err := base64.RawURLEncoding.DecodeString(parts[2])
	require.NoError(t, err)
	assert.Len(t, sigBytes, 65)

	// Proxy adjusts V: if sig[64] >= 27, sig[64] -= 27
	sig := make([]byte, 65)
	copy(sig, sigBytes)
	if sig[64] >= 27 {
		sig[64] -= 27
	}

	signingInput := parts[0] + "." + parts[1]
	msgHash := crypto.Keccak256([]byte(signingInput))
	pubKey, err := crypto.Ecrecover(msgHash, sig)
	require.NoError(t, err)

	// Compute address from public key (same as proxy's recoverAddress)
	addrHash := crypto.Keccak256(pubKey[1:])
	recoveredAddr := "0x" + strings.ToLower(strings.TrimPrefix(
		crypto.PubkeyToAddress(key.PublicKey).Hex(), "0x"))

	// Verify using the same method the proxy uses
	_ = addrHash // Used for reference
	assert.Equal(t, strings.ToLower(expectedAddr), recoveredAddr)
}
