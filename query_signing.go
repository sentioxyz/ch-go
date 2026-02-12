package ch

import (
	"crypto/ecdsa"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"

	"github.com/ethereum/go-ethereum/crypto"
)

// jwsHeader represents the header of a JWS token.
type jwsHeader struct {
	Alg string `json:"alg"`
	Typ string `json:"typ"`
}

// jwsPayload represents the payload of a JWS authentication token.
// This matches the proxy validator's expected format.
type jwsPayload struct {
	// Iat is the issued-at timestamp (Unix seconds).
	Iat int64 `json:"iat"`
	// QueryHash is the Keccak256 hash of the SQL query body (hex encoded with 0x prefix).
	QueryHash string `json:"qhash"`
}

const (
	ethereumRecoveryIDOffset = 27
	ethereumSignatureLength  = 65
)

var (
	jwsHeaderV1        = jwsHeader{Alg: "ES256K", Typ: "JWT"}
	jwsHeaderBase64URL string
)

func init() {
	headerBytes, _ := json.Marshal(jwsHeaderV1)
	jwsHeaderBase64URL = base64.RawURLEncoding.EncodeToString(headerBytes)
}

// keccak256Hex computes the Keccak256 hash and returns it as a hex string with 0x prefix.
func keccak256Hex(data []byte) string {
	return "0x" + hex.EncodeToString(crypto.Keccak256(data))
}

// SignQuery generates a JWS token for the given query body,
// signed with the provided private key.
// The token format is: base64url(header).base64url(payload).base64url(signature)
// This matches the proxy validator's expected JWS compact serialization format.
func SignQuery(privateKey *ecdsa.PrivateKey, queryBody, queryID string) (string, error) {
	if privateKey == nil {
		return "", fmt.Errorf("private key is nil")
	}

	// 1. Construct JWS Payload (matching proxy validator's JWSPayload struct)
	payloadBytes, err := json.Marshal(jwsPayload{
		Iat:       time.Now().Unix(),
		QueryHash: keccak256Hex([]byte(queryBody)),
	})
	if err != nil {
		return "", fmt.Errorf("failed to marshal JWS payload: %w", err)
	}
	payloadB64 := base64.RawURLEncoding.EncodeToString(payloadBytes)

	// 2. Create Signing Input: header.payload
	signingInput := jwsHeaderBase64URL + "." + payloadB64

	// 3. Keccak256 hash the signing input
	msgHash := crypto.Keccak256([]byte(signingInput))

	// 4. Sign with secp256k1 private key
	sig, err := crypto.Sign(msgHash, privateKey)
	if err != nil {
		return "", fmt.Errorf("failed to sign query: %w", err)
	}

	// 5. Validate signature
	if len(sig) != ethereumSignatureLength {
		return "", fmt.Errorf("invalid signature length: expected %d, got %d", ethereumSignatureLength, len(sig))
	}

	recoveryID := sig[64]
	if recoveryID > 1 {
		return "", fmt.Errorf("invalid recovery ID: expected 0 or 1, got %d", recoveryID)
	}

	// 6. Adjust V value for Ethereum standard (V + 27)
	ethSig := make([]byte, ethereumSignatureLength)
	copy(ethSig, sig)
	ethSig[64] = recoveryID + ethereumRecoveryIDOffset

	sigB64 := base64.RawURLEncoding.EncodeToString(ethSig)

	// 7. Concatenate: header.payload.signature
	return signingInput + "." + sigB64, nil
}

// GenerateRandomKey helper for tests
func GenerateRandomKey() (*ecdsa.PrivateKey, error) {
	return ecdsa.GenerateKey(crypto.S256(), rand.Reader)
}
