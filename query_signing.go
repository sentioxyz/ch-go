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

// JWSSignPayload represents the payload to be signed in the JWS token.
type JWSSignPayload struct {
	Sub       string `json:"sub"`
	Qid       string `json:"qid"`
	BodyHash  string `json:"body_hash"`
	Timestamp int64  `json:"timestamp"`
}

// SignQuery generates a JWS token for the given query body and query ID,
// signed with the provided private key.
func SignQuery(privateKey *ecdsa.PrivateKey, queryBody, queryID string) (string, error) {
	if privateKey == nil {
		return "", fmt.Errorf("private key is nil")
	}

	// 1. Calculate Keccak256 hash of the query body
	queryHash := crypto.Keccak256([]byte(queryBody))
	queryHashHex := hex.EncodeToString(queryHash)

	// 2. Construct JWS Header
	header := map[string]string{
		"alg": "ES256K",
		"typ": "JWT",
	}
	headerJSON, err := json.Marshal(header)
	if err != nil {
		return "", fmt.Errorf("failed to marshal JWS header: %w", err)
	}
	headerEncoded := base64.RawURLEncoding.EncodeToString(headerJSON)

	// 3. Construct JWS Payload
	// Using "sub" as the address derived from private key
	address := crypto.PubkeyToAddress(privateKey.PublicKey).Hex()
	payload := JWSSignPayload{
		Sub:       address,
		Qid:       queryID,
		BodyHash:  queryHashHex,
		Timestamp: time.Now().UnixMilli(),
	}
	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		return "", fmt.Errorf("failed to marshal JWS payload: %w", err)
	}
	payloadEncoded := base64.RawURLEncoding.EncodeToString(payloadJSON)

	// 4. Create Signing Input
	signingInput := fmt.Sprintf("%s.%s", headerEncoded, payloadEncoded)
	signingInputHash := crypto.Keccak256([]byte(signingInput))

	// 5. Sign
	signature, err := crypto.Sign(signingInputHash, privateKey)
	if err != nil {
		return "", fmt.Errorf("failed to sign query: %w", err)
	}
	signatureEncoded := base64.RawURLEncoding.EncodeToString(signature)

	// 6. Concatenate
	token := fmt.Sprintf("%s.%s", signingInput, signatureEncoded)
	return token, nil
}

// GenerateRandomKey helper for tests
func GenerateRandomKey() (*ecdsa.PrivateKey, error) {
	return ecdsa.GenerateKey(crypto.S256(), rand.Reader)
}
