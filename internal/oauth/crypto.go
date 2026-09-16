package oauth

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
)

// seal returns nonce||ciphertext (AES-256-GCM, fresh nonce each call).
func seal(key, plaintext []byte) ([]byte, error) {
	g, err := newGCM(key)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, g.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	return g.Seal(nonce, nonce, plaintext, nil), nil
}

// open reverses seal; wrong key, tampering, or truncation fail the GCM tag.
func open(key, sealed []byte) ([]byte, error) {
	g, err := newGCM(key)
	if err != nil {
		return nil, err
	}
	if len(sealed) < g.NonceSize() {
		return nil, errDecrypt
	}
	nonce, ct := sealed[:g.NonceSize()], sealed[g.NonceSize():]
	pt, err := g.Open(nil, nonce, ct, nil)
	if err != nil {
		return nil, errDecrypt
	}
	return pt, nil
}

func codeChallenge(verifier []byte) string {
	h := sha256.Sum256(verifier)
	return base64.RawURLEncoding.EncodeToString(h[:])
}

func newGCM(key []byte) (cipher.AEAD, error) {
	blk, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(blk)
}

// sha256Sum hashes the state nonce and session token; only hashes are stored.
func sha256Sum(b []byte) []byte {
	h := sha256.Sum256(b)
	return h[:]
}

// sessionHash maps an empty token to nil (NULL), matching only another no-session flow.
func sessionHash(token string) []byte {
	if token == "" {
		return nil
	}
	return sha256Sum([]byte(token))
}

func randBytes(n int) ([]byte, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return nil, err
	}
	return b, nil
}
