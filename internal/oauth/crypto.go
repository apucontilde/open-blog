package oauth

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
)

// seal encrypts plaintext with AES-256-GCM under key and returns
// nonce||ciphertext. Every call draws a fresh nonce, so two seals of the same
// plaintext differ. This is the at-rest envelope for oauth_tokens: neither the
// access nor the refresh token ever exists in the DB in the clear.
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

// open reverses seal; a wrong key, a tampered ciphertext, or a truncated blob
// all fail the GCM authentication tag.
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

// codeChallenge is the S256 PKCE challenge of a verifier: base64url(sha256).
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

// sha256Sum hashes bytes (used for the opaque state nonce and the bound
// session token); only hashes are stored or looked up, never the raw values.
func sha256Sum(b []byte) []byte {
	h := sha256.Sum256(b)
	return h[:]
}

// sessionHash binds a flow to the initiating session token (bytea column). The
// empty token means "no session" and maps to NULL — a guest start matches only
// a guest callback (IS NOT DISTINCT FROM in the consume statement).
func sessionHash(token string) []byte {
	if token == "" {
		return nil
	}
	return sha256Sum([]byte(token))
}

// sameHash is the Go-side mirror of SQL IS NOT DISTINCT FROM: two empty/"no
// session" values match, an empty never matches a real hash.
func sameHash(a, b []byte) bool {
	if len(a) == 0 || len(b) == 0 {
		return len(a) == 0 && len(b) == 0
	}
	return bytes.Equal(a, b)
}

// randBytes returns n cryptographically random bytes.
func randBytes(n int) ([]byte, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return nil, err
	}
	return b, nil
}
