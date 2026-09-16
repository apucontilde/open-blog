package auth

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"sync"

	"golang.org/x/crypto/argon2"
)

// ErrPasswordMismatch is internal: a stored-hash verification failed.
// Callers (verifyBestEffort) always map it to ErrInvalidCredentials.
var ErrPasswordMismatch = errors.New("auth: password mismatch")

// dummyPassword is hashed once at init and verified against when the identity
// check must burn the same argon2 cost (unknown email / SSO-only account). It
// is never accepted: verifyBestEffort returns ErrInvalidCredentials on that
// branch regardless of the outcome.
const dummyPassword = "openblog-internal-dummy-hash"

// limiter caps concurrent argon2 invocations to bound peak memory
// (cap × 64 MiB). It is the only CPU- and memory-heavy operation here.
type limiter struct {
	sem chan struct{}
}

func newLimiter(cap int) *limiter {
	return &limiter{sem: make(chan struct{}, cap)}
}

func (l *limiter) acquire(ctx context.Context) error {
	select {
	case l.sem <- struct{}{}:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (l *limiter) release() {
	<-l.sem
}

// dummyHash is the cached argon2 encoding of dummyPassword, computed once.
var dummyHash = sync.OnceValue(func() string {
	encoded, err := hashPassword(context.Background(), newLimiter(1), dummyPassword)
	if err != nil {
		panic(err) // encoding with fixed params cannot fail
	}
	return encoded
})

// hashPassword encodes password as $argon2id$v=19$m=…,t=…,p=…$salt$key with a
// fresh 16-byte salt. Must run under a limiter (64 MiB per call).
func hashPassword(ctx context.Context, l *limiter, password string) (string, error) {
	if err := l.acquire(ctx); err != nil {
		return "", err
	}
	defer l.release()
	salt := make([]byte, argon2SaltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	key := argon2.IDKey([]byte(password), salt, argon2Time, argon2Memory, argon2Threads, argon2KeyLen)
	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version, argon2Memory, argon2Time, argon2Threads,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(key)), nil
}

// verifyPassword compares a plaintext password against an encoded argon2id
// string in constant time (constant-time compare on derived keys). Malformed
// encodings fail closed (ErrPasswordMismatch).
func verifyPassword(ctx context.Context, l *limiter, encoded, password string) error {
	if err := l.acquire(ctx); err != nil {
		return err
	}
	defer l.release()
	parts := strings.Split(encoded, "$")
	// $argon2id$v=19$m=...,t=...,p=...$salt$key
	if len(parts) != 6 || parts[1] != "argon2id" {
		return ErrPasswordMismatch
	}
	var version int
	if _, err := fmt.Sscanf(parts[2], "v=%d", &version); err != nil || version != argon2.Version {
		return ErrPasswordMismatch
	}
	var memory, timec, threads uint32
	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &memory, &timec, &threads); err != nil {
		return ErrPasswordMismatch
	}
	if timec < 1 || threads < 1 || threads > 255 || memory < 8*threads {
		return ErrPasswordMismatch
	}
	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return ErrPasswordMismatch
	}
	key, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil || len(key) == 0 {
		return ErrPasswordMismatch
	}
	want := argon2.IDKey([]byte(password), salt, timec, memory, uint8(threads), uint32(len(key)))
	if subtle.ConstantTimeCompare(want, key) != 1 {
		return ErrPasswordMismatch
	}
	return nil
}
