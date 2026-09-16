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

// Internal; callers map it to ErrInvalidCredentials.
var ErrPasswordMismatch = errors.New("auth: password mismatch")

// dummyPassword is only ever hashed to burn the same argon2 cost for unknown
// identities; it is never accepted.
const dummyPassword = "openblog-internal-dummy-hash"

// limiter bounds concurrent argon2 to cap×64 MiB peak.
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

var dummyHash = sync.OnceValue(func() string {
	encoded, err := hashPassword(context.Background(), newLimiter(1), dummyPassword)
	if err != nil {
		panic(err) // fixed params cannot fail
	}
	return encoded
})

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

// verifyPassword compares in constant time; malformed encodings fail closed.
func verifyPassword(ctx context.Context, l *limiter, encoded, password string) error {
	if err := l.acquire(ctx); err != nil {
		return err
	}
	defer l.release()
	parts := strings.Split(encoded, "$")
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
