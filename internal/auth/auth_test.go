package auth

import (
	"context"
	"encoding/base64"
	"errors"
	"strings"
	"testing"
	"time"
)

func TestNewTokenRoundTrip(t *testing.T) {
	token, err := newToken()
	if err != nil {
		t.Fatalf("newToken: %v", err)
	}
	raw, err := base64.RawURLEncoding.DecodeString(token)
	if err != nil {
		t.Fatalf("decoding token: %v", err)
	}
	if len(raw) != TokenLen {
		t.Fatalf("decoded token length = %d, want %d", len(raw), TokenLen)
	}
	// Re-encoding the decoded bytes reproduces the exact token string.
	if re := base64.RawURLEncoding.EncodeToString(raw); re != token {
		t.Fatalf("encode/decode round-trip mismatch: %q != %q", re, token)
	}

	token2, err := newToken()
	if err != nil {
		t.Fatalf("newToken: %v", err)
	}
	if token == token2 {
		t.Fatal("two issued tokens must differ")
	}
}

func TestTokenHashDeterministic(t *testing.T) {
	token, err := newToken()
	if err != nil {
		t.Fatalf("newToken: %v", err)
	}
	h1, h2 := tokenHash(token), tokenHash(token)
	if h1 != h2 {
		t.Fatal("tokenHash must be deterministic")
	}
	if h1 == tokenHash(token+":\x00") || h1 == tokenHash(token[:len(token)-1]) {
		t.Fatal("tokenHash must depend on the whole token")
	}
}

func TestLimiterCapsConcurrency(t *testing.T) {
	l := newLimiter(2)
	ctx := context.Background()
	if err := l.acquire(ctx); err != nil {
		t.Fatalf("acquire 1: %v", err)
	}
	if err := l.acquire(ctx); err != nil {
		t.Fatalf("acquire 2: %v", err)
	}

	// A third acquire must block: a cancelled context surfaces immediately.
	cctx, cancel := context.WithCancel(ctx)
	cancel()
	if err := l.acquire(cctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("acquire beyond cap = %v, want context.Canceled", err)
	}

	l.release()
	if err := l.acquire(ctx); err != nil {
		t.Fatalf("acquire after release: %v", err)
	}
	l.release()
	l.release()
}

func TestHashPasswordRoundTrip(t *testing.T) {
	l := newLimiter(argon2Concurrency)
	ctx := context.Background()
	encoded, err := hashPassword(ctx, l, "s3cret")
	if err != nil {
		t.Fatalf("hashPassword: %v", err)
	}
	if !strings.HasPrefix(encoded, "$argon2id$v=19$m=65536,t=3,p=2$") {
		t.Fatalf("unexpected encoding prefix: %s", encoded)
	}
	if err := verifyPassword(ctx, l, encoded, "s3cret"); err != nil {
		t.Fatalf("verify correct password: %v", err)
	}
	if err := verifyPassword(ctx, l, encoded, "wrong"); !errors.Is(err, ErrPasswordMismatch) {
		t.Fatalf("verify wrong password = %v, want ErrPasswordMismatch", err)
	}
	// Each hash must draw a fresh salt.
	encoded2, err := hashPassword(ctx, l, "s3cret")
	if err != nil {
		t.Fatalf("hashPassword: %v", err)
	}
	if encoded == encoded2 {
		t.Fatal("two hashes of the same password must differ (salt)")
	}
}

func TestVerifyMalformedHashFailsClosed(t *testing.T) {
	l := newLimiter(1)
	ctx := context.Background()
	for _, encoded := range []string{
		"", "plaintext", "$argon2id$v=19$m=65536,t=3,p=2$AAAA$", // valid shape, garbage key
		"$bcrypt$v=19$m=65536,t=3,p=2$AAAA$AAAA",
		"$argon2id$v=18$m=65536,t=3,p=2$AAAA$AAAA",
		"$argon2id$v=19$m=1,t=0,p=2$AAAA$AAAA", // argon2-IDKey would panic on t=0
		"$argon2id$v=19$m=1,t=3,p=2$AAAA$AAAA", // memory < 8*threads
	} {
		if err := verifyPassword(ctx, l, encoded, "pw"); !errors.Is(err, ErrPasswordMismatch) {
			t.Fatalf("verifyPassword(%q) = %v, want ErrPasswordMismatch", encoded, err)
		}
	}
}

// TestVerifyBestEffortConstantTime covers the unknown-email / passwordless
// branch: the dummy hash is exercised (real argon2 run) but always fails.
func TestVerifyBestEffort(t *testing.T) {
	a := &Auth{lim: newLimiter(argon2Concurrency)}
	ctx := context.Background()

	// NULL stored hash (unknown email or SSO-only account): always rejected.
	if err := a.verifyBestEffort(ctx, nil, dummyPassword); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("dummy branch with dummy password = %v, want ErrInvalidCredentials", err)
	}
	if err := a.verifyBestEffort(ctx, nil, "anything"); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("dummy branch = %v, want ErrInvalidCredentials", err)
	}

	// The stored hash is fixed and future calls reuse it (sync.Once).
	if !strings.HasPrefix(dummyHash(), "$argon2id$") {
		t.Fatalf("dummyHash not argon2id-encoded: %q", dummyHash())
	}

	// Real stored hash: success only on the correct password.
	encoded, err := hashPassword(ctx, a.lim, "hunter2")
	if err != nil {
		t.Fatalf("hashPassword: %v", err)
	}
	if err := a.verifyBestEffort(ctx, &encoded, "hunter2"); err != nil {
		t.Fatalf("stored branch correct password = %v, want nil", err)
	}
	if err := a.verifyBestEffort(ctx, &encoded, "wrong"); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("stored branch wrong password = %v, want ErrInvalidCredentials", err)
	}
}

func TestNormalizeEmail(t *testing.T) {
	for in, want := range map[string]string{
		"  Alice@Example.COM ": "alice@example.com",
		"alice@example.com":    "alice@example.com",
		"":                     "",
	} {
		if got := normalizeEmail(in); got != want {
			t.Fatalf("normalizeEmail(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestTokenTTL(t *testing.T) {
	if TokenTTL != 30*24*time.Hour {
		t.Fatalf("TokenTTL = %v, want 30d", TokenTTL)
	}
}
