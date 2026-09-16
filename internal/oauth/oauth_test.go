package oauth

import (
	"bytes"
	"net/url"
	"strings"
	"testing"

	"golang.org/x/oauth2"
)

func testKey() []byte {
	return bytes.Repeat([]byte{0x42}, 32)
}

func TestSealOpenRoundTrip(t *testing.T) {
	key := testKey()
	pt := []byte("access-token-secret")
	sealed, err := seal(key, pt)
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	if bytes.Equal(sealed, pt) {
		t.Fatal("ciphertext must not equal plaintext")
	}
	if bytes.Contains(sealed, pt) {
		t.Fatal("plaintext leaked into ciphertext")
	}
	got, err := open(key, sealed)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if !bytes.Equal(got, pt) {
		t.Fatalf("open = %q, want %q", got, pt)
	}
}

func TestSealFreshNonce(t *testing.T) {
	key := testKey()
	pt := []byte("same-plaintext")
	a, err := seal(key, pt)
	if err != nil {
		t.Fatalf("seal 1: %v", err)
	}
	b, err := seal(key, pt)
	if err != nil {
		t.Fatalf("seal 2: %v", err)
	}
	if bytes.Equal(a, b) {
		t.Fatal("two seals of the same plaintext must differ (nonce)")
	}
}

func TestOpenRejectsWrongKeyTamperAndTruncation(t *testing.T) {
	pt := []byte("sensitive")
	sealed, err := seal(testKey(), pt)
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	if _, err := open([]byte(strings.Repeat("A", 32)), sealed); err == nil {
		t.Fatal("wrong key must fail GCM authentication")
	}
	tampered := append([]byte{}, sealed...)
	tampered[len(tampered)-1] ^= 0x01
	if _, err := open(testKey(), tampered); err == nil {
		t.Fatal("tampered ciphertext must fail GCM authentication")
	}
	if _, err := open(testKey(), sealed[:len(sealed)-1]); err == nil {
		t.Fatal("truncated ciphertext must fail")
	}
	if _, err := open(testKey(), []byte{1, 2, 3}); err == nil {
		t.Fatal("too-short ciphertext must fail")
	}
}

func TestNewRequires32ByteKey(t *testing.T) {
	for _, k := range [][]byte{nil, bytes.Repeat([]byte{0x01}, 31), bytes.Repeat([]byte{0x01}, 16)} {
		if _, err := New(Config{Store: nil, Key: k}); err == nil {
			t.Fatalf("New with %d-byte key must fail", len(k))
		}
	}
}

func TestCodeChallenge(t *testing.T) {
	v := []byte("verifier-value")
	c1, c2 := codeChallenge(v), codeChallenge(v)
	if c1 != c2 {
		t.Fatal("code challenge must be deterministic")
	}
	if len(c1) != 43 {
		t.Fatalf("challenge length = %d, want 43 (base64url of sha256, no padding)", len(c1))
	}
	if strings.ContainsAny(c1, "=+/") {
		t.Fatalf("challenge must be unpadded base64url, got %q", c1)
	}
	if c1 == codeChallenge([]byte("other")) {
		t.Fatal("challenge must depend on the verifier")
	}
}

func TestSessionHashBinding(t *testing.T) {
	if h := sessionHash(""); h != nil {
		t.Fatalf("empty token must map to nil (NULL), got %x", h)
	}
	h1, h2 := sessionHash("tok-123"), sessionHash("tok-123")
	if !bytes.Equal(h1, h2) || len(h1) != 32 {
		t.Fatalf("session hash must be a deterministic sha256, got %x/%x", h1, h2)
	}
}

func TestSHA256SumDeterministic(t *testing.T) {
	a, b := sha256Sum([]byte("state")), sha256Sum([]byte("state"))
	if !bytes.Equal(a, b) || len(a) != 32 {
		t.Fatalf("sha256Sum must be deterministic 32 bytes, got %x/%x", a, b)
	}
	if bytes.Equal(a, sha256Sum([]byte("other"))) {
		t.Fatal("sha256Sum must depend on input")
	}
}

func TestIsAllowedRedirect(t *testing.T) {
	o := &OAuth{allow: []*url.URL{{Scheme: "https", Host: "app.example.com", Path: "/app"}}}
	allowed := []string{
		"https://app.example.com/app",
		"https://app.example.com/app/dashboard",
		"https://app.example.com/app/dashboard?tab=posts", // query ignored, same host
		"https://APP.EXAMPLE.COM/app/x",                   // host case-insensitive
	}
	for _, u := range allowed {
		if !o.isAllowedRedirect(u) {
			t.Fatalf("isAllowedRedirect(%q) = false, want true", u)
		}
	}
	disallowed := []string{
		"http://app.example.com/app",    // wrong scheme
		"https://evil.com/app",          // wrong host
		"https://app.example.com/apped", // sibling path, not a descendant
		"https://app.example.com/",      // outside base path
		"ftp://app.example.com/app",
		"javascript:alert(1)",
		"",
		"not-a-url",
		"https://user:pass@app.example.com/app", // userinfo rejected
	}
	for _, u := range disallowed {
		if o.isAllowedRedirect(u) {
			t.Fatalf("isAllowedRedirect(%q) = true, want false", u)
		}
	}
}

func TestIsAllowedRedirectRootBase(t *testing.T) {
	o := &OAuth{allow: []*url.URL{{Scheme: "https", Host: "app.example.com"}}}
	for _, u := range []string{"https://app.example.com/", "https://app.example.com/anywhere"} {
		if !o.isAllowedRedirect(u) {
			t.Fatalf("isAllowedRedirect(%q) = false, want true (empty base path)", u)
		}
	}
}

func TestStartFailFast(t *testing.T) {
	// Failure paths return before touching the (nil) store.
	o := &OAuth{
		providers: map[string]provider{"google": {name: ProviderGoogle}},
		allow:     []*url.URL{{Scheme: "https", Host: "app.example.com", Path: "/app"}},
	}
	if _, err := o.Start(nil, "github", "https://app.example.com/app", ""); err != ErrUnknownProvider {
		t.Fatalf("unknown provider = %v, want ErrUnknownProvider", err)
	}
	if _, err := o.Start(nil, "google", "https://evil.com/app", ""); err != ErrDisallowedRedirect {
		t.Fatalf("disallowed redirect = %v, want ErrDisallowedRedirect", err)
	}
}

func TestMergeScopes(t *testing.T) {
	base := []string{"openid", "email", "profile"}
	got := mergeScopes(base, []string{"https://www.googleapis.com/auth/drive.readonly", "openid"})
	if len(got) != 4 || got[3] != GoogleDriveReadonly {
		t.Fatalf("mergeScopes = %v, want base + drive (openid deduped)", got)
	}
}

func TestScopeSetAndGrantedFallback(t *testing.T) {
	got := scopeSet("openid,email,profile,https://www.googleapis.com/auth/drive.readonly")
	if !got["openid"] || !got[GoogleDriveReadonly] || got["drive"] {
		t.Fatalf("scopeSet missing/extra entries: %v", got)
	}
	// Google echoes granted scopes; GitHub falls back to the config set.
	ghConf := &oauth2.Config{Scopes: []string{"read:user", "user:email"}}
	gh := scopeSet(grantedScopes(ProviderGitHub, &oauth2.Token{}, ghConf))
	if !gh["read:user"] || !gh["user:email"] {
		t.Fatalf("github granted fallback = %v", gh)
	}
	gConf := &oauth2.Config{Scopes: []string{"openid", "email", "profile"}}
	// Google's granted scope string wins when the exchange echoed it.
	g := scopeSet(grantedScopes(ProviderGoogle, tokenWithExtraScope(), gConf))
	if !g["openid"] || !g[GoogleDriveReadonly] {
		t.Fatalf("google granted-echo handling = %v", g)
	}
}

// tokenWithExtraScope simulates a Google exchange that echoed the granted
// scopes including the ad-hoc drive.readonly.
func tokenWithExtraScope() *oauth2.Token {
	t := &oauth2.Token{}
	t = t.WithExtra(map[string]interface{}{
		"scope": "openid email profile " + GoogleDriveReadonly,
	})
	return t
}

func TestNormalizeEmail(t *testing.T) {
	for in, want := range map[string]string{
		"  Foo@Example.COM ": "foo@example.com",
		"foo@example.com":    "foo@example.com",
		"":                   "",
	} {
		if got := normalizeEmail(in); got != want {
			t.Fatalf("normalizeEmail(%q) = %q, want %q", in, got, want)
		}
	}
}
