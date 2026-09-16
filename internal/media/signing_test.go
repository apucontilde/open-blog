package media

import (
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
)

// TestSigV4PresignAWSVector pins the signer against the AWS docs' canonical
// query-parameter example (signature aeeed9bb…404).
func TestSigV4PresignAWSVector(t *testing.T) {
	now := time.Date(2013, 5, 24, 0, 0, 0, 0, time.UTC)
	docQuery := "X-Amz-Algorithm=AWS4-HMAC-SHA256" +
		"&X-Amz-Credential=AKIAIOSFODNN7EXAMPLE%2F20130524%2Fus-east-1%2Fs3%2Faws4_request" +
		"&X-Amz-Date=20130524T000000Z&X-Amz-Expires=86400&X-Amz-SignedHeaders=host"
	sig := presignedSignature(
		"AKIAIOSFODNN7EXAMPLE",
		"wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
		"us-east-1",
		now,
		"GET", "examplebucket.s3.amazonaws.com", "/test.txt", docQuery)
	if sig != "aeeed9bbccd4d02ee5c0109b86d86835f995330da4c265957d157751f604d404" {
		t.Fatalf("signature = %q, want the AWS docs vector aeeed9…404", sig)
	}
}

// TestPresignURLStructure: the URL carries the SigV4 params, endpoint host, and
// full path-style object path.
func TestPresignURLStructure(t *testing.T) {
	now := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	u, err := PresignPutURL(
		"https://acct.r2.cloudflarestorage.com",
		"openblog",
		"acme/posts/0a1b2c3d-0000-0000-0000-000000000000/img.jpg",
		"AKID",
		"SECRET",
		now,
		15*time.Minute,
	)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := url.Parse(u)
	if err != nil {
		t.Fatal(err)
	}
	if parsed.Host != "acct.r2.cloudflarestorage.com" {
		t.Fatalf("host = %q", parsed.Host)
	}
	if parsed.Path != "/openblog/acme/posts/0a1b2c3d-0000-0000-0000-000000000000/img.jpg" {
		t.Fatalf("path = %q", parsed.Path)
	}
	qs := parsed.Query()
	for _, k := range []string{"X-Amz-Algorithm", "X-Amz-Credential", "X-Amz-Date", "X-Amz-Expires", "X-Amz-SignedHeaders", "X-Amz-Signature"} {
		if qs.Get(k) == "" {
			t.Fatalf("missing presign param %s", k)
		}
	}
	if !strings.HasPrefix(qs.Get("X-Amz-Credential"), "AKID/") {
		t.Fatalf("credential = %q", qs.Get("X-Amz-Credential"))
	}
}

// TestSignV4SignsHeaders: the worker signer produces a real SigV4 credential
// scope over host+date+payload-hash.
func TestSignV4SignsHeaders(t *testing.T) {
	req, err := http.NewRequest("PUT", "https://acct.r2.cloudflarestorage.com/openblog/a/b", nil)
	if err != nil {
		t.Fatal(err)
	}
	signV4(req, "AKID", "SECRET", []byte("hello"))
	auth := req.Header.Get("Authorization")
	if !strings.HasPrefix(auth, "AWS4-HMAC-SHA256 Credential=AKID/") {
		t.Fatalf("authorization = %q", auth)
	}
	if !strings.Contains(auth, "SignedHeaders=host;x-amz-content-sha256;x-amz-date") {
		t.Fatalf("authorization signed headers mismatch: %q", auth)
	}
	// deterministic sha256 of "hello" must be the payload hash
	if req.Header.Get("x-amz-content-sha256") != "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824" {
		t.Fatalf("payload hash = %q", req.Header.Get("x-amz-content-sha256"))
	}
	if req.Header.Get("x-amz-date") == "" {
		t.Fatal("missing x-amz-date")
	}
}

// TestEncodeQueryValue verifies RFC 3986 percent-encoding (the SigV4 rule).
func TestEncodeQueryValue(t *testing.T) {
	cases := []struct{ in, want string }{
		{"AKIAIOSFODNN7EXAMPLE/20130524/us-east-1/s3/aws4_request",
			"AKIAIOSFODNN7EXAMPLE%2F20130524%2Fus-east-1%2Fs3%2Faws4_request"},
		{"20130524T000000Z", "20130524T000000Z"},
		{"a b&c=d", "a%20b%26c%3Dd"},
	}
	for _, c := range cases {
		if got := encodeQueryValue(c.in); got != c.want {
			t.Fatalf("encodeQueryValue(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestExtFromName(t *testing.T) {
	cases := []struct{ in, want string }{
		{"photo.jpg", ".jpg"},
		{"photo.JPEG", ".jpg"},
		{"tenant/posts/x/u.png", ".png"},
		{"u-480.webp", ".webp"},
		{"photo.gif", ".gif"},
		{"photo", ""},
		{"photo.exe", ""},
	}
	for _, c := range cases {
		if got := extFromName(c.in); got != c.want {
			t.Fatalf("extFromName(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

var keyRe = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/posts/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[0-9a-f]{4}-[0-9a-f]{12}\.jpg$`)

func TestPresignKeyLayout(t *testing.T) {
	m := New(Config{
		Endpoint:        "https://acct.r2.cloudflarestorage.com",
		Bucket:          "openblog",
		AccessKeyID:     "AKID",
		SecretAccessKey: "SECRET",
		CDNBase:         "https://media.example.com",
	}, nil, nil)
	// uuid v7 mints a key with a '7' in the third group.
	now := time.Unix(0, 0)
	pu, err := m.Presign(uuid.New(), uuid.New(), "cover.jpg", now)
	if err != nil {
		t.Fatal(err)
	}
	if !keyRe.MatchString(pu.Key) {
		t.Fatalf("key layout %q does not match %q", pu.Key, keyRe)
	}
	if !strings.Contains(pu.URL, "X-Amz-Signature=") {
		t.Fatalf("presigned URL missing signature: %s", pu.URL)
	}
	if d := pu.ExpiresAt.Sub(now); d != 15*time.Minute {
		t.Fatalf("expiry = %v, want 15m", d)
	}
}
