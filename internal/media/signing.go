package media

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"
)

// Hand-rolled SigV4 presigning against R2's S3-compatible endpoint (no AWS SDK).
// Only the host header is signed and the payload hash is UNSIGNED-PAYLOAD, so a
// presigned PUT carries any body.

const signingAlgorithm = "AWS4-HMAC-SHA256"
const unsignedPayload = "UNSIGNED-PAYLOAD"

// PresignPutURL presigns a path-style PUT (bucket in the canonical URI) with
// region "auto"; the signature is pinned to now.
func PresignPutURL(endpoint, bucket, key, accessKey, secretKey string, now time.Time, expiry time.Duration) (string, error) {
	return PresignPutURLWithRegion(endpoint, bucket, key, accessKey, secretKey, "auto", now, expiry)
}

// PresignPutURLWithRegion exposes an explicit region for the SigV4 vector tests.
func PresignPutURLWithRegion(endpoint, bucket, key, accessKey, secretKey, region string, now time.Time, expiry time.Duration) (string, error) {
	ep, err := url.Parse(endpoint)
	if err != nil {
		return "", fmt.Errorf("media: bad endpoint: %w", err)
	}
	if expiry <= 0 {
		return "", fmt.Errorf("media: presign expiry must be positive")
	}
	if ep.Host == "" {
		return "", fmt.Errorf("media: endpoint %q has no host", endpoint)
	}

	canonicalURI := "/" + encodePath(bucket) + "/" + encodePath(key)
	query := canonicalQuery(params{
		{"X-Amz-Algorithm", signingAlgorithm},
		{"X-Amz-Credential", accessKey + "/" + credentialScope(now, region)},
		{"X-Amz-Date", now.UTC().Format("20060102T150405Z")},
		{"X-Amz-Expires", fmt.Sprintf("%d", int64(expiry/time.Second))},
		{"X-Amz-SignedHeaders", "host"},
	})

	sig := presignedSignature(accessKey, secretKey, region, now,
		http.MethodPut, ep.Host, canonicalURI, query)

	u := *ep
	u.Path = canonicalURI
	u.RawQuery = query + "&X-Amz-Signature=" + encodeQueryValue(sig)
	return u.String(), nil
}

// credentialScope is yyyyMMdd/<region>/s3/aws4_request.
func credentialScope(now time.Time, region string) string {
	return now.UTC().Format("20060102") + "/" + region + "/s3/aws4_request"
}

// presignedSignature builds the SigV4 query-param signature; it is independent
// of how the bucket appears in the URI, so it pins to the AWS docs' exact
// example vector.
func presignedSignature(accessKey, secretKey, region string, now time.Time, method, host, canonicalURI, canonicalQuery string) string {
	timeStr := now.UTC().Format("20060102T150405Z")
	dateStr := now.UTC().Format("20060102")
	scope := credentialScope(now, region)

	canonicalRequest := strings.Join([]string{
		method,
		canonicalURI,
		canonicalQuery,
		"host:" + host + "\n",
		"host",
		unsignedPayload,
	}, "\n")

	stringToSign := strings.Join([]string{
		signingAlgorithm,
		timeStr,
		scope,
		hexSHA256([]byte(canonicalRequest)),
	}, "\n")

	signingKey := deriveSigningKey(secretKey, dateStr, region)
	return hex.EncodeToString(hmacSHA256(signingKey, []byte(stringToSign)))
}

type param struct{ k, v string }

type params []param

func canonicalQuery(ps params) string {
	sort.Slice(ps, func(i, j int) bool { return ps[i].k < ps[j].k })
	var b strings.Builder
	for i, p := range ps {
		if i > 0 {
			b.WriteByte('&')
		}
		b.WriteString(encodeQueryValue(p.k))
		b.WriteByte('=')
		b.WriteString(encodeQueryValue(p.v))
	}
	return b.String()
}

func deriveSigningKey(secret, date, region string) []byte {
	kDate := hmacSHA256([]byte("AWS4"+secret), []byte(date))
	kRegion := hmacSHA256(kDate, []byte(region))
	kService := hmacSHA256(kRegion, []byte("s3"))
	return hmacSHA256(kService, []byte("aws4_request"))
}

func hmacSHA256(key, data []byte) []byte {
	h := hmac.New(sha256.New, key)
	h.Write(data)
	return h.Sum(nil)
}

func hexSHA256(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// encodeQueryValue percent-encodes every byte except RFC 3986 unreserved —
// URI-encoding for SigV4 query params. A `/` in the value (X-Amz-Credential)
// becomes %2F.
func encodeQueryValue(s string) string {
	const hextab = "0123456789ABCDEF"
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		if isUnreserved(c) {
			b.WriteByte(c)
		} else {
			b.WriteByte('%')
			b.WriteByte(hextab[c>>4])
			b.WriteByte(hextab[c&0x0f])
		}
	}
	return b.String()
}

func isUnreserved(c byte) bool {
	return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
		(c >= '0' && c <= '9') || c == '-' || c == '_' || c == '.' || c == '~'
}

// encodePath escapes each path segment, preserving '/' separators, for the
// canonical URI.
func encodePath(s string) string {
	segs := strings.Split(s, "/")
	for i, seg := range segs {
		segs[i] = encodeQueryValue(seg)
	}
	return strings.Join(segs, "/")
}
