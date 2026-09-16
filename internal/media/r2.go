package media

import (
	"bytes"
	"context"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// R2Client is the worker's SigV4 HTTP client against the R2 S3 endpoint (read
// original, PUT variants); bytes flow R2 → Go → R2, never through the request
// path.
type R2Client struct {
	endpoint  string
	bucket    string
	accessKey string
	secretKey string
	http      *http.Client
}

func NewR2Client(cfg Config) *R2Client {
	return &R2Client{
		endpoint:  cfg.Endpoint,
		bucket:    cfg.Bucket,
		accessKey: cfg.AccessKeyID,
		secretKey: cfg.SecretAccessKey,
		http:      &http.Client{Timeout: 60 * time.Second},
	}
}

func (c *R2Client) Get(ctx context.Context, key string) ([]byte, error) {
	u := c.objectURL(key)
	body := []byte{}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	signV4(req, c.accessKey, c.secretKey, body)
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("media: r2 get %s: %s", key, resp.Status)
	}
	return io.ReadAll(resp.Body)
}

func (c *R2Client) Put(ctx context.Context, key string, data []byte) error {
	u := c.objectURL(key)
	req, err := http.NewRequestWithContext(ctx, http.MethodPut, u, bytes.NewReader(data))
	if err != nil {
		return err
	}
	signV4(req, c.accessKey, c.secretKey, data)
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return fmt.Errorf("media: r2 put %s: %s", key, resp.Status)
	}
	return nil
}

func (c *R2Client) objectURL(key string) string {
	ep, _ := url.Parse(c.endpoint)
	ep.Path = "/" + c.bucket + "/" + key
	return ep.String()
}

// signV4 signs req in place with SigV4, payload hashing SHA-256 of body. The
// signature covers host, x-amz-date and x-amz-content-sha256.
func signV4(req *http.Request, accessKey, secretKey string, body []byte) {
	now := time.Now().UTC()
	dateStr := now.Format("20060102")
	timeStr := now.Format("20060102T150405Z")
	const region = "auto"

	payloadHash := hexSHA256(body)
	req.Header.Set("x-amz-date", timeStr)
	req.Header.Set("x-amz-content-sha256", payloadHash)
	req.Header.Set("host", req.URL.Host)

	canonicalURI := req.URL.EscapedPath()
	if canonicalURI == "" {
		canonicalURI = "/"
	}
	canonicalHeaders := "host:" + req.URL.Host + "\n" +
		"x-amz-content-sha256:" + payloadHash + "\n" +
		"x-amz-date:" + timeStr + "\n"
	signedHeaders := "host;x-amz-content-sha256;x-amz-date"

	scope := dateStr + "/" + region + "/s3/aws4_request"
	canonicalRequest := strings.Join([]string{
		req.Method,
		canonicalURI,
		"",
		canonicalHeaders,
		signedHeaders,
		payloadHash,
	}, "\n")

	stringToSign := strings.Join([]string{
		signingAlgorithm,
		timeStr,
		scope,
		hexSHA256([]byte(canonicalRequest)),
	}, "\n")

	key := deriveSigningKey(secretKey, dateStr, region)
	signature := hex.EncodeToString(hmacSHA256(key, []byte(stringToSign)))

	req.Header.Set("Authorization", fmt.Sprintf(
		"%s Credential=%s/%s, SignedHeaders=%s, Signature=%s",
		signingAlgorithm, accessKey, scope, signedHeaders, signature))
}
