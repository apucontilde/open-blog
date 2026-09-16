package main

import (
	"encoding/hex"
	"errors"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
)

// Config is the environment parsed once at startup; zero values select defaults.
type Config struct {
	DBURL    string
	Port     int
	Session  sessionCfg
	Origins  []string
	Posts    postsCfg
	Media    mediaCfg
	OAuth    oauthCfg
	Workers  int
	OAuthKey []byte
}

type sessionCfg struct {
	Name   string
	Secure bool
}

type postsCfg struct {
	MediaOrigin string
}

type mediaCfg struct {
	Endpoint        string
	Bucket          string
	AccessKeyID     string
	SecretAccessKey string
	PresignExpiry   time.Duration
	CDNBase         string
}

type oauthCfg struct {
	Google struct {
		ClientID     string
		ClientSecret string
		RedirectURL  string
	}
	GitHub struct {
		ClientID     string
		ClientSecret string
		RedirectURL  string
	}
	RedirectAllow []*url.URL
}

func loadConfig() (*Config, error) {
	var cfg Config
	var err error

	cfg.DBURL = os.Getenv("DATABASE_URL")
	if cfg.DBURL == "" {
		return nil, errors.New("DATABASE_URL is required")
	}
	cfg.Port, err = intEnv("PORT", 8080)
	if err != nil {
		return nil, err
	}
	keyHex, ok := os.LookupEnv("SESSION_KEY")
	if !ok {
		return nil, errors.New("SESSION_KEY is required (64 hex chars = 32 bytes AES-256)")
	}
	cfg.OAuthKey, err = decodeHexKey(keyHex)
	if err != nil {
		return nil, err
	}
	cfg.Session.Name = strEnv("SESSION_COOKIE_NAME", "openblog_session")
	cfg.Session.Secure = boolEnv("COOKIE_SECURE", false)
	cfg.Origins = splitCSV(os.Getenv("EDITOR_ORIGINS"))
	cfg.Posts.MediaOrigin = os.Getenv("POSTS_MEDIA_ORIGIN")

	cfg.Media.Endpoint = os.Getenv("R2_ENDPOINT")
	cfg.Media.Bucket = os.Getenv("R2_BUCKET")
	cfg.Media.AccessKeyID = os.Getenv("R2_ACCESS_KEY_ID")
	cfg.Media.SecretAccessKey = os.Getenv("R2_SECRET_ACCESS_KEY")
	cfg.Media.CDNBase = strings.TrimRight(os.Getenv("R2_CDN_BASE"), "/")
	cfg.Media.PresignExpiry, err = durEnv("MEDIA_PRESIGN_TTL", 15*time.Minute)
	if err != nil {
		return nil, err
	}

	cfg.OAuth.Google.ClientID = os.Getenv("GOOGLE_OAUTH_CLIENT_ID")
	cfg.OAuth.Google.ClientSecret = os.Getenv("GOOGLE_OAUTH_CLIENT_SECRET")
	cfg.OAuth.Google.RedirectURL = os.Getenv("GOOGLE_OAUTH_REDIRECT_URL")
	cfg.OAuth.GitHub.ClientID = os.Getenv("GITHUB_OAUTH_CLIENT_ID")
	cfg.OAuth.GitHub.ClientSecret = os.Getenv("GITHUB_OAUTH_CLIENT_SECRET")
	cfg.OAuth.GitHub.RedirectURL = os.Getenv("GITHUB_OAUTH_REDIRECT_URL")
	for _, s := range splitCSV(os.Getenv("OAUTH_REDIRECT_ALLOW")) {
		if s == "" {
			continue
		}
		u, uerr := url.Parse(s)
		if uerr != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") {
			return nil, errors.New("OAUTH_REDIRECT_ALLOW entry is not an absolute http(s) URL: " + s)
		}
		cfg.OAuth.RedirectAllow = append(cfg.OAuth.RedirectAllow, u)
	}

	cfg.Workers, err = intEnv("JOBS_WORKERS", 3)
	if err != nil {
		return nil, err
	}
	return &cfg, nil
}

func splitCSV(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

func strEnv(name, def string) string {
	if v := os.Getenv(name); v != "" {
		return v
	}
	return def
}

func intEnv(name string, def int) (int, error) {
	v, ok := os.LookupEnv(name)
	if !ok || v == "" {
		return def, nil
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return 0, errors.New(name + " must be an integer")
	}
	return n, nil
}

func durEnv(name string, def time.Duration) (time.Duration, error) {
	if v, ok := os.LookupEnv(name); ok && v != "" {
		d, err := time.ParseDuration(v)
		if err != nil {
			return 0, errors.New(name + " must be a duration")
		}
		return d, nil
	}
	return def, nil
}

func boolEnv(name string, def bool) bool {
	v, ok := os.LookupEnv(name)
	if !ok || v == "" {
		return def
	}
	return v == "1" || v == "true" || v == "True"
}

func decodeHexKey(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	if len(s) != 64 {
		return nil, errors.New("SESSION_KEY must be 64 hex chars")
	}
	b, err := hex.DecodeString(s)
	if err != nil {
		return nil, errors.New("SESSION_KEY must be valid hex")
	}
	return b, nil
}
