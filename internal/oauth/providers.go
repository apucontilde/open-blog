package oauth

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"

	"golang.org/x/oauth2"
)

const (
	googleAuthURL     = "https://accounts.google.com/o/oauth2/v2/auth"
	googleTokenURL    = "https://oauth2.googleapis.com/token"
	googleUserinfoURL = "https://openidconnect.googleapis.com/v1/userinfo"
	googleLoginScopes = "openid email profile"

	githubAuthURL     = "https://github.com/login/oauth/authorize"
	githubTokenURL    = "https://github.com/login/oauth/access_token"
	githubUserURL     = "https://api.github.com/user"
	githubEmailsURL   = "https://api.github.com/user/emails"
	githubLoginScopes = "read:user user:email"
)

type Claims struct {
	Subject       string
	Email         string
	EmailVerified bool
	DisplayName   string
}

type provider struct {
	name   string
	conf   *oauth2.Config
	claims func(ctx context.Context, accessToken string) (Claims, error)
}

// oidcUserinfo fetches Google's OIDC userinfo; email_verified is honored exactly.
func oidcUserinfo(userinfoURL string, client *http.Client) func(ctx context.Context, accessToken string) (Claims, error) {
	return func(ctx context.Context, accessToken string) (Claims, error) {
		b, err := getJSON(ctx, client, userinfoURL, accessToken, nil)
		if err != nil {
			return Claims{}, err
		}
		var v struct {
			Sub           string `json:"sub"`
			Email         string `json:"email"`
			EmailVerified bool   `json:"email_verified"`
			Name          string `json:"name"`
		}
		if err := json.Unmarshal(b, &v); err != nil {
			return Claims{}, err
		}
		if v.Sub == "" {
			return Claims{}, fmt.Errorf("oauth: google userinfo missing sub")
		}
		return Claims{
			Subject:       v.Sub,
			Email:         v.Email,
			EmailVerified: v.EmailVerified,
			DisplayName:   v.Name,
		}, nil
	}
}

// githubUserAndEmails resolves the numeric user id and the verified primary email.
func githubUserAndEmails(userURL, emailsURL string, client *http.Client) func(ctx context.Context, accessToken string) (Claims, error) {
	return func(ctx context.Context, accessToken string) (Claims, error) {
		b, err := getJSON(ctx, client, userURL, accessToken, map[string]string{
			"Accept": "application/vnd.github+json",
		})
		if err != nil {
			return Claims{}, err
		}
		var u struct {
			ID    int64  `json:"id"`
			Login string `json:"login"`
			Name  string `json:"name"`
			Email string `json:"email"`
		}
		if err := json.Unmarshal(b, &u); err != nil {
			return Claims{}, err
		}
		if u.ID == 0 {
			return Claims{}, fmt.Errorf("oauth: github user missing id")
		}
		c := Claims{
			Subject:     strconv.FormatInt(u.ID, 10),
			Email:       u.Email,
			DisplayName: u.Name,
		}
		if c.DisplayName == "" {
			c.DisplayName = u.Login
		}
		eb, err := getJSON(ctx, client, emailsURL, accessToken, map[string]string{
			"Accept": "application/vnd.github+json",
		})
		if err != nil {
			return c, nil // emails optional; fall back to the /user email
		}
		var es []struct {
			Email    string `json:"email"`
			Primary  bool   `json:"primary"`
			Verified bool   `json:"verified"`
		}
		if err := json.Unmarshal(eb, &es); err != nil {
			return c, nil
		}
		for _, e := range es { // verified primary, else verified, else first
			if e.Verified && e.Primary {
				c.Email, c.EmailVerified = e.Email, true
				return c, nil
			}
		}
		for _, e := range es {
			if e.Verified {
				c.Email, c.EmailVerified = e.Email, true
				return c, nil
			}
		}
		if len(es) > 0 {
			c.Email, c.EmailVerified = es[0].Email, es[0].Verified
		}
		return c, nil
	}
}

func getJSON(ctx context.Context, client *http.Client, url, accessToken string, headers map[string]string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("oauth: userinfo %s returned %d", url, resp.StatusCode)
	}
	return io.ReadAll(io.LimitReader(resp.Body, 1<<20))
}
