package publicapi

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestCursorRoundTrip(t *testing.T) {
	id := uuid.New()
	when := time.Date(2026, 1, 2, 3, 4, 5, 123456789, time.UTC)
	c := Cursor{PublishedAt: when, ID: id}

	got, err := decodeCursor(encodeCursor(c))
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got.ID != id || !got.PublishedAt.Equal(when) {
		t.Fatalf("round-trip mismatch: got %+v want %+v", got, c)
	}
}

func TestDecodeCursorMalformed(t *testing.T) {
	id := uuid.New()
	j := func(s string) string { return base64.RawURLEncoding.EncodeToString([]byte(s)) }
	cases := []string{
		"",
		"!!!not-base64!!!",
		j(`{"published_at":123,"id":"` + id.String() + `"}`), // wrong published_at type
		j(`not json`), // not object
		j(`{"published_at":"2026-01-02T03:04:05Z","id":"00000000-0000-0000-0000-000000000000"}`), // nil id
		j(`{"published_at":"0001-01-01T00:00:00Z","id":"` + id.String() + `"}`),                  // zero time
		j(`{"published_at":"not-a-time","id":"` + id.String() + `"}`),                            // bad time string
		j(`{"id":"` + id.String() + `"}`),                                                        // missing published_at
		j(`{"published_at":"2026-01-02T03:04:05Z"}`),                                             // missing id
	}
	for _, s := range cases {
		if _, err := decodeCursor(s); !errors.Is(err, ErrMalformedCursor) {
			t.Fatalf("cursor %q: want ErrMalformedCursor, got %v", s, err)
		}
	}
}

func TestDecodeCursor_Valid_MinimalShellPaddingRejected(t *testing.T) {
	// Strict base64url (unpadded) by contract: a padded or standard-encoded
	// variant must not decode.
	c := Cursor{PublishedAt: time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC), ID: uuid.New()}
	padded := base64.URLEncoding.EncodeToString(mustJSON(c))
	if _, err := decodeCursor(padded); !errors.Is(err, ErrMalformedCursor) {
		t.Fatalf("padded cursor accepted: %v", err)
	}
}

func mustJSON(v any) []byte {
	b, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return b
}
