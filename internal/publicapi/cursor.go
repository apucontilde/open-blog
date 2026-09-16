package publicapi

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
)

// ErrMalformedCursor is returned by decodeCursor for any cursor that is not a
// canonical base64url-encoded {published_at, id} object: malformed cursors map
// to 422 so the decode itself acts as the injection protection (arg binding
// is the second layer).
var ErrMalformedCursor = errors.New("publicapi: malformed cursor")

// Cursor is the keyset position (published_at, id). The list walks the 001
// index (tenant_id, status, published_at desc, id desc) as a pure range scan
// strictly before this tuple — no OFFSET, stable under concurrent writes.
type Cursor struct {
	PublishedAt time.Time `json:"published_at"`
	ID          uuid.UUID `json:"id"`
}

// encodeCursor serializes a keyset position opaque to clients (base64url).
func encodeCursor(c Cursor) string {
	b, _ := json.Marshal(c)
	return base64.RawURLEncoding.EncodeToString(b)
}

// decodeCursor parses a client-supplied cursor. Anything that is not a
// well-formed, complete (published_at, id) tuple is ErrMalformedCursor.
func decodeCursor(s string) (Cursor, error) {
	b, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		return Cursor{}, ErrMalformedCursor
	}
	var c Cursor
	if err := json.Unmarshal(b, &c); err != nil {
		return Cursor{}, ErrMalformedCursor
	}
	if c.ID == uuid.Nil || c.PublishedAt.IsZero() {
		return Cursor{}, ErrMalformedCursor
	}
	return c, nil
}

// listStatement builds the keyset list query and its args. $1 is the tenant
// id; an optional tag containment probe and cursor tuple follow; the final
// arg is limit = pageSize+1 so the caller can detect a next page. The cursor
// tuple keeps the whole scan on the composite index (sweep finding 10).
func listStatement(tenantID uuid.UUID, pageSize int, tag string, cur *Cursor) (string, []any) {
	var sb strings.Builder
	sb.WriteString("select id, slug, title, excerpt, published_at, metadata\nfrom posts\nwhere tenant_id = $1 and status = 'published'")
	args := []any{tenantID}
	if tag != "" {
		args = append(args, mustTagJSON(tag))
		fmt.Fprintf(&sb, " and metadata @> $%d::jsonb", len(args))
	}
	if cur != nil {
		args = append(args, cur.PublishedAt, cur.ID)
		fmt.Fprintf(&sb, "\n  and (published_at, id) < ($%d, $%d)", len(args)-1, len(args))
	}
	args = append(args, pageSize+1)
	fmt.Fprintf(&sb, "\norder by published_at desc, id desc\nlimit $%d", len(args))
	return sb.String(), args
}

// mustTagJSON renders the ?tag= containment probe {"tags":[$tag]}, backed by
// the 001 GIN metadata index; marshal of our own fixed shape cannot fail.
func mustTagJSON(tag string) string {
	b, _ := json.Marshal(map[string]any{"tags": []string{tag}})
	return string(b)
}
