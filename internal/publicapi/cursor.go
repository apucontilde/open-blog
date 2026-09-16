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

// ErrMalformedCursor maps to 422; strict decode is the first injection defense, arg binding the second.
var ErrMalformedCursor = errors.New("publicapi: malformed cursor")

// Cursor is the keyset position (published_at, id) for a strictly-before range scan — no OFFSET.
type Cursor struct {
	PublishedAt time.Time `json:"published_at"`
	ID          uuid.UUID `json:"id"`
}

func encodeCursor(c Cursor) string {
	b, _ := json.Marshal(c)
	return base64.RawURLEncoding.EncodeToString(b)
}

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

// listStatement builds the keyset query; the final arg is limit=pageSize+1 so the caller can detect a next page.
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

// mustTagJSON renders {"tags":[tag]}, the GIN metadata containment probe.
func mustTagJSON(tag string) string {
	b, _ := json.Marshal(map[string]any{"tags": []string{tag}})
	return string(b)
}
