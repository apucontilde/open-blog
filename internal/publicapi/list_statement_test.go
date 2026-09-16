package publicapi

import (
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestListStatementNoFilters(t *testing.T) {
	tenant := uuid.New()
	q, args := listStatement(tenant, 25, "", nil)
	if len(args) != 2 {
		t.Fatalf("args = %d, want 2 (tenant + limit)", len(args))
	}
	if args[0] != tenant {
		t.Fatalf("arg0 = %v, want tenant", args[0])
	}
	if args[1] != 26 {
		t.Fatalf("arg1 = %v, want pageSize+1", args[1])
	}
	for _, want := range []string{
		"where tenant_id = $1", "status = 'published'",
		"order by published_at desc, id desc", "limit $2",
	} {
		if !strings.Contains(q, want) {
			t.Fatalf("query missing %q:\n%s", want, q)
		}
	}
	if strings.Contains(q, "metadata @>") || strings.Contains(q, "(published_at, id) <") {
		t.Fatalf("unexpected filters:\n%s", q)
	}
}

func TestListStatementTagOnly(t *testing.T) {
	tenant := uuid.New()
	q, args := listStatement(tenant, 10, "go", nil)
	if len(args) != 3 {
		t.Fatalf("args = %d, want 3 (tenant + tag + limit)", len(args))
	}
	tagJSON, ok := args[1].(string)
	if !ok {
		t.Fatalf("arg1 type = %T, want string", args[1])
	}
	if !strings.Contains(tagJSON, `"tags":{"`) && !strings.Contains(tagJSON, `{"tags":["go"]}`) {
		t.Fatalf("tag arg = %q, want a {\"tags\":[\"go\"]} probe", tagJSON)
	}
	if !strings.Contains(q, "metadata @> $2::jsonb") || !strings.Contains(q, "limit $3") {
		t.Fatalf("query wrong:\n%s", q)
	}
}

func TestListStatementCursorOnly(t *testing.T) {
	tenant := uuid.New()
	when := time.Date(2026, 5, 6, 7, 8, 9, 0, time.UTC)
	cur := &Cursor{PublishedAt: when, ID: uuid.New()}
	q, args := listStatement(tenant, 10, "", cur)
	if len(args) != 4 {
		t.Fatalf("args = %d, want 4 (tenant + cursor pair + limit)", len(args))
	}
	if args[1] != when || args[2] != cur.ID || args[3] != 11 {
		t.Fatalf("args = %v, want [tenant published_at id 11]", args)
	}
	if !strings.Contains(q, "(published_at, id) < ($2, $3)") || !strings.Contains(q, "limit $4") {
		t.Fatalf("query wrong:\n%s", q)
	}
}

func TestListStatementTagAndCursor(t *testing.T) {
	tenant := uuid.New()
	when := time.Date(2026, 5, 6, 7, 8, 9, 0, time.UTC)
	cur := &Cursor{PublishedAt: when, ID: uuid.New()}
	q, args := listStatement(tenant, 10, "go", cur)
	if len(args) != 5 {
		t.Fatalf("args = %d, want 5 (tenant + tag + cursor pair + limit)", len(args))
	}
	if !strings.Contains(q, "metadata @> $2::jsonb") {
		t.Fatalf("tag predicate missing or wrong placeholder:\n%s", q)
	}
	if !strings.Contains(q, "(published_at, id) < ($3, $4)") || !strings.Contains(q, "limit $5") {
		t.Fatalf("cursor/limit placeholders wrong:\n%s", q)
	}
}

func TestMustTagJSON(t *testing.T) {
	if got := mustTagJSON("go"); got != `{"tags":["go"]}` {
		t.Fatalf("mustTagJSON = %q", got)
	}
}
