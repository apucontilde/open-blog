package authz

import (
	"context"
	"errors"
	"os"
	"testing"

	"github.com/google/uuid"

	"openblog/internal/store"
)

// TestResolveActor skips unless DATABASE_URL is set; seed rows are created
// unscoped because memberships and users are not RLS-scoped.
func TestResolveActor(t *testing.T) {
	dsn := os.Getenv("DATABASE_URL")
	if dsn == "" {
		t.Skip("DATABASE_URL not set")
	}
	db, err := store.New(context.Background(), dsn)
	if err != nil {
		t.Fatalf("store.New: %v", err)
	}
	defer db.Close()

	seed := func(t *testing.T, db *store.DB, super bool, role string) (userID, tenantID uuid.UUID) {
		t.Helper()
		var (
			ctx   = context.Background()
			u, t2 = uuid.New(), uuid.New()
		)
		err := db.ScopedRW(ctx, store.Scope{Platform: true}, func(q *store.Queries) error {
			if err := q.CreateTenant(ctx, t2, "t-"+uuid.NewString(), "T"); err != nil {
				return err
			}
			if err := q.CreateUser(ctx, u, uuid.NewString()+"@x.test", "U", nil); err != nil {
				return err
			}
			if role != "" {
				if err := q.AddMembership(ctx, t2, u, role); err != nil {
					return err
				}
			}
			if super {
				return q.SetSuperAdmin(ctx, u, true)
			}
			return nil
		})
		if err != nil {
			t.Fatalf("seed: %v", err)
		}
		return u, t2
	}

	t.Run("member with role", func(t *testing.T) {
		u, t2 := seed(t, db, false, "editor")
		a, err := ResolveActor(context.Background(), db, u, t2)
		if err != nil {
			t.Fatalf("ResolveActor: %v", err)
		}
		if a.UserID != u || a.Role != RoleEditor || a.Tenant == nil || *a.Tenant != t2 || a.Platform {
			t.Fatalf("bad actor: %+v", a)
		}
	})
	t.Run("super_admin resolves platform-wide", func(t *testing.T) {
		u, _ := seed(t, db, true, "")
		a, err := ResolveActor(context.Background(), db, u, uuid.New())
		if err != nil {
			t.Fatalf("ResolveActor: %v", err)
		}
		if !a.Platform || a.Tenant != nil || a.Role != 0 {
			t.Fatalf("bad platform actor: %+v", a)
		}
	})
	t.Run("non-member non-super is ErrNotMember", func(t *testing.T) {
		u, t2 := seed(t, db, false, "")
		_, err := ResolveActor(context.Background(), db, u, t2)
		if !errors.Is(err, store.ErrNotMember) {
			t.Fatalf("err = %v, want ErrNotMember", err)
		}
	})
}
