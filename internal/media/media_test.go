package media

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"image"
	"image/color"
	"image/png"
	"testing"

	"github.com/google/uuid"

	"openblog/internal/authz"
)

// TestConfirmValidation: mime allow-list and size cap are enforced before any
// row is written.
func TestConfirmValidation(t *testing.T) {
	m := New(Config{CDNBase: "https://media.example.com"}, nil, nil)
	ctx := context.Background()

	if _, err := m.Confirm(ctx, nil, uuid.New(), uuid.New(), "a/posts/b/c.jpg", 100, "image/pdf"); !errors.Is(err, ErrInvalidMime) {
		t.Fatalf("pdf mime err = %v, want ErrInvalidMime", err)
	}
	if _, err := m.Confirm(ctx, nil, uuid.New(), uuid.New(), "a/posts/b/c.svg", 100, "image/svg+xml"); !errors.Is(err, ErrInvalidMime) {
		t.Fatalf("svg mime err = %v, want ErrInvalidMime", err)
	}
	if _, err := m.Confirm(ctx, nil, uuid.New(), uuid.New(), "a/posts/b/c.png", 16_000_000, "image/png"); !errors.Is(err, ErrPayloadTooLarge) {
		t.Fatalf("oversize err = %v, want ErrPayloadTooLarge", err)
	}
}

// TestBuildVariantsJSON: one entry per width, url/width/height present, pending
// marked in the no-vips branch.
func TestBuildVariantsJSON(t *testing.T) {
	p := Processed{
		OriginalWidth:  1600,
		OriginalHeight: 900,
		Variants: []Result{
			{Label: "480", Key: "a/posts/b/u-480.webp", Data: []byte{1}, Width: 480, Height: 270},
			{Label: "800", Key: "a/posts/b/u-800.webp", Width: 800, Height: 450},
			{Label: "1200", Key: "a/posts/b/u-1200.webp", Data: []byte{3}, Width: 1200, Height: 675},
		},
	}
	b, err := buildVariantsJSON(p, "https://media.example.com", "a/posts/b/u.jpg")
	if err != nil {
		t.Fatal(err)
	}

	var got map[string]struct {
		URL        string `json:"url"`
		Width      int    `json:"width"`
		Height     int    `json:"height"`
		Processing string `json:"processing"`
	}
	if err := json.Unmarshal(b, &got); err != nil {
		t.Fatal(err)
	}
	if len(got) != 3 {
		t.Fatalf("got %d entries, want 3", len(got))
	}
	for _, w := range []string{"480", "800", "1200"} {
		e, ok := got[w]
		if !ok {
			t.Fatalf("missing variant %s", w)
		}
		if e.Width == 0 || e.Height == 0 {
			t.Fatalf("variant %s has zero dims: %+v", w, e)
		}
	}
	if got["480"].URL != "https://media.example.com/a/posts/b/u-480.webp" {
		t.Fatalf("480 url = %q", got["480"].URL)
	}
	if got["800"].Processing != "pending" {
		t.Fatalf("800 (no data) should be pending, got %q", got["800"].Processing)
	}
	if got["800"].URL != "https://media.example.com/a/posts/b/u.jpg" {
		t.Fatalf("800 pending should point at the original: %q", got["800"].URL)
	}
}

// TestNoopProcessorDegradation: without libvips the processor derives variant
// keys, reads png header dims, and yields no encoded data.
func TestNoopProcessorDegradation(t *testing.T) {
	var buf bytes.Buffer
	img := image.NewRGBA(image.Rect(0, 0, 2, 1))
	img.Set(0, 0, color.RGBA{R: 255, A: 255})
	img.Set(1, 0, color.RGBA{G: 255, A: 255})
	if err := png.Encode(&buf, img); err != nil {
		t.Fatal(err)
	}
	pngBytes := buf.Bytes()

	p, err := NewNoopProcessor().Process(context.Background(), ".png", pngBytes, "ten/posts/pid/u.png")
	if err != nil {
		t.Fatal(err)
	}
	if p.OriginalWidth != 2 || p.OriginalHeight != 1 {
		t.Fatalf("dimensions = %dx%d, want 2x1", p.OriginalWidth, p.OriginalHeight)
	}
	if len(p.Variants) != 3 {
		t.Fatalf("variants = %d, want 3", len(p.Variants))
	}
	for _, v := range p.Variants {
		if v.Data != nil {
			t.Fatalf("default build must not encode: %s has data", v.Label)
		}
		wantKey := "ten/posts/pid/u-" + v.Label + ".webp"
		if v.Key != wantKey {
			t.Fatalf("variant key %q, want %q", v.Key, wantKey)
		}
	}
}

// TestDeletePermissionMatrix: editors+ delete any row; a plain author only
// images on a post they own.
func TestDeletePermissionMatrix(t *testing.T) {
	user := uuid.New()
	other := uuid.New()
	tid := uuid.New()

	actors := []struct {
		name    string
		actor   authz.Actor
		author  uuid.UUID // author of the target post
		allowed bool
	}{
		{"author owns", authz.Actor{UserID: user, Tenant: &tid, Role: authz.RoleAuthor}, user, true},
		{"author other's", authz.Actor{UserID: user, Tenant: &tid, Role: authz.RoleAuthor}, other, false},
		{"editor any", authz.Actor{UserID: user, Tenant: &tid, Role: authz.RoleEditor}, other, true},
		{"admin any", authz.Actor{UserID: user, Tenant: &tid, Role: authz.RoleAdmin}, other, true},
		{"owner any", authz.Actor{UserID: user, Tenant: &tid, Role: authz.RoleOwner}, other, true},
		{"platform any", authz.Actor{UserID: user, Platform: true}, other, true},
	}

	for _, c := range actors {
		t.Run(c.name, func(t *testing.T) {
			// Mirrors media.Delete's decision.
			var decision bool
			if c.actor.Can(authz.CapEditAnyPost) {
				decision = true
			} else {
				decision = c.actor.OwnsPost(c.author)
			}
			if decision != c.allowed {
				t.Fatalf("allowed = %v, want %v", decision, c.allowed)
			}
		})
	}
}

// TestScopeFromActorUsedByDelete: a platform actor gets a nil tenant so RLS is
// widened by app_scope, never by a guessed tenant.
func TestScopeFromActorUsedByDelete(t *testing.T) {
	tid := uuid.New()
	s := authz.ScopeFromActor(authz.Actor{UserID: uuid.New(), Tenant: &tid, Role: authz.RoleOwner})
	if s.TenantID != tid || s.Platform {
		t.Fatalf("scope = %+v", s)
	}
	ps := authz.ScopeFromActor(authz.Actor{UserID: uuid.New(), Platform: true})
	if ps.TenantID != uuid.Nil || !ps.Platform {
		t.Fatalf("platform scope = %+v", ps)
	}
}
