package httptest

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/google/uuid"

	"openblog/internal/store"
)

type postJSON struct {
	ID          uuid.UUID `json:"id"`
	TenantID    uuid.UUID `json:"tenant_id"`
	AuthorID    uuid.UUID `json:"author_id"`
	Slug        string    `json:"slug"`
	Title       string    `json:"title"`
	Status      string    `json:"status"`
	ContentHTML string    `json:"content_html"`
}

type publicPostJSON struct {
	Slug        string `json:"slug"`
	Title       string `json:"title"`
	ContentHTML string `json:"content_html"`
	Author      string `json:"author"`
}

type listJSON struct {
	Posts []struct {
		Slug  string `json:"slug"`
		Title string `json:"title"`
	} `json:"posts"`
	NextCursor string `json:"next_cursor"`
}

type meJSON struct {
	UserID      uuid.UUID  `json:"user_id"`
	TenantID    *uuid.UUID `json:"tenant_id"`
	Role        string     `json:"role"`
	Platform    bool       `json:"platform"`
	Memberships []struct {
		TenantID uuid.UUID `json:"tenant_id"`
		Slug     string    `json:"slug"`
		Name     string    `json:"name"`
		Role     string    `json:"role"`
	} `json:"memberships"`
}

type tenantJSON struct {
	ID             uuid.UUID `json:"id"`
	Slug           string    `json:"slug"`
	Name           string    `json:"name"`
	ContentVersion int64     `json:"content_version"`
}

type errEnvelope struct {
	Error struct {
		Code    string `json:"code"`
		Message string `json:"message"`
	} `json:"error"`
}

func mustStatus(t *testing.T, resp *http.Response, want int) {
	t.Helper()
	if resp.StatusCode != want {
		b, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		t.Fatalf("%s %s: status = %d, want %d; body=%s",
			resp.Request.Method, resp.Request.URL.Path, resp.StatusCode, want, b)
	}
}

func createPost(t *testing.T, srv *httptest.Server, token, title, md string) postJSON {
	t.Helper()
	resp := do(t, srv, req(t, http.MethodPost, srv.URL+"/admin/posts", map[string]any{
		"title": title, "content_markdown": md,
	}), token)
	mustStatus(t, resp, http.StatusCreated)
	var p postJSON
	decode(t, resp, &p)
	return p
}

// ST-1/ST-5: publish renders once; public read serves it; client tenant_id ignored.
func TestST1_RenderOnPublishAndPublicRead(t *testing.T) {
	h := newHarness(t)
	srv := h.httpServer()
	defer srv.Close()

	tenant := h.createTenant("alpha", "Alpha")
	editor := h.createUser("editor@example.com", "pw")
	h.addMembership(tenant, editor, "editor")
	token := h.issueToken(editor, &tenant)

	other := h.createTenant("other", "Other")
	resp := do(t, srv, req(t, http.MethodPost, srv.URL+"/admin/posts", map[string]any{
		"title":            "Hello",
		"content_markdown": "# Heading\n\n**bold** text",
		"tenant_id":        other.String(), // must be ignored (ST-5)
	}), token)
	mustStatus(t, resp, http.StatusCreated)
	var p postJSON
	decode(t, resp, &p)
	if p.TenantID != tenant {
		t.Fatalf("client tenant_id not ignored: got %s, want %s", p.TenantID, tenant)
	}
	if p.Status != "draft" {
		t.Fatalf("status = %q, want draft", p.Status)
	}

	// ST-2: a draft is invisible on the public path.
	r := do(t, srv, req(t, http.MethodGet, srv.URL+"/public/alpha/posts/"+p.Slug, nil), "")
	mustStatus(t, r, http.StatusNotFound)
	r.Body.Close()

	pr := do(t, srv, req(t, http.MethodPost, srv.URL+"/admin/posts/"+p.ID.String()+"/publish", nil), token)
	mustStatus(t, pr, http.StatusOK)
	pr.Body.Close()

	gr := do(t, srv, req(t, http.MethodGet, srv.URL+"/public/alpha/posts/"+p.Slug, nil), "")
	mustStatus(t, gr, http.StatusOK)
	var pub publicPostJSON
	decode(t, gr, &pub)
	if !strings.Contains(pub.ContentHTML, "<h1") || !strings.Contains(pub.ContentHTML, "<strong>") {
		t.Fatalf("content_html not rendered: %q", pub.ContentHTML)
	}
	if strings.Contains(pub.ContentHTML, "**bold**") {
		t.Fatalf("raw markdown leaked into content_html: %q", pub.ContentHTML)
	}
	if pub.Author != "editor" {
		t.Fatalf("author = %q, want editor", pub.Author)
	}
}

// HTML-only preview endpoints: public serves published posts, admin serves any
// post the actor can read (so drafts can be previewed before publishing).
func TestPostsHTMLPreview(t *testing.T) {
	h := newHarness(t)
	srv := h.httpServer()
	defer srv.Close()

	tenant := h.createTenant("alpha", "Alpha")
	editor := h.createUser("editor@example.com", "pw")
	h.addMembership(tenant, editor, "editor")
	token := h.issueToken(editor, &tenant)

	p := createPost(t, srv, token, "Hello", "# Heading\n\n**bold** text")

	// Admin preview works on a draft and is HTML, not JSON.
	admin := do(t, srv, req(t, http.MethodGet, srv.URL+"/admin/posts/"+p.ID.String()+"/html", nil), token)
	mustStatus(t, admin, http.StatusOK)
	if ct := admin.Header.Get("Content-Type"); !strings.HasPrefix(ct, "text/html") {
		t.Fatalf("admin preview content-type = %q, want text/html", ct)
	}
	body, _ := io.ReadAll(admin.Body)
	admin.Body.Close()
	if !strings.Contains(string(body), "<h1") || strings.Contains(string(body), "**bold**") {
		t.Fatalf("admin preview body not rendered: %q", body)
	}

	// Draft is not publicly previewable.
	draftHTML := do(t, srv, req(t, http.MethodGet, srv.URL+"/public/alpha/posts/"+p.Slug+"/html", nil), "")
	mustStatus(t, draftHTML, http.StatusNotFound)
	draftHTML.Body.Close()

	pr := do(t, srv, req(t, http.MethodPost, srv.URL+"/admin/posts/"+p.ID.String()+"/publish", nil), token)
	mustStatus(t, pr, http.StatusOK)
	pr.Body.Close()

	pub := do(t, srv, req(t, http.MethodGet, srv.URL+"/public/alpha/posts/"+p.Slug+"/html", nil), "")
	mustStatus(t, pub, http.StatusOK)
	if ct := pub.Header.Get("Content-Type"); !strings.HasPrefix(ct, "text/html") {
		t.Fatalf("public preview content-type = %q, want text/html", ct)
	}
	pubBody, _ := io.ReadAll(pub.Body)
	pub.Body.Close()
	if !strings.Contains(string(pubBody), "<h1") || !strings.Contains(string(pubBody), "<strong>") {
		t.Fatalf("public preview body not rendered: %q", pubBody)
	}

	// Admin preview still requires a session.
	noAuth := do(t, srv, req(t, http.MethodGet, srv.URL+"/admin/posts/"+p.ID.String()+"/html", nil), "")
	mustStatus(t, noAuth, http.StatusUnauthorized)
	noAuth.Body.Close()
}

// ST-3: a tenant never sees another tenant's posts, publicly or in admin.
func TestST3_TenantIsolation(t *testing.T) {
	h := newHarness(t)
	srv := h.httpServer()
	defer srv.Close()

	alpha := h.createTenant("alpha", "Alpha")
	beta := h.createTenant("beta", "Beta")
	edA := h.createUser("ed-a@example.com", "pw")
	edB := h.createUser("ed-b@example.com", "pw")
	h.addMembership(alpha, edA, "editor")
	h.addMembership(beta, edB, "editor")
	tokA := h.issueToken(edA, &alpha)
	tokB := h.issueToken(edB, &beta)

	pA := createPost(t, srv, tokA, "Alpha post", "alpha")
	r := do(t, srv, req(t, http.MethodPost, srv.URL+"/admin/posts/"+pA.ID.String()+"/publish", nil), tokA)
	mustStatus(t, r, http.StatusOK)
	r.Body.Close()
	pB := createPost(t, srv, tokB, "Beta post", "beta")
	rb := do(t, srv, req(t, http.MethodPost, srv.URL+"/admin/posts/"+pB.ID.String()+"/publish", nil), tokB)
	mustStatus(t, rb, http.StatusOK)
	rb.Body.Close()

	lr := do(t, srv, req(t, http.MethodGet, srv.URL+"/public/beta/posts", nil), "")
	mustStatus(t, lr, http.StatusOK)
	var list listJSON
	decode(t, lr, &list)
	if len(list.Posts) != 1 || list.Posts[0].Slug != "beta-post" {
		t.Fatalf("beta listing = %+v, want only beta-post", list.Posts)
	}

	gr := do(t, srv, req(t, http.MethodGet, srv.URL+"/public/beta/posts/"+pA.Slug, nil), "")
	mustStatus(t, gr, http.StatusNotFound)
	gr.Body.Close()
}

// ST-6/ST-13: authors are pinned to their own drafts; editors act tenant-wide.
func TestST6_AuthorOwnership(t *testing.T) {
	h := newHarness(t)
	srv := h.httpServer()
	defer srv.Close()

	tenant := h.createTenant("alpha", "Alpha")
	authorA := h.createUser("a@example.com", "pw")
	authorB := h.createUser("b@example.com", "pw")
	editor := h.createUser("ed@example.com", "pw")
	h.addMembership(tenant, authorA, "author")
	h.addMembership(tenant, authorB, "author")
	h.addMembership(tenant, editor, "editor")
	tokA := h.issueToken(authorA, &tenant)
	tokB := h.issueToken(authorB, &tenant)
	tokE := h.issueToken(editor, &tenant)

	p := createPost(t, srv, tokA, "A draft", "body")

	for _, tc := range []struct {
		name, method, path string
		body               any
	}{
		{"get", http.MethodGet, "/admin/posts/" + p.ID.String(), nil},
		{"patch", http.MethodPatch, "/admin/posts/" + p.ID.String(), map[string]any{"title": "hijack"}},
		{"publish", http.MethodPost, "/admin/posts/" + p.ID.String() + "/publish", nil},
		{"delete", http.MethodDelete, "/admin/posts/" + p.ID.String(), nil},
	} {
		r := do(t, srv, req(t, tc.method, srv.URL+tc.path, tc.body), tokB)
		if r.StatusCode != http.StatusForbidden {
			b, _ := io.ReadAll(r.Body)
			r.Body.Close()
			t.Fatalf("authorB %s: status = %d, want 403; body=%s", tc.name, r.StatusCode, b)
		}
		r.Body.Close()
	}

	r := do(t, srv, req(t, http.MethodPost, srv.URL+"/admin/posts/"+p.ID.String()+"/publish", nil), tokA)
	mustStatus(t, r, http.StatusForbidden)
	r.Body.Close()

	er := do(t, srv, req(t, http.MethodPatch, srv.URL+"/admin/posts/"+p.ID.String(), map[string]any{"title": "Edited"}), tokE)
	mustStatus(t, er, http.StatusOK)
	er.Body.Close()
	pr := do(t, srv, req(t, http.MethodPost, srv.URL+"/admin/posts/"+p.ID.String()+"/publish", nil), tokE)
	mustStatus(t, pr, http.StatusOK)
	pr.Body.Close()

	// ST-13: an author cannot delete a published post; an editor can.
	dr := do(t, srv, req(t, http.MethodDelete, srv.URL+"/admin/posts/"+p.ID.String(), nil), tokA)
	mustStatus(t, dr, http.StatusForbidden)
	dr.Body.Close()

	draft := createPost(t, srv, tokA, "Throwaway", "x")
	dd := do(t, srv, req(t, http.MethodDelete, srv.URL+"/admin/posts/"+draft.ID.String(), nil), tokA)
	mustStatus(t, dd, http.StatusNoContent)
	dd.Body.Close()
}

// ST-10: unpublish removes the post from the public surface.
func TestST10_Unpublish(t *testing.T) {
	h := newHarness(t)
	srv := h.httpServer()
	defer srv.Close()

	tenant := h.createTenant("alpha", "Alpha")
	editor := h.createUser("ed@example.com", "pw")
	h.addMembership(tenant, editor, "editor")
	token := h.issueToken(editor, &tenant)

	p := createPost(t, srv, token, "Post", "body")
	r := do(t, srv, req(t, http.MethodPost, srv.URL+"/admin/posts/"+p.ID.String()+"/publish", nil), token)
	mustStatus(t, r, http.StatusOK)
	r.Body.Close()

	u := do(t, srv, req(t, http.MethodPost, srv.URL+"/admin/posts/"+p.ID.String()+"/unpublish", nil), token)
	mustStatus(t, u, http.StatusOK)
	u.Body.Close()

	g := do(t, srv, req(t, http.MethodGet, srv.URL+"/public/alpha/posts/"+p.Slug, nil), "")
	mustStatus(t, g, http.StatusNotFound)
	g.Body.Close()
}

// ST-15: owner settings change bumps content_version and enqueues a purge.
func TestST15_TenantSettings(t *testing.T) {
	h := newHarness(t)
	srv := h.httpServer()
	defer srv.Close()

	tenant := h.createTenant("alpha", "Alpha")
	owner := h.createUser("owner@example.com", "pw")
	editor := h.createUser("ed@example.com", "pw")
	h.addMembership(tenant, owner, "owner")
	h.addMembership(tenant, editor, "editor")
	tokOwner := h.issueToken(owner, &tenant)
	tokEditor := h.issueToken(editor, &tenant)

	resp := do(t, srv, req(t, http.MethodPatch, srv.URL+"/admin/tenants/"+tenant.String(), map[string]any{"name": "Renamed"}), tokOwner)
	mustStatus(t, resp, http.StatusOK)
	var out tenantJSON
	decode(t, resp, &out)
	if out.Name != "Renamed" {
		t.Fatalf("name = %q, want Renamed", out.Name)
	}
	if out.ContentVersion < 1 {
		t.Fatalf("content_version = %d, want >= 1", out.ContentVersion)
	}

	var jobs int
	if err := h.pool.QueryRow(context.Background(),
		"select count(*) from jobs where kind = 'purge' and dedupe_key = $1", tenant.String()).Scan(&jobs); err != nil {
		t.Fatal(err)
	}
	if jobs != 1 {
		t.Fatalf("purge jobs for tenant = %d, want 1", jobs)
	}

	dr := do(t, srv, req(t, http.MethodPatch, srv.URL+"/admin/tenants/"+tenant.String(), map[string]any{"name": "Nope"}), tokEditor)
	mustStatus(t, dr, http.StatusForbidden)
	dr.Body.Close()
}

// ST-16: platform provisions tenants; duplicate slug is a conflict.
func TestST16_TenantProvisioning(t *testing.T) {
	h := newHarness(t)
	srv := h.httpServer()
	defer srv.Close()

	super := h.createUser("root@example.com", "pw")
	h.setSuperAdmin(super, true)
	tokSuper := h.issueToken(super, nil)

	resp := do(t, srv, req(t, http.MethodPost, srv.URL+"/admin/tenants", map[string]any{"slug": "gamma", "name": "Gamma"}), tokSuper)
	mustStatus(t, resp, http.StatusCreated)
	var created tenantJSON
	decode(t, resp, &created)
	if created.Slug != "gamma" {
		t.Fatalf("slug = %q, want gamma", created.Slug)
	}

	dup := do(t, srv, req(t, http.MethodPost, srv.URL+"/admin/tenants", map[string]any{"slug": "gamma", "name": "Gamma 2"}), tokSuper)
	mustStatus(t, dup, http.StatusConflict)
	dup.Body.Close()

	tenant := h.createTenant("alpha", "Alpha")
	editor := h.createUser("ed@example.com", "pw")
	h.addMembership(tenant, editor, "editor")
	tokEditor := h.issueToken(editor, &tenant)
	forbidden := do(t, srv, req(t, http.MethodPost, srv.URL+"/admin/tenants", map[string]any{"slug": "delta", "name": "Delta"}), tokEditor)
	mustStatus(t, forbidden, http.StatusForbidden)
	forbidden.Body.Close()
}

// ST-17: platform drill-down reads any tenant; others cannot.
func TestST17_TenantDrilldown(t *testing.T) {
	h := newHarness(t)
	srv := h.httpServer()
	defer srv.Close()

	tenant := h.createTenant("alpha", "Alpha")
	super := h.createUser("root@example.com", "pw")
	h.setSuperAdmin(super, true)
	tokSuper := h.issueToken(super, nil)

	resp := do(t, srv, req(t, http.MethodGet, srv.URL+"/admin/tenants/"+tenant.String(), nil), tokSuper)
	mustStatus(t, resp, http.StatusOK)
	var out tenantJSON
	decode(t, resp, &out)
	if out.ID != tenant || out.Slug != "alpha" {
		t.Fatalf("drilldown = %+v, want alpha", out)
	}

	editor := h.createUser("ed@example.com", "pw")
	h.addMembership(tenant, editor, "editor")
	tokEditor := h.issueToken(editor, &tenant)
	denied := do(t, srv, req(t, http.MethodGet, srv.URL+"/admin/tenants/"+tenant.String(), nil), tokEditor)
	mustStatus(t, denied, http.StatusForbidden)
	denied.Body.Close()
}

// ST-20: a tenant-less session can switch to any tenant it belongs to.
func TestST20_ActiveTenantSwitch(t *testing.T) {
	h := newHarness(t)
	srv := h.httpServer()
	defer srv.Close()

	alpha := h.createTenant("alpha", "Alpha")
	beta := h.createTenant("beta", "Beta")
	outsider := h.createTenant("outsider", "Outsider")
	user := h.createUser("multi@example.com", "pw")
	h.addMembership(alpha, user, "editor")
	h.addMembership(beta, user, "editor")
	token := h.issueToken(user, nil)

	sw := do(t, srv, req(t, http.MethodPut, srv.URL+"/auth/me/active-tenant", map[string]any{"tenant_id": alpha}), token)
	mustStatus(t, sw, http.StatusOK)
	sw.Body.Close()

	me := do(t, srv, req(t, http.MethodGet, srv.URL+"/auth/me", nil), token)
	mustStatus(t, me, http.StatusOK)
	var m meJSON
	decode(t, me, &m)
	if m.TenantID == nil || *m.TenantID != alpha {
		t.Fatalf("active tenant = %v, want %s", m.TenantID, alpha)
	}

	sw2 := do(t, srv, req(t, http.MethodPut, srv.URL+"/auth/me/active-tenant", map[string]any{"tenant_id": beta}), token)
	mustStatus(t, sw2, http.StatusOK)
	sw2.Body.Close()

	denied := do(t, srv, req(t, http.MethodPut, srv.URL+"/auth/me/active-tenant", map[string]any{"tenant_id": outsider}), token)
	mustStatus(t, denied, http.StatusForbidden)
	denied.Body.Close()
}

// ST-18 + seeding flow: a platform super admin creates a tenant, switches into
// it without a membership, and authors a post under the assumed owner role.
func TestST18_SuperAdminAuthorsInActiveTenant(t *testing.T) {
	h := newHarness(t)
	srv := h.httpServer()
	defer srv.Close()

	super := h.createUser("root@example.com", "pw")
	h.setSuperAdmin(super, true)
	tokSuper := h.issueToken(super, nil)

	created := do(t, srv, req(t, http.MethodPost, srv.URL+"/admin/tenants", map[string]any{"slug": "gamma", "name": "Gamma"}), tokSuper)
	mustStatus(t, created, http.StatusCreated)
	var tenant tenantJSON
	decode(t, created, &tenant)

	sw := do(t, srv, req(t, http.MethodPut, srv.URL+"/auth/me/active-tenant", map[string]any{"tenant_id": tenant.ID}), tokSuper)
	mustStatus(t, sw, http.StatusOK)
	sw.Body.Close()

	me := do(t, srv, req(t, http.MethodGet, srv.URL+"/auth/me", nil), tokSuper)
	mustStatus(t, me, http.StatusOK)
	var m meJSON
	decode(t, me, &m)
	if !m.Platform || m.TenantID == nil || *m.TenantID != tenant.ID || m.Role != "owner" {
		t.Fatalf("scoped super me = %+v", m)
	}

	post := createPost(t, srv, tokSuper, "Root post", "body")
	if post.TenantID != tenant.ID {
		t.Fatalf("post tenant = %s, want %s", post.TenantID, tenant.ID)
	}
}

// /auth/me lists memberships with tenant slug+name for the UI switcher.
func TestAuthMe_Memberships(t *testing.T) {
	h := newHarness(t)
	srv := h.httpServer()
	defer srv.Close()

	alpha := h.createTenant("alpha", "Alpha Blog")
	user := h.createUser("member@example.com", "pw")
	h.addMembership(alpha, user, "editor")
	token := h.issueToken(user, nil)

	me := do(t, srv, req(t, http.MethodGet, srv.URL+"/auth/me", nil), token)
	mustStatus(t, me, http.StatusOK)
	var m meJSON
	decode(t, me, &m)
	if len(m.Memberships) != 1 || m.Memberships[0].TenantID != alpha ||
		m.Memberships[0].Slug != "alpha" || m.Memberships[0].Role != "editor" {
		t.Fatalf("memberships = %+v", m.Memberships)
	}
}

// ST-23: applying an import that already produced a draft is a conflict.
func TestST23_ImportApplyIdempotency(t *testing.T) {
	h := newHarness(t)
	srv := h.httpServer()
	defer srv.Close()

	tenant := h.createTenant("alpha", "Alpha")
	editor := h.createUser("ed@example.com", "pw")
	h.addMembership(tenant, editor, "editor")
	token := h.issueToken(editor, &tenant)

	post := createPost(t, srv, token, "Imported", "body")
	importID, err := uuid.NewV7()
	if err != nil {
		t.Fatal(err)
	}
	// imports is RLS-scoped: insert under the tenant scope that policy allows.
	if err := h.db.ScopedRW(context.Background(), store.Scope{TenantID: tenant}, func(q *store.Queries) error {
		_, e := q.Tx().Exec(context.Background(), `
			insert into imports (id, tenant_id, user_id, post_id, source_format, source_key, status, markdown_out)
			values ($1, $2, $3, $4, 'pdf', 'k.pdf', 'done', 'body')`,
			importID, tenant, editor, post.ID)
		return e
	}); err != nil {
		t.Fatal(err)
	}

	resp := do(t, srv, req(t, http.MethodPost, srv.URL+"/admin/imports/"+importID.String()+"/apply", nil), token)
	mustStatus(t, resp, http.StatusConflict)
	var e errEnvelope
	decode(t, resp, &e)
	if e.Error.Code != "conflict" {
		t.Fatalf("error code = %q, want conflict", e.Error.Code)
	}
}

// Auth round-trip plus strict-decode rejection of unknown fields.
func TestAuth_SignupLoginLogout(t *testing.T) {
	h := newHarness(t)
	srv := h.httpServer()
	defer srv.Close()

	su := do(t, srv, req(t, http.MethodPost, srv.URL+"/auth/signup", map[string]any{"email": "user@example.com", "password": "secret123"}), "")
	mustStatus(t, su, http.StatusCreated)
	su.Body.Close()

	dup := do(t, srv, req(t, http.MethodPost, srv.URL+"/auth/signup", map[string]any{"email": "USER@example.com", "password": "secret123"}), "")
	mustStatus(t, dup, http.StatusConflict)
	dup.Body.Close()

	bad := do(t, srv, req(t, http.MethodPost, srv.URL+"/auth/login", map[string]any{"email": "user@example.com", "password": "wrong"}), "")
	mustStatus(t, bad, http.StatusUnauthorized)
	bad.Body.Close()

	li := do(t, srv, req(t, http.MethodPost, srv.URL+"/auth/login", map[string]any{"email": "user@example.com", "password": "secret123"}), "")
	mustStatus(t, li, http.StatusOK)
	var tok struct {
		Token string `json:"token"`
	}
	decode(t, li, &tok)
	if tok.Token == "" {
		t.Fatal("login returned empty token")
	}

	me := do(t, srv, req(t, http.MethodGet, srv.URL+"/auth/me", nil), tok.Token)
	mustStatus(t, me, http.StatusOK)
	me.Body.Close()

	lo := do(t, srv, req(t, http.MethodPost, srv.URL+"/auth/logout", nil), tok.Token)
	mustStatus(t, lo, http.StatusOK)
	lo.Body.Close()

	gone := do(t, srv, req(t, http.MethodGet, srv.URL+"/auth/me", nil), tok.Token)
	mustStatus(t, gone, http.StatusUnauthorized)
	gone.Body.Close()

	// Strict decode: an unknown field is a 422, not silently ignored.
	strict := do(t, srv, req(t, http.MethodPost, srv.URL+"/auth/login", map[string]any{
		"email": "user@example.com", "password": "secret123", "typo_field": 1,
	}), "")
	mustStatus(t, strict, http.StatusUnprocessableEntity)
	strict.Body.Close()
}
