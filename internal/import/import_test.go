package docimport

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"reflect"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"openblog/internal/authz"
	"openblog/internal/jobs"
	"openblog/internal/posts"
	"openblog/internal/store"
)

func withFakeExec(t *testing.T, cmds map[string]string) {
	t.Helper()
	origNewCmd := newCmd
	origLookPath := lookPath
	t.Cleanup(func() {
		newCmd = origNewCmd
		lookPath = origLookPath
	})
	lookPath = func(name string) (string, error) {
		if path, ok := cmds[name]; ok {
			return path, nil
		}
		return "", &exec.Error{Name: name, Err: errors.New("not found")}
	}
	newCmd = func(name string, args ...string) *exec.Cmd {
		return exec.Command(name, args...)
	}
}

func fakeCommand(t *testing.T, stdout string) string {
	t.Helper()
	dir := t.TempDir()
	script := dir + "/fake-cmd"
	if err := os.WriteFile(script, []byte("#!/bin/sh\nprintf '%s' '"+strings.ReplaceAll(stdout, "'", "'\\''")+"'"), 0o755); err != nil {
		t.Fatal(err)
	}
	return script
}

func TestDispatch_DOCX_UsesPandoc(t *testing.T) {
	withFakeExec(t, map[string]string{"pandoc": "/usr/bin/pandoc"})
	c, ok := dispatch("docx")
	if !ok || c == nil {
		t.Fatal("expected pandoc converter for docx")
	}
}

func TestDispatch_PDF_UsesPdftotext(t *testing.T) {
	c, ok := dispatch("pdf")
	if !ok || c == nil {
		t.Fatal("expected pdftotext converter for pdf")
	}
	// dispatch to pdftotext cannot be compared with !=; compare function pointers.
	if convPtr := reflect.ValueOf(c); convPtr.Pointer() != reflect.ValueOf(pdftotext).Pointer() {
		t.Fatal("pdf dispatch should return pdftotext")
	}
}

func TestDispatch_ODT_RTF_HTML_MD_AllUsePandoc(t *testing.T) {
	withFakeExec(t, map[string]string{}) // pandoc unavailable: only a pandoc converter reports this
	for _, format := range []string{"odt", "rtf", "html", "md"} {
		c, ok := dispatch(format)
		if !ok || c == nil {
			t.Fatalf("expected converter for %s", format)
		}
		if _, _, err := c(context.Background(), []byte("x")); err == nil || !strings.Contains(err.Error(), "pandoc not found") {
			t.Fatalf("%s should dispatch to pandoc, got err %v", format, err)
		}
	}
}

func TestPandoc_PassesSourceFormat(t *testing.T) {
	dir := t.TempDir()
	argsFile := dir + "/args"
	script := dir + "/pandoc"
	if err := os.WriteFile(script, []byte("#!/bin/sh\nprintf '%s\\n' \"$@\" > "+argsFile+"\nprintf 'ok'"), 0o755); err != nil {
		t.Fatal(err)
	}
	withFakeExec(t, map[string]string{"pandoc": script})

	c, ok := dispatch("docx")
	if !ok {
		t.Fatal("expected pandoc converter for docx")
	}
	if _, _, err := c(context.Background(), []byte("x")); err != nil {
		t.Fatal(err)
	}
	args, err := os.ReadFile(argsFile)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(args), "-f\ndocx") {
		t.Fatalf("pandoc args = %q, want -f docx", args)
	}
}

func TestDispatch_Unknown_ReturnsFalse(t *testing.T) {
	_, ok := dispatch("xlsx")
	if ok {
		t.Fatal("unknown format should not dispatch")
	}
}

func TestPandoc_LookPathFails(t *testing.T) {
	withFakeExec(t, map[string]string{}) // empty = nothing on PATH
	_, _, err := runPandoc(context.Background(), "markdown", []byte("# Hello"))
	if err == nil {
		t.Fatal("expected error when pandoc not found")
	}
	if !strings.Contains(err.Error(), "pandoc not found") {
		t.Fatalf("expected setup hint, got: %v", err)
	}
}

func TestPdftotext_LookPathFails(t *testing.T) {
	withFakeExec(t, map[string]string{})
	_, _, err := pdftotext(context.Background(), []byte("%PDF-1.4 fake"))
	if err == nil {
		t.Fatal("expected error when pdftotext not found")
	}
	if !strings.Contains(err.Error(), "pdftotext not found") {
		t.Fatalf("expected setup hint, got: %v", err)
	}
}

func TestPandoc_OutputTooLarge(t *testing.T) {
	big := strings.Repeat("A", 3<<20)
	script := fakeCommand(t, big)
	withFakeExec(t, map[string]string{"pandoc": script})
	_, _, err := runPandoc(context.Background(), "markdown", []byte("input"))
	if err == nil {
		t.Fatal("expected output-size error")
	}
	if !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("expected size error, got: %v", err)
	}
}

func TestParseSource_Multipart(t *testing.T) {
	ext, format, err := parseSource(Source{
		Kind:     SourceMultipart,
		File:     []byte("data"),
		Filename: "doc.pdf",
		MimeType: "application/pdf",
	})
	if err != nil {
		t.Fatal(err)
	}
	if ext != ".pdf" || format != "pdf" {
		t.Fatalf("expected .pdf/pdf, got %s/%s", ext, format)
	}
}

func TestParseSource_GoogleDocs(t *testing.T) {
	ext, format, err := parseSource(Source{Kind: SourceGoogleDocs, DocID: "abc123"})
	if err != nil {
		t.Fatal(err)
	}
	if ext != ".docx" || format != "gdoc" {
		t.Fatalf("expected .docx/gdoc, got %s/%s", ext, format)
	}
}

func TestParseSource_EmptyFile(t *testing.T) {
	_, _, err := parseSource(Source{Kind: SourceMultipart, Filename: "a.pdf"})
	if !errors.Is(err, ErrInvalidSource) {
		t.Fatalf("expected ErrInvalidSource, got: %v", err)
	}
}

func TestParseSource_EmptyDocID(t *testing.T) {
	_, _, err := parseSource(Source{Kind: SourceGoogleDocs})
	if !errors.Is(err, ErrInvalidSource) {
		t.Fatalf("expected ErrInvalidSource, got: %v", err)
	}
}

func TestApplyGate_TruthTable(t *testing.T) {
	md := "# Title\n\nBody"
	postID := uuid.New()

	cases := []struct {
		name string
		imp  store.Import
		want error
	}{
		{"converting status refues apply", store.Import{Status: store.ImportConverting, PostID: nil, MarkdownOut: &md}, ErrNotConverted},
		{"error status refuses apply", store.Import{Status: store.ImportError, PostID: nil, MarkdownOut: &md}, ErrNotConverted},
		{"done + nil post_id applies", store.Import{Status: store.ImportDone, PostID: nil, MarkdownOut: &md}, nil},
		{"done + set post_id refused (409)", store.Import{Status: store.ImportDone, PostID: &postID, MarkdownOut: &md}, ErrAlreadyApplied},
		{"done + nil markdown refused", store.Import{Status: store.ImportDone, PostID: nil, MarkdownOut: nil}, ErrNotConverted},
		{"done + empty markdown refused", store.Import{Status: store.ImportDone, PostID: nil, MarkdownOut: ptrString("   ")}, ErrNotConverted},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := applyGate(c.imp)
			if !errors.Is(got, c.want) {
				t.Fatalf("applyGate: want %v, got %v", c.want, got)
			}
		})
	}
}

func ptrString(s string) *string { return &s }

func TestFidelityForFormat(t *testing.T) {
	if f := fidelityForFormat("pdf"); f != "medium" {
		t.Fatalf("pdf fidelity should be medium, got %s", f)
	}
	if f := fidelityForFormat("docx"); f != "high" {
		t.Fatalf("docx fidelity should be high, got %s", f)
	}
	if f := fidelityForFormat("gdoc"); f != "high" {
		t.Fatalf("gdoc fidelity should be high, got %s", f)
	}
}

func TestImportPayload_RoundTrip(t *testing.T) {
	p := importPayload{
		ImportID:     uuid.New(),
		SourceFormat: "docx",
		SourceKey:    "key/path",
	}
	b, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	var got importPayload
	if err := json.Unmarshal(b, &got); err != nil {
		t.Fatal(err)
	}
	if got.ImportID != p.ImportID || got.SourceFormat != p.SourceFormat || got.SourceKey != p.SourceKey {
		t.Fatalf("round-trip mismatch: got %+v", got)
	}
}

func testDBURL(t *testing.T) string {
	t.Helper()
	return os.Getenv("DATABASE_URL")
}

func testPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	if testDBURL(t) == "" {
		t.Skip("DATABASE_URL not set; skipping DB-backed import tests")
	}
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, testDBURL(t))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	for _, tbl := range []string{"imports", "posts", "memberships", "tenants", "users"} {
		pool.Exec(ctx, "DELETE FROM "+tbl+" WHERE true")
	}
	return pool
}

func testDB(pool *pgxpool.Pool) *store.DB { return store.NewFromPool(pool) }

func seedTenantUser(t *testing.T, pool *pgxpool.Pool) (tenantID, userID uuid.UUID) {
	t.Helper()
	ctx := context.Background()
	tenantID = uuid.New()
	userID = uuid.New()
	if _, err := pool.Exec(ctx, "INSERT INTO tenants (id, slug, name) VALUES ($1, $2, $3)",
		tenantID, "test-tenant-"+tenantID.String()[:8], "Test Tenant"); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, "INSERT INTO users (id, email, display_name) VALUES ($1, $2, $3)",
		userID, "user-"+uuid.New().String()[:8]+"@test.com", "Test User"); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, "INSERT INTO memberships (tenant_id, user_id, role) VALUES ($1, $2, 'owner')",
		tenantID, userID); err != nil {
		t.Fatal(err)
	}
	return tenantID, userID
}

func testActor(tenantID, userID uuid.UUID) authz.Actor {
	return authz.Actor{
		UserID: userID,
		Tenant: &tenantID,
		Role:   authz.RoleOwner,
	}
}

func newTestService(pool *pgxpool.Pool) *Service {
	return &Service{
		db:    store.NewFromPool(pool),
		posts: posts.New(store.NewFromPool(pool), posts.Config{}),
		r2:    &fakeR2{orig: map[string][]byte{}},
	}
}

// fakeR2 is an in-memory R2Put.
type fakeR2 struct {
	orig map[string][]byte
}

func (f *fakeR2) Put(_ context.Context, key string, data []byte) error {
	f.orig[key] = append([]byte(nil), data...)
	return nil
}

func (f *fakeR2) Get(_ context.Context, key string) ([]byte, error) {
	b, ok := f.orig[key]
	if !ok {
		return nil, errors.New("fakeR2: key not found")
	}
	return b, nil
}

func ptrImportStatus(s store.ImportStatus) *store.ImportStatus { return &s }

func TestDB_Apply_CreateDraftAndLink(t *testing.T) {
	pool := testPool(t)
	tenantID, userID := seedTenantUser(t, pool)
	ctx := context.Background()

	var importID uuid.UUID
	md := "# Converted\n\nHello from import"
	err := testDB(pool).ScopedRW(ctx, store.Scope{TenantID: tenantID}, func(q *store.Queries) error {
		id, _ := uuid.NewV7()
		importID = id
		return q.CreateImport(ctx, id, tenantID, userID, nil, "docx", "test/key.docx")
	})
	if err != nil {
		t.Fatal("create import:", err)
	}
	err = testDB(pool).ScopedRW(ctx, store.Scope{TenantID: tenantID}, func(q *store.Queries) error {
		return q.UpdateImport(ctx, importID, store.ImportUpdate{
			Status:      ptrImportStatus(store.ImportDone),
			MarkdownOut: &md,
		})
	})
	if err != nil {
		t.Fatal("update import:", err)
	}

	svc := newTestService(pool)
	actor := testActor(tenantID, userID)
	post, err := svc.Apply(ctx, actor, importID)
	if err != nil {
		t.Fatal("apply:", err)
	}
	if post.ContentMarkdown != md {
		t.Fatalf("content mismatch: got %q", post.ContentMarkdown)
	}
	if post.TenantID != tenantID {
		t.Fatal("wrong tenant")
	}

	// Verify post_id is now set.
	err = testDB(pool).ScopedRW(ctx, store.Scope{TenantID: tenantID}, func(q *store.Queries) error {
		imp, err := q.GetImportByID(ctx, importID)
		if err != nil {
			return err
		}
		if imp.PostID == nil || *imp.PostID != post.ID {
			t.Fatal("post_id not linked")
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestDB_Apply_ReApplyReturns409(t *testing.T) {
	pool := testPool(t)
	tenantID, userID := seedTenantUser(t, pool)
	ctx := context.Background()

	var importID uuid.UUID
	md := "# Title\n\nBody"
	err := testDB(pool).ScopedRW(ctx, store.Scope{TenantID: tenantID}, func(q *store.Queries) error {
		id, _ := uuid.NewV7()
		importID = id
		if err := q.CreateImport(ctx, id, tenantID, userID, nil, "docx", "key"); err != nil {
			return err
		}
		return q.UpdateImport(ctx, id, store.ImportUpdate{
			Status:      ptrImportStatus(store.ImportDone),
			MarkdownOut: &md,
		})
	})
	if err != nil {
		t.Fatal(err)
	}

	svc := newTestService(pool)
	actor := testActor(tenantID, userID)

	if _, err := svc.Apply(ctx, actor, importID); err != nil {
		t.Fatal("first apply:", err)
	}
	_, err = svc.Apply(ctx, actor, importID)
	if !errors.Is(err, ErrAlreadyApplied) {
		t.Fatalf("expected ErrAlreadyApplied, got: %v", err)
	}
}

func TestDB_Apply_DeleteDraftReApplySucceeds(t *testing.T) {
	pool := testPool(t)
	tenantID, userID := seedTenantUser(t, pool)
	ctx := context.Background()

	var importID uuid.UUID
	md := "# Title\n\nBody"
	err := testDB(pool).ScopedRW(ctx, store.Scope{TenantID: tenantID}, func(q *store.Queries) error {
		id, _ := uuid.NewV7()
		importID = id
		if err := q.CreateImport(ctx, id, tenantID, userID, nil, "docx", "key"); err != nil {
			return err
		}
		return q.UpdateImport(ctx, id, store.ImportUpdate{
			Status:      ptrImportStatus(store.ImportDone),
			MarkdownOut: &md,
		})
	})
	if err != nil {
		t.Fatal(err)
	}

	svc := newTestService(pool)
	actor := testActor(tenantID, userID)

	post, err := svc.Apply(ctx, actor, importID)
	if err != nil {
		t.Fatal("first apply:", err)
	}

	// FK ON DELETE SET NULL nulls imports.post_id.
	err = testDB(pool).ScopedRW(ctx, store.Scope{TenantID: tenantID}, func(q *store.Queries) error {
		return q.DeletePost(ctx, post.ID)
	})
	if err != nil {
		t.Fatal("delete post:", err)
	}

	post2, err := svc.Apply(ctx, actor, importID)
	if err != nil {
		t.Fatal("re-apply:", err)
	}
	if post2.ID == post.ID {
		t.Fatal("expected a new draft, not the same post ID")
	}
}

func TestDB_Apply_NotConverted_ReturnsError(t *testing.T) {
	pool := testPool(t)
	tenantID, userID := seedTenantUser(t, pool)
	ctx := context.Background()

	var importID uuid.UUID
	err := testDB(pool).ScopedRW(ctx, store.Scope{TenantID: tenantID}, func(q *store.Queries) error {
		id, _ := uuid.NewV7()
		importID = id
		return q.CreateImport(ctx, id, tenantID, userID, nil, "docx", "key")
	})
	if err != nil {
		t.Fatal(err)
	}

	svc := newTestService(pool)
	actor := testActor(tenantID, userID)
	_, err = svc.Apply(ctx, actor, importID)
	if !errors.Is(err, ErrNotConverted) {
		t.Fatalf("expected ErrNotConverted, got: %v", err)
	}
}

func TestDB_Apply_ErrorStatus_ReturnsError(t *testing.T) {
	pool := testPool(t)
	tenantID, userID := seedTenantUser(t, pool)
	ctx := context.Background()

	var importID uuid.UUID
	errMsg := "pandoc failed"
	err := testDB(pool).ScopedRW(ctx, store.Scope{TenantID: tenantID}, func(q *store.Queries) error {
		id, _ := uuid.NewV7()
		importID = id
		if err := q.CreateImport(ctx, id, tenantID, userID, nil, "pdf", "key"); err != nil {
			return err
		}
		return q.UpdateImport(ctx, id, store.ImportUpdate{
			Status: ptrImportStatus(store.ImportError),
			Error:  &errMsg,
		})
	})
	if err != nil {
		t.Fatal(err)
	}

	svc := newTestService(pool)
	actor := testActor(tenantID, userID)
	_, err = svc.Apply(ctx, actor, importID)
	if !errors.Is(err, ErrNotConverted) {
		t.Fatalf("expected ErrNotConverted, got: %v", err)
	}
}

func TestDB_Apply_FidelityPersistence(t *testing.T) {
	pool := testPool(t)
	tenantID, userID := seedTenantUser(t, pool)
	ctx := context.Background()

	var importID uuid.UUID
	errMsg := "fidelity=medium: scanned PDF"
	md := "# Title\n\nSome content"
	err := testDB(pool).ScopedRW(ctx, store.Scope{TenantID: tenantID}, func(q *store.Queries) error {
		id, _ := uuid.NewV7()
		importID = id
		if err := q.CreateImport(ctx, id, tenantID, userID, nil, "pdf", "key"); err != nil {
			return err
		}
		return q.UpdateImport(ctx, id, store.ImportUpdate{
			Status:      ptrImportStatus(store.ImportDone),
			MarkdownOut: &md,
			Error:       &errMsg,
		})
	})
	if err != nil {
		t.Fatal(err)
	}

	svc := newTestService(pool)
	actor := testActor(tenantID, userID)
	res, err := svc.Get(ctx, actor, importID)
	if err != nil {
		t.Fatal("get:", err)
	}
	if res.Error == nil || *res.Error != errMsg {
		t.Fatalf("expected fidelity error to persist, got: %v", res.Error)
	}
	if res.Fidelity != "medium" {
		t.Fatalf("expected medium fidelity for pdf, got: %s", res.Fidelity)
	}
}

func TestDB_Apply_MaliciousDocumentSanitized(t *testing.T) {
	pool := testPool(t)
	tenantID, userID := seedTenantUser(t, pool)
	ctx := context.Background()

	var importID uuid.UUID
	// Hostile "converted" markdown: raw <script>, data: URI image, iframe.
	md := "# Safe Title\n\n<script>alert('xss')</script>\n\n" +
		"<img src=\"data:text/html,<script>alert(1)</script>\">\n\n" +
		"<iframe src=\"https://evil.example\"></iframe>\n\nNormal text"
	err := testDB(pool).ScopedRW(ctx, store.Scope{TenantID: tenantID}, func(q *store.Queries) error {
		id, _ := uuid.NewV7()
		importID = id
		if err := q.CreateImport(ctx, id, tenantID, userID, nil, "docx", "key"); err != nil {
			return err
		}
		return q.UpdateImport(ctx, id, store.ImportUpdate{
			Status:      ptrImportStatus(store.ImportDone),
			MarkdownOut: &md,
		})
	})
	if err != nil {
		t.Fatal(err)
	}

	svc := newTestService(pool)
	actor := testActor(tenantID, userID)
	post, err := svc.Apply(ctx, actor, importID)
	if err != nil {
		t.Fatal("apply:", err)
	}

	// 005's renderer (inside posts.Create) must not let hostile HTML survive.
	html := post.ContentHTML
	if strings.Contains(html, "<script") {
		t.Fatalf("script survived 005 sanitizer: %s", html)
	}
	if strings.Contains(html, "data:") {
		t.Fatalf("data: URI survived 005 sanitizer: %s", html)
	}
	if strings.Contains(html, "iframe") {
		t.Fatalf("iframe survived 005 sanitizer: %s", html)
	}
	if !strings.Contains(html, "Normal text") {
		t.Fatalf("expected safe content to survive: %s", html)
	}
}

func TestDB_EnqueueInSameTx_RollbackLosesBoth(t *testing.T) {
	pool := testPool(t)
	tenantID, userID := seedTenantUser(t, pool)
	ctx := context.Background()

	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(ctx)
	if _, err := tx.Exec(ctx, "SELECT set_config('app.tenant_id', $1, true)", tenantID); err != nil {
		t.Fatal(err)
	}

	q := store.NewQueries(tx)
	id, _ := uuid.NewV7()
	if err := q.CreateImport(ctx, id, tenantID, userID, nil, "docx", "rollback-test"); err != nil {
		t.Fatal(err)
	}
	if _, err := jobs.Enqueue(ctx, tx, JobKind, id.String(), jobs.JobPayload{
		TenantID: tenantID,
	}); err != nil {
		t.Fatal(err)
	}

	if err := tx.Rollback(ctx); err != nil {
		t.Fatal(err)
	}

	// Verify neither import nor job exists after rollback.
	var importCount, jobCount int
	pool.QueryRow(ctx, "SELECT count(*) FROM imports WHERE id = $1", id).Scan(&importCount)
	pool.QueryRow(ctx, "SELECT count(*) FROM jobs WHERE dedupe_key = $1", id.String()).Scan(&jobCount)

	if importCount != 0 {
		t.Fatal("import row survived rollback")
	}
	if jobCount != 0 {
		t.Fatal("job row survived rollback")
	}
}

func TestDB_Get_ImportNotFound(t *testing.T) {
	pool := testPool(t)
	tenantID, userID := seedTenantUser(t, pool)
	ctx := context.Background()

	svc := newTestService(pool)
	actor := testActor(tenantID, userID)
	_, err := svc.Get(ctx, actor, uuid.New())
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected ErrNotFound, got: %v", err)
	}
}

func TestDB_Get_ReturnsCorrectData(t *testing.T) {
	pool := testPool(t)
	tenantID, userID := seedTenantUser(t, pool)
	ctx := context.Background()

	var importID uuid.UUID
	md := "# Hello\n\nWorld"
	err := testDB(pool).ScopedRW(ctx, store.Scope{TenantID: tenantID}, func(q *store.Queries) error {
		id, _ := uuid.NewV7()
		importID = id
		if err := q.CreateImport(ctx, id, tenantID, userID, nil, "docx", "key"); err != nil {
			return err
		}
		return q.UpdateImport(ctx, id, store.ImportUpdate{
			Status:      ptrImportStatus(store.ImportDone),
			MarkdownOut: &md,
		})
	})
	if err != nil {
		t.Fatal(err)
	}

	svc := newTestService(pool)
	actor := testActor(tenantID, userID)
	res, err := svc.Get(ctx, actor, importID)
	if err != nil {
		t.Fatal(err)
	}
	if res.Status != store.ImportDone {
		t.Fatalf("expected done, got: %s", res.Status)
	}
	if res.Markdown == nil || *res.Markdown != md {
		t.Fatalf("markdown mismatch: got %v", res.Markdown)
	}
}

func TestWorker_ConversionError_RecordsError(t *testing.T) {
	pool := testPool(t)
	tenantID, userID := seedTenantUser(t, pool)
	ctx := context.Background()

	var importID uuid.UUID
	err := testDB(pool).ScopedRW(ctx, store.Scope{TenantID: tenantID}, func(q *store.Queries) error {
		id, _ := uuid.NewV7()
		importID = id
		return q.CreateImport(ctx, id, tenantID, userID, nil, "docx", "nonexistent-key")
	})
	if err != nil {
		t.Fatal(err)
	}

	withFakeExec(t, map[string]string{}) // no pandoc on PATH → conversion error
	svc := newTestService(pool)
	svc.r2.(*fakeR2).orig["nonexistent-key"] = []byte("fake docx bytes")

	err = svc.handleJob(ctx, jobs.JobPayload{
		TenantID: tenantID,
		Data: mustJSON(importPayload{
			ImportID:     importID,
			SourceFormat: "docx",
			SourceKey:    "nonexistent-key",
		}),
	})
	if err != nil {
		t.Fatal("handler should not propagate error (records it in DB):", err)
	}

	err = testDB(pool).ScopedRW(ctx, store.Scope{TenantID: tenantID}, func(q *store.Queries) error {
		imp, err := q.GetImportByID(ctx, importID)
		if err != nil {
			return err
		}
		if imp.Status != store.ImportError {
			t.Fatalf("expected error status, got: %s", imp.Status)
		}
		if imp.Error == nil || !strings.Contains(*imp.Error, "pandoc not found") {
			t.Fatalf("expected pandoc error, got: %v", imp.Error)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestWorker_SkipsNonConvertingImport(t *testing.T) {
	pool := testPool(t)
	tenantID, userID := seedTenantUser(t, pool)
	ctx := context.Background()

	var importID uuid.UUID
	err := testDB(pool).ScopedRW(ctx, store.Scope{TenantID: tenantID}, func(q *store.Queries) error {
		id, _ := uuid.NewV7()
		importID = id
		if err := q.CreateImport(ctx, id, tenantID, userID, nil, "docx", "key"); err != nil {
			return err
		}
		return q.UpdateImport(ctx, id, store.ImportUpdate{
			Status: ptrImportStatus(store.ImportDone),
		})
	})
	if err != nil {
		t.Fatal(err)
	}

	svc := newTestService(pool)
	err = svc.handleJob(ctx, jobs.JobPayload{
		TenantID: tenantID,
		Data: mustJSON(importPayload{
			ImportID:     importID,
			SourceFormat: "docx",
			SourceKey:    "key",
		}),
	})
	if err != nil {
		t.Fatal("handler should silently skip non-converting import:", err)
	}
}

func TestWorker_UnknownImport_SilentSkip(t *testing.T) {
	pool := testPool(t)
	tenantID, _ := seedTenantUser(t, pool)
	ctx := context.Background()

	svc := newTestService(pool)
	err := svc.handleJob(ctx, jobs.JobPayload{
		TenantID: tenantID,
		Data: mustJSON(importPayload{
			ImportID:     uuid.New(),
			SourceFormat: "docx",
			SourceKey:    "key",
		}),
	})
	if err != nil {
		t.Fatal("handler should silently skip unknown import:", err)
	}
}

func TestWorker_UnsupportedFormat(t *testing.T) {
	pool := testPool(t)
	tenantID, userID := seedTenantUser(t, pool)
	ctx := context.Background()

	var importID uuid.UUID
	err := testDB(pool).ScopedRW(ctx, store.Scope{TenantID: tenantID}, func(q *store.Queries) error {
		id, _ := uuid.NewV7()
		importID = id
		return q.CreateImport(ctx, id, tenantID, userID, nil, "xlsx", "key")
	})
	if err != nil {
		t.Fatal(err)
	}

	svc := newTestService(pool)
	svc.r2.(*fakeR2).orig["key"] = []byte("fake xlsx bytes")
	err = svc.handleJob(ctx, jobs.JobPayload{
		TenantID: tenantID,
		Data: mustJSON(importPayload{
			ImportID:     importID,
			SourceFormat: "xlsx",
			SourceKey:    "key",
		}),
	})
	if err != nil {
		t.Fatal("handler should not propagate error:", err)
	}

	err = testDB(pool).ScopedRW(ctx, store.Scope{TenantID: tenantID}, func(q *store.Queries) error {
		imp, err := q.GetImportByID(ctx, importID)
		if err != nil {
			return err
		}
		if imp.Status != store.ImportError {
			t.Fatalf("expected error status, got: %s", imp.Status)
		}
		if imp.Error == nil || !strings.Contains(*imp.Error, "unsupported format") {
			t.Fatalf("expected unsupported format error, got: %v", imp.Error)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestWorker_BadPayload(t *testing.T) {
	svc := &Service{} // fails on unmarshal before any DB access
	err := svc.handleJob(context.Background(), jobs.JobPayload{
		TenantID: uuid.New(),
		Data:     []byte("not json"),
	})
	if err == nil {
		t.Fatal("expected error for bad payload")
	}
}
