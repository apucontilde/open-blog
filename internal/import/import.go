package docimport

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"mime"
	"path/filepath"
	"strings"
	"unicode/utf8"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"openblog/internal/authz"
	"openblog/internal/jobs"
	"openblog/internal/oauth"
	"openblog/internal/posts"
	"openblog/internal/store"
)

const (
	JobKind = "import"
)

type SourceKind int

const (
	SourceMultipart SourceKind = iota
	SourceGoogleDocs
)

type Source struct {
	Kind     SourceKind
	File     []byte // multipart file bytes (SourceMultipart)
	Filename string
	MimeType string
	DocID    string // Google Doc ID (SourceGoogleDocs)
}

// Start inserts the imports row and enqueues the "import" job in the same tx, storing the original in R2.
func (s *Service) Start(ctx context.Context, actor authz.Actor, source Source) (uuid.UUID, error) {
	if err := authz.Require(actor, authz.CapRunImport); err != nil {
		return uuid.Nil, err
	}
	scope := authz.ScopeFromActor(actor)
	if scope.TenantID == uuid.Nil {
		return uuid.Nil, ErrInvalidSource
	}

	ext, sourceFormat, err := parseSource(source)
	if err != nil {
		return uuid.Nil, err
	}

	importID, err := uuid.NewV7()
	if err != nil {
		return uuid.Nil, fmt.Errorf("import: mint id: %w", err)
	}

	var sourceKey string
	var jobPayload importPayload

	switch source.Kind {
	case SourceMultipart:
		tenantSlug := s.tenantSlug
		if tenantSlug == "" {
			tenantSlug = scope.TenantID.String()
		}
		objID, err := uuid.NewV7()
		if err != nil {
			return uuid.Nil, fmt.Errorf("import: mint key id: %w", err)
		}
		sourceKey = fmt.Sprintf("%s/imports/%s/%s%s", tenantSlug, importID, objID, ext)
		if err := s.r2.Put(ctx, sourceKey, source.File); err != nil {
			return uuid.Nil, fmt.Errorf("import: upload original: %w", err)
		}
		jobPayload = importPayload{
			ImportID:     importID,
			SourceFormat: sourceFormat,
			SourceKey:    sourceKey,
		}

	case SourceGoogleDocs:
		sourceKey = fmt.Sprintf("gdoc/%s/%s", scope.TenantID, importID)
		jobPayload = importPayload{
			ImportID:     importID,
			SourceFormat: "gdoc",
			GDocID:       source.DocID,
		}
	}

	dedupeKey := importID.String()
	err = s.db.ScopedRW(ctx, scope, func(q *store.Queries) error {
		if err := q.CreateImport(ctx, importID, scope.TenantID, actor.UserID, nil, sourceFormat, sourceKey); err != nil {
			return fmt.Errorf("import: insert row: %w", err)
		}
		if _, err := jobs.Enqueue(ctx, q.Tx(), JobKind, dedupeKey, jobs.JobPayload{
			TenantID: scope.TenantID,
			Data:     mustJSON(jobPayload),
		}); err != nil {
			return fmt.Errorf("import: enqueue: %w", err)
		}
		return nil
	})
	return importID, err
}

func (s *Service) Get(ctx context.Context, actor authz.Actor, importID uuid.UUID) (ImportResult, error) {
	scope := authz.ScopeFromActor(actor)
	var imp store.Import
	err := s.db.Scoped(ctx, scope, func(q *store.Queries) error {
		var err error
		imp, err = q.GetImportByID(ctx, importID)
		return err
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return ImportResult{}, ErrNotFound
	}
	if err != nil {
		return ImportResult{}, err
	}

	res := ImportResult{
		ID:       imp.ID,
		Status:   imp.Status,
		Fidelity: fidelityForFormat(imp.SourceFormat),
	}
	if imp.MarkdownOut != nil {
		md := *imp.MarkdownOut
		res.Markdown = &md
	}
	if imp.Error != nil {
		e := *imp.Error
		res.Error = &e
	}
	return res, nil
}

type ImportResult struct {
	ID       uuid.UUID          `json:"id"`
	Status   store.ImportStatus `json:"status"`
	Markdown *string            `json:"markdown_out,omitempty"`
	Fidelity string             `json:"fidelity"`
	Error    *string            `json:"error,omitempty"`
}

// Apply creates a draft via posts.Create (005 renders + sanitizes untrusted content).
// post_id already set → ErrAlreadyApplied (409); deleting the draft nulls the FK and re-apply is allowed.
// An applied import is never re-converted.
func (s *Service) Apply(ctx context.Context, actor authz.Actor, importID uuid.UUID) (store.Post, error) {
	if err := authz.Require(actor, authz.CapRunImport); err != nil {
		return store.Post{}, err
	}
	scope := authz.ScopeFromActor(actor)

	var imp store.Import
	err := s.db.Scoped(ctx, scope, func(q *store.Queries) error {
		var err error
		imp, err = q.GetImportByID(ctx, importID)
		return err
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return store.Post{}, ErrNotFound
	}
	if err != nil {
		return store.Post{}, err
	}
	if err := applyGate(imp); err != nil {
		return store.Post{}, err
	}

	post, err := s.posts.Create(ctx, actor, posts.CreateInput{
		Title:           titleFromContent(*imp.MarkdownOut),
		ContentMarkdown: *imp.MarkdownOut,
		Slug:            deriveSlug(*imp.MarkdownOut, imp.ID),
	})
	if err != nil {
		return store.Post{}, err
	}

	// CAS-link: only a NULL post_id can be claimed, so a concurrent Apply loses the race.
	err = s.db.ScopedRW(ctx, scope, func(q *store.Queries) error {
		if err := q.SetImportPostID(ctx, importID, post.ID); err != nil {
			return ErrAlreadyApplied // another apply won the race
		}
		return nil
	})
	if errors.Is(err, ErrAlreadyApplied) {
		return store.Post{}, ErrAlreadyApplied
	}
	if err != nil {
		return store.Post{}, err
	}
	return post, nil
}

// applyGate allows apply only when conversion succeeded with markdown and no draft is linked.
func applyGate(imp store.Import) error {
	if imp.Status != store.ImportDone {
		return ErrNotConverted
	}
	if imp.PostID != nil {
		return ErrAlreadyApplied
	}
	if imp.MarkdownOut == nil || strings.TrimSpace(*imp.MarkdownOut) == "" {
		return ErrNotConverted
	}
	return nil
}

func (s *Service) RegisterWorker(w *jobs.Worker, getGoogleToken oauth.GoogleExporter) {
	s.getGoogleToken = getGoogleToken
	w.Register(JobKind, s.handleJob)
}

func (s *Service) handleJob(ctx context.Context, p jobs.JobPayload) error {
	var payload importPayload
	if err := json.Unmarshal(p.Data, &payload); err != nil {
		return fmt.Errorf("import: unmarshal payload: %w", err)
	}

	var imp store.Import
	err := s.db.Scoped(ctx, store.Scope{TenantID: p.TenantID}, func(q *store.Queries) error {
		var err error
		imp, err = q.GetImportByID(ctx, payload.ImportID)
		return err
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return nil // import deleted; nothing to do
	}
	if err != nil {
		return fmt.Errorf("import: load row: %w", err)
	}
	if imp.Status != store.ImportConverting {
		return nil // already done or errored — idempotent
	}

	var (
		md       []byte
		fidelity string
		convErr  error
	)

	switch payload.SourceFormat {
	case "gdoc":
		if s.getGoogleToken == nil {
			convErr = fmt.Errorf("import: Google token provider not configured")
			break
		}
		accessToken, err := s.getGoogleToken(ctx, imp.UserID, true)
		if err != nil {
			convErr = fmt.Errorf("%w: %v", ErrGoogleToken, err)
			break
		}
		md, fidelity, convErr = gdocExport(ctx, payload.GDocID, accessToken)
	default:
		orig, err := s.r2.Get(ctx, payload.SourceKey)
		if err != nil {
			return fmt.Errorf("import: fetch original from R2: %w", err)
		}
		conv, ok := dispatch(payload.SourceFormat)
		if !ok {
			convErr = fmt.Errorf("unsupported format %q", payload.SourceFormat)
			break
		}
		md, fidelity, convErr = conv(ctx, orig)
	}

	if convErr != nil {
		errMsg := fmt.Sprintf("fidelity=%s: %s", fidelity, convErr.Error())
		if fidelity == "" {
			errMsg = convErr.Error()
		}
		return s.db.ScopedRW(ctx, store.Scope{TenantID: p.TenantID}, func(q *store.Queries) error {
			return q.UpdateImport(ctx, imp.ID, store.ImportUpdate{
				Status: ptrStatus(store.ImportError),
				Error:  &errMsg,
			})
		})
	}

	mdStr := string(md)
	return s.db.ScopedRW(ctx, store.Scope{TenantID: p.TenantID}, func(q *store.Queries) error {
		return q.UpdateImport(ctx, imp.ID, store.ImportUpdate{
			Status:      ptrStatus(store.ImportDone),
			MarkdownOut: &mdStr,
		})
	})
}

type importPayload struct {
	ImportID     uuid.UUID `json:"import_id"`
	SourceFormat string    `json:"source_format"`
	SourceKey    string    `json:"source_key,omitempty"`
	GDocID       string    `json:"gdoc_id,omitempty"`
}

// R2Put is the minimal R2 surface the service needs; media's *R2Client satisfies it.
type R2Put interface {
	Put(ctx context.Context, key string, data []byte) error
	Get(ctx context.Context, key string) ([]byte, error)
}

type Service struct {
	db             *store.DB
	posts          *posts.Service
	r2             R2Put
	tenantSlug     string
	getGoogleToken oauth.GoogleExporter
}

type Config struct {
	DB         *pgxpool.Pool
	R2         R2Put
	TenantSlug string // optional human-readable tenant slug for R2 key prefix
	Posts      *posts.Service
}

func New(cfg Config) *Service {
	if cfg.Posts == nil {
		cfg.Posts = posts.New(store.NewFromPool(cfg.DB), posts.Config{})
	}
	return &Service{
		db:         store.NewFromPool(cfg.DB),
		posts:      cfg.Posts,
		r2:         cfg.R2,
		tenantSlug: cfg.TenantSlug,
	}
}

func parseSource(source Source) (ext, format string, err error) {
	switch source.Kind {
	case SourceMultipart:
		if len(source.File) == 0 {
			return "", "", ErrInvalidSource
		}
		ext = extFromMimeOrName(source.MimeType, source.Filename)
		format = strings.TrimPrefix(ext, ".")
		if format == "" {
			return "", "", fmt.Errorf("import: unsupported file type (mime=%s, name=%s)", source.MimeType, source.Filename)
		}
		return ext, format, nil

	case SourceGoogleDocs:
		if source.DocID == "" {
			return "", "", ErrInvalidSource
		}
		return ".docx", "gdoc", nil

	default:
		return "", "", ErrInvalidSource
	}
}

func extFromMimeOrName(mimeType, filename string) string {
	if mimeType != "" {
		exts, _ := mime.ExtensionsByType(mimeType)
		for _, e := range exts {
			switch e {
			case ".docx", ".odt", ".rtf", ".html", ".htm", ".pdf", ".md", ".txt":
				return e
			}
		}
	}
	if filename != "" {
		ext := strings.ToLower(filepath.Ext(filename))
		switch ext {
		case ".docx", ".odt", ".rtf", ".html", ".htm", ".pdf", ".md", ".txt":
			return ext
		}
	}
	return ""
}

func deriveSlug(content string, importID uuid.UUID) string {
	title := titleFromContent(content)
	if title == "" {
		title = "import-" + importID.String()[:8]
	}
	slug := strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
			return r
		case r >= 'A' && r <= 'Z':
			return r + ('a' - 'A')
		case r == '_' || r == ' ' || r == '-':
			return '-'
		}
		return -1
	}, title)
	slug = strings.Trim(slug, "-")
	if len(slug) > 63 {
		// re-trim: a trailing '-' fails the DB slug CHECK.
		slug = strings.TrimRight(slug[:63], "-")
	}
	if slug == "" {
		slug = "import-" + importID.String()[:8]
	}
	return slug
}

func titleFromContent(content string) string {
	for _, line := range strings.Split(content, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		line = strings.TrimPrefix(line, "# ")
		if len(line) > 200 {
			cut := 200
			for cut > 0 && !utf8.RuneStart(line[cut]) {
				cut--
			}
			line = line[:cut]
		}
		return line
	}
	return ""
}

func fidelityForFormat(format string) string {
	if format == "pdf" {
		return "medium"
	}
	return "high"
}

func mustJSON(v any) json.RawMessage {
	b, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return b
}

func ptrStatus(s store.ImportStatus) *store.ImportStatus { return &s }
