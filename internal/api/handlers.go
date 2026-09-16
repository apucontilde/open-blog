package api

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"openblog/internal/auth"
	"openblog/internal/authz"
	"openblog/internal/import"
	"openblog/internal/jobs"
	"openblog/internal/posts"
	"openblog/internal/store"
	"openblog/internal/tenancy"
)

// decodeJSON decodes one JSON value with unknown fields rejected so client
// typos fail loudly instead of being silently dropped.
func decodeJSON(w http.ResponseWriter, r *http.Request, dst any) error {
	dec := json.NewDecoder(io.LimitReader(r.Body, 1<<20))
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		return err
	}
	if dec.More() {
		return errors.New("unexpected trailing JSON data")
	}
	return nil
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeServiceError(w http.ResponseWriter, err error) {
	status, msg := mapError(err)
	writeError(w, status, codeForStatus(status), msg)
}

func codeForStatus(status int) string {
	switch status {
	case http.StatusNotFound:
		return codeNotFound
	case http.StatusForbidden:
		return codeForbidden
	case http.StatusUnauthorized:
		return codeUnauthorized
	case http.StatusConflict:
		return codeConflict
	case http.StatusUnprocessableEntity:
		return codeValidation
	case http.StatusTooManyRequests:
		return codeRateLimited
	default:
		return codeInternal
	}
}

func isUniqueViolation(err error) bool {
	var pgerr *pgconn.PgError
	return errors.As(err, &pgerr) && pgerr.Code == "23505"
}

func pathID(r *http.Request) (uuid.UUID, bool) {
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		return uuid.Nil, false
	}
	return id, true
}

func hashToken(t string) []byte {
	h := sha256.Sum256([]byte(t))
	return h[:]
}

// --- auth entry ---

type credsRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

func (s *server) handleSignup(w http.ResponseWriter, r *http.Request) {
	var req credsRequest
	if err := decodeJSON(w, r, &req); err != nil {
		writeError(w, http.StatusUnprocessableEntity, codeValidation, err.Error())
		return
	}
	if req.Email == "" || req.Password == "" {
		writeError(w, http.StatusUnprocessableEntity, codeValidation, "email and password are required")
		return
	}
	userID, err := s.session.Signup(r.Context(), req.Email, req.Password)
	if err != nil {
		if errors.Is(err, auth.ErrInvited) {
			writeError(w, http.StatusConflict, codeConflict, err.Error())
			return
		}
		if isUniqueViolation(err) {
			writeError(w, http.StatusConflict, codeConflict, "email already registered")
			return
		}
		writeServiceError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{"user_id": userID})
}

func (s *server) handleLogin(w http.ResponseWriter, r *http.Request) {
	var req credsRequest
	if err := decodeJSON(w, r, &req); err != nil {
		writeError(w, http.StatusUnprocessableEntity, codeValidation, err.Error())
		return
	}
	if req.Email == "" || req.Password == "" {
		writeError(w, http.StatusUnprocessableEntity, codeValidation, "email and password are required")
		return
	}
	token, err := s.session.Login(r.Context(), req.Email, req.Password)
	if err != nil {
		writeError(w, http.StatusUnauthorized, codeUnauthorized, "invalid credentials")
		return
	}
	s.setSession(w, token)
	writeJSON(w, http.StatusOK, map[string]any{"token": token})
}

func (s *server) setSession(w http.ResponseWriter, token string) {
	http.SetCookie(w, s.sessionCookie(token))
}

func (s *server) clearSession(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name: s.sessionName, Value: "", Path: "/", MaxAge: -1,
		HttpOnly: true, Secure: s.sessionSecure, SameSite: http.SameSiteLaxMode,
	})
}

// --- oauth ---

func (s *server) handleOAuthStart(w http.ResponseWriter, r *http.Request) {
	if s.oauth == nil {
		writeError(w, http.StatusNotFound, codeNotFound, "oauth not configured")
		return
	}
	var req struct {
		Provider string `json:"provider"`
		Redirect string `json:"redirect"`
	}
	if err := decodeJSON(w, r, &req); err != nil {
		writeError(w, http.StatusUnprocessableEntity, codeValidation, err.Error())
		return
	}
	if req.Provider == "" {
		writeError(w, http.StatusUnprocessableEntity, codeValidation, "provider is required")
		return
	}
	url, err := s.oauth.Start(r.Context(), req.Provider, req.Redirect, s.sessionToken(r))
	if err != nil {
		writeServiceError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"url": url})
}

// handleOAuthCallback is the GET callback the IdP redirects to. It verifies
// the replayed state, completes the PKCE exchange, resolves/links the identity,
// consumes a first-link invitation, and sets the fresh session cookie.
func (s *server) handleOAuthCallback(w http.ResponseWriter, r *http.Request) {
	if s.oauth == nil {
		writeError(w, http.StatusNotFound, codeNotFound, "oauth not configured")
		return
	}
	res, err := s.oauth.Callback(r.Context(),
		r.URL.Query().Get("state"),
		r.URL.Query().Get("code"),
		s.sessionToken(r))
	if err != nil {
		writeServiceError(w, err)
		return
	}
	s.setSession(w, res.SessionToken)
	writeJSON(w, http.StatusOK, map[string]any{
		"token":    res.SessionToken,
		"provider": res.Provider,
		"user_id":  res.UserID,
		"redirect": res.Redirect,
	})
}

// --- admin: session + me ---

func (s *server) handleLogout(w http.ResponseWriter, r *http.Request) {
	_ = s.session.Logout(r.Context(), tokenFrom(r))
	s.clearSession(w)
	writeJSON(w, http.StatusOK, map[string]string{"ok": "true"})
}

func (s *server) handleMe(w http.ResponseWriter, r *http.Request) {
	a := actorFrom(r)
	scope := scopeFrom(r)
	writeJSON(w, http.StatusOK, map[string]any{
		"user_id":   a.UserID,
		"tenant_id": nilOrUUID(scope.TenantID),
		"role":      roleName(a),
		"platform":  a.Platform,
	})
}

func roleName(a authz.Actor) string {
	if a.Tenant != nil {
		return a.Role.String()
	}
	return ""
}

func nilOrUUID(id uuid.UUID) any {
	if id == uuid.Nil {
		return nil
	}
	return id
}

// handleSetTenant switches the session's active tenant (ST-20). It runs on a
// verified session even before an actor is resolvable: the switcher is the
// path that turns a tenant-less session into a scoped one.
func (s *server) handleSetTenant(w http.ResponseWriter, r *http.Request) {
	var req struct {
		TenantID uuid.UUID `json:"tenant_id"`
	}
	if err := decodeJSON(w, r, &req); err != nil {
		writeError(w, http.StatusUnprocessableEntity, codeValidation, err.Error())
		return
	}
	if req.TenantID == uuid.Nil {
		writeError(w, http.StatusUnprocessableEntity, codeValidation, "tenant_id is required")
		return
	}
	userID := actorFrom(r).UserID
	if _, err := s.db.MembershipRole(r.Context(), userID, req.TenantID); err != nil {
		writeError(w, http.StatusForbidden, codeForbidden, "not a member of this tenant")
		return
	}
	err := s.db.ScopedRW(r.Context(), store.Scope{}, func(q *store.Queries) error {
		return q.SetSessionScope(r.Context(), hashToken(tokenFrom(r)), &req.TenantID)
	})
	if err != nil {
		writeServiceError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"tenant_id": req.TenantID})
}

// --- admin: posts ---

type postOut struct {
	ID              uuid.UUID       `json:"id"`
	TenantID        uuid.UUID       `json:"tenant_id"`
	AuthorID        uuid.UUID       `json:"author_id"`
	Slug            string          `json:"slug"`
	Title           string          `json:"title"`
	Excerpt         string          `json:"excerpt"`
	ContentMarkdown string          `json:"content_markdown,omitempty"`
	ContentHTML     string          `json:"content_html,omitempty"`
	Status          string          `json:"status"`
	PublishedAt     *time.Time      `json:"published_at"`
	Metadata        json.RawMessage `json:"metadata"`
	CreatedAt       time.Time       `json:"created_at"`
	UpdatedAt       time.Time       `json:"updated_at"`
}

func postOutFrom(p store.Post) postOut {
	meta := p.Metadata
	if len(meta) == 0 {
		meta = json.RawMessage("{}")
	}
	return postOut{
		ID: p.ID, TenantID: p.TenantID, AuthorID: p.AuthorID, Slug: p.Slug,
		Title: p.Title, Excerpt: p.Excerpt,
		ContentMarkdown: p.ContentMarkdown, ContentHTML: p.ContentHTML,
		Status: p.Status.String(), PublishedAt: p.PublishedAt,
		Metadata: meta, CreatedAt: p.CreatedAt, UpdatedAt: p.UpdatedAt,
	}
}

func (s *server) handlePostsList(w http.ResponseWriter, r *http.Request) {
	var status *string
	if v := r.URL.Query().Get("status"); v != "" {
		status = &v
	}
	sums, err := s.posts.List(r.Context(), actorFrom(r), posts.ListFilter{Status: status})
	if err != nil {
		writeServiceError(w, err)
		return
	}
	out := make([]postOut, 0, len(sums))
	for _, sm := range sums {
		out = append(out, postOut{
			ID: sm.ID, TenantID: sm.TenantID, AuthorID: sm.AuthorID,
			Slug: sm.Slug, Title: sm.Title, Excerpt: sm.Excerpt,
			Status: sm.Status.String(), PublishedAt: sm.PublishedAt, CreatedAt: sm.CreatedAt,
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{"posts": out})
}

func (s *server) handlePostsCreate(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Title           string          `json:"title"`
		ContentMarkdown string          `json:"content_markdown"`
		Slug            string          `json:"slug"`
		Excerpt         string          `json:"excerpt"`
		Metadata        json.RawMessage `json:"metadata"`
		// client-supplied tenant_id is IGNORED (ST-5): scope comes from actor.
		TenantID *uuid.UUID `json:"tenant_id"`
	}
	if err := decodeJSON(w, r, &req); err != nil {
		writeError(w, http.StatusUnprocessableEntity, codeValidation, err.Error())
		return
	}
	if req.Title == "" {
		writeError(w, http.StatusUnprocessableEntity, codeValidation, "title is required")
		return
	}
	p, err := s.posts.Create(r.Context(), actorFrom(r), posts.CreateInput{
		Title:           req.Title,
		ContentMarkdown: req.ContentMarkdown,
		Slug:            req.Slug,
		Excerpt:         req.Excerpt,
		Metadata:        req.Metadata,
	})
	if err != nil {
		writeServiceError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, postOutFrom(p))
}

func (s *server) handlePostsGet(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(r)
	if !ok {
		writeError(w, http.StatusUnprocessableEntity, codeValidation, "invalid post id")
		return
	}
	p, err := s.posts.Get(r.Context(), actorFrom(r), id)
	if err != nil {
		writeServiceError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, postOutFrom(p))
}

func (s *server) handlePostsUpdate(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(r)
	if !ok {
		writeError(w, http.StatusUnprocessableEntity, codeValidation, "invalid post id")
		return
	}
	var req struct {
		Title           *string          `json:"title"`
		ContentMarkdown *string          `json:"content_markdown"`
		Slug            *string          `json:"slug"`
		Excerpt         *string          `json:"excerpt"`
		Metadata        *json.RawMessage `json:"metadata"`
	}
	if err := decodeJSON(w, r, &req); err != nil {
		writeError(w, http.StatusUnprocessableEntity, codeValidation, err.Error())
		return
	}
	in := posts.UpdateInput{
		Title:           req.Title,
		ContentMarkdown: req.ContentMarkdown,
		Slug:            req.Slug,
		Excerpt:         req.Excerpt,
	}
	if req.Metadata != nil {
		b := []byte(*req.Metadata)
		in.Metadata = &b
	}
	p, err := s.posts.Update(r.Context(), actorFrom(r), id, in)
	if err != nil {
		writeServiceError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, postOutFrom(p))
}

func (s *server) handlePostsDelete(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(r)
	if !ok {
		writeError(w, http.StatusUnprocessableEntity, codeValidation, "invalid post id")
		return
	}
	if err := s.posts.Delete(r.Context(), actorFrom(r), id); err != nil {
		writeServiceError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *server) handlePostsPublish(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(r)
	if !ok {
		writeError(w, http.StatusUnprocessableEntity, codeValidation, "invalid post id")
		return
	}
	p, err := s.posts.Publish(r.Context(), actorFrom(r), id)
	if err != nil {
		writeServiceError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, postOutFrom(p))
}

func (s *server) handlePostsUnpublish(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(r)
	if !ok {
		writeError(w, http.StatusUnprocessableEntity, codeValidation, "invalid post id")
		return
	}
	p, err := s.posts.Unpublish(r.Context(), actorFrom(r), id)
	if err != nil {
		writeServiceError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, postOutFrom(p))
}

// --- admin: media ---

func (s *server) handleMediaPresign(w http.ResponseWriter, r *http.Request) {
	a := actorFrom(r)
	if err := authz.Require(a, authz.CapUploadMedia); err != nil {
		writeServiceError(w, err)
		return
	}
	scope := scopeFrom(r)
	if scope.TenantID == uuid.Nil {
		writeError(w, http.StatusForbidden, codeForbidden, "no tenant in scope")
		return
	}
	var req struct {
		PostID   uuid.UUID `json:"post_id"`
		Slug     string    `json:"slug"`
		Filename string    `json:"filename"`
	}
	if err := decodeJSON(w, r, &req); err != nil {
		writeError(w, http.StatusUnprocessableEntity, codeValidation, err.Error())
		return
	}
	if req.PostID == uuid.Nil || req.Filename == "" {
		writeError(w, http.StatusUnprocessableEntity, codeValidation, "post_id and filename are required")
		return
	}
	up, err := s.media.Presign(scope.TenantID, req.PostID, req.Slug, req.Filename, time.Now())
	if err != nil {
		writeServiceError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"url": up.URL, "key": up.Key, "expires_at": up.ExpiresAt})
}

func (s *server) handleMediaConfirm(w http.ResponseWriter, r *http.Request) {
	a := actorFrom(r)
	if err := authz.Require(a, authz.CapUploadMedia); err != nil {
		writeServiceError(w, err)
		return
	}
	scope := scopeFrom(r)
	if scope.TenantID == uuid.Nil {
		writeError(w, http.StatusForbidden, codeForbidden, "no tenant in scope")
		return
	}
	var req struct {
		PostID    uuid.UUID `json:"post_id"`
		Key       string    `json:"key"`
		SizeBytes int64     `json:"size_bytes"`
		MimeType  string    `json:"mime_type"`
	}
	if err := decodeJSON(w, r, &req); err != nil {
		writeError(w, http.StatusUnprocessableEntity, codeValidation, err.Error())
		return
	}
	if req.Key == "" || req.PostID == uuid.Nil {
		writeError(w, http.StatusUnprocessableEntity, codeValidation, "post_id and key are required")
		return
	}
	var created bool
	err := s.db.ScopedRW(r.Context(), scope, func(q *store.Queries) error {
		var e error
		created, e = s.media.Confirm(r.Context(), q, scope.TenantID, req.PostID, req.Key, req.SizeBytes, req.MimeType)
		return e
	})
	if err != nil {
		writeServiceError(w, err)
		return
	}
	if created {
		writeJSON(w, http.StatusCreated, map[string]any{"ok": true})
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *server) handleMediaDelete(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(r)
	if !ok {
		writeError(w, http.StatusUnprocessableEntity, codeValidation, "invalid image id")
		return
	}
	if err := s.media.Delete(r.Context(), actorFrom(r), id); err != nil {
		writeServiceError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// --- admin: imports ---

func (s *server) handleImportsStart(w http.ResponseWriter, r *http.Request) {
	a := actorFrom(r)
	if err := authz.Require(a, authz.CapRunImport); err != nil {
		writeServiceError(w, err)
		return
	}
	if strings.HasPrefix(r.Header.Get("Content-Type"), "multipart/form-data") {
		f, h, err := r.FormFile("file")
		if err != nil {
			writeError(w, http.StatusUnprocessableEntity, codeValidation, "multipart field \"file\" is required")
			return
		}
		defer f.Close()
		data, err := io.ReadAll(io.LimitReader(f, 32<<20))
		if err != nil {
			writeError(w, http.StatusUnprocessableEntity, codeValidation, "cannot read file")
			return
		}
		id, err := s.imports.Start(r.Context(), a, docimport.Source{
			Kind:     docimport.SourceMultipart,
			File:     data,
			Filename: h.Filename,
			MimeType: h.Header.Get("Content-Type"),
		})
		if err != nil {
			writeServiceError(w, err)
			return
		}
		writeJSON(w, http.StatusCreated, map[string]any{"id": id})
		return
	}
	var req struct {
		DocID string `json:"doc_id"`
	}
	if err := decodeJSON(w, r, &req); err != nil {
		writeError(w, http.StatusUnprocessableEntity, codeValidation, err.Error())
		return
	}
	if req.DocID == "" {
		writeError(w, http.StatusUnprocessableEntity, codeValidation, "doc_id is required")
		return
	}
	id, err := s.imports.Start(r.Context(), a, docimport.Source{Kind: docimport.SourceGoogleDocs, DocID: req.DocID})
	if err != nil {
		writeServiceError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{"id": id})
}

func (s *server) handleImportsStatus(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(r)
	if !ok {
		writeError(w, http.StatusUnprocessableEntity, codeValidation, "invalid import id")
		return
	}
	res, err := s.imports.Get(r.Context(), actorFrom(r), id)
	if err != nil {
		writeServiceError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, res)
}

func (s *server) handleImportsApply(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(r)
	if !ok {
		writeError(w, http.StatusUnprocessableEntity, codeValidation, "invalid import id")
		return
	}
	p, err := s.imports.Apply(r.Context(), actorFrom(r), id)
	if err != nil {
		writeServiceError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, postOutFrom(p))
}

// --- admin: members ---

func (s *server) requireTenantScope(w http.ResponseWriter, a authz.Actor) bool {
	if a.Platform || a.Tenant == nil {
		writeError(w, http.StatusUnprocessableEntity, codeValidation, "no tenant in scope")
		return false
	}
	return true
}

func (s *server) handleMembersList(w http.ResponseWriter, r *http.Request) {
	a := actorFrom(r)
	if err := authz.Require(a, authz.CapViewMembers); err != nil {
		writeServiceError(w, err)
		return
	}
	if !s.requireTenantScope(w, a) {
		return
	}
	var ms []store.TenantMember
	err := s.db.Scoped(r.Context(), store.Scope{}, func(q *store.Queries) error {
		var e error
		ms, e = q.ListTenantMembers(r.Context(), *a.Tenant)
		return e
	})
	if err != nil {
		writeServiceError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"members": ms})
}

func (s *server) handleMembersInvite(w http.ResponseWriter, r *http.Request) {
	a := actorFrom(r)
	if err := authz.Require(a, authz.CapInviteMembers); err != nil {
		writeServiceError(w, err)
		return
	}
	if !s.requireTenantScope(w, a) {
		return
	}
	var req struct {
		Email *string `json:"email"`
		Role  string  `json:"role"`
	}
	if err := decodeJSON(w, r, &req); err != nil {
		writeError(w, http.StatusUnprocessableEntity, codeValidation, err.Error())
		return
	}
	if req.Email == nil || strings.TrimSpace(*req.Email) == "" {
		writeError(w, http.StatusUnprocessableEntity, codeValidation, "email is required")
		return
	}
	if !validRole(req.Role) {
		writeError(w, http.StatusUnprocessableEntity, codeValidation, "invalid role")
		return
	}
	if req.Role == "owner" && a.Role != authz.RoleOwner {
		writeError(w, http.StatusForbidden, codeForbidden, "only owners may invite owners")
		return
	}
	email := strings.ToLower(strings.TrimSpace(*req.Email))
	id, err := uuid.NewV7()
	if err != nil {
		writeServiceError(w, err)
		return
	}
	expires := time.Now().Add(7 * 24 * time.Hour)
	err = s.db.ScopedRW(r.Context(), store.Scope{}, func(q *store.Queries) error {
		return q.InsertInvitation(r.Context(), id, *a.Tenant, &email, req.Role, nil, expires)
	})
	if err != nil {
		writeServiceError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{"id": id})
}

func validRole(role string) bool {
	switch role {
	case "author", "editor", "admin", "owner":
		return true
	}
	return false
}

func (s *server) handleMembersSetRole(w http.ResponseWriter, r *http.Request) {
	a := actorFrom(r)
	if err := authz.Require(a, authz.CapChangeRoles); err != nil {
		writeServiceError(w, err)
		return
	}
	if !s.requireTenantScope(w, a) {
		return
	}
	userID, err := uuid.Parse(r.PathValue("userId"))
	if err != nil {
		writeError(w, http.StatusUnprocessableEntity, codeValidation, "invalid user id")
		return
	}
	var req struct {
		Role string `json:"role"`
	}
	if err := decodeJSON(w, r, &req); err != nil {
		writeError(w, http.StatusUnprocessableEntity, codeValidation, err.Error())
		return
	}
	if !validRole(req.Role) {
		writeError(w, http.StatusUnprocessableEntity, codeValidation, "invalid role")
		return
	}
	if req.Role == "owner" && a.Role != authz.RoleOwner {
		writeError(w, http.StatusForbidden, codeForbidden, "only owners may grant owner")
		return
	}
	err = s.db.ScopedRW(r.Context(), store.Scope{}, func(q *store.Queries) error {
		return q.SetMembershipRole(r.Context(), *a.Tenant, userID, req.Role)
	})
	if errors.Is(err, pgx.ErrNoRows) {
		writeError(w, http.StatusNotFound, codeNotFound, "member not found")
		return
	}
	if err != nil {
		writeServiceError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *server) handleMembersRemove(w http.ResponseWriter, r *http.Request) {
	a := actorFrom(r)
	if err := authz.Require(a, authz.CapRemoveMembers); err != nil {
		writeServiceError(w, err)
		return
	}
	if !s.requireTenantScope(w, a) {
		return
	}
	userID, err := uuid.Parse(r.PathValue("userId"))
	if err != nil {
		writeError(w, http.StatusUnprocessableEntity, codeValidation, "invalid user id")
		return
	}
	if userID == a.UserID {
		writeError(w, http.StatusUnprocessableEntity, codeValidation, "cannot remove self")
		return
	}
	err = s.db.ScopedRW(r.Context(), store.Scope{}, func(q *store.Queries) error {
		return q.RemoveMembership(r.Context(), *a.Tenant, userID)
	})
	if errors.Is(err, pgx.ErrNoRows) {
		writeError(w, http.StatusNotFound, codeNotFound, "member not found")
		return
	}
	if err != nil {
		writeServiceError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// --- admin: tenants (ST-16/ST-17) ---

type tenantOut struct {
	ID             uuid.UUID       `json:"id"`
	Slug           string          `json:"slug"`
	Name           string          `json:"name"`
	Settings       json.RawMessage `json:"settings"`
	ContentVersion int64           `json:"content_version"`
	CreatedAt      time.Time       `json:"created_at"`
	UpdatedAt      time.Time       `json:"updated_at"`
}

func tenantOutFrom(t store.Tenant) tenantOut {
	settings := t.Settings
	if len(settings) == 0 {
		settings = json.RawMessage("{}")
	}
	return tenantOut{
		ID: t.ID, Slug: t.Slug, Name: t.Name, Settings: settings,
		ContentVersion: t.ContentVersion, CreatedAt: t.CreatedAt, UpdatedAt: t.UpdatedAt,
	}
}

// tenantManageable reports whether the actor can manage tenant id: platform
// super-admin, or the tenant's own owner (ST-15/ST-17).
func tenantManageable(a authz.Actor, id uuid.UUID) bool {
	if a.Platform {
		return true
	}
	return a.Tenant != nil && *a.Tenant == id && a.Role == authz.RoleOwner
}

func (s *server) handleTenantsList(w http.ResponseWriter, r *http.Request) {
	if !actorFrom(r).Platform {
		writeError(w, http.StatusForbidden, codeForbidden, "platform role required")
		return
	}
	var tenants []store.Tenant
	err := s.db.Scoped(r.Context(), store.Scope{}, func(q *store.Queries) error {
		var e error
		tenants, e = q.ListTenants(r.Context())
		return e
	})
	if err != nil {
		writeServiceError(w, err)
		return
	}
	out := make([]tenantOut, 0, len(tenants))
	for _, t := range tenants {
		out = append(out, tenantOutFrom(t))
	}
	writeJSON(w, http.StatusOK, map[string]any{"tenants": out})
}

func (s *server) handleTenantsCreate(w http.ResponseWriter, r *http.Request) {
	if !actorFrom(r).Platform {
		writeError(w, http.StatusForbidden, codeForbidden, "platform role required")
		return
	}
	var req struct {
		Slug string `json:"slug"`
		Name string `json:"name"`
	}
	if err := decodeJSON(w, r, &req); err != nil {
		writeError(w, http.StatusUnprocessableEntity, codeValidation, err.Error())
		return
	}
	if req.Slug == "" || req.Name == "" {
		writeError(w, http.StatusUnprocessableEntity, codeValidation, "slug and name are required")
		return
	}
	if !tenancy.ValidSlug(req.Slug) {
		writeError(w, http.StatusUnprocessableEntity, codeValidation, "invalid slug")
		return
	}
	id, err := uuid.NewV7()
	if err != nil {
		writeServiceError(w, err)
		return
	}
	err = s.db.ScopedRW(r.Context(), store.Scope{}, func(q *store.Queries) error {
		return q.CreateTenant(r.Context(), id, req.Slug, req.Name)
	})
	if isUniqueViolation(err) {
		writeError(w, http.StatusConflict, codeConflict, "slug already in use")
		return
	}
	if err != nil {
		writeServiceError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{"id": id, "slug": req.Slug})
}

func (s *server) handleTenantsGet(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(r)
	if !ok {
		writeError(w, http.StatusUnprocessableEntity, codeValidation, "invalid tenant id")
		return
	}
	a := actorFrom(r)
	if !tenantManageable(a, id) {
		writeError(w, http.StatusForbidden, codeForbidden, "forbidden")
		return
	}
	var t store.Tenant
	err := s.db.Scoped(r.Context(), store.Scope{}, func(q *store.Queries) error {
		var e error
		t, e = q.GetTenant(r.Context(), id)
		return e
	})
	if errors.Is(err, pgx.ErrNoRows) {
		writeError(w, http.StatusNotFound, codeNotFound, "tenant not found")
		return
	}
	if err != nil {
		writeServiceError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, tenantOutFrom(t))
}

func (s *server) handleTenantsUpdate(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(r)
	if !ok {
		writeError(w, http.StatusUnprocessableEntity, codeValidation, "invalid tenant id")
		return
	}
	a := actorFrom(r)
	if !tenantManageable(a, id) {
		writeError(w, http.StatusForbidden, codeForbidden, "forbidden")
		return
	}
	var req struct {
		Name     *string          `json:"name"`
		Settings *json.RawMessage `json:"settings"`
	}
	if err := decodeJSON(w, r, &req); err != nil {
		writeError(w, http.StatusUnprocessableEntity, codeValidation, err.Error())
		return
	}
	var name string
	if req.Name != nil {
		name = *req.Name
	}
	var settings []byte
	if req.Settings != nil {
		settings = *req.Settings
	}
	var out store.Tenant
	err := s.db.ScopedRW(r.Context(), store.Scope{}, func(q *store.Queries) error {
		var e error
		out, e = q.UpdateTenant(r.Context(), id, name, settings)
		if e != nil {
			return e
		}
		// A settings change is public-visible content: bump content_version and
		// enqueue the same-tx CDN purge (sweep finding 7, plan §Middleware).
		_, e = jobs.Enqueue(r.Context(), q.Tx(), posts.PurgeJobKind, id.String(), jobs.JobPayload{
			TenantID: id,
			Data: mustJSON(struct {
				TenantID uuid.UUID `json:"tenant_id"`
				Version  int64     `json:"version"`
				Paths    []string  `json:"paths"`
			}{TenantID: id, Version: out.ContentVersion, Paths: []string{"/"}}),
		})
		if errors.Is(e, jobs.ErrDuplicate) {
			return nil
		}
		return e
	})
	if errors.Is(err, pgx.ErrNoRows) {
		writeError(w, http.StatusNotFound, codeNotFound, "tenant not found")
		return
	}
	if err != nil {
		writeServiceError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, tenantOutFrom(out))
}

func (s *server) handleTenantsDelete(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(r)
	if !ok {
		writeError(w, http.StatusUnprocessableEntity, codeValidation, "invalid tenant id")
		return
	}
	a := actorFrom(r)
	if !tenantManageable(a, id) {
		writeError(w, http.StatusForbidden, codeForbidden, "forbidden")
		return
	}
	err := s.db.ScopedRW(r.Context(), store.Scope{}, func(q *store.Queries) error {
		_, e := jobs.Enqueue(r.Context(), q.Tx(), posts.PurgeJobKind, id.String(), jobs.JobPayload{
			TenantID: id,
			Data: mustJSON(struct {
				TenantID uuid.UUID `json:"tenant_id"`
				Paths    []string  `json:"paths"`
			}{TenantID: id, Paths: []string{"/"}}),
		})
		if errors.Is(e, jobs.ErrDuplicate) {
			e = nil
		}
		if e != nil {
			return e
		}
		return q.DeleteTenant(r.Context(), id)
	})
	if errors.Is(err, pgx.ErrNoRows) {
		writeError(w, http.StatusNotFound, codeNotFound, "tenant not found")
		return
	}
	if err != nil {
		writeServiceError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func mustJSON(v any) json.RawMessage {
	b, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return b
}
