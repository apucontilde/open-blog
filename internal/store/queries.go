package store

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// Queries is a thin, explicit query handle over one scoped transaction:
// handwritten SQL that returns domain types, with no ORM or generated model
// layer. RLS sees exactly the tuples each statement touches.
type Queries struct {
	tx pgx.Tx
}

// Tx exposes the underlying pgx transaction so co-owned modules can enqueue
// jobs inside the same transaction (008 sweep: enqueue-in-tx).
func (q *Queries) Tx() pgx.Tx { return q.tx }

// NewQueries wraps an existing pgx transaction for ad-hoc use by co-owned
// modules and tests that manage their own transaction lifecycle.
func NewQueries(tx pgx.Tx) *Queries { return &Queries{tx: tx} }

// PostStatus mirrors the DB CHECK-constrained text values; the iota enum owns
// ordering/authz semantics, the parser maps it to and from the wire.
type PostStatus uint8

const (
	PostDraft PostStatus = iota
	PostPublished
	PostArchived
)

func (s PostStatus) String() string {
	switch s {
	case PostPublished:
		return "published"
	case PostArchived:
		return "archived"
	default:
		return "draft"
	}
}

func parsePostStatus(s string) (PostStatus, error) {
	switch s {
	case "draft":
		return PostDraft, nil
	case "published":
		return PostPublished, nil
	case "archived":
		return PostArchived, nil
	default:
		return 0, fmt.Errorf("store: unknown post_status %q", s)
	}
}

// Post is one row of posts. IDs are opaque and never ordered by; ordering is
// by created_at / published_at / content_version.
type Post struct {
	ID              uuid.UUID
	TenantID        uuid.UUID
	AuthorID        uuid.UUID
	Slug            string
	Title           string
	Excerpt         string
	ContentMarkdown string
	ContentHTML     string
	Status          PostStatus
	PublishedAt     *time.Time
	Metadata        []byte
	CreatedAt       time.Time
	UpdatedAt       time.Time
}

const postColumns = `id, tenant_id, author_id, slug, title, excerpt, content_markdown,
	content_html, status, published_at, metadata, created_at, updated_at`

// CreatePost inserts a draft post. Insertion and visibility require the
// caller's scope to match p.TenantID — RLS `with check` is the enforcement.
// ContentHTML and Metadata are written through so a create renders once; a
// nil Metadata falls back to the '{}' column default.
func (q *Queries) CreatePost(ctx context.Context, p Post) (Post, error) {
	row := q.tx.QueryRow(ctx, `
		insert into posts (id, tenant_id, author_id, slug, title, excerpt, content_markdown, content_html, metadata)
		values ($1, $2, $3, $4, $5, $6, $7, $8, coalesce($9, '{}'::jsonb))
		returning `+postColumns,
		p.ID, p.TenantID, p.AuthorID, p.Slug, p.Title, p.Excerpt, p.ContentMarkdown, p.ContentHTML, p.Metadata)
	return scanPost(row)
}

// ListPosts returns every post the current scope may read: the scoped tenant's
// rows, or all rows under a platform scope, and none under a nil tenant.
func (q *Queries) ListPosts(ctx context.Context) ([]Post, error) {
	rows, err := q.tx.Query(ctx, `select `+postColumns+` from posts`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	ps := []Post{}
	for rows.Next() {
		var p Post
		p, err = scanPost(rows)
		if err != nil {
			return nil, err
		}
		ps = append(ps, p)
	}
	return ps, rows.Err()
}

func scanPost(row pgx.Row) (Post, error) {
	var p Post
	var status string
	if err := row.Scan(&p.ID, &p.TenantID, &p.AuthorID, &p.Slug, &p.Title, &p.Excerpt,
		&p.ContentMarkdown, &p.ContentHTML, &status, &p.PublishedAt, &p.Metadata,
		&p.CreatedAt, &p.UpdatedAt); err != nil {
		return Post{}, err
	}
	ps, err := parsePostStatus(status)
	if err != nil {
		return Post{}, err
	}
	p.Status = ps
	return p, nil
}

// CreatePostImage attaches an image row to a post. The composite
// (tenant_id, post_id) FK rejects cross-tenant attachment.
func (q *Queries) CreatePostImage(ctx context.Context, id, tenantID, postID uuid.UUID, r2Key, url string, width, height int, sizeBytes int64, mimeType string) error {
	_, err := q.tx.Exec(ctx, `
		insert into post_images (id, tenant_id, post_id, r2_key, url, width, height, size_bytes, mime_type)
		values ($1, $2, $3, $4, $5, $6, $7, $8, $9)`,
		id, tenantID, postID, r2Key, url, width, height, sizeBytes, mimeType)
	return err
}

// PostImage is one post_images row. Width/height/variants are populated
// server-side by the variants worker after decode.
type PostImage struct {
	ID        uuid.UUID
	TenantID  uuid.UUID
	PostID    uuid.UUID
	R2Key     string
	URL       string
	Width     int
	Height    int
	SizeBytes int64
	MimeType  string
	Variants  []byte
	CreatedAt time.Time
}

const postImageColumns = `id, tenant_id, post_id, r2_key, url, width, height, size_bytes, mime_type, variants, created_at`

// InsertPostImageOnConflict inserts a post_images row, treating a duplicate
// (tenant_id, r2_key) as a 0-row no-op — confirm is idempotent (sweep
// finding 23). Width/height start at 0: the worker records them after decode.
// The composite FK (tenant_id, post_id) → posts(tenant_id, id) rejects
// attaching the image to another tenant's post even under a platform scope.
func (q *Queries) InsertPostImageOnConflict(ctx context.Context, id, tenantID, postID uuid.UUID, r2Key, url, mimeType string, sizeBytes int64) (int64, error) {
	tag, err := q.tx.Exec(ctx, `
		insert into post_images (id, tenant_id, post_id, r2_key, url, width, height, size_bytes, mime_type)
		values ($1, $2, $3, $4, $5, 0, 0, $6, $7)
		on conflict (tenant_id, r2_key) do nothing`,
		id, tenantID, postID, r2Key, url, sizeBytes, mimeType)
	return tag.RowsAffected(), err
}

// GetPostImageByID reads one post_images row under the ambient scope.
func (q *Queries) GetPostImageByID(ctx context.Context, id uuid.UUID) (PostImage, error) {
	row := q.tx.QueryRow(ctx, "select "+postImageColumns+" from post_images where id = $1", id)
	return scanPostImage(row)
}

// GetPostImageByR2Key reads the row for an object key under the ambient scope
// (the scope itself confines the read to the tenant the key belongs to).
func (q *Queries) GetPostImageByR2Key(ctx context.Context, r2Key string) (PostImage, error) {
	row := q.tx.QueryRow(ctx, "select "+postImageColumns+" from post_images where r2_key = $1", r2Key)
	return scanPostImage(row)
}

// DeletePostImage removes one post_images row; orphaned R2 objects are
// reclaimed by the sweeper, not here.
func (q *Queries) DeletePostImage(ctx context.Context, id uuid.UUID) error {
	_, err := q.tx.Exec(ctx, "delete from post_images where id = $1", id)
	return err
}

// UpdatePostImageVariants records the worker's output: the decoded original
// dimensions and the canonical variants jsonb. Scoped to the row by RLS.
func (q *Queries) UpdatePostImageVariants(ctx context.Context, id uuid.UUID, width, height int, variants []byte) error {
	_, err := q.tx.Exec(ctx, `
		update post_images set width = $2, height = $3, variants = $4
		where id = $1`,
		id, width, height, variants)
	return err
}

// GetPostByID reads one post row under the ambient scope.
func (q *Queries) GetPostByID(ctx context.Context, id uuid.UUID) (Post, error) {
	row := q.tx.QueryRow(ctx, "select "+postColumns+" from posts where id = $1", id)
	return scanPost(row)
}

// PostSummary is the list projection of posts: metadata and slug only, no
// markdown body (005: the list path never reads content_html).
type PostSummary struct {
	ID          uuid.UUID
	TenantID    uuid.UUID
	AuthorID    uuid.UUID
	Slug        string
	Title       string
	Excerpt     string
	Status      PostStatus
	PublishedAt *time.Time
	CreatedAt   time.Time
}

// ListPostSummaries projects the list view under the ambient scope, optionally
// filtered by status and author (a nil filter is open). Ordering is stable:
// published_at/created_at desc with id as the tiebreaker.
func (q *Queries) ListPostSummaries(ctx context.Context, status *string, authorID *uuid.UUID) ([]PostSummary, error) {
	rows, err := q.tx.Query(ctx, `
		select id, tenant_id, author_id, slug, title, excerpt, status, published_at, created_at
		from posts
		where ($1::post_status is null or status = $1)
		  and ($2::uuid is null or author_id = $2)
		order by created_at desc, id desc`, status, authorID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	ps := []PostSummary{}
	for rows.Next() {
		var s PostSummary
		var status string
		if err := rows.Scan(&s.ID, &s.TenantID, &s.AuthorID, &s.Slug, &s.Title,
			&s.Excerpt, &status, &s.PublishedAt, &s.CreatedAt); err != nil {
			return nil, err
		}
		s.Status, err = parsePostStatus(status)
		if err != nil {
			return nil, err
		}
		ps = append(ps, s)
	}
	return ps, rows.Err()
}

// UpdatePost rewrites the mutable fields (title, slug, excerpt, markdown and
// the re-rendered content_html); updated_at is bumped by the DB. Slug
// immutability once published is enforced by the caller (005).
func (q *Queries) UpdatePost(ctx context.Context, p Post) (Post, error) {
	row := q.tx.QueryRow(ctx, `
		update posts set
			title = $2, slug = $3, excerpt = $4,
			content_markdown = $5, content_html = $6,
			updated_at = now()
		where id = $1
		returning `+postColumns,
		p.ID, p.Title, p.Slug, p.Excerpt, p.ContentMarkdown, p.ContentHTML)
	return scanPost(row)
}

// SetPostStatus transitions a post to status with an explicitly supplied
// published_at (now() on publish, nil on unpublish/archive) and the freshly
// re-rendered content_html; every lifecycle transition re-renders (005 sweep
// resolution Q1). updated_at is bumped by the DB.
func (q *Queries) SetPostStatus(ctx context.Context, id uuid.UUID, status PostStatus, publishedAt *time.Time, contentHTML string) (Post, error) {
	row := q.tx.QueryRow(ctx, `
		update posts set status = $2, published_at = $3, content_html = $4, updated_at = now()
		where id = $1
		returning `+postColumns,
		id, status.String(), publishedAt, contentHTML)
	return scanPost(row)
}

// BumpContentVersion increments tenants.content_version — the ETag anchor for
// public-visible changes (005/009 sweep finding 6) — and returns the new value.
func (q *Queries) BumpContentVersion(ctx context.Context, tenantID uuid.UUID) (int64, error) {
	var v int64
	err := q.tx.QueryRow(ctx, `
		update tenants set content_version = content_version + 1, updated_at = now()
		where id = $1
		returning content_version`, tenantID).Scan(&v)
	return v, err
}

// SlugExists reports whether a slug is taken inside the tenant, a cheap probe
// of the unique (tenant_id, slug) constraint.
func (q *Queries) SlugExists(ctx context.Context, tenantID uuid.UUID, slug string) (bool, error) {
	var exists bool
	err := q.tx.QueryRow(ctx,
		"select exists(select 1 from posts where tenant_id = $1 and slug = $2)",
		tenantID, slug).Scan(&exists)
	return exists, err
}

// DeletePost removes one post row: post_images cascade, imports.post_id is set
// NULL so the same source can be re-imported. RLS confines the delete to rows
// visible to the ambient scope.
func (q *Queries) DeletePost(ctx context.Context, id uuid.UUID) error {
	_, err := q.tx.Exec(ctx, "delete from posts where id = $1", id)
	return err
}

func scanPostImage(row pgx.Row) (PostImage, error) {
	var im PostImage
	if err := row.Scan(&im.ID, &im.TenantID, &im.PostID, &im.R2Key, &im.URL,
		&im.Width, &im.Height, &im.SizeBytes, &im.MimeType, &im.Variants, &im.CreatedAt); err != nil {
		return PostImage{}, err
	}
	return im, nil
}

// CreateImport records a conversion job for sourceKey; postID may be nil before
// the converted post exists. Same composite-FK guard as CreatePostImage.
func (q *Queries) CreateImport(ctx context.Context, id, tenantID, userID uuid.UUID, postID *uuid.UUID, sourceFormat, sourceKey string) error {
	_, err := q.tx.Exec(ctx, `
		insert into imports (id, tenant_id, user_id, post_id, source_format, source_key)
		values ($1, $2, $3, $4, $5, $6)`,
		id, tenantID, userID, postID, sourceFormat, sourceKey)
	return err
}

// CreateTenant inserts an unscoped platform row. IDs are app-minted (uuid v7
// by convention); the DDL default is a v4 safety fallback for tooling.
func (q *Queries) CreateTenant(ctx context.Context, id uuid.UUID, slug, name string) error {
	_, err := q.tx.Exec(ctx,
		"insert into tenants (id, slug, name) values ($1, $2, $3)", id, slug, name)
	return err
}

// CreateUser inserts an unscoped identity row with a nullable password hash.
func (q *Queries) CreateUser(ctx context.Context, id uuid.UUID, email, displayName string, passwordHash *string) error {
	_, err := q.tx.Exec(ctx,
		"insert into users (id, email, display_name, password_hash) values ($1, $2, $3, $4)",
		id, email, displayName, passwordHash)
	return err
}

// AddMembership joins actorID to tenantID with role. memberships is unscoped
// by design; role values are constrained by the DB CHECK.
func (q *Queries) AddMembership(ctx context.Context, tenantID, userID uuid.UUID, role string) error {
	_, err := q.tx.Exec(ctx,
		"insert into memberships (tenant_id, user_id, role) values ($1, $2, $3)",
		tenantID, userID, role)
	return err
}

// SetSuperAdmin sets or clears users.super_admin, the single platform-wide
// flag backing Actor.Platform (plan 004). Identities are unscoped rows.
func (q *Queries) SetSuperAdmin(ctx context.Context, userID uuid.UUID, on bool) error {
	_, err := q.tx.Exec(ctx,
		"update users set super_admin = $2 where id = $1", userID, on)
	return err
}

// Session is one row of sessions. TokenHash is the sha256 of the opaque token
// the client holds; the raw token never reaches the DB.
type Session struct {
	TokenHash []byte
	UserID    uuid.UUID
	Scope     *uuid.UUID
	ExpiresAt time.Time
	CreatedAt time.Time
}

// InsertSession records a new session row. sessions is unscoped (platform
// identity); the user_id FK rejects a zero/unknown user.
func (q *Queries) InsertSession(ctx context.Context, s Session) error {
	_, err := q.tx.Exec(ctx, `
		insert into sessions (token_hash, user_id, scope, expires_at)
		values ($1, $2, $3, $4)`,
		s.TokenHash, s.UserID, s.Scope, s.ExpiresAt)
	return err
}

// GetSessionByTokenHash is the single verify-path read: a PK hit on token_hash.
func (q *Queries) GetSessionByTokenHash(ctx context.Context, tokenHash []byte) (Session, error) {
	row := q.tx.QueryRow(ctx,
		"select token_hash, user_id, scope, expires_at, created_at from sessions where token_hash = $1",
		tokenHash)
	return scanSession(row)
}

// DeleteSessionByTokenHash removes the row for the presented token (logout).
func (q *Queries) DeleteSessionByTokenHash(ctx context.Context, tokenHash []byte) error {
	_, err := q.tx.Exec(ctx,
		"delete from sessions where token_hash = $1", tokenHash)
	return err
}

// SetSessionScope updates the active-tenant scope of one session (ST-20);
// scope may be nil to clear it.
func (q *Queries) SetSessionScope(ctx context.Context, tokenHash []byte, scope *uuid.UUID) error {
	tag, err := q.tx.Exec(ctx,
		"update sessions set scope = $2 where token_hash = $1", tokenHash, scope)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return pgx.ErrNoRows
	}
	return nil
}

func scanSession(row pgx.Row) (Session, error) {
	var s Session
	if err := row.Scan(&s.TokenHash, &s.UserID, &s.Scope, &s.ExpiresAt, &s.CreatedAt); err != nil {
		return Session{}, err
	}
	return s, nil
}

// User is one row of users as seen by auth: email and password identity only.
type User struct {
	ID           uuid.UUID
	Email        string
	PasswordHash *string // NULL for SSO-only accounts
	DisplayName  string
}

// GetUserByEmail resolves a user by lowercase email (the uniqueness key).
func (q *Queries) GetUserByEmail(ctx context.Context, email string) (User, error) {
	row := q.tx.QueryRow(ctx,
		"select id, email, password_hash, display_name from users where lower(email) = lower($1)",
		email)
	return scanUser(row)
}

func scanUser(row pgx.Row) (User, error) {
	var u User
	if err := row.Scan(&u.ID, &u.Email, &u.PasswordHash, &u.DisplayName); err != nil {
		return User{}, err
	}
	return u, nil
}

// HasPendingInvitation reports whether a live (unconsumed) invitation exists
// for the email. invitations is unscoped; the caller normalizes email.
func (q *Queries) HasPendingInvitation(ctx context.Context, email string) (bool, error) {
	var exists bool
	err := q.tx.QueryRow(ctx, `
		select exists(
			select 1 from invitations
			where lower(email) = lower($1) and consumed_at is null and expires_at > now()
		)`, email).Scan(&exists)
	return exists, err
}

// InsertInvitation records a live invitation, pure-email (email set, token
// nil) or role-baked (token set). Scoped to tenantID by the tenant FK.
func (q *Queries) InsertInvitation(ctx context.Context, id, tenantID uuid.UUID, email *string, role string, tokenHash []byte, expiresAt time.Time) error {
	_, err := q.tx.Exec(ctx, `
		insert into invitations (id, tenant_id, email, role, token_hash, expires_at)
		values ($1, $2, $3, $4, $5, $6)`,
		id, tenantID, email, role, tokenHash, expiresAt)
	return err
}

// ConsumeInvitationByEmail marks invitations for an email consumed (SSO
// verified-email consumption; un-consumes are a no-op).
func (q *Queries) ConsumeInvitationByEmail(ctx context.Context, email string) error {
	_, err := q.tx.Exec(ctx,
		"update invitations set consumed_at = now() where lower(email) = lower($1) and consumed_at is null",
		email)
	return err
}

// OAuthFlow mirrors one oauth_flows row. State is the sha256 of the raw state
// nonce the client was redirected with; the raw nonce itself never lands in DB.
type OAuthFlow struct {
	ID               uuid.UUID
	Provider         string
	State            []byte
	CodeVerifier     []byte
	Redirect         string
	SessionTokenHash []byte // nil = flow started without a session
	ExpiresAt        time.Time
	CreatedAt        time.Time
}

// InsertOAuthFlow records a new flow bound to the initiating session hash.
// oauth_flows is an unscoped platform table (001 sweep).
func (q *Queries) InsertOAuthFlow(ctx context.Context, f OAuthFlow) error {
	_, err := q.tx.Exec(ctx, `
		insert into oauth_flows (id, provider, state, code_verifier, redirect, session_token_hash, expires_at)
		values ($1, $2, $3, $4, $5, $6, $7)`,
		f.ID, f.Provider, f.State, f.CodeVerifier, f.Redirect, f.SessionTokenHash, f.ExpiresAt)
	return err
}

// ConsumeOAuthFlow atomically claims the flow whose state hash matches and
// whose bound session matches (NULL-safe IS NOT DISTINCT FROM). The DELETE
// makes the state single-use in the same statement that returns it: a replay,
// an expired flow, or a session mismatch yields zero rows and no IdP traffic.
func (q *Queries) ConsumeOAuthFlow(ctx context.Context, state, sessionTokenHash []byte) (OAuthFlow, error) {
	row := q.tx.QueryRow(ctx, `
		delete from oauth_flows
		where state = $1
		  and expires_at > now()
		  and session_token_hash is not distinct from $2
		returning id, provider, state, code_verifier, redirect, session_token_hash, expires_at, created_at`,
		state, sessionTokenHash)
	return scanOAuthFlow(row)
}

func scanOAuthFlow(row pgx.Row) (OAuthFlow, error) {
	var f OAuthFlow
	if err := row.Scan(&f.ID, &f.Provider, &f.State, &f.CodeVerifier, &f.Redirect,
		&f.SessionTokenHash, &f.ExpiresAt, &f.CreatedAt); err != nil {
		return OAuthFlow{}, err
	}
	return f, nil
}

// OAuthToken is one row of oauth_tokens. RefreshToken and AccessToken hold
// AEAD-GCM ciphertext; the plaintext never reaches the DB (plan 003).
type OAuthToken struct {
	UserID       uuid.UUID
	Provider     string
	RefreshToken []byte
	AccessToken  []byte
	TokenScopes  string
	TokenExpiry  *time.Time
}

// UpsertOAuthToken stores or rotates the (user, provider) token pair. The
// refresh_token is preserved when the provider returns none again (Google
// issues a refresh token only on first consent), and token_scopes are merged
// as a sorted union so a lazy drive.readonly grant survives a later bare login.
func (q *Queries) UpsertOAuthToken(ctx context.Context, t OAuthToken) error {
	_, err := q.tx.Exec(ctx, `
		insert into oauth_tokens (user_id, provider, refresh_token, access_token, token_scopes, token_expiry)
		values ($1, $2, $3, $4, $5, $6)
		on conflict (user_id, provider) do update set
			refresh_token = coalesce(excluded.refresh_token, oauth_tokens.refresh_token),
			access_token  = excluded.access_token,
			token_scopes  = coalesce((
				select string_agg(distinct s, ',' order by s)
				from unnest(string_to_array(oauth_tokens.token_scopes, ',')
				         || string_to_array(excluded.token_scopes, ',')) as s
				where s <> ''), ''),
			token_expiry  = excluded.token_expiry`,
		t.UserID, t.Provider, t.RefreshToken, t.AccessToken, t.TokenScopes, t.TokenExpiry)
	return err
}

// GetOAuthTokenByUser reads the stored (user, provider) token row.
func (q *Queries) GetOAuthTokenByUser(ctx context.Context, userID uuid.UUID, provider string) (OAuthToken, error) {
	row := q.tx.QueryRow(ctx, `
		select user_id, provider, refresh_token, access_token, token_scopes, token_expiry
		from oauth_tokens where user_id = $1 and provider = $2`,
		userID, provider)
	var t OAuthToken
	if err := row.Scan(&t.UserID, &t.Provider, &t.RefreshToken, &t.AccessToken,
		&t.TokenScopes, &t.TokenExpiry); err != nil {
		return OAuthToken{}, err
	}
	return t, nil
}

// Identity is one row of identities; (provider, subject) is the unique PK.
type Identity struct {
	Provider string
	Subject  string
	UserID   uuid.UUID
}

// GetIdentity resolves the user an (provider, subject) pair is linked to.
func (q *Queries) GetIdentity(ctx context.Context, provider, subject string) (Identity, error) {
	row := q.tx.QueryRow(ctx,
		"select provider, subject, user_id from identities where provider = $1 and subject = $2",
		provider, subject)
	var i Identity
	if err := row.Scan(&i.Provider, &i.Subject, &i.UserID); err != nil {
		return Identity{}, err
	}
	return i, nil
}

// InsertIdentity links a new (provider, subject) to userID; the PK rejects a
// duplicate pair.
func (q *Queries) InsertIdentity(ctx context.Context, provider, subject string, userID uuid.UUID) error {
	_, err := q.tx.Exec(ctx,
		"insert into identities (provider, subject, user_id) values ($1, $2, $3)",
		provider, subject, userID)
	return err
}

// Invitation is what a consumed invitation grants: the tenant and the role.
type Invitation struct {
	TenantID uuid.UUID
	Role     string
}

// ConsumePendingInvitation atomically claims ONE live invitation for the
// email (optionally scoped to tenantID by the same-statement UPDATE). A
// concurrent or repeated consume returns pgx.ErrNoRows — idempotent (ST-19).
func (q *Queries) ConsumePendingInvitation(ctx context.Context, email string, tenantID *uuid.UUID) (Invitation, error) {
	row := q.tx.QueryRow(ctx, `
		update invitations set consumed_at = now()
		where id = (
			select id from invitations
			where lower(email) = lower($1) and consumed_at is null and expires_at > now()
			  and ($2::uuid is null or tenant_id = $2)
			order by expires_at, id
			limit 1
			for update skip locked
		)
		returning tenant_id, role`,
		email, tenantID)
	return scanInvitation(row)
}

// ConsumePendingInvitationByToken consumes a role-baked link the same way:
// the consumed_at guard makes a double-consume a zero-row no-op.
func (q *Queries) ConsumePendingInvitationByToken(ctx context.Context, tokenHash []byte) (Invitation, error) {
	row := q.tx.QueryRow(ctx, `
		update invitations set consumed_at = now()
		where token_hash = $1 and consumed_at is null and expires_at > now()
		returning tenant_id, role`,
		tokenHash)
	return scanInvitation(row)
}

func scanInvitation(row pgx.Row) (Invitation, error) {
	var inv Invitation
	if err := row.Scan(&inv.TenantID, &inv.Role); err != nil {
		return Invitation{}, err
	}
	return inv, nil
}

// AddMembershipIfAbsent grants role in tenantID unless the member exists —
// the membership half of invitation consumption (ST-19).
func (q *Queries) AddMembershipIfAbsent(ctx context.Context, tenantID, userID uuid.UUID, role string) error {
	_, err := q.tx.Exec(ctx, `
		insert into memberships (tenant_id, user_id, role) values ($1, $2, $3)
		on conflict (tenant_id, user_id) do nothing`,
		tenantID, userID, role)
	return err
}

// ImportStatus mirrors the DB CHECK-constrained text values for imports.status.
type ImportStatus uint8

const (
	ImportConverting ImportStatus = iota
	ImportDone
	ImportError
)

func (s ImportStatus) String() string {
	switch s {
	case ImportDone:
		return "done"
	case ImportError:
		return "error"
	default:
		return "converting"
	}
}

func parseImportStatus(s string) (ImportStatus, error) {
	switch s {
	case "converting":
		return ImportConverting, nil
	case "done":
		return ImportDone, nil
	case "error":
		return ImportError, nil
	default:
		return 0, fmt.Errorf("store: unknown import_status %q", s)
	}
}

// Import is one row of the imports table. PostID is NULL before Apply; the
// FK ON DELETE SET NULL means deleting the draft lets the user re-apply.
type Import struct {
	ID           uuid.UUID
	TenantID     uuid.UUID
	UserID       uuid.UUID
	PostID       *uuid.UUID
	SourceFormat string
	SourceKey    string
	Status       ImportStatus
	MarkdownOut  *string
	Error        *string
	CreatedAt    time.Time
	UpdatedAt    time.Time
}

const importColumns = `id, tenant_id, user_id, post_id, source_format, source_key,
	status, markdown_out, error, created_at, updated_at`

// GetImportByID reads one import row under the ambient scope.
func (q *Queries) GetImportByID(ctx context.Context, id uuid.UUID) (Import, error) {
	row := q.tx.QueryRow(ctx, "select "+importColumns+" from imports where id = $1", id)
	return scanImport(row)
}

// SetImportPostID links an import to its created draft atomically: only a
// NULL post_id may be claimed (CAS), so concurrent Apply calls cannot both
// link the same import. Zero rows affected => post_id was already set.
func (q *Queries) SetImportPostID(ctx context.Context, id uuid.UUID, postID uuid.UUID) error {
	tag, err := q.tx.Exec(ctx, `
		update imports set post_id = $2, updated_at = now()
		where id = $1 and post_id is null`, id, postID)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return pgx.ErrNoRows
	}
	return nil
}

// ImportUpdate carries the mutable fields for an imports row. A nil pointer
// means "leave unchanged"; a pointer to a zero value means "set to NULL/default".
type ImportUpdate struct {
	Status      *ImportStatus
	PostID      *uuid.UUID
	MarkdownOut *string
	Error       *string
}

// UpdateImport overwrites the mutable fields of an import row. RLS confines
// the update to rows visible to the ambient scope.
func (q *Queries) UpdateImport(ctx context.Context, id uuid.UUID, u ImportUpdate) error {
	tag, err := q.tx.Exec(ctx, `
		update imports set
			status      = coalesce($2, status),
			post_id     = coalesce($3, post_id),
			markdown_out = coalesce($4, markdown_out),
			error       = coalesce($5, error),
			updated_at  = now()
		where id = $1`,
		id,
		importStatusPtr(u.Status),
		u.PostID,
		u.MarkdownOut,
		u.Error,
	)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return pgx.ErrNoRows
	}
	return nil
}

func importStatusPtr(s *ImportStatus) any {
	if s == nil {
		return nil
	}
	return s.String()
}

// Tenant is one row of tenants.
type Tenant struct {
	ID             uuid.UUID
	Slug           string
	Name           string
	Settings       json.RawMessage
	ContentVersion int64
	CreatedAt      time.Time
	UpdatedAt      time.Time
}

// GetTenant reads one tenant by ID (unscoped).
func (q *Queries) GetTenant(ctx context.Context, id uuid.UUID) (Tenant, error) {
	row := q.tx.QueryRow(ctx,
		`select id, slug, name, settings, content_version, created_at, updated_at
		 from tenants where id = $1`, id)
	return scanTenant(row)
}

// ListTenants returns all tenants ordered by created_at (unscoped).
func (q *Queries) ListTenants(ctx context.Context) ([]Tenant, error) {
	rows, err := q.tx.Query(ctx,
		`select id, slug, name, settings, content_version, created_at, updated_at
		 from tenants order by created_at, id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var ts []Tenant
	for rows.Next() {
		t, err := scanTenant(rows)
		if err != nil {
			return nil, err
		}
		ts = append(ts, t)
	}
	return ts, rows.Err()
}

func scanTenant(row pgx.Row) (Tenant, error) {
	var t Tenant
	if err := row.Scan(&t.ID, &t.Slug, &t.Name, &t.Settings,
		&t.ContentVersion, &t.CreatedAt, &t.UpdatedAt); err != nil {
		return Tenant{}, err
	}
	return t, nil
}

// TenantMember is one membership row for the admin members list.
type TenantMember struct {
	UserID      uuid.UUID
	Email       string
	DisplayName string
	Role        string
}

// ListTenantMembers returns every member of tenantID (unscoped).
func (q *Queries) ListTenantMembers(ctx context.Context, tenantID uuid.UUID) ([]TenantMember, error) {
	rows, err := q.tx.Query(ctx, `
		select u.id, u.email, u.display_name, m.role
		from memberships m
		join users u on u.id = m.user_id
		where m.tenant_id = $1
		order by u.created_at, u.id`, tenantID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var ms []TenantMember
	for rows.Next() {
		var m TenantMember
		if err := rows.Scan(&m.UserID, &m.Email, &m.DisplayName, &m.Role); err != nil {
			return nil, err
		}
		ms = append(ms, m)
	}
	return ms, rows.Err()
}

// SetMembershipRole updates a membership role (unscoped).
func (q *Queries) SetMembershipRole(ctx context.Context, tenantID, userID uuid.UUID, role string) error {
	tag, err := q.tx.Exec(ctx,
		"update memberships set role = $3 where tenant_id = $1 and user_id = $2",
		tenantID, userID, role)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return pgx.ErrNoRows
	}
	return nil
}

// RemoveMembership deletes a membership (unscoped).
func (q *Queries) RemoveMembership(ctx context.Context, tenantID, userID uuid.UUID) error {
	tag, err := q.tx.Exec(ctx,
		"delete from memberships where tenant_id = $1 and user_id = $2",
		tenantID, userID)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return pgx.ErrNoRows
	}
	return nil
}

// UpdateTenant updates a tenant's name and settings, bumping content_version
// because any settings change is public-visible content (unscoped).
func (q *Queries) UpdateTenant(ctx context.Context, id uuid.UUID, name string, settings json.RawMessage) (Tenant, error) {
	row := q.tx.QueryRow(ctx, `
		update tenants set
			name = coalesce(nullif($2, ''), name),
			settings = coalesce($3::jsonb, settings),
			content_version = content_version + 1, updated_at = now()
		where id = $1
		returning id, slug, name, settings, content_version, created_at, updated_at`,
		id, name, settings)
	return scanTenant(row)
}

// DeleteTenant removes a tenant row (unscoped).
func (q *Queries) DeleteTenant(ctx context.Context, id uuid.UUID) error {
	_, err := q.tx.Exec(ctx, "delete from tenants where id = $1", id)
	return err
}

func scanImport(row pgx.Row) (Import, error) {
	var imp Import
	var status string
	if err := row.Scan(&imp.ID, &imp.TenantID, &imp.UserID, &imp.PostID,
		&imp.SourceFormat, &imp.SourceKey, &status, &imp.MarkdownOut,
		&imp.Error, &imp.CreatedAt, &imp.UpdatedAt); err != nil {
		return Import{}, err
	}
	ps, err := parseImportStatus(status)
	if err != nil {
		return Import{}, err
	}
	imp.Status = ps
	return imp, nil
}
