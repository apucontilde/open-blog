// Package media owns image presign/confirm/delete and the variants worker.
// Images never pass through the API: bytes go client → R2, DB keeps metadata.
package media

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"openblog/internal/authz"
	"openblog/internal/jobs"
	"openblog/internal/store"
)

const (
	maxImageSize  = 15 << 20 // 15 MiB
	defaultExpiry = 15 * time.Minute
	kindVariants  = "variants"
)

var allowedMimes = map[string]bool{
	"image/jpeg": true,
	"image/png":  true,
	"image/webp": true,
	"image/gif":  true,
	"image/avif": true,
}

// variantSizes are the widths the worker derives from the original (WebP).
var variantSizes = []int{480, 800, 1200}

var (
	ErrForbidden       = errors.New("media: forbidden")
	ErrInvalidMime     = errors.New("media: mime type not allowed")
	ErrPayloadTooLarge = errors.New("media: payload too large")
	ErrImageNotFound   = errors.New("media: image not found")
)

// Config holds R2 presign settings. Supplied by 010 from env, never parsed here.
type Config struct {
	Endpoint        string // e.g. https://<account>.r2.cloudflarestorage.com
	Bucket          string
	AccessKeyID     string
	SecretAccessKey string
	PresignExpiry   time.Duration // 0 => defaultExpiry
	CDNBase         string        // e.g. https://media.example.com
}

// Media is the entry point for presign/confirm/delete and worker wiring.
type Media struct {
	cfg       Config
	db        *store.DB
	processor VariantProcessor
}

// New builds a Media over db with cfg; processor may be nil (then the fallback
// processor is used).
func New(cfg Config, db *store.DB, processor VariantProcessor) *Media {
	if cfg.PresignExpiry == 0 {
		cfg.PresignExpiry = defaultExpiry
	}
	if processor == nil {
		processor = NewNoopProcessor()
	}
	return &Media{cfg: cfg, db: db, processor: processor}
}

// PresignedUpload is the result of Presign: the URL the client PUTs to, the
// R2 key that upload is bound to, and when the URL expires.
type PresignedUpload struct {
	URL       string
	Key       string
	ExpiresAt time.Time
}

// VariantPayload is the job payload for the variants worker. The worker reads
// the original object from R2, so payload carries only row coordinates.
type VariantPayload struct {
	TenantID uuid.UUID `json:"tenant_id"`
	ImageID  uuid.UUID `json:"image_id"`
	R2Key    string    `json:"r2_key"`
	OrigExt  string    `json:"orig_ext"`
}

// variantEntry is one entry of post_images.variants. Canonical shape (sweep
// finding 13): {"480":{"url","width","height"},...}. 009 builds srcset in Go
// from width/url pairs; it never reads ->'srcset' — no shape drift allowed.
// Processing is "pending" only in the no-vips fallback branch (data never made
// it to the object store); 009 ignores it and simply sees the original's url.
type variantEntry struct {
	URL        string `json:"url"`
	Width      int    `json:"width"`
	Height     int    `json:"height"`
	Processing string `json:"processing,omitempty"`
}

// Presign mints a key app-side (uuid v7, so two presigns never collide) and
// returns a SigV4 presigned PUT URL for the R2 endpoint. key embeds the event
// object: tenant/postID/random.
func (m *Media) Presign(tenantID, postID uuid.UUID, slug, filename string, now time.Time) (PresignedUpload, error) {
	ext := extFromName(filename)
	if ext == "" {
		return PresignedUpload{}, fmt.Errorf("media: filename %q has no allowed extension", filename)
	}
	objID, err := uuid.NewV7() // app-minted v7: key known BEFORE the row exists
	if err != nil {
		return PresignedUpload{}, fmt.Errorf("media: mint key id: %w", err)
	}
	key := fmt.Sprintf("%s/posts/%s/%s%s", slug, postID, objID, ext)
	expiresAt := now.Add(m.cfg.PresignExpiry)

	u, err := PresignPutURL(m.cfg.Endpoint, m.cfg.Bucket, key,
		m.cfg.AccessKeyID, m.cfg.SecretAccessKey, now, m.cfg.PresignExpiry)
	if err != nil {
		return PresignedUpload{}, fmt.Errorf("media: presign: %w", err)
	}
	return PresignedUpload{URL: u, Key: key, ExpiresAt: expiresAt}, nil
}

// Confirm validates mime+size, inserts the post_images row, and enqueues the
// variants job IN THE SAME TX (q) — a commit carries both, a rollback takes
// both (008 sweep: enqueue-in-tx). Idempotent by construction: the
// unique(tenant_id, r2_key) index makes a double-confirm a 0-row ON CONFLICT
// DO NOTHING, which reports inserted=false (the 204 the handler maps). The
// composite FK (tenant_id, post_id) → posts(tenant_id, id) rejects attaching
// to another tenant's post even with a compromised presign. Width/height are
// placeholders (decode is server-side, in the worker); the worker fills them.
func (m *Media) Confirm(ctx context.Context, q *store.Queries, tenantID, postID uuid.UUID, key string, sizeBytes int64, mimeType string) (bool, error) {
	if !allowedMimes[mimeType] {
		return false, ErrInvalidMime
	}
	if sizeBytes > maxImageSize {
		return false, ErrPayloadTooLarge
	}

	id, err := uuid.NewV7()
	if err != nil {
		return false, fmt.Errorf("media: confirm: %w", err)
	}
	url := m.cfg.CDNBase + "/" + key
	n, err := q.InsertPostImageOnConflict(ctx, id, tenantID, postID, key, url, mimeType, sizeBytes)
	if err != nil {
		return false, fmt.Errorf("media: confirm: %w", err)
	}
	if n == 0 {
		return false, nil // duplicate (tenant_id, r2_key): already confirmed
	}

	payload, err := json.Marshal(VariantPayload{
		TenantID: tenantID,
		ImageID:  id,
		R2Key:    key,
		OrigExt:  extFromName(key),
	})
	if err != nil {
		return false, fmt.Errorf("media: confirm payload: %w", err)
	}
	if _, err := jobs.Enqueue(ctx, q.Tx(), kindVariants, key,
		jobs.JobPayload{TenantID: tenantID, Data: payload}); err != nil {
		return false, fmt.Errorf("media: confirm enqueue: %w", err)
	}
	return true, nil
}

// Delete removes a post_images row under the 005-aligned rule: a plain author
// may only delete an image attached to one of their own posts; editors+ may
// delete any in the tenant. The R2 objects are not touched here — the
// sweeper owns orphan reclamation. The transaction is scoped to the actor so
// RLS constrains visibility to their tenant.
func (m *Media) Delete(ctx context.Context, actor authz.Actor, imageID uuid.UUID) error {
	return m.db.ScopedRW(ctx, authz.ScopeFromActor(actor), func(q *store.Queries) error {
		img, err := q.GetPostImageByID(ctx, imageID)
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrImageNotFound
		}
		if err != nil {
			return err
		}
		// author-own-draft backstop (plan 005): a plain author may only
		// delete an image attached to one of their own posts. RLS has
		// already confined the read to the actor's tenant.
		if !actor.Can(authz.CapEditAnyPost) {
			post, err := q.GetPostByID(ctx, img.PostID)
			if err != nil {
				return err
			}
			if !actor.OwnsPost(post.AuthorID) {
				return ErrForbidden
			}
		}
		return q.DeletePostImage(ctx, imageID)
	})
}

// RegisterVariantsWorker binds the variants handler to w. The handler loads
// the post_image row (authoritative key + tenant), fetches the original from
// R2, derives variants with the processor, PUTs them, and writes the canonical
// post_images.variants back. Any failure returns an error so the queue
// requeues; attempts are capped by jobs.MaxAttempts. A deleted row short-
// circuits: its objects are orphaned and left to the sweeper.
func (m *Media) RegisterVariantsWorker(w *jobs.Worker, r2 *R2Client) {
	w.Register(kindVariants, func(ctx context.Context, p jobs.JobPayload) error {
		var vp VariantPayload
		if err := json.Unmarshal(p.Data, &vp); err != nil {
			return fmt.Errorf("media: variants payload: %w", err)
		}
		var img store.PostImage
		err := m.db.Scoped(ctx, store.Scope{TenantID: p.TenantID}, func(q *store.Queries) error {
			var e error
			img, e = q.GetPostImageByID(ctx, vp.ImageID)
			return e
		})
		if errors.Is(err, pgx.ErrNoRows) {
			return nil
		}
		if err != nil {
			return fmt.Errorf("media: variants load row: %w", err)
		}

		orig, err := r2.Get(ctx, img.R2Key)
		if err != nil {
			return fmt.Errorf("media: variants get original: %w", err)
		}
		processed, err := m.processor.Process(ctx, vp.OrigExt, orig, img.R2Key)
		if err != nil {
			return fmt.Errorf("media: variants process: %w", err)
		}
		for _, v := range processed.Variants {
			if len(v.Data) > 0 {
				if err := r2.Put(ctx, v.Key, v.Data); err != nil {
					return fmt.Errorf("media: variants put %s: %w", v.Key, err)
				}
			}
		}
		return m.writeVariants(ctx, p.TenantID, vp.ImageID, processed, img.R2Key)
	})
}

// writeVariants persists the canonical variants jsonb and backfills the
// server-side width/height from the decode (the entire update is scoped to the
// tenant). A variant with no encoded data is stored as processing:"pending"
// with url pointing at the original — the no-vips fallback's degradation.
func (m *Media) writeVariants(ctx context.Context, tenantID, imageID uuid.UUID, p Processed, originalKey string) error {
	b, err := buildVariantsJSON(p, m.cfg.CDNBase, originalKey)
	if err != nil {
		return err
	}
	return m.db.ScopedRW(ctx, store.Scope{TenantID: tenantID}, func(q *store.Queries) error {
		return q.UpdatePostImageVariants(ctx, imageID, p.OriginalWidth, p.OriginalHeight, b)
	})
}

// buildVariantsJSON renders the canonical variants shape (sweep finding 13):
// {"480":{"url","width","height"},...}, 480/800/1200 ordered by width. An
// encode-less (pending) variant points at the original object.
func buildVariantsJSON(p Processed, cdnBase, originalKey string) ([]byte, error) {
	vj := make(map[string]variantEntry, len(p.Variants))
	for _, v := range p.Variants {
		e := variantEntry{Width: v.Width, Height: v.Height}
		if len(v.Data) > 0 {
			e.URL = cdnBase + "/" + v.Key
		} else {
			e.URL = cdnBase + "/" + originalKey
			e.Processing = "pending"
		}
		vj[v.Label] = e
	}
	return json.Marshal(vj)
}

// extFromName returns the lowercased allow-listed extension from a filename
// or R2 key, or "" when absent/not allow-listed.
func extFromName(name string) string {
	ext := strings.ToLower(filepath.Ext(name))
	switch ext {
	case ".jpg", ".jpeg":
		return ".jpg"
	case ".png", ".webp", ".gif", ".avif":
		return ext
	}
	return ""
}
