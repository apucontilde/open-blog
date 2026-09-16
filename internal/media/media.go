// Package media owns image presign/confirm/delete and the variants worker;
// image bytes go client → R2, never through the API.
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

// Config holds R2 presign settings, supplied from env.
type Config struct {
	Endpoint        string
	Bucket          string
	AccessKeyID     string
	SecretAccessKey string
	PresignExpiry   time.Duration // 0 => defaultExpiry
	CDNBase         string
}

type Media struct {
	cfg       Config
	db        *store.DB
	processor VariantProcessor
}

// New builds a Media; a nil processor falls back to the no-vips one.
func New(cfg Config, db *store.DB, processor VariantProcessor) *Media {
	if cfg.PresignExpiry == 0 {
		cfg.PresignExpiry = defaultExpiry
	}
	if processor == nil {
		processor = NewNoopProcessor()
	}
	return &Media{cfg: cfg, db: db, processor: processor}
}

// PresignedUpload is Presign's result: the PUT URL, the R2 key it is bound to,
// and when the URL expires.
type PresignedUpload struct {
	URL       string
	Key       string
	ExpiresAt time.Time
}

// VariantPayload carries row coordinates for the variants job; the worker reads
// the object from R2, not the payload.
type VariantPayload struct {
	TenantID uuid.UUID `json:"tenant_id"`
	ImageID  uuid.UUID `json:"image_id"`
	R2Key    string    `json:"r2_key"`
}

// variantEntry is one post_images.variants entry. Canonical shape:
// {"480":{url,width,height},...} — 009 builds srcset from width/url and never
// reads a "srcset" key. "pending" only appears in the no-vips fallback.
type variantEntry struct {
	URL        string `json:"url"`
	Width      int    `json:"width"`
	Height     int    `json:"height"`
	Processing string `json:"processing,omitempty"`
}

// Presign mints a uuid v7 R2 key app-side (known before the row exists), pinned
// to the active tenant, and returns its SigV4 presigned PUT URL.
func (m *Media) Presign(tenantID, postID uuid.UUID, filename string, now time.Time) (PresignedUpload, error) {
	ext := extFromName(filename)
	if ext == "" {
		return PresignedUpload{}, fmt.Errorf("media: filename %q has no allowed extension", filename)
	}
	objID, err := uuid.NewV7()
	if err != nil {
		return PresignedUpload{}, fmt.Errorf("media: mint key id: %w", err)
	}
	key := fmt.Sprintf("%s/posts/%s/%s%s", tenantID, postID, objID, ext)
	expiresAt := now.Add(m.cfg.PresignExpiry)

	u, err := PresignPutURL(m.cfg.Endpoint, m.cfg.Bucket, key,
		m.cfg.AccessKeyID, m.cfg.SecretAccessKey, now, m.cfg.PresignExpiry)
	if err != nil {
		return PresignedUpload{}, fmt.Errorf("media: presign: %w", err)
	}
	return PresignedUpload{URL: u, Key: key, ExpiresAt: expiresAt}, nil
}

// Confirm validates mime/size, inserts the row and enqueues the variants job in
// the same tx. Idempotent: unique(tenant_id, r2_key) + ON CONFLICT DO NOTHING
// makes a double-confirm a no-op (inserted=false). The composite FK
// (tenant_id, post_id) rejects cross-tenant attaches even with a forged presign.
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
		return false, nil // duplicate (tenant_id, r2_key)
	}

	payload, err := json.Marshal(VariantPayload{
		TenantID: tenantID,
		ImageID:  id,
		R2Key:    key,
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

// Delete enforces the 005 rule: a plain author may delete only an image on their
// own post; editors+ any in the tenant. R2 objects are the sweeper's.
func (m *Media) Delete(ctx context.Context, actor authz.Actor, imageID uuid.UUID) error {
	return m.db.ScopedRW(ctx, authz.ScopeFromActor(actor), func(q *store.Queries) error {
		img, err := q.GetPostImageByID(ctx, imageID)
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrImageNotFound
		}
		if err != nil {
			return err
		}
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

// RegisterVariantsWorker runs the variants job: the worker trusts the loaded DB
// row (authoritative tenant/key), not the payload, then fetches/derives/PUTs
// variants and writes them back. Failures requeue; a deleted row is skipped and
// its objects left to the sweeper.
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
		processed, err := m.processor.Process(ctx, extFromName(img.R2Key), orig, img.R2Key)
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
// server-side width/height from the decode.
func (m *Media) writeVariants(ctx context.Context, tenantID, imageID uuid.UUID, p Processed, originalKey string) error {
	b, err := buildVariantsJSON(p, m.cfg.CDNBase, originalKey)
	if err != nil {
		return err
	}
	return m.db.ScopedRW(ctx, store.Scope{TenantID: tenantID}, func(q *store.Queries) error {
		return q.UpdatePostImageVariants(ctx, imageID, p.OriginalWidth, p.OriginalHeight, b)
	})
}

// buildVariantsJSON renders {"480":{url,width,height},...}; a data-less variant
// points at the original and is marked processing:"pending" (no-vips fallback).
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

// extFromName returns the lowercased allow-listed extension from a filename or
// R2 key, or "".
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
