package media

import (
	"bytes"
	"context"
	"image"
	_ "image/gif"
	_ "image/jpeg"
	_ "image/png"
	"strconv"
	"strings"
)

// Result is one derived variant object ready to PUT. Data is nil when the
// processor degrades (no encode path available) — the worker then records the
// variant as processing:"pending" and skips the R2 PUT rather than writing a
// mislabeled object.
type Result struct {
	Label  string // canonical srcset label: "480"
	Key    string // full R2 key for the variant object
	Data   []byte
	Width  int
	Height int
}

// Processed is one original decoded into its variant set.
type Processed struct {
	OriginalWidth  int
	OriginalHeight int
	Variants       []Result
}

// VariantProcessor decodes an original and derives the 480/800/1200 WebP
// variant set. The govips/libvips implementation lives behind //go:build vips
// (granted via the cgo branch); the default build carries the no-vips
// fallback so the module always compiles and the pipeline stays testable.
type VariantProcessor interface {
	// Process takes the decoded (or raw, pre-decode) original; ext is the
	// normalized original extension (".jpg", …). originalKey anchors the
	// derived variant keys: base minus ext + "-{size}.webp".
	Process(ctx context.Context, ext string, original []byte, originalKey string) (Processed, error)
}

// ResizeVariants is the plan's worker surface: derive the variant blobs for
// sizes. With the default (no-vips) build every entry's data is zero-length.
func (m *Media) ResizeVariants(ctx context.Context, original []byte, sizes []int) (map[string][]byte, error) {
	p, err := m.processor.Process(ctx, "", original, "")
	if err != nil {
		return nil, err
	}
	out := make(map[string][]byte, len(sizes))
	for _, v := range p.Variants {
		for _, s := range sizes {
			if s == variantWidth(v.Label) {
				out[v.Label] = v.Data
			}
		}
	}
	return out, nil
}

func variantWidth(label string) int {
	w, _ := strconv.Atoi(label)
	return w
}

// noopProcessor is the default VariantProcessor when libvips/govips is not
// available. It cannot resize or encode WebP (that is the exact reason the
// cgo branch exists); it degrades gracefully by deriving the variant object
// keys, reading the original dimensions from the header where stdlib can (png,
// jpeg, gif), and marking every variant processing:"pending" — the worker
// skips the PUTs and stores pending entries whose url points at the original.
type noopProcessor struct{}

// NewNoopProcessor returns the always-available, encode-less processor used
// when the binary is built without the vips tag.
func NewNoopProcessor() VariantProcessor { return noopProcessor{} }

func (noopProcessor) Process(_ context.Context, _ string, original []byte, originalKey string) (Processed, error) {
	w, h := decodeSize(original)
	p := Processed{OriginalWidth: w, OriginalHeight: h}
	base := strings.TrimSuffix(originalKey, extFromName(originalKey))
	for _, size := range variantSizes {
		label := strconv.Itoa(size)
		p.Variants = append(p.Variants, Result{
			Label:  label,
			Key:    base + "-" + label + ".webp",
			Width:  w,
			Height: h,
		})
	}
	return p, nil
}

// decodeSize reads the pixel dimensions from an image header via stdlib
// (png/jpeg/gif; webp/avif have no stdlib decoder → 0,0).
func decodeSize(b []byte) (int, int) {
	cfg, _, err := image.DecodeConfig(bytes.NewReader(b))
	if err != nil {
		return 0, 0
	}
	return cfg.Width, cfg.Height
}
