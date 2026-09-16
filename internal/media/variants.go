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

// Result is one derived variant ready to PUT. Nil Data means the processor
// degraded: the worker records it processing:"pending" and skips the PUT rather
// than writing a mislabeled object.
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

// VariantProcessor derives the 480/800/1200 WebP set. The govips impl is behind
// //go:build vips; the default build uses the no-vips fallback so the module
// always compiles.
type VariantProcessor interface {
	// Process: ext is the normalized original extension; originalKey anchors
	// variant keys as base minus ext + "-{label}.webp".
	Process(ctx context.Context, ext string, original []byte, originalKey string) (Processed, error)
}

// ResizeVariants derives the variant blobs for sizes; the no-vips build yields
// empty data.
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

// noopProcessor is the no-vips fallback: derive keys, read header dims where
// stdlib can, and mark every variant pending.
type noopProcessor struct{}

// NewNoopProcessor returns the encode-less processor used without the vips tag.
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

// decodeSize reads header dims via stdlib (png/jpeg/gif; webp/avif -> 0,0).
func decodeSize(b []byte) (int, int) {
	cfg, _, err := image.DecodeConfig(bytes.NewReader(b))
	if err != nil {
		return 0, 0
	}
	return cfg.Width, cfg.Height
}
