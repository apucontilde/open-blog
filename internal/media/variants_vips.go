//go:build vips

// The govips/libvips processor. Build with -tags vips when libvips dev libs
// are installed (pkg-config --exists vips). Worker-only by construction (job
// queue never runs a request goroutine); concurrency is capped by a semaphore
// so libvips memory stays bounded across concurrent variant jobs.
package media

import (
	"context"
	"strconv"
	"strings"

	"github.com/davidbyttow/govips/v2/vips"
)

func init() {
	if err := vips.Startup(nil); err != nil {
		panic("media: vips.Startup: " + err.Error())
	}
}

// vipsConcurrency caps concurrent libvips encode/decode (plan 006: 2–4).
const vipsConcurrency = 2

var vipsSem = make(chan struct{}, vipsConcurrency)

// vipsProcessor is the cgo VariantProcessor. Decode happens through libvips:
// animated GIFs load their first page only (ImportParams{Page:0,NumPages:1})
// and AVIF decodes via the libvips heif loader.
type vipsProcessor struct{}

// NewVipsProcessor returns the libvips-backed processor. Callers running a
// variant job queue should share one instance.
func NewVipsProcessor() VariantProcessor { return vipsProcessor{} }

func (vipsProcessor) Process(ctx context.Context, _ string, original []byte, originalKey string) (Processed, error) {
	select {
	case vipsSem <- struct{}{}:
		defer func() { <-vipsSem }()
	case <-ctx.Done():
		return Processed{}, ctx.Err()
	}

	img, err := vips.LoadImageFromBuffer(original, &vips.ImportParams{Page: 0, NumPages: 1})
	if err != nil {
		return Processed{}, err
	}
	defer img.Close()

	p := Processed{OriginalWidth: img.Width(), OriginalHeight: img.Height()}
	base := strings.TrimSuffix(originalKey, extFromName(originalKey))
	for _, size := range variantSizes {
		resized, err := img.Thumbnail(size, 0, vips.InterestingNone)
		if err != nil {
			return Processed{}, err
		}
		data, _, err := resized.ExportWebp(&vips.WebpExportParams{Quality: 80})
		vw, vh := resized.Width(), resized.Height()
		resized.Close()
		if err != nil {
			return Processed{}, err
		}
		label := strconv.Itoa(size)
		p.Variants = append(p.Variants, Result{
			Label:  label,
			Key:    base + "-" + label + ".webp",
			Data:   data,
			Width:  vw,
			Height: vh,
		})
	}
	return p, nil
}
