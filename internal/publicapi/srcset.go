package publicapi

import (
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"
)

// variantEnt mirrors one canonical post_images.variants entry (006); srcset is built in Go, never read from JSON.
type variantEnt struct {
	URL    string `json:"url"`
	Width  int    `json:"width"`
	Height int    `json:"height"`
}

type imageItem struct {
	URL    string   `json:"url"`
	Width  int      `json:"width"`
	Height int      `json:"height"`
	Srcset []string `json:"srcset,omitempty"`
}

// imageFromVariants builds an image from one variants jsonb: labels sort ascending (url tiebreak),
// non-numeric or URL-less entries are skipped, and an absent/empty object yields no image.
func imageFromVariants(raw []byte, mediaOrigin string) (imageItem, bool) {
	var m map[string]variantEnt
	if len(raw) == 0 || json.Unmarshal(raw, &m) != nil || len(m) == 0 {
		return imageItem{}, false
	}
	type kv struct {
		width int
		e     variantEnt
	}
	pairs := make([]kv, 0, len(m))
	for label, e := range m {
		w, err := strconv.Atoi(label)
		if err != nil || e.URL == "" {
			continue
		}
		if e.Width > 0 {
			w = e.Width
		}
		pairs = append(pairs, kv{width: w, e: e})
	}
	if len(pairs) == 0 {
		return imageItem{}, false
	}
	sort.Slice(pairs, func(i, j int) bool {
		if pairs[i].width != pairs[j].width {
			return pairs[i].width < pairs[j].width
		}
		return pairs[i].e.URL < pairs[j].e.URL
	})
	srcset := make([]string, 0, len(pairs))
	for _, p := range pairs {
		srcset = append(srcset, fmt.Sprintf("%s %dw", resolveURL(p.e.URL, mediaOrigin), p.width))
	}
	primary := pairs[len(pairs)-1]
	return imageItem{
		URL:    resolveURL(primary.e.URL, mediaOrigin),
		Width:  primary.width,
		Height: primary.e.Height,
		Srcset: srcset,
	}, true
}

func resolveURL(u, mediaOrigin string) string {
	if (u == "" || strings.HasPrefix(u, "/")) && mediaOrigin != "" {
		return mediaOrigin + "/" + strings.TrimLeft(u, "/")
	}
	return u
}
