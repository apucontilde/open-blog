package publicapi

import (
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"
)

// variantEnt mirrors one entry of the canonical post_images.variants shape
// (006, sweep finding 13): {"480":{"url","width","height"},...}. Only the
// width/url pair is consumed here (009 builds srcset in Go, never ->'srcset');
// extra fields such as processing are ignored.
type variantEnt struct {
	URL    string `json:"url"`
	Width  int    `json:"width"`
	Height int    `json:"height"`
}

// imageItem is one post image in List/Get responses: the primary url (the
// largest recorded variant) with its dimensions plus the responsive srcset
// derived from the canonical variants, ascending by width.
type imageItem struct {
	URL    string   `json:"url"`
	Width  int      `json:"width"`
	Height int      `json:"height"`
	Srcset []string `json:"srcset,omitempty"`
}

// imageFromVariants builds an imageItem from one post_images.variants jsonb.
// Deterministic by construction: label widths sort ascending with a url
// tiebreak, independent of the JSON key order. Non-numeric or url-less
// entries are skipped (missing-key tolerated); an absent, empty or unparsable
// variants object yields no image. mediaOrigin is the fallback base for a
// relative/empty url — never assumed to exist.
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
		Width:  primary.e.Width,
		Height: primary.e.Height,
		Srcset: srcset,
	}, true
}

// resolveURL returns u as-is when absolute; a relative or empty url is
// prefixed with mediaOrigin when one is configured.
func resolveURL(u, mediaOrigin string) string {
	if (u == "" || strings.HasPrefix(u, "/")) && mediaOrigin != "" {
		return mediaOrigin + "/" + strings.TrimLeft(u, "/")
	}
	return u
}
