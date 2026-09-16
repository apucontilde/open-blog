package publicapi

import (
	"reflect"
	"testing"
)

func TestImageFromVariantsSorted(t *testing.T) {
	// Keys are deliberately out of order; the builder must sort deterministically.
	raw := []byte(`{
		"1200": {"url":"https://m.example/a-1200.webp","width":1200,"height":600},
		"480":  {"url":"https://m.example/a-480.webp","width":480,"height":240},
		"800":  {"url":"https://m.example/a-800.webp","width":800,"height":400}
	}`)
	img, ok := imageFromVariants(raw, "")
	if !ok {
		t.Fatal("imageFromVariants want ok=true")
	}
	wantSrcset := []string{
		"https://m.example/a-480.webp 480w",
		"https://m.example/a-800.webp 800w",
		"https://m.example/a-1200.webp 1200w",
	}
	if !reflect.DeepEqual(img.Srcset, wantSrcset) {
		t.Fatalf("srcset = %v, want %v", img.Srcset, wantSrcset)
	}
	if img.URL != "https://m.example/a-1200.webp" || img.Width != 1200 || img.Height != 600 {
		t.Fatalf("primary = %+v, want 1200x600 from 1200.webp", img)
	}
}

func TestImageFromVariantsDeterministicAcrossKeyOrder(t *testing.T) {
	raw1 := []byte(`{"480":{"url":"u4","width":480,"height":1},"1200":{"url":"u12","width":1200,"height":2},"800":{"url":"u8","width":800,"height":3}}`)
	raw2 := []byte(`{"1200":{"url":"u12","width":1200,"height":2},"800":{"url":"u8","width":800,"height":3},"480":{"url":"u4","width":480,"height":1}}`)
	img1, ok1 := imageFromVariants(raw1, "")
	img2, ok2 := imageFromVariants(raw2, "")
	if !ok1 || !ok2 {
		t.Fatal("both should be ok")
	}
	if img1.URL != img2.URL || img1.Width != img2.Width || img1.Height != img2.Height {
		t.Fatalf("primary mismatch: %+v vs %+v", img1, img2)
	}
	if !reflect.DeepEqual(img1.Srcset, img2.Srcset) {
		t.Fatalf("srcset order not deterministic:\n  %v\n  %v", img1.Srcset, img2.Srcset)
	}
}

func TestImageFromVariantsMissingKeyTolerated(t *testing.T) {
	raw := []byte(`{"480":{"url":"u4","width":480,"height":240},"1200":{"url":"u12","width":1200,"height":600}}`)
	img, ok := imageFromVariants(raw, "")
	if !ok {
		t.Fatal("want ok=true")
	}
	if len(img.Srcset) != 2 {
		t.Fatalf("srcset len = %d, want 2 (480 and 1200, no 800)", len(img.Srcset))
	}
	if img.URL != "u12" {
		t.Fatalf("primary = %q", img.URL)
	}
}

func TestImageFromVariantsNonNumericLabelSkipped(t *testing.T) {
	raw := []byte(`{"full":{"url":"https://raw","width":2000,"height":1000},"480":{"url":"https://u4","width":480,"height":240}}`)
	img, ok := imageFromVariants(raw, "")
	if !ok {
		t.Fatal("want ok=true")
	}
	if len(img.Srcset) != 1 {
		t.Fatalf("srcset len = %d, want 1 (480 only)", len(img.Srcset))
	}
	if img.Srcset[0] != "https://u4 480w" {
		t.Fatalf("srcset[0] = %q", img.Srcset[0])
	}
	if img.URL != "https://u4" {
		t.Fatalf("primary = %q", img.URL)
	}
}

func TestImageFromVariantsEmptyJsonSkipped(t *testing.T) {
	if _, ok := imageFromVariants([]byte(`{}`), ""); ok {
		t.Fatal("empty variants must not yield an image")
	}
	if _, ok := imageFromVariants(nil, ""); ok {
		t.Fatal("nil raw must not yield an image")
	}
	if _, ok := imageFromVariants([]byte(`[]`), ""); ok {
		t.Fatal("array (not object) must not yield an image")
	}
	if _, ok := imageFromVariants([]byte(`{bad json`), ""); ok {
		t.Fatal("invalid json must not yield an image")
	}
}

func TestImageFromVariantsRelativeUrlResolved(t *testing.T) {
	raw := []byte(`{"480":{"url":"/media/hero.webp","width":480,"height":270}}`)
	img, ok := imageFromVariants(raw, "https://cdn.example.com")
	if !ok {
		t.Fatal("want ok=true")
	}
	if img.URL != "https://cdn.example.com/media/hero.webp" {
		t.Fatalf("url = %q, want absolute", img.URL)
	}
	if img.Srcset[0] != "https://cdn.example.com/media/hero.webp 480w" {
		t.Fatalf("srcset = %q", img.Srcset[0])
	}
}
