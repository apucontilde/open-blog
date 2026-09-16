package posts

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRenderGolden(t *testing.T) {
	goldenMD, err := os.ReadFile(filepath.Join("testdata", "golden.md"))
	if err != nil {
		t.Fatal(err)
	}
	want, err := os.ReadFile(filepath.Join("testdata", "golden.html"))
	if err != nil {
		t.Fatal(err)
	}
	got, err := renderGFM(goldenMD)
	if err != nil {
		t.Fatal(err)
	}
	if strings.TrimRight(string(got), "\n") != strings.TrimRight(string(want), "\n") {
		t.Fatalf("golden mismatch:\n--- got ---\n%s\n--- want ---\n%s", got, want)
	}
}

// TestRenderRejectsXSS asserts the sanitizer drops whole elements whose
// payload can't be represented safely: javascript:/data: sources, raw script
// or iframe, and attribute-injected handlers.
func TestRenderRejectsXSS(t *testing.T) {
	cases := []struct {
		name    string
		md      string
		forbid  []string
		require []string
	}{
		{
			name:   "raw script",
			md:     "before <script>alert(1)</script> after",
			forbid: []string{"<script"},
		},
		{
			name:   "raw iframe",
			md:     "<iframe src=\"https://evil.example.com\"></iframe>",
			forbid: []string{"<iframe"},
		},
		{
			name:    "javascript link",
			md:      "[x](javascript:alert(1))",
			require: []string{"<a>x</a>"},
			forbid:  []string{"href"},
		},
		{
			name:    "data link",
			md:      "[x](data:text/html,pwn)",
			require: []string{"<a>x</a>"},
			forbid:  []string{"href"},
		},
		{
			name:   "javascript image",
			md:     "<img src=\"javascript:alert(1)\" onerror=\"bad()\">",
			forbid: []string{"<img"},
		},
		{
			name:   "data image",
			md:     "![x](data:image/png;base64,AAAA)",
			forbid: []string{"<img"},
		},
		{
			name:   "off-origin image",
			md:     "![x](https://evil.example.com/x.png)",
			forbid: []string{"<img"},
		},
		{
			name:   "handler attributes",
			md:     "<div onmouseover=\"evil()\" class=\"ok\" id=\"nope\" title=\"t\">x</div>",
			forbid: []string{"onmouseover", "id="},
		},
		{
			name:    "raw javascript link",
			md:      "<p onclick=\"bad()\">para <b>ok</b></p>",
			forbid:  []string{"onclick"},
			require: []string{"<b>ok</b>"},
		},
		{
			name:    "relative url preserved",
			md:      "[x](/tenant/inner)",
			require: []string{`href="/tenant/inner"`},
		},
		{
			name:    "http url preserved",
			md:      "[x](http://example.com/a?b=c)",
			require: []string{`href="http://example.com/a?b=c"`},
		},
		{
			name:   "evil style",
			md:     "<p style=\"background:url(javascript:x)\">x</p>",
			forbid: []string{"style="},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := renderGFM([]byte(tc.md))
			if err != nil {
				t.Fatal(err)
			}
			out := string(got)
			for _, want := range tc.require {
				if !strings.Contains(out, want) {
					t.Errorf("missing %q in output:\n%s", want, out)
				}
			}
			for _, bad := range tc.forbid {
				if strings.Contains(out, bad) {
					t.Errorf("forbidden %q present in output:\n%s", bad, out)
				}
			}
		})
	}
}

// TestRenderMetadataOptIn exercises the service-level policy knob: the default
// host allow-list rejects off-origin images; the metadata opt-in opens them.
func TestRenderMetadataOptIn(t *testing.T) {
	const md = "![x](https://cdn.other.example/img.png)"
	svc := New(nil, Config{})

	defaultMeta, err := renderGFMHosts([]byte(md), []string{defaultMediaOrigin})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(defaultMeta), "<img") {
		t.Fatalf("off-origin img survived default policy: %s", defaultMeta)
	}

	optIn, err := svc.render([]byte(md), []byte(`{"allow_external_images":true}`))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(optIn), `<img src="https://cdn.other.example/img.png"`) {
		t.Fatalf("opt-in img missing: %s", optIn)
	}

	garbage, err := svc.render([]byte(md), []byte(`not json`))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(garbage), "<img") {
		t.Fatalf("bad metadata must keep default policy: %s", garbage)
	}
}

// TestRenderPathForms asserts valid image path shapes pass so the golden and
// service builds agree on what "media" means.
func TestRenderPathForms(t *testing.T) {
	valid := []string{
		"https://media.example.com/tenant/posts/abc.png",
		"https://media.example.com/tenant/imports/x.png",
		"https://media.example.com/tenant/posts/a/b/c.png",
	}
	for _, src := range valid {
		md := "![x](" + src + ")"
		got, err := renderGFM([]byte(md))
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(got), `src="`+src+`"`) {
			t.Errorf("valid src rejected: %s -> %s", src, got)
		}
	}
}

// TestRenderFixtureSanity covers the shape-check helpers directly so a typo in
// the allowed-url regexes can't silently regress the host allow-list.
func TestRenderFixtureSanity(t *testing.T) {
	if !imageHostAllowed("https://media.example.com/x.png", []string{"media.example.com"}) {
		t.Error("exact host should match")
	}
	if imageHostAllowed("https://media.example.com/x.png", []string{"evil.example.com"}) {
		t.Error("different host should be rejected")
	}
	if !safeLinkURL("/tenant/posts/abc") {
		t.Error("relative link rejected")
	}
	if safeLinkURL("//evil.example.com/x") {
		t.Error("protocol-relative link accepted")
	}
	if !safeStyle("text-align:center") {
		t.Error("table alignment style rejected")
	}
	if safeStyle("background:url(javascript:x)") {
		t.Error("javascript url style accepted")
	}
	if _, ok := allowedTags["script"]; ok {
		t.Error("script must not be allow-listed anywhere")
	}
	if !metadataAllowsExternalImages([]byte(`{"allow_external_images":true}`)) {
		t.Error("opt-in flag not parsed")
	}
	if metadataAllowsExternalImages([]byte(`{"allow_external_images":false}`)) {
		t.Error("opt-out flag must be false")
	}
	if metadataAllowsExternalImages([]byte(`{"other":1}`)) {
		t.Error("missing flag must be false")
	}
}
