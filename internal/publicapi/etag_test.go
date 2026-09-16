package publicapi

import "testing"

func TestETagDeterministic(t *testing.T) {
	a := etag(42, "abc")
	b := etag(42, "abc")
	if a != b {
		t.Fatalf("same inputs yielded different tags: %s vs %s", a, b)
	}
}

func TestETagDifferentInputsYieldDifferentTags(t *testing.T) {
	a := etag(1, 2, "x")
	b := etag(2, 2, "x")
	if a == b {
		t.Fatal("different inputs must yield different tags")
	}
	a2 := etag(1, 2, "x")
	if a != a2 {
		t.Fatal("same input is not stable across calls")
	}
}

func TestETagMatches(t *testing.T) {
	v := etag(1, 2, "test")
	cases := []struct {
		inm, tag string
		want     bool
	}{
		{`"` + v + `"`, v, true},           // quoted, match
		{`W/"` + v + `"`, v, true},         // weak, match
		{`*`, v, true},                     // wildcard (unquoted)
		{`"` + v + `", "zzz"`, v, true},    // list, first matches
		{`"zzz", "` + v + `"`, v, true},    // list, second matches
		{`"zzz"`, v, false},                // no match
		{"", v, false},                     // empty header
		{`"` + etag(99) + `"`, v, false},   // different tag
		{`W/"` + etag(99) + `"`, v, false}, // weak, different
	}
	for _, tc := range cases {
		got := etagMatches(tc.inm, tc.tag)
		if got != tc.want {
			t.Errorf("etagMatches(%q, %q) = %v, want %v", tc.inm, tc.tag, got, tc.want)
		}
	}
}
