package tenancy

import "testing"

func TestValidSlug(t *testing.T) {
	cases := []struct {
		slug string
		want bool
	}{
		{"a", true},
		{"alpha", true},
		{"tenant-a", true},
		{"a1b2c3", true},
		{"1a-2b", true},
		{"0", true},
		{"a" + repeat(61), true}, // total 62 chars (within 63 limit)
		{"a" + repeat(62), true}, // total 63 chars (max)
		{"", false},
		{"A", false},              // uppercase
		{"alpha-beta_", false},    // underscore
		{"-a", false},             // leading hyphen
		{"a-", false},             // trailing hyphen
		{"a/b", false},            // slash
		{"a.b", false},            // dot
		{"a" + repeat(63), false}, // total 64 chars (too long)
		{" ", false},
		{"alpha beta", false},
		{"привет", false},
	}
	for _, tc := range cases {
		got := ValidSlug(tc.slug)
		if got != tc.want {
			t.Errorf("ValidSlug(%q) = %v, want %v", tc.slug, got, tc.want)
		}
	}
}

func repeat(n int) string {
	b := make([]byte, n)
	for i := range b {
		b[i] = 'a'
	}
	return string(b)
}
