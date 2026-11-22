package fastpath

import (
	"reflect"
	"testing"
)

func TestLocalTargetPaths(t *testing.T) {
	for _, tc := range []struct {
		target string
		want   []string
		ok     bool
	}{
		{"readme.md", []string{"readme.md"}, true},
		{`d\readme.md`, []string{`d\readme.md`}, true},
		{"readme.md\u0085", nil, false},
		{"readme.md\u00a0", nil, false},
		{" readme.md", nil, false},
		{"readme.md\n", nil, false},
		{"https://example.com/a b", []string{"https://example.com/a b"}, true},
		{"file:///ws/plain.txt", []string{"/ws/plain.txt"}, true},
		{"file://localhost/ws/plain.txt", []string{"/ws/plain.txt"}, true},
		{"FILE://LocalHost/ws/plain.txt", []string{"/ws/plain.txt"}, true},
		{"file:///C:/ws/plain.txt", []string{"C:/ws/plain.txt"}, true},
		{"file://localhost/c:/ws/plain.txt", []string{"c:/ws/plain.txt"}, true},
		{"file:///ws/%2e%2e/etc/passwd", []string{"/ws/../etc/passwd", "/ws/%2e%2e/etc/passwd"}, true},
		{"file:///ws/%2eenv", []string{"/ws/.env", "/ws/%2eenv"}, true},
		{"file:///ws/a%20b", []string{"/ws/a b", "/ws/a%20b"}, true},
		{"file://otherhost/x", nil, false},
		{"file://server/share/x", nil, false},
		{"file://C:/ws/x", nil, false},
		{"file://localhost:80/x", nil, false},
		{"file://u@localhost/x", nil, false},
		{"file:///x?y", nil, false},
		{"file:///x#y", nil, false},
		{"file:///x%00", nil, false},
		{"file:///x%zz", nil, false},
		{"file://", nil, false},
		{" file:///x", nil, false},
	} {
		got, ok := LocalTargetPaths(tc.target)
		if ok != tc.ok || !reflect.DeepEqual(got, tc.want) {
			t.Errorf("LocalTargetPaths(%q) = %q, %v; want %q, %v", tc.target, got, ok, tc.want, tc.ok)
		}
	}
}
