package main

import "testing"

func TestParseAuditArgs(t *testing.T) {
	tests := []struct {
		args    []string
		want    string
		wantErr bool
	}{
		{[]string{"verify"}, "HEAD", false},
		{[]string{"verify", "abc123"}, "abc123", false},
		{nil, "", true},
		{[]string{"bogus"}, "", true},
		{[]string{"verify", "a", "b"}, "", true},
		{[]string{"verify", "--flag"}, "", true},
	}
	for _, tc := range tests {
		got, err := parseAuditArgs(tc.args)
		if (err != nil) != tc.wantErr || got != tc.want {
			t.Errorf("parseAuditArgs(%v) = %q, %v", tc.args, got, err)
		}
	}
}
