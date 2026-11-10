package main

import (
	"errors"
	"testing"
)

func TestClassify(t *testing.T) {
	cases := []struct {
		name   string
		status int
		err    error
		body   []byte
		want   string
	}{
		{"ok", 200, nil, []byte(`{"data":1}`), "200 ok"},
		{"rejected", 401, nil, []byte(`{"error":"x"}`), "401 x"},
		{"transport", 0, errors.New("remote error: tls: bad certificate"), nil, "tls rejected: remote error: tls: bad certificate"},
	}
	for _, c := range cases {
		if got := classify(c.status, c.err, c.body); got != c.want {
			t.Errorf("%s: got %q want %q", c.name, got, c.want)
		}
	}
}
