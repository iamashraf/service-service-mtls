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

func TestMatches(t *testing.T) {
	rejected := classify(0, errors.New("remote error: tls: expired certificate"), nil)
	refused := classify(0, errors.New("dial tcp: connection refused"), nil)
	if !matches("expired certificate", rejected) {
		t.Error("tls error should match its text")
	}
	if matches("expired certificate", refused) || matches("certificate required", rejected) {
		t.Error("wrong or unrelated error must not match")
	}
	if matches("401 no_cnf", "401 no_cnf_extra") || !matches("200 ok", "200 ok") {
		t.Error("status rows must match exactly")
	}
}
