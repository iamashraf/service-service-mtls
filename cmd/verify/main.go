// verify runs the five demo scenarios against the live servers and prints a table.
package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	"mtlsdemo/internal/jwt"
	"mtlsdemo/internal/pki"
)

const (
	authURL = "https://auth.demo:8443/token"
	apiURL  = "https://api.demo:8443/data"
)

// classify turns a response or transport error into the "actual" column.
func classify(status int, err error, body []byte) string {
	if err != nil {
		return "tls rejected: " + err.Error()
	}
	if status == 200 {
		return "200 ok"
	}
	var e struct {
		Error string `json:"error"`
	}
	_ = json.Unmarshal(body, &e)
	return fmt.Sprintf("%d %s", status, e.Error)
}

func clientFor(dir, name, server string) *http.Client {
	cfg, err := pki.LoadClientTLS(dir, name, server)
	if err != nil {
		fmt.Println("load", name, err)
		os.Exit(2)
	}
	return &http.Client{Transport: &http.Transport{TLSClientConfig: cfg}, Timeout: 5 * time.Second}
}

// do sends the request, retrying connection refused while the servers start.
func do(c *http.Client, req *http.Request) (int, []byte, error) {
	var err error
	for i := 0; i < 20; i++ {
		var resp *http.Response
		resp, err = c.Do(req)
		if err == nil {
			defer resp.Body.Close()
			b, _ := io.ReadAll(resp.Body)
			return resp.StatusCode, b, nil
		}
		if !strings.Contains(err.Error(), "refused") && !strings.Contains(err.Error(), "no such host") {
			return 0, nil, err
		}
		time.Sleep(250 * time.Millisecond)
	}
	return 0, nil, err
}

func getToken(c *http.Client) (string, error) {
	req, _ := http.NewRequest("POST", authURL, nil)
	st, b, err := do(c, req)
	if err != nil || st != 200 {
		return "", fmt.Errorf("token request: status %d err %v body %s", st, err, b)
	}
	var t struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.Unmarshal(b, &t); err != nil {
		return "", err
	}
	return t.AccessToken, nil
}

func call(c *http.Client, tok string) string {
	req, _ := http.NewRequest("GET", apiURL, nil)
	if tok != "" {
		req.Header.Set("Authorization", "Bearer "+tok)
	}
	st, b, err := do(c, req)
	return classify(st, err, b)
}

func main() {
	dir := os.Getenv("CERTS_DIR")
	if dir == "" {
		dir = "/certs"
	}
	a := clientFor(dir, "client-a", "api.demo")
	aAuth := clientFor(dir, "client-a", "auth.demo")
	b := clientFor(dir, "client-b", "api.demo")
	expired := clientFor(dir, "client-expired", "api.demo")
	rogue := clientFor(dir, "client-rogue", "api.demo")

	tok, err := getToken(aAuth)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	key, err := pki.LoadSigningKey(dir)
	if err != nil {
		fmt.Println(err)
		os.Exit(2)
	}
	unbound, err := jwt.Sign(jwt.Claims{Iss: "https://auth.demo", Sub: "client-a", Aud: "api.demo", Exp: time.Now().Unix() + 300}, key)
	if err != nil {
		fmt.Println(err)
		os.Exit(2)
	}

	rows := []struct{ name, expected, actual string }{
		{"1 client-a, own token", "200 ok", call(a, tok)},
		{"2 client-b replays token", "401 thumbprint_mismatch", call(b, tok)},
		{"3 token without cnf", "401 no_cnf", call(a, unbound)},
		{"4 expired client cert", "tls rejected", call(expired, tok)},
		{"5 rogue-CA client cert", "tls rejected", call(rogue, tok)},
	}
	w := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
	fmt.Fprintln(w, "SCENARIO\tEXPECTED\tMATCH\tACTUAL (incl. server reason)")
	fail := false
	for _, r := range rows {
		ok := strings.HasPrefix(r.actual, r.expected)
		if !ok {
			fail = true
		}
		fmt.Fprintf(w, "%s\t%s\t%v\t%s\n", r.name, r.expected, ok, r.actual)
	}
	w.Flush()
	if fail {
		os.Exit(1)
	}
}
