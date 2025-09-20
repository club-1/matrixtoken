// matrixtoken, tool to let users generate Matrix registration tokens
//
// Copyright (C) 2025  Nicolas Peugnet <nicolas@club1.fr>
//
// This program is free software; you can redistribute it and/or
// modify it under the terms of the GNU General Public License
// as published by the Free Software Foundation; either version 2
// of the License, or (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program; if not, see <https://www.gnu.org/licenses/>.

package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"
)

func setup(t *testing.T, config string) (stdout *os.File) {
	tmp := t.TempDir()

	// setup stdout
	stdoutPath := filepath.Join(tmp, "stdout")
	stdoutWriter, err := os.Create(stdoutPath)
	if err != nil {
		t.Fatal(err)
	}
	prevStdout := os.Stdout
	os.Stdout = stdoutWriter
	t.Cleanup(func() { os.Stdout = prevStdout })
	stdout, err = os.Open(stdoutPath)
	if err != nil {
		t.Fatal(err)
	}

	// setup config file
	configPath := filepath.Join(tmp, "matrixtoken.conf")
	err = os.WriteFile(configPath, []byte(config), 0664)
	if err != nil {
		t.Fatal(err)
	}
	os.Args = []string{"matrixtoken", "-c", configPath}

	// save default conf
	prevConf := conf
	t.Cleanup(func() { conf = prevConf })

	return stdout
}

func mustReadAll(t *testing.T, r io.Reader) []byte {
	buf, err := io.ReadAll(r)
	if err != nil {
		t.Fatal("error reading all: ", err)
	}
	return buf
}

func TestMain(t *testing.T) {
	adminToken := "syt_AjfVef2_L33JNpafeif_0feKJfeaf0CQpoZk"
	expected := "testtoken"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		agent := r.Header.Get("User-Agent")
		expectedAgent := "matrixtoken/" + version
		if agent != expectedAgent {
			t.Errorf("expected User-Agent header %q, got %q", expectedAgent, agent)
		}

		auth := r.Header.Get("Authorization")
		expectedAuth := "Bearer " + adminToken
		if auth != expectedAuth {
			t.Errorf("expected Authorization header %q, got %q", expectedAuth, auth)
		}

		path := r.URL.Path
		expectedPath := "/_synapse/admin/v1/registration_tokens/new"
		if path != expectedPath {
			t.Errorf("expected path %q, got %q", expectedPath, path)
		}

		var token Token
		if err := json.NewDecoder(r.Body).Decode(&token); err != nil {
			t.Error("unexpected error decoding body: ", err)
		}
		expectedUses := 3
		if token.UsesAllowed != expectedUses {
			t.Errorf("expected UsesAllowed %d, got %d", expectedUses, token.UsesAllowed)
		}
		expectedDate := time.Now().AddDate(0, 0, 15)
		date := time.UnixMilli(token.ExpiryTime)
		minutes := expectedDate.Sub(date).Minutes()
		if minutes > 1 || minutes < -1 {
			t.Errorf("expected ExpiryTime around 1 minute of %v, got %v", expectedDate, date)
		}

		token = Token{
			Token: expected,
		}
		if err := json.NewEncoder(w).Encode(&token); err != nil {
			t.Error("encode response: ", err)
		}
	}))
	defer server.Close()

	config := fmt.Sprintf(`
AdminToken = %q
ServerBaseURL = %q
ServerSoftware = "synapse"
UsesAllowed = 3
ExpiryDays = 15
`,
		adminToken,
		server.URL,
	)

	stdout := setup(t, config)
	main()
	buf := mustReadAll(t, stdout)
	actual := string(bytes.TrimSpace(buf))
	if actual != expected {
		t.Errorf("expected: %q, got: %q", expected, actual)
	}
}

type TestRequestsCase struct {
	name          string
	config        string
	expectedToken string
}

func TestRequests(t *testing.T) {
	cases := []TestRequestsCase{
		{
			name:          "style server",
			config:        `TokenStyle = "server"`,
			expectedToken: `^$`,
		},
		{
			name:          "style rfc1751",
			config:        `TokenStyle = "rfc1751"`,
			expectedToken: `^[a-z]+-[a-z]+-[a-z]+-[a-z]+-[a-z]+-[a-z]+$`,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			subTestRequests(t, tc)
		})
	}
}

func subTestRequests(t *testing.T, tc TestRequestsCase) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var token Token
		if err := json.NewDecoder(r.Body).Decode(&token); err != nil {
			t.Error("unexpected error decoding body: ", err)
		}
		if tc.expectedToken != "" {
			ok, _ := regexp.MatchString(tc.expectedToken, token.Token)
			if !ok {
				t.Errorf("expected token to match %q, got %q", tc.expectedToken, token.Token)
			}
		}
		if err := json.NewEncoder(w).Encode(&token); err != nil {
			t.Error("encode response: ", err)
		}
	}))
	config := fmt.Sprintf("ServerBaseURL = %q\n"+tc.config, server.URL)
	defer server.Close()
	setup(t, config)
	main()
}

func TestJSON(t *testing.T) {
	expected := `{"token":"ZsaQ","uses_allowed":1,"expiry_time":1760729693138}`
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(expected))
	}))
	config := fmt.Sprintf("ServerBaseURL = %q", server.URL)
	defer server.Close()
	stdout := setup(t, config)
	os.Args = append(os.Args, "--json")
	main()
	buf := mustReadAll(t, stdout)
	actual := string(bytes.TrimSpace(buf))
	if actual != expected {
		t.Errorf("expected: %q, got: %q", expected, actual)
	}
}

func TestUnixSocket(t *testing.T) {
	tmp := t.TempDir()
	socketPath := tmp + "/synapse_admin.sock"
	expected := "testtoken"

	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatal("unexpected error: ", err)
	}
	defer listener.Close()
	server := http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			token := Token{
				Token: expected,
			}
			if err := json.NewEncoder(w).Encode(&token); err != nil {
				t.Error("encode response: ", err)
			}
		}),
	}
	go server.Serve(listener)
	defer server.Close()

	config := fmt.Sprintf(`
AdminToken = "syt_AjfVef2_L33JNpafeif_0feKJfeaf0CQpoZk"
ServerBaseURL = "http+unix://%s"
ServerSoftware = "synapse"
UsesAllowed = 3
ExpiryDays = 15
`, socketPath)

	stdout := setup(t, config)
	main()
	buf := mustReadAll(t, stdout)
	actual := string(bytes.TrimSpace(buf))
	if actual != expected {
		t.Errorf("expected: %q, got: %q", expected, actual)
	}
}

func TestGenerateErrors(t *testing.T) {
	var cases = []struct {
		name   string
		url    string
		status int
		res    string
		err    string
	}{
		{
			name: "invalid port",
			url:  "http://localhost:100000/",
			err:  "post request: ",
		},
		{
			name: "missing scheme",
			url:  "localhost:8008",
			err:  `post request: base URL "localhost:8008": scheme not found`,
		},
		{
			name: "invalid url syntax",
			url:  "http://invalid\\url/",
			err:  "post request: create request: ",
		},
		{
			name:   "error status",
			status: 502,
			err:    "response status: 502",
		},
		{
			name:   "empty response",
			status: 200,
			res:    "",
			err:    "decode response: EOF",
		},
		{
			name:   "invalid json response",
			status: 200,
			res:    "[]",
			err:    "decode response: json: ",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			prev := conf
			t.Cleanup(func() { conf = prev })
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(c.status)
				w.Write([]byte(c.res))
			}))
			defer server.Close()

			if c.url != "" {
				conf.ServerBaseURL = c.url
			} else {
				conf.ServerBaseURL = server.URL
			}

			err := generate(false)

			if err == nil {
				t.Fatal("expected an error, got nil")
			}
			if !strings.HasPrefix(err.Error(), c.err) {
				t.Errorf("expected prefix:\n%s\ngot:\n%v", c.err, err)
			}
		})
	}
}

func TestHelp(t *testing.T) {
	stdout := setup(t, "")
	os.Args = append(os.Args, "--help")
	expected := []byte("Usage: matrixtoken [OPTION]...")
	main()
	buf := mustReadAll(t, stdout)
	if !bytes.Contains(buf, expected) {
		t.Errorf("expected stdout to conatin: %s\ngot:\n%s", expected, buf)
	}
}

func TestVersion(t *testing.T) {
	stdout := setup(t, "")
	os.Args = append(os.Args, "--version")
	main()
	buf := mustReadAll(t, stdout)
	if !bytes.Contains(buf, []byte(version)) {
		t.Errorf("expected stdout to contain: %s\ngot:\n%s", version, buf)
	}
}
