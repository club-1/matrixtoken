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

func TestMain(t *testing.T) {
	adminToken := "syt_AjfVef2_L33JNpafeif_0feKJfeaf0CQpoZk"
	expected := "testtoken"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

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
	buf, err := io.ReadAll(stdout)
	if err != nil {
		t.Error("error reading stdout: ", err)
	}
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
	buf, err := io.ReadAll(stdout)
	if err != nil {
		t.Error("error reading stdout: ", err)
	}
	actual := string(bytes.TrimSpace(buf))
	if actual != expected {
		t.Errorf("expected: %q, got: %q", expected, actual)
	}
}
