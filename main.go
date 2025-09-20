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
	"crypto/rand"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/BurntSushi/toml"
	"github.com/number571/go-rfc1751"
)

type Software string

const (
	softwareDendrite Software = "dendrite"
	softwareSynapse  Software = "synapse"
)

func (s *Software) UnmarshalText(text []byte) error {
	switch Software(text) {
	case softwareDendrite:
		*s = softwareDendrite
	case softwareSynapse:
		*s = softwareSynapse
	default:
		return fmt.Errorf("unknown software: %s", text)
	}
	return nil
}

func (s *Software) RouteNewToken() string {
	switch *s {
	case softwareDendrite:
		return "/_dendrite/admin/registrationTokens/new"
	case softwareSynapse:
		return "/_synapse/admin/v1/registration_tokens/new"
	default:
		panic("unknown software: " + string(*s))
	}
}

type Style string

const (
	styleServer  Style = "server"
	styleRFC1751 Style = "rfc1751"
)

func (s *Style) UnmarshalText(text []byte) error {
	switch Style(text) {
	case styleServer:
		*s = styleServer
	case styleRFC1751:
		*s = styleRFC1751
	default:
		return fmt.Errorf("unknown style: %s", text)
	}
	return nil
}

func (s *Style) Generate(bits uint64) string {
	switch *s {
	case styleServer:
		return ""
	case styleRFC1751:
		token, _ := gorfc1751.NewMnemonic(rand.Reader, bits)
		return strings.ToLower(strings.ReplaceAll(token, " ", "-"))
	default:
		panic("unknown style: " + string(*s))
	}
}

type Conf struct {
	AdminToken     string
	ServerBaseURL  string
	ServerSoftware Software
	UsesAllowed    int
	ExpiryDays     int
	TokenStyle     Style
}

// Default values
var conf = Conf{
	ServerBaseURL:  "http://localhost:8008/",
	ServerSoftware: softwareSynapse,
	UsesAllowed:    1,
	ExpiryDays:     30,
	TokenStyle:     styleServer,
}

// Set by the compiler
var version = "unknown"

var l *log.Logger = log.New(os.Stderr, "", 0)

// UnixTransport is an [http.RoundTripper] that can handle URLs of the form
// http+unix or https+unix, and that connects to a server using UNIX sockets.
type UnixTransport struct {
	t http.Transport
}

func NewUnixTransport(path string) *UnixTransport {
	return &UnixTransport{http.Transport{
		Dial: func(_, _ string) (net.Conn, error) {
			return net.Dial("unix", path)
		},
	}}
}

func (t *UnixTransport) RoundTrip(req *http.Request) (res *http.Response, err error) {
	scheme, _, ok := strings.Cut(req.URL.Scheme, "+")
	if !ok {
		return nil, fmt.Errorf(`scheme does not contain "+": %q`, req.URL.Scheme)
	}
	req.URL.Scheme = scheme
	req.URL.Host = "localhost"
	return t.t.RoundTrip(req)
}

// Token is the structure used for the bodies of both the request and the
// response of the admin API of Matrix servers.
type Token struct {
	Token       string `json:"token,omitempty"`
	UsesAllowed int    `json:"uses_allowed,omitempty"`
	Pending     int    `json:"pending,omitempty"`
	Completed   int    `json:"completed,omitempty"`
	ExpiryTime  int64  `json:"expiry_time,omitempty"`
}

func newRequest(method, path string, body io.Reader) (*http.Request, error) {
	url := strings.TrimSuffix(conf.ServerBaseURL, "/") + path
	request, err := http.NewRequest(method, url, body)
	if err != nil {
		return nil, err
	}
	request.Header.Set("User-Agent", "matrixtoken/"+version)
	request.Header.Set("Authorization", "Bearer "+conf.AdminToken)
	return request, nil
}

func post(path string, content any) (*http.Response, error) {
	buf := &bytes.Buffer{}
	encoder := json.NewEncoder(buf)
	if err := encoder.Encode(&content); err != nil {
		return nil, fmt.Errorf("encode request body: %w", err)
	}

	request, err := newRequest(http.MethodPost, path, buf)
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}
	request.Header.Set("Content-Type", "application/json")

	var transport http.RoundTripper
	scheme, path, ok := strings.Cut(conf.ServerBaseURL, "://")
	if !ok {
		return nil, fmt.Errorf("base URL %q: scheme not found", conf.ServerBaseURL)
	}
	switch scheme {
	case "http+unix", "https+unix":
		t := &http.Transport{}
		t.RegisterProtocol(scheme, NewUnixTransport(path))
		transport = t
	default:
		transport = http.DefaultTransport
	}

	client := &http.Client{Transport: transport}
	return client.Do(request)
}

func generate(fmtJSON bool) error {
	body := Token{
		Token:       conf.TokenStyle.Generate(64),
		UsesAllowed: conf.UsesAllowed,
		ExpiryTime:  time.Now().AddDate(0, 0, conf.ExpiryDays).UnixMilli(),
	}
	response, err := post(conf.ServerSoftware.RouteNewToken(), body)
	if err != nil {
		return fmt.Errorf("post request: %w", err)
	}
	defer response.Body.Close()

	if response.StatusCode != 200 {
		return fmt.Errorf("response status: %s", response.Status)
	}

	var token Token
	decoder := json.NewDecoder(response.Body)
	if err := decoder.Decode(&token); err != nil {
		return fmt.Errorf("decode response: %w", err)
	}

	if fmtJSON {
		encoder := json.NewEncoder(os.Stdout)
		if err := encoder.Encode(&token); err != nil {
			return fmt.Errorf("encode JSON: %w", err)
		}
	} else {
		fmt.Println(token.Token)
	}
	return nil
}

const (
	usageFmt = `Usage: matrixtoken [OPTION]...

Tool to let users of the system generate Matrix registration tokens from
the homeserver admin API.

Options:
  -c FILE       Read config from FILE. (default %q)
  -h, --help    Show this help and exit.
  -j, --json    Output results in JSON format.
  --version     Show version and exit.
`
	flagConfDef = "/etc/matrixtoken.conf"
)

func main() {
	cli := flag.NewFlagSet("matrixtoken", flag.ExitOnError)
	cli.Usage = func() {
		fmt.Fprintf(cli.Output(), usageFmt, flagConfDef)
	}
	var (
		flagConf    string
		flagHelp    bool
		flagJSON    bool
		flagVersion bool
	)
	cli.StringVar(&flagConf, "c", flagConfDef, "")
	cli.BoolVar(&flagHelp, "h", false, "")
	cli.BoolVar(&flagHelp, "help", false, "")
	cli.BoolVar(&flagJSON, "j", false, "")
	cli.BoolVar(&flagJSON, "json", false, "")
	cli.BoolVar(&flagVersion, "version", false, "")
	cli.Parse(os.Args[1:])

	if flagHelp {
		cli.SetOutput(os.Stdout)
		cli.Usage()
		return
	}

	if flagVersion {
		fmt.Println("matrixtoken", version)
		return
	}

	conffile, err := os.Open(flagConf)
	if err != nil {
		l.Fatal("Failed to open conf file: ", err)
	}
	decoder := toml.NewDecoder(conffile)
	if _, err := decoder.Decode(&conf); err != nil {
		l.Fatalf("Failed to parse conf file %s: %v", flagConf, err)
	}

	if err := generate(flagJSON); err != nil {
		l.Fatal("Failed to generate token: ", err)
	}
}
