// Copyright (c) 2025-2026 waldh4ri
// SPDX-License-Identifier: GPL-2.0-only OR BSD-2-Clause

package btfhub

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/sha1" //nolint:gosec // git blob hash, as in the package
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ulikunitz/xz"
)

func TestPath(t *testing.T) {
	for _, c := range []struct{ id, ver, rel, arch, want string }{
		{"ubuntu", "20.04", "5.4.0-72-generic", "amd64", "ubuntu/20.04/x86_64/5.4.0-72-generic.btf.tar.xz"},
		{"rhel", "8.4", "4.18.0-305.el8.x86_64", "amd64", "rhel/8/x86_64/4.18.0-305.el8.x86_64.btf.tar.xz"},
		{"centos", "7", "3.10.0-1160.el7.x86_64", "amd64", "centos/7/x86_64/3.10.0-1160.el7.x86_64.btf.tar.xz"},
		{"debian", "10", "4.19.0-16-cloud-arm64", "arm64", "debian/10/arm64/4.19.0-16-cloud-arm64.btf.tar.xz"},
	} {
		got, err := Path(c.id, c.ver, c.rel, c.arch)
		if err != nil || got != c.want {
			t.Errorf("Path(%s %s %s %s) = %q, %v; want %q", c.id, c.ver, c.rel, c.arch, got, err, c.want)
		}
	}
	for _, c := range [][4]string{
		{"almalinux", "9.4", "5.14.0", "amd64"}, // not mapped: only exact IDs
		{"ubuntu", "", "5.4.0", "amd64"},
		{"ubuntu", "20.04", "5.4.0", "riscv64"},
		{"ubuntu", "20.04", "../../x", "amd64"},
		{"ubuntu", "20.04", "5.4?x=1", "amd64"},
	} {
		if _, err := Path(c[0], c[1], c[2], c[3]); !errors.Is(err, ErrNotPublished) {
			t.Errorf("Path(%v) = %v, want ErrNotPublished", c, err)
		}
	}
}

func TestOSRelease(t *testing.T) {
	p := filepath.Join(t.TempDir(), "os-release")
	os.WriteFile(p, []byte("NAME=\"Ubuntu\"\nID=ubuntu\nVERSION_ID=\"20.04\"\nID_LIKE=debian\n"), 0o644)
	if id, v := OSRelease(p); id != "ubuntu" || v != "20.04" {
		t.Errorf("OSRelease = %q, %q", id, v)
	}
}

// minimalBTF is a valid BTF header with an empty type section and a
// one-byte string section.
func minimalBTF() []byte {
	b := make([]byte, 25)
	le := binary.LittleEndian
	le.PutUint16(b[0:], btfMagic)
	b[2] = btfVersion
	le.PutUint32(b[4:], btfHdrMin)
	le.PutUint32(b[20:], 1) // str_len
	return b
}

func archive(t *testing.T, name string, content []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw, err := xz.NewWriter(&buf)
	if err != nil {
		t.Fatal(err)
	}
	tw := tar.NewWriter(zw)
	tw.WriteHeader(&tar.Header{Name: "./README", Mode: 0o644, Size: 2, Typeflag: tar.TypeReg})
	tw.Write([]byte("hi"))
	tw.WriteHeader(&tar.Header{Name: "./" + name, Mode: 0o644, Size: int64(len(content)), Typeflag: tar.TypeReg})
	tw.Write(content)
	tw.Close()
	zw.Close()
	return buf.Bytes()
}

func gitBlob(b []byte) string {
	h := sha1.New() //nolint:gosec
	fmt.Fprintf(h, "blob %d\x00", len(b))
	h.Write(b)
	return hex.EncodeToString(h.Sum(nil))
}

// hub serves a fake contents API and raw downloads over TLS: files maps
// archive paths to their bytes, and meta can alter what the API publishes.
func hub(t *testing.T, files map[string][]byte, meta func(path string, p *published)) *httptest.Server {
	t.Helper()
	var srv *httptest.Server
	srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasPrefix(r.URL.Path, "/contents/"):
			p := strings.TrimPrefix(r.URL.Path, "/contents/")
			b, ok := files[p]
			if !ok {
				http.NotFound(w, r)
				return
			}
			pub := published{Type: "file", SHA: gitBlob(b), Size: int64(len(b)), DownloadURL: srv.URL + "/raw/" + p}
			if meta != nil {
				meta(p, &pub)
			}
			json.NewEncoder(w).Encode(pub)
		case strings.HasPrefix(r.URL.Path, "/raw/"):
			b, ok := files[strings.TrimPrefix(r.URL.Path, "/raw/")]
			if !ok {
				http.NotFound(w, r)
				return
			}
			w.Write(b)
		case r.URL.Path == "/redirect":
			http.Redirect(w, r, r.URL.Query().Get("to"), http.StatusFound)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	u, _ := url.Parse(srv.URL)
	oldBase := apiBase
	apiBase = srv.URL + "/contents"
	allowedHosts[u.Hostname()] = true
	t.Cleanup(func() { apiBase = oldBase; delete(allowedHosts, u.Hostname()) })
	return srv
}

const rel = "5.4.0-72-generic"

func TestFetchVerified(t *testing.T) {
	btf := minimalBTF()
	arc := archive(t, rel+".btf", btf)
	srv := hub(t, map[string][]byte{"ubuntu/ok.btf.tar.xz": arc}, nil)

	f, err := Fetch(context.Background(), srv.Client(), "ubuntu/ok.btf.tar.xz", rel, t.TempDir(), "zygarde/test")
	if err != nil {
		t.Fatal(err)
	}
	got, _ := os.ReadFile(f.Path)
	sum := sha256.Sum256(arc)
	if !bytes.Equal(got, btf) || f.GitBlobSHA1 != gitBlob(arc) || f.ArchiveSHA256 != hex.EncodeToString(sum[:]) || f.Size != int64(len(arc)) {
		t.Errorf("fetched %+v", f)
	}
	if st, _ := os.Stat(f.Path); st.Mode().Perm() != 0o600 {
		t.Errorf("BTF file mode %v, want 0600", st.Mode().Perm())
	}
}

// Every validation refuses the file and leaves nothing behind.
func TestFetchRefuses(t *testing.T) {
	good := archive(t, rel+".btf", minimalBTF())
	badHeader := minimalBTF()
	binary.LittleEndian.PutUint32(badHeader[20:], 4096) // string section past EOF
	files := map[string][]byte{
		"notxz":          []byte("PK\x03\x04 a zip, not xz"),
		"badheader":      archive(t, rel+".btf", badHeader),
		"notbtf":         archive(t, rel+".btf", []byte("ELF? no, just text, long enough for a header")),
		"wrongentry":     archive(t, "6.1.0-other.btf", minimalBTF()),
		"good-wronghash": good,
		"good-wrongsize": good,
		"good-http":      good,
		"good-elsewhere": good,
	}
	var srv *httptest.Server // the callback runs per request, after srv is set
	srv = hub(t, files, func(p string, pub *published) {
		switch p {
		case "good-wronghash":
			pub.SHA = strings.Repeat("0", 40)
		case "good-wrongsize":
			pub.Size++
		case "good-http":
			pub.DownloadURL = strings.Replace(pub.DownloadURL, "https://", "http://", 1)
		case "good-elsewhere":
			pub.DownloadURL = srv.URL + "/redirect?to=" + url.QueryEscape("https://evil.example/x.tar.xz")
		}
	})

	for p, want := range map[string]string{
		"missing":        ErrNotPublished.Error(),
		"notxz":          "not an xz archive",
		"badheader":      "extends past the end",
		"notbtf":         "not a BTF file",
		"wrongentry":     "has no " + rel + ".btf",
		"good-wronghash": "does not match the published",
		"good-wrongsize": "GitHub publishes",
		"good-http":      "HTTPS only",
		"good-elsewhere": "not a BTFHub/GitHub host",
	} {
		dir := t.TempDir()
		_, err := Fetch(context.Background(), srv.Client(), p, rel, dir, "z")
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%s: %v, want an error containing %q", p, err, want)
		}
		if left, _ := os.ReadDir(dir); len(left) != 0 {
			t.Errorf("%s: left %d file(s) behind", p, len(left))
		}
	}
	if _, err := Fetch(context.Background(), srv.Client(), "missing", rel, t.TempDir(), "z"); !errors.Is(err, ErrNotPublished) {
		t.Errorf("missing: %v, want ErrNotPublished", err)
	}
}

func TestCheckSource(t *testing.T) {
	for raw, ok := range map[string]bool{
		"https://github.com/aquasecurity/btfhub-archive/raw/main/x": true,
		"https://raw.githubusercontent.com/x":                       true,
		"http://github.com/x":                                       false,
		"https://github.com.evil.example/x":                         false,
		"https://evil.example/github.com":                           false,
	} {
		u, _ := url.Parse(raw)
		if err := checkSource(u); (err == nil) != ok {
			t.Errorf("checkSource(%s) = %v, want ok=%v", raw, err, ok)
		}
	}
}
