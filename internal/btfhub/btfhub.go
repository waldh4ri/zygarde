// Copyright (c) 2025-2026 waldh4ri
// SPDX-License-Identifier: GPL-2.0-only OR BSD-2-Clause

// Package btfhub fetches kernel BTF from the BTFHub archive
// (github.com/aquasecurity/btfhub-archive) for kernels built without
// CONFIG_DEBUG_INFO_BTF, so CO-RE programs can still be relocated.
//
// The archive is laid out as <distro>/<version>/<arch>/<uname -r>.btf.tar.xz,
// each tarball holding <uname -r>.btf. Only exact distribution IDs are mapped:
// BTF describes one kernel build, and wrong type information would make CO-RE
// programs read the wrong fields.
//
// Everything is validated before the BTF is used:
//   - source: HTTPS only, GitHub hosts only, also after every redirect;
//   - integrity: the archive's git blob SHA-1 and size are taken from the
//     GitHub contents API (a separate endpoint from the raw download) and
//     recomputed over the downloaded bytes; without them the BTF is not used;
//   - format: xz magic, a regular tar entry named exactly <uname -r>.btf, size
//     caps, and a BTF header whose sections fit inside the file.
package btfhub

import (
	"archive/tar"
	"bufio"
	"bytes"
	"context"
	"crypto/sha1" //nolint:gosec // git's blob hash: the only digest BTFHub publishes
	"crypto/sha256"
	"crypto/tls"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/ulikunitz/xz"
)

// The archive's repository, branch, and the endpoints used to read it.
var (
	apiBase = "https://api.github.com/repos/aquasecurity/btfhub-archive/contents"
	ref     = "main"
)

// Limits: a compressed BTF is a few MB, an uncompressed one tens of MB.
const (
	maxArchive   = 64 << 20
	maxBTF       = 256 << 20
	maxAPIReply  = 1 << 20
	maxRedirects = 5
	Timeout      = 60 * time.Second
)

// ErrNotPublished means BTFHub has no BTF for this distribution or kernel.
var ErrNotPublished = errors.New("BTFHub publishes no BTF for this kernel")

// allowedHosts are the only hosts a fetch may touch: the GitHub API, GitHub,
// and the hosts it serves raw files from. Tests add their server.
var allowedHosts = map[string]bool{
	"api.github.com":                true,
	"github.com":                    true,
	"raw.githubusercontent.com":     true,
	"media.githubusercontent.com":   true,
	"objects.githubusercontent.com": true,
}

// checkSource accepts only HTTPS URLs on an allowed host.
func checkSource(u *url.URL) error {
	if u.Scheme != "https" {
		return fmt.Errorf("refusing BTF download over %q (HTTPS only)", u.Scheme)
	}
	if !allowedHosts[u.Hostname()] {
		return fmt.Errorf("refusing BTF download from %s (not a BTFHub/GitHub host)", u.Hostname())
	}
	return nil
}

// NewClient returns the HTTP client for BTFHub: TLS 1.2+, the environment's
// proxy settings, and a deadline.
func NewClient() *http.Client {
	tr := &http.Transport{Proxy: http.ProxyFromEnvironment}
	if def, ok := http.DefaultTransport.(*http.Transport); ok {
		tr = def.Clone()
	}
	tr.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12}
	return &http.Client{Transport: tr, Timeout: Timeout}
}

// distros maps os-release IDs to BTFHub directories, and says whether the
// archive uses the major version only (RHEL-family "8" for VERSION_ID "8.4").
var distros = map[string]struct {
	dir   string
	major bool
}{
	"ubuntu": {"ubuntu", false},
	"debian": {"debian", true},
	"fedora": {"fedora", false},
	"centos": {"centos", true},
	"rhel":   {"rhel", true},
	"ol":     {"ol", true},
	"amzn":   {"amzn", false},
	"sles":   {"sles", false},
}

// archs maps GOARCH to BTFHub's architecture directories.
var archs = map[string]string{"amd64": "x86_64", "arm64": "arm64"}

// Path returns the archive path of a kernel's BTF, from os-release ID and
// VERSION_ID, the kernel release (uname -r) and GOARCH.
func Path(id, versionID, release, goarch string) (string, error) {
	d, ok := distros[id]
	a, aok := archs[goarch]
	if !ok || !aok || versionID == "" || release == "" || strings.ContainsAny(release, "/ ?#%") || strings.HasPrefix(release, ".") {
		return "", fmt.Errorf("%w (%s %s, %s)", ErrNotPublished, id, versionID, goarch)
	}
	v := versionID
	if d.major {
		v, _, _ = strings.Cut(v, ".")
	}
	return fmt.Sprintf("%s/%s/%s/%s.btf.tar.xz", d.dir, v, a, release), nil
}

// OSRelease reads ID and VERSION_ID from an os-release file.
func OSRelease(path string) (id, versionID string) {
	f, err := os.Open(path)
	if err != nil {
		return "", ""
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		k, v, ok := strings.Cut(sc.Text(), "=")
		if !ok {
			continue
		}
		v = strings.Trim(v, `"'`)
		switch k {
		case "ID":
			id = v
		case "VERSION_ID":
			versionID = v
		}
	}
	return id, versionID
}

// Fetched describes a BTF obtained from BTFHub and how it was verified.
type Fetched struct {
	Path          string // the extracted .btf file
	URL           string // where the archive was downloaded from
	GitBlobSHA1   string // published by the GitHub contents API, verified
	ArchiveSHA256 string // of the downloaded .tar.xz, to check it later
	Size          int64
}

// fetcher holds one fetch's client and request settings.
type fetcher struct {
	client    *http.Client
	userAgent string
}

// get issues a GET to an allowed HTTPS source, re-checking every redirect.
func (f *fetcher) get(ctx context.Context, rawURL, accept string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, err
	}
	if err := checkSource(req.URL); err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", f.userAgent)
	if accept != "" {
		req.Header.Set("Accept", accept)
	}
	c := *f.client
	c.CheckRedirect = func(r *http.Request, via []*http.Request) error {
		if len(via) >= maxRedirects {
			return errors.New("too many redirects fetching BTF")
		}
		return checkSource(r.URL)
	}
	return c.Do(req)
}

// published is what the GitHub contents API says about a file.
type published struct {
	Type        string `json:"type"`
	SHA         string `json:"sha"` // git blob SHA-1
	Size        int64  `json:"size"`
	DownloadURL string `json:"download_url"`
}

// lookup asks the contents API for the archive's blob hash, size and URL.
func (f *fetcher) lookup(ctx context.Context, path string) (*published, error) {
	resp, err := f.get(ctx, apiBase+"/"+path+"?ref="+url.QueryEscape(ref), "application/vnd.github+json")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	switch {
	case resp.StatusCode == http.StatusNotFound:
		return nil, ErrNotPublished
	case resp.StatusCode != http.StatusOK:
		return nil, fmt.Errorf("GitHub API answered %s; the BTF can't be verified, so it is not used", resp.Status)
	}
	var p published
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxAPIReply)).Decode(&p); err != nil {
		return nil, fmt.Errorf("GitHub API reply: %w", err)
	}
	if p.Type != "file" || len(p.SHA) != 40 || p.Size <= 0 || p.Size > maxArchive || p.DownloadURL == "" {
		return nil, fmt.Errorf("GitHub API reply does not describe a usable BTF archive (type %q, size %d)", p.Type, p.Size)
	}
	if _, err := hex.DecodeString(p.SHA); err != nil {
		return nil, fmt.Errorf("GitHub API reply: bad blob hash %q", p.SHA)
	}
	return &p, nil
}

// Fetch looks up the archive at path, downloads it, verifies its size and git
// blob hash, and extracts <release>.btf into dir (which should be private).
// A file BTFHub does not have returns ErrNotPublished.
func Fetch(ctx context.Context, client *http.Client, path, release, dir, userAgent string) (*Fetched, error) {
	f := &fetcher{client: client, userAgent: userAgent}
	pub, err := f.lookup(ctx, path)
	if err != nil {
		return nil, err
	}
	resp, err := f.get(ctx, pub.DownloadURL, "")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("BTFHub download answered %s", resp.Status)
	}

	// git hashes a blob as SHA-1("blob <size>\0" + content).
	blob := sha1.New() //nolint:gosec // see import
	fmt.Fprintf(blob, "blob %d\x00", pub.Size)
	sum := sha256.New()
	counted := &counter{}
	body := io.TeeReader(io.LimitReader(resp.Body, pub.Size+1), io.MultiWriter(blob, sum, counted))

	btfPath, err := extract(body, release, dir)
	if err == nil {
		_, err = io.Copy(io.Discard, body) // hash the rest of the archive
	}
	if err == nil {
		err = verify(blob, pub, counted.n)
	}
	if err == nil {
		err = CheckHeader(btfPath)
	}
	if err != nil {
		if btfPath != "" {
			os.Remove(btfPath)
		}
		return nil, err
	}
	return &Fetched{
		Path:          btfPath,
		URL:           resp.Request.URL.Redacted(),
		GitBlobSHA1:   pub.SHA,
		ArchiveSHA256: hex.EncodeToString(sum.Sum(nil)),
		Size:          counted.n,
	}, nil
}

// verify compares the downloaded size and git blob hash with the published ones.
func verify(blob hash.Hash, pub *published, n int64) error {
	if n != pub.Size {
		return fmt.Errorf("BTFHub archive is %d bytes, GitHub publishes %d: refusing it", n, pub.Size)
	}
	if got := hex.EncodeToString(blob.Sum(nil)); got != pub.SHA {
		return fmt.Errorf("BTFHub archive git blob hash %s does not match the published %s: refusing it", got, pub.SHA)
	}
	return nil
}

type counter struct{ n int64 }

func (c *counter) Write(p []byte) (int, error) { c.n += int64(len(p)); return len(p), nil }

// xzMagic starts every xz stream.
var xzMagic = []byte{0xfd, '7', 'z', 'X', 'Z', 0x00}

// extract finds <release>.btf in an xz-compressed tar and writes it to dir.
func extract(r io.Reader, release, dir string) (string, error) {
	br := bufio.NewReader(r)
	if head, err := br.Peek(len(xzMagic)); err != nil || !bytes.Equal(head, xzMagic) {
		return "", errors.New("BTFHub download is not an xz archive")
	}
	zr, err := xz.NewReader(br)
	if err != nil {
		return "", fmt.Errorf("BTFHub archive: %w", err)
	}
	tr := tar.NewReader(zr)
	want := release + ".btf"
	for {
		h, err := tr.Next()
		if errors.Is(err, io.EOF) {
			return "", fmt.Errorf("BTFHub archive has no %s", want)
		}
		if err != nil {
			return "", fmt.Errorf("BTFHub archive: %w", err)
		}
		if h.Typeflag != tar.TypeReg || filepath.Base(h.Name) != want {
			continue
		}
		if h.Size <= 0 || h.Size > maxBTF {
			return "", fmt.Errorf("BTFHub archive: %s has an implausible size (%d bytes)", want, h.Size)
		}
		out := filepath.Join(dir, want)
		f, err := os.OpenFile(out, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if err != nil {
			return "", err
		}
		_, err = io.Copy(f, io.LimitReader(tr, maxBTF))
		if cerr := f.Close(); err == nil {
			err = cerr
		}
		if err != nil {
			os.Remove(out)
			return "", err
		}
		return out, nil
	}
}

// BTF header (include/uapi/linux/btf.h): magic, version, flags, hdr_len, then
// type and string section offsets and lengths, relative to the header's end.
const (
	btfMagic   = 0xeb9f
	btfVersion = 1
	btfHdrMin  = 24
)

// CheckHeader validates a raw BTF file's header before anything parses it:
// little-endian magic 0xeB9F (x86_64 and arm64 are little-endian), version 1,
// a plausible header length, and type and string sections inside the file.
func CheckHeader(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return err
	}
	var h [btfHdrMin]byte
	if _, err := io.ReadFull(f, h[:]); err != nil {
		return errors.New("not a BTF file: too short")
	}
	le := binary.LittleEndian
	if m := le.Uint16(h[0:]); m != btfMagic {
		return fmt.Errorf("not a BTF file: magic %#04x", m)
	}
	if h[2] != btfVersion {
		return fmt.Errorf("unsupported BTF version %d", h[2])
	}
	hdrLen := uint64(le.Uint32(h[4:]))
	size := uint64(st.Size())
	if hdrLen < btfHdrMin || hdrLen > size {
		return fmt.Errorf("invalid BTF header length %d", hdrLen)
	}
	for _, sec := range [][2]uint64{
		{uint64(le.Uint32(h[8:])), uint64(le.Uint32(h[12:]))},  // types
		{uint64(le.Uint32(h[16:])), uint64(le.Uint32(h[20:]))}, // strings
	} {
		if hdrLen+sec[0]+sec[1] > size {
			return errors.New("invalid BTF header: a section extends past the end of the file")
		}
	}
	return nil
}
