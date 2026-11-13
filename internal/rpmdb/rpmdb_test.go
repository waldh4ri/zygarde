package rpmdb

import (
	"encoding/binary"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const testPageSize = 4096

func putVarint(v uint64) []byte {
	// Big-endian base-128, up to 8 bytes (values < 2^56): enough for the tests.
	var tmp []byte
	for {
		tmp = append([]byte{byte(v & 0x7f)}, tmp...)
		v >>= 7
		if v == 0 {
			break
		}
	}
	for i := 0; i < len(tmp)-1; i++ {
		tmp[i] |= 0x80
	}
	return tmp
}

// record builds an SQLite record from (type, bytes) columns.
func record(cols ...[2]any) []byte {
	var hdr, body []byte
	for _, c := range cols {
		st := c[0].(uint64)
		hdr = append(hdr, putVarint(st)...)
		body = append(body, c[1].([]byte)...)
	}
	hsize := uint64(len(hdr) + 1)
	return append(append(putVarint(hsize), hdr...), body...)
}

func textCol(s string) [2]any { return [2]any{uint64(13 + 2*len(s)), []byte(s)} }
func blobCol(b []byte) [2]any { return [2]any{uint64(12 + 2*len(b)), b} }
func intCol(v byte) [2]any    { return [2]any{uint64(1), []byte{v}} }
func nullCol() [2]any         { return [2]any{uint64(0), []byte{}} }

// leafPage builds a table leaf page (hdrOff is 100 on page 1) from cells.
func leafPage(hdrOff int, cells [][]byte) []byte {
	pg := make([]byte, testPageSize)
	pg[hdrOff] = 0x0d
	binary.BigEndian.PutUint16(pg[hdrOff+3:], uint16(len(cells)))
	end := testPageSize
	ptrs := hdrOff + 8
	for i, c := range cells {
		end -= len(c)
		copy(pg[end:], c)
		binary.BigEndian.PutUint16(pg[ptrs+2*i:], uint16(end))
	}
	binary.BigEndian.PutUint16(pg[hdrOff+5:], uint16(end))
	return pg
}

// buildDB writes an SQLite file with sqlite_master on page 1 and a Packages
// table on page 2 holding the blobs; blobs too large for a leaf spill into
// overflow pages after page 2.
func buildDB(t *testing.T, blobs [][]byte) []byte {
	t.Helper()
	master := record(textCol("table"), textCol("Packages"), textCol("Packages"), intCol(2), textCol("CREATE TABLE Packages(hnum INTEGER PRIMARY KEY, blob BLOB)"))
	cell := append(append(putVarint(uint64(len(master))), 1), master...)
	page1 := leafPage(100, [][]byte{cell})
	copy(page1, "SQLite format 3\x00")
	binary.BigEndian.PutUint16(page1[16:], testPageSize)

	u := testPageSize
	maxLocal, minLocal := u-35, (u-12)*32/255-23
	var cells [][]byte
	var overflow [][]byte
	next := uint32(3)
	for i, b := range blobs {
		rec := record(nullCol(), blobCol(b))
		c := append(putVarint(uint64(len(rec))), byte(i+1))
		if len(rec) <= maxLocal {
			cells = append(cells, append(c, rec...))
			continue
		}
		local := minLocal + (len(rec)-minLocal)%(u-4)
		if local > maxLocal {
			local = minLocal
		}
		c = append(c, rec[:local]...)
		c = binary.BigEndian.AppendUint32(c, next)
		rest := rec[local:]
		for len(rest) > 0 {
			take := u - 4
			if len(rest) < take {
				take = len(rest)
			}
			pg := make([]byte, testPageSize)
			if len(rest) > take {
				binary.BigEndian.PutUint32(pg, next+1)
			}
			copy(pg[4:], rest[:take])
			overflow = append(overflow, pg)
			rest = rest[take:]
			next++
		}
		cells = append(cells, c)
	}
	db := append(page1, leafPage(0, cells)...)
	for _, o := range overflow {
		db = append(db, o...)
	}
	return db
}

// rpmHeader builds an rpmdb header blob for one package.
func rpmHeader(name string, algo int32, files map[string]string) []byte {
	var dirs []string
	dirIdx := map[string]int32{}
	var bases, digests []string
	var idx []int32
	for path, digest := range files {
		d, b := path[:strings.LastIndex(path, "/")+1], path[strings.LastIndex(path, "/")+1:]
		if _, ok := dirIdx[d]; !ok {
			dirIdx[d] = int32(len(dirs))
			dirs = append(dirs, d)
		}
		bases = append(bases, b)
		digests = append(digests, digest)
		idx = append(idx, dirIdx[d])
	}
	var data []byte
	type entry struct {
		tag, typ uint32
		off, cnt int
	}
	var entries []entry
	addStrings := func(tag uint32, ss []string) {
		entries = append(entries, entry{tag, typeStringArray, len(data), len(ss)})
		for _, s := range ss {
			data = append(append(data, s...), 0)
		}
	}
	addInts := func(tag uint32, vs []int32) {
		for len(data)%4 != 0 {
			data = append(data, 0)
		}
		entries = append(entries, entry{tag, typeInt32, len(data), len(vs)})
		for _, v := range vs {
			data = binary.BigEndian.AppendUint32(data, uint32(v))
		}
	}
	entries = append(entries, entry{tagName, typeString, 0, 1})
	data = append(append(data, name...), 0)
	addStrings(tagBasenames, bases)
	addStrings(tagDirnames, dirs)
	addInts(tagDirindexes, idx)
	addStrings(tagFileDigests, digests)
	addInts(tagFileDigestAlg, []int32{algo})

	out := binary.BigEndian.AppendUint32(nil, uint32(len(entries)))
	out = binary.BigEndian.AppendUint32(out, uint32(len(data)))
	for _, e := range entries {
		out = binary.BigEndian.AppendUint32(out, e.tag)
		out = binary.BigEndian.AppendUint32(out, e.typ)
		out = binary.BigEndian.AppendUint32(out, uint32(e.off))
		out = binary.BigEndian.AppendUint32(out, uint32(e.cnt))
	}
	return append(out, data...)
}

const sha = "e65f468b0665491670bafb487f5fbe7be5fb777c78fa8d6d0474febf7681ef57"

func TestDigests(t *testing.T) {
	small := rpmHeader("keyutils-libs", 8, map[string]string{
		"/usr/lib64/libkeyutils.so.1.10": sha,
		"/usr/lib64/libkeyutils.so.1":    "", // symlink: no digest
		"/usr/bin/keyctl":                "AB" + strings.Repeat("cd", 31),
	})
	// A package large enough to need an overflow chain across several pages.
	bigFiles := map[string]string{"/usr/lib64/libbig.so.1": strings.Repeat("0a", 16)}
	for i := 0; i < 1500; i++ {
		bigFiles["/usr/share/doc/big/file"+strings.Repeat("x", i%40)+string(rune('a'+i%26))+strings.Repeat("y", i/26)] = strings.Repeat("11", 16)
	}
	big := rpmHeader("big", 1, bigFiles)
	if len(big) < 3*testPageSize {
		t.Fatalf("fixture too small to overflow: %d bytes", len(big))
	}

	dir := t.TempDir()
	dbPath := filepath.Join(dir, "rpmdb.sqlite")
	if err := os.WriteFile(dbPath, buildDB(t, [][]byte{small, big}), 0o644); err != nil {
		t.Fatal(err)
	}
	wanted := map[string]bool{"/usr/lib64/libkeyutils.so.1.10": true, "/usr/lib64/libkeyutils.so.1": true, "/usr/bin/keyctl": true, "/usr/lib64/libbig.so.1": true, "/nope": true}
	got, err := Digests(dbPath, wanted)
	if err != nil {
		t.Fatal(err)
	}
	if d := got["/usr/lib64/libkeyutils.so.1.10"]; len(d) != 1 || d[0] != (Digest{"sha256", sha, "keyutils-libs"}) {
		t.Errorf("libkeyutils: %+v", d)
	}
	if len(got["/usr/lib64/libkeyutils.so.1"]) != 0 || len(got["/nope"]) != 0 {
		t.Errorf("symlink or unknown path got digests: %+v", got)
	}
	if d := got["/usr/bin/keyctl"]; len(d) != 1 || d[0].Hex != "ab"+strings.Repeat("cd", 31) {
		t.Errorf("digest not lower-cased: %+v", d)
	}
	if d := got["/usr/lib64/libbig.so.1"]; len(d) != 1 || d[0].Algo != "md5" || d[0].Package != "big" {
		t.Errorf("overflow row: %+v", d)
	}
}

func TestWALOverridesPage(t *testing.T) {
	old := rpmHeader("old", 8, map[string]string{"/usr/lib64/libx.so.1": strings.Repeat("aa", 32)})
	db := buildDB(t, [][]byte{old})
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "rpmdb.sqlite")
	if err := os.WriteFile(dbPath, db, 0o644); err != nil {
		t.Fatal(err)
	}

	// The upgrade lives only in the WAL: a new page 2, committed.
	upgraded := rpmHeader("new", 8, map[string]string{"/usr/lib64/libx.so.1": strings.Repeat("bb", 32)})
	rec := record(nullCol(), blobCol(upgraded))
	cell := append(append(putVarint(uint64(len(rec))), 1), rec...)
	page2 := leafPage(0, [][]byte{cell})

	wal := make([]byte, 32)
	binary.BigEndian.PutUint32(wal[0:], 0x377f0682)
	binary.BigEndian.PutUint32(wal[8:], testPageSize)
	binary.BigEndian.PutUint32(wal[16:], 7) // salts
	binary.BigEndian.PutUint32(wal[20:], 9)
	frame := func(pgno, commit, s1 uint32, page []byte) []byte {
		h := make([]byte, 24)
		binary.BigEndian.PutUint32(h[0:], pgno)
		binary.BigEndian.PutUint32(h[4:], commit)
		binary.BigEndian.PutUint32(h[8:], s1)
		binary.BigEndian.PutUint32(h[12:], 9)
		return append(h, page...)
	}
	wal = append(wal, frame(2, 2, 7, page2)...)
	// A later frame that was never committed, and a stale-salt frame, must be ignored.
	wal = append(wal, frame(2, 0, 7, leafPage(0, nil))...)
	wal = append(wal, frame(2, 2, 99, leafPage(0, nil))...)
	if err := os.WriteFile(dbPath+"-wal", wal, 0o644); err != nil {
		t.Fatal(err)
	}

	got, err := Digests(dbPath, map[string]bool{"/usr/lib64/libx.so.1": true})
	if err != nil {
		t.Fatal(err)
	}
	if d := got["/usr/lib64/libx.so.1"]; len(d) != 1 || d[0].Package != "new" || d[0].Hex != strings.Repeat("bb", 32) {
		t.Errorf("WAL page not applied: %+v", d)
	}
}

func TestRejectsOtherFormats(t *testing.T) {
	p := filepath.Join(t.TempDir(), "Packages")
	if err := os.WriteFile(p, append([]byte("\x00\x00\x00\x00\x61\x15\x06\x00"), make([]byte, 1024)...), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Digests(p, nil); err == nil || !strings.Contains(err.Error(), "not an SQLite") {
		t.Errorf("got %v", err)
	}
}

func TestVarint(t *testing.T) {
	for _, tc := range []struct {
		in   []byte
		want uint64
		n    int
	}{{[]byte{0x05}, 5, 1}, {[]byte{0x81, 0x00}, 128, 2}, {[]byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}, ^uint64(0), 9}} {
		if v, n := varint(tc.in); v != tc.want || n != tc.n {
			t.Errorf("varint(% x) = %d, %d", tc.in, v, n)
		}
	}
}
