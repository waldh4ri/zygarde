// Package rpmdb reads file checksums from an RPM package database stored as
// SQLite (rpmdb.sqlite: Fedora 33+, RHEL/Alma/Rocky 9+, openSUSE Tumbleweed).
//
// It is a small read-only reader for the one table rpm uses, written so that
// a static scanner does not need a SQLite library or the rpm binary: it
// parses the b-tree pages directly, applies the write-ahead log (recent
// upgrades live there until a checkpoint) and decodes each package's header
// blob for its file names and digests.
package rpmdb

import (
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"strings"
)

// Digest is a file checksum declared by an installed package.
type Digest struct {
	Algo    string // "md5" or "sha256"
	Hex     string
	Package string // package name
}

// maxDBSize bounds how much of the database is read into memory.
const maxDBSize = 1 << 30

// Digests returns, for each wanted absolute path, the checksums installed
// packages declare for it. dbPath is the rpmdb.sqlite file; its -wal file is
// applied if present.
func Digests(dbPath string, wanted map[string]bool) (map[string][]Digest, error) {
	d, _, err := Scan(dbPath, wanted)
	return d, err
}

// Scan is Digests plus ownership: owners maps each wanted path that some
// installed package ships (with or without a checksum) to that package.
func Scan(dbPath string, wanted map[string]bool) (digests map[string][]Digest, owners map[string]string, err error) {
	db, err := open(dbPath)
	if err != nil {
		return nil, nil, err
	}
	root, err := db.tableRoot("Packages")
	if err != nil {
		return nil, nil, err
	}
	digests = map[string][]Digest{}
	owners = map[string]string{}
	err = db.walkTable(root, func(_ int64, rec []byte) {
		blob, ok := recordBlob(rec, 1)
		if !ok {
			return
		}
		h, err := parseHeader(blob)
		if err != nil {
			return
		}
		for i := range h.basenames {
			if i >= len(h.dirindexes) {
				continue
			}
			di := int(h.dirindexes[i])
			if di < 0 || di >= len(h.dirnames) {
				continue
			}
			p := h.dirnames[di] + h.basenames[i]
			if !wanted[p] {
				continue
			}
			owners[p] = h.name
			if i < len(h.digests) && h.digests[i] != "" {
				digests[p] = append(digests[p], Digest{Algo: h.algo, Hex: strings.ToLower(h.digests[i]), Package: h.name})
			}
		}
	})
	return digests, owners, err
}

// ---- SQLite b-tree reader -------------------------------------------------

type sqliteDB struct {
	data     []byte
	wal      map[uint32][]byte // page number -> latest committed page image
	pageSize int
	usable   int
}

func open(path string) (*sqliteDB, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if st.Size() < 512 || st.Size() > maxDBSize {
		return nil, fmt.Errorf("rpmdb: unexpected database size %d", st.Size())
	}
	data := make([]byte, st.Size())
	if _, err := f.ReadAt(data, 0); err != nil {
		return nil, err
	}
	if string(data[:16]) != "SQLite format 3\x00" {
		return nil, errors.New("rpmdb: not an SQLite database (Berkeley DB and ndb databases are not supported)")
	}
	ps := int(binary.BigEndian.Uint16(data[16:]))
	if ps == 1 {
		ps = 65536
	}
	if ps < 512 || ps&(ps-1) != 0 {
		return nil, fmt.Errorf("rpmdb: bad page size %d", ps)
	}
	db := &sqliteDB{data: data, pageSize: ps, usable: ps - int(data[20])}
	if wal, err := os.ReadFile(path + "-wal"); err == nil {
		db.applyWAL(wal)
	}
	return db, nil
}

// applyWAL records the newest committed image of each page. Frames after the
// last commit frame, and frames written under another salt (a previous WAL
// generation), are ignored.
func (db *sqliteDB) applyWAL(wal []byte) {
	if len(wal) < 32 {
		return
	}
	magic := binary.BigEndian.Uint32(wal[0:])
	if magic != 0x377f0682 && magic != 0x377f0683 {
		return
	}
	if int(binary.BigEndian.Uint32(wal[8:])) != db.pageSize {
		return
	}
	salt1, salt2 := binary.BigEndian.Uint32(wal[16:]), binary.BigEndian.Uint32(wal[20:])
	type frame struct {
		pgno uint32
		off  int
	}
	var pending []frame
	db.wal = map[uint32][]byte{}
	for off := 32; off+24+db.pageSize <= len(wal); off += 24 + db.pageSize {
		hdr := wal[off:]
		pgno := binary.BigEndian.Uint32(hdr[0:])
		commit := binary.BigEndian.Uint32(hdr[4:])
		if pgno == 0 || binary.BigEndian.Uint32(hdr[8:]) != salt1 || binary.BigEndian.Uint32(hdr[12:]) != salt2 {
			break
		}
		pending = append(pending, frame{pgno, off + 24})
		if commit != 0 {
			for _, fr := range pending {
				db.wal[fr.pgno] = wal[fr.off : fr.off+db.pageSize]
			}
			pending = pending[:0]
		}
	}
}

func (db *sqliteDB) page(n uint32) ([]byte, error) {
	if n == 0 {
		return nil, errors.New("rpmdb: page 0")
	}
	if p, ok := db.wal[n]; ok {
		return p, nil
	}
	start := (int64(n) - 1) * int64(db.pageSize)
	if start+int64(db.pageSize) > int64(len(db.data)) {
		return nil, fmt.Errorf("rpmdb: page %d beyond the database", n)
	}
	return db.data[start : start+int64(db.pageSize)], nil
}

func varint(b []byte) (uint64, int) {
	var v uint64
	for i := 0; i < 9 && i < len(b); i++ {
		if i == 8 {
			return v<<8 | uint64(b[i]), 9
		}
		v = v<<7 | uint64(b[i]&0x7f)
		if b[i]&0x80 == 0 {
			return v, i + 1
		}
	}
	return 0, 0
}

// walkTable calls fn with the rowid and payload of every row of the table
// b-tree rooted at page root.
func (db *sqliteDB) walkTable(root uint32, fn func(rowid int64, payload []byte)) error {
	return db.walk(root, 0, fn)
}

func (db *sqliteDB) walk(pgno uint32, depth int, fn func(int64, []byte)) error {
	if depth > 20 {
		return errors.New("rpmdb: b-tree too deep")
	}
	pg, err := db.page(pgno)
	if err != nil {
		return err
	}
	hdr := 0
	if pgno == 1 {
		hdr = 100
	}
	typ := pg[hdr]
	ncells := int(binary.BigEndian.Uint16(pg[hdr+3:]))
	switch typ {
	case 0x05: // interior table page
		ptrs := hdr + 12
		for i := 0; i < ncells; i++ {
			cell := int(binary.BigEndian.Uint16(pg[ptrs+2*i:]))
			if cell+4 > len(pg) {
				return errors.New("rpmdb: bad cell pointer")
			}
			if err := db.walk(binary.BigEndian.Uint32(pg[cell:]), depth+1, fn); err != nil {
				return err
			}
		}
		return db.walk(binary.BigEndian.Uint32(pg[hdr+8:]), depth+1, fn)
	case 0x0d: // leaf table page
		ptrs := hdr + 8
		for i := 0; i < ncells; i++ {
			cell := int(binary.BigEndian.Uint16(pg[ptrs+2*i:]))
			if cell >= len(pg) {
				return errors.New("rpmdb: bad cell pointer")
			}
			size, n1 := varint(pg[cell:])
			rowid, n2 := varint(pg[cell+n1:])
			if n1 == 0 || n2 == 0 {
				return errors.New("rpmdb: bad cell")
			}
			payload, err := db.payload(pg[cell+n1+n2:], size)
			if err != nil {
				return err
			}
			fn(int64(rowid), payload)
		}
		return nil
	}
	return fmt.Errorf("rpmdb: unexpected b-tree page type %#x", typ)
}

// payload returns a cell's payload of the given total size, following the
// overflow page chain when it does not fit locally.
func (db *sqliteDB) payload(cell []byte, size uint64) ([]byte, error) {
	if size > maxDBSize {
		return nil, errors.New("rpmdb: payload too large")
	}
	u := db.usable
	maxLocal := u - 35
	if int(size) <= maxLocal {
		if int(size) > len(cell) {
			return nil, errors.New("rpmdb: truncated cell")
		}
		return cell[:size], nil
	}
	minLocal := (u-12)*32/255 - 23
	local := minLocal + (int(size)-minLocal)%(u-4)
	if local > maxLocal {
		local = minLocal
	}
	if local+4 > len(cell) {
		return nil, errors.New("rpmdb: truncated cell")
	}
	buf := make([]byte, 0, size)
	buf = append(buf, cell[:local]...)
	next := binary.BigEndian.Uint32(cell[local:])
	for uint64(len(buf)) < size {
		if next == 0 {
			return nil, errors.New("rpmdb: overflow chain ends early")
		}
		pg, err := db.page(next)
		if err != nil {
			return nil, err
		}
		take := u - 4
		if rest := int(size) - len(buf); rest < take {
			take = rest
		}
		buf = append(buf, pg[4:4+take]...)
		next = binary.BigEndian.Uint32(pg)
	}
	return buf, nil
}

// recordBlob returns column col of an SQLite record if it is a BLOB or TEXT.
func recordBlob(rec []byte, col int) ([]byte, bool) {
	hsize, n := varint(rec)
	if n == 0 || int(hsize) > len(rec) {
		return nil, false
	}
	pos, off := n, int(hsize)
	for i := 0; pos < int(hsize); i++ {
		st, m := varint(rec[pos:])
		if m == 0 {
			return nil, false
		}
		pos += m
		size := serialSize(st)
		if i == col {
			if st < 12 || off+size > len(rec) {
				return nil, false
			}
			return rec[off : off+size], true
		}
		off += size
	}
	return nil, false
}

func serialSize(st uint64) int {
	switch st {
	case 0, 8, 9:
		return 0
	case 1:
		return 1
	case 2:
		return 2
	case 3:
		return 3
	case 4:
		return 4
	case 5:
		return 6
	case 6, 7:
		return 8
	case 10, 11:
		return 0
	}
	return int(st-12) / 2
}

// tableRoot finds the root page of a table in sqlite_master.
func (db *sqliteDB) tableRoot(name string) (uint32, error) {
	var root uint32
	err := db.walkTable(1, func(_ int64, rec []byte) {
		// sqlite_master(type, name, tbl_name, rootpage, sql)
		typ, ok1 := recordBlob(rec, 0)
		nm, ok2 := recordBlob(rec, 1)
		if !ok1 || !ok2 || string(typ) != "table" || string(nm) != name {
			return
		}
		root = uint32(recordInt(rec, 3))
	})
	if err != nil {
		return 0, err
	}
	if root == 0 {
		return 0, fmt.Errorf("rpmdb: no %s table", name)
	}
	return root, nil
}

// recordInt returns column col of a record as an integer (0 if it is not one).
func recordInt(rec []byte, col int) int64 {
	hsize, n := varint(rec)
	if n == 0 {
		return 0
	}
	pos, off := n, int(hsize)
	for i := 0; pos < int(hsize); i++ {
		st, m := varint(rec[pos:])
		if m == 0 {
			return 0
		}
		pos += m
		size := serialSize(st)
		if i == col {
			if st == 8 {
				return 0
			}
			if st == 9 {
				return 1
			}
			if st < 1 || st > 6 || off+size > len(rec) {
				return 0
			}
			v := int64(int8(rec[off]))
			for _, b := range rec[off+1 : off+size] {
				v = v<<8 | int64(b)
			}
			return v
		}
		off += size
	}
	return 0
}

// ---- RPM header blob ------------------------------------------------------

// RPM tags and types (rpmtag.h, rpmtypes.h).
const (
	tagName          = 1000
	tagBasenames     = 1117
	tagDirnames      = 1118
	tagDirindexes    = 1116
	tagFileDigests   = 1035
	tagFileDigestAlg = 5011

	typeInt32       = 4
	typeString      = 6
	typeStringArray = 8
)

type header struct {
	name       string
	basenames  []string
	dirnames   []string
	dirindexes []int32
	digests    []string
	algo       string
}

// parseHeader decodes an rpmdb header blob: il, dl, il 16-byte index entries,
// then the data store.
func parseHeader(b []byte) (header, error) {
	var h header
	if len(b) < 8 {
		return h, errors.New("rpmdb: short header")
	}
	il, dl := int(binary.BigEndian.Uint32(b[0:])), int(binary.BigEndian.Uint32(b[4:]))
	if il < 0 || dl < 0 || 8+il*16+dl > len(b) || il > 1<<20 {
		return h, errors.New("rpmdb: bad header sizes")
	}
	index, data := b[8:8+il*16], b[8+il*16:8+il*16+dl]
	algo := int32(1) // PGPHASHALGO_MD5 unless the header says otherwise
	for i := 0; i < il; i++ {
		e := index[i*16:]
		tag, typ := binary.BigEndian.Uint32(e[0:]), binary.BigEndian.Uint32(e[4:])
		off, cnt := int(int32(binary.BigEndian.Uint32(e[8:]))), int(binary.BigEndian.Uint32(e[12:]))
		if off < 0 || off > len(data) || cnt < 0 || cnt > len(data) {
			continue
		}
		switch tag {
		case tagName:
			if typ == typeString {
				h.name = firstString(data[off:])
			}
		case tagBasenames:
			h.basenames = stringArray(data[off:], cnt, typ)
		case tagDirnames:
			h.dirnames = stringArray(data[off:], cnt, typ)
		case tagFileDigests:
			h.digests = stringArray(data[off:], cnt, typ)
		case tagDirindexes:
			h.dirindexes = int32Array(data[off:], cnt, typ)
		case tagFileDigestAlg:
			if a := int32Array(data[off:], cnt, typ); len(a) > 0 {
				algo = a[0]
			}
		}
	}
	switch algo {
	case 1:
		h.algo = "md5"
	case 8:
		h.algo = "sha256"
	default:
		h.algo = fmt.Sprintf("hash%d", algo) // never matches a computed digest
	}
	return h, nil
}

func firstString(b []byte) string {
	if i := indexNUL(b); i >= 0 {
		return string(b[:i])
	}
	return ""
}

func indexNUL(b []byte) int {
	for i, c := range b {
		if c == 0 {
			return i
		}
	}
	return -1
}

func stringArray(b []byte, count int, typ uint32) []string {
	if typ != typeStringArray {
		return nil
	}
	out := make([]string, 0, count)
	for i := 0; i < count; i++ {
		n := indexNUL(b)
		if n < 0 {
			break
		}
		out = append(out, string(b[:n]))
		b = b[n+1:]
	}
	return out
}

func int32Array(b []byte, count int, typ uint32) []int32 {
	if typ != typeInt32 || count*4 > len(b) {
		return nil
	}
	out := make([]int32, count)
	for i := range out {
		out[i] = int32(binary.BigEndian.Uint32(b[4*i:]))
	}
	return out
}
