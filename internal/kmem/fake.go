package kmem

import "encoding/binary"

// Fake is a kernel memory for tests. Writing to an address maps its 4 KiB
// page; bytes never written in a mapped page read as zero, and a read that
// touches an unmapped page fails, as on real memory.
type Fake struct {
	bytes map[uint64]byte
	pages map[uint64]bool
}

// NewFake returns an empty fake memory.
func NewFake() *Fake {
	return &Fake{bytes: map[uint64]byte{}, pages: map[uint64]bool{}}
}

// Write stores b at addr.
func (f *Fake) Write(addr uint64, b []byte) {
	for i, c := range b {
		a := addr + uint64(i)
		f.bytes[a] = c
		f.pages[a>>12] = true
	}
}

// Unmap makes the page holding addr unreadable, as freed vmalloc memory is.
func (f *Fake) Unmap(addr uint64) { delete(f.pages, addr>>12) }

// Put64 stores a little-endian 64-bit value at addr.
func (f *Fake) Put64(addr, v uint64) {
	var b [8]byte
	binary.LittleEndian.PutUint64(b[:], v)
	f.Write(addr, b[:])
}

// Put32 stores a little-endian 32-bit value at addr.
func (f *Fake) Put32(addr uint64, v uint32) {
	var b [4]byte
	binary.LittleEndian.PutUint32(b[:], v)
	f.Write(addr, b[:])
}

// PutString stores s and its NUL terminator at addr.
func (f *Fake) PutString(addr uint64, s string) {
	f.Write(addr, append([]byte(s), 0))
}

// Read implements Memory.
func (f *Fake) Read(reqs []Req) ([][]byte, error) {
	out := make([][]byte, len(reqs))
	for i, q := range reqs {
		if q.Len <= 0 || q.Len > ChunkSize || !Valid(q.Addr, q.Len) {
			continue
		}
		b := make([]byte, q.Len)
		ok := true
		for j := range b {
			a := q.Addr + uint64(j)
			if !f.pages[a>>12] {
				ok = false
				break
			}
			b[j] = f.bytes[a]
		}
		if ok {
			out[i] = b
		}
	}
	return out, nil
}
