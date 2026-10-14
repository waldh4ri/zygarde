// Package bpfutil holds helpers shared by the eBPF-based Cells.
package bpfutil

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"golang.org/x/sys/unix"

	"github.com/waldh4ri/zygarde/internal/core"
)

// Load loads the objects of spec referenced by the fields of objs (a
// bpf2go-generated *xxxObjects), using the shared options from env.
func Load(env *core.Env, spec *ebpf.CollectionSpec, objs any) error {
	return core.WrapBPF("load BPF objects", spec.LoadAndAssign(objs, env.CollectionOptions()))
}

// SetVariable sets a `const volatile` global in spec before loading.
func SetVariable(spec *ebpf.CollectionSpec, name string, value any) error {
	v, ok := spec.Variables[name]
	if !ok {
		return fmt.Errorf("BPF variable %q not found", name)
	}
	if err := v.Set(value); err != nil {
		return fmt.Errorf("setting BPF variable %q: %w", name, err)
	}
	return nil
}

// initPIDNSInode is the inode of the initial PID namespace
// (PROC_PID_INIT_INO / PID_NS_INIT_INO in the kernel).
const initPIDNSInode = 0xEFFFFFFC

// InInitPIDNS reports whether this process runs in the initial PID namespace,
// where PIDs match the kernel's init-namespace numbers.
func InInitPIDNS() (bool, error) {
	var st unix.Stat_t
	if err := unix.Stat("/proc/self/ns/pid", &st); err != nil {
		return false, fmt.Errorf("stat /proc/self/ns/pid: %w", err)
	}
	return st.Ino == initPIDNSInode, nil
}

// SetTarget configures the is_target() helper (bpf/include/zygarde.h) to
// match the current process, in its own PID namespace.
func SetTarget(env *core.Env, spec *ebpf.CollectionSpec) error {
	var st unix.Stat_t
	if err := unix.Stat("/proc/self/ns/pid", &st); err != nil {
		return fmt.Errorf("stat /proc/self/ns/pid: %w", err)
	}
	// Without bpf_get_ns_current_pid_tgid() (Linux 5.7+, its struct
	// bpf_pidns_info is in BTF), is_target() compares init-namespace PIDs.
	if st.Ino != initPIDNSInode && env.BTF != nil {
		if _, err := env.BTF.AnyTypeByName("bpf_pidns_info"); err != nil {
			return core.Skip("kernel lacks bpf_get_ns_current_pid_tgid() (Linux 5.7+) and zygarde is not in the initial PID namespace")
		}
	}
	for name, v := range map[string]any{
		"pidns_dev":   uint64(st.Dev),
		"pidns_ino":   st.Ino,
		"target_tgid": uint32(unix.Getpid()),
	} {
		if err := SetVariable(spec, name, v); err != nil {
			return err
		}
	}
	return nil
}

// ReadIter attaches an iterator program, runs it once and returns its output.
func ReadIter(prog *ebpf.Program) ([]byte, error) {
	it, err := link.AttachIter(link.IterOptions{Program: prog})
	if err != nil {
		return nil, core.WrapBPF("attach iterator", err)
	}
	defer it.Close()

	rd, err := it.Open()
	if err != nil {
		return nil, core.WrapBPF("open iterator", err)
	}
	defer rd.Close()

	// Read everything before decoding: a record may straddle read() calls.
	data, err := io.ReadAll(rd)
	if err != nil {
		return nil, fmt.Errorf("reading iterator: %w", err)
	}
	return data, nil
}

// Decode splits iterator output into fixed-size records of type T.
func Decode[T any](data []byte) ([]T, error) {
	var zero T
	size := binary.Size(zero)
	if size <= 0 {
		return nil, fmt.Errorf("record type %T has no fixed size", zero)
	}
	if len(data)%size != 0 {
		return nil, fmt.Errorf("iterator output (%d bytes) is not a multiple of the record size (%d)", len(data), size)
	}
	out := make([]T, len(data)/size)
	if err := binary.Read(bytes.NewReader(data), binary.NativeEndian, out); err != nil {
		return nil, fmt.Errorf("decoding records: %w", err)
	}
	return out, nil
}

// EnumerateProgIDs lists program IDs the way userspace tools do, by calling
// BPF_PROG_GET_NEXT_ID until the kernel reports the end with ENOENT.
func EnumerateProgIDs() ([]uint32, error) {
	var ids []uint32
	var id ebpf.ProgramID
	for {
		next, err := ebpf.ProgramGetNextID(id)
		if errors.Is(err, unix.ENOENT) {
			return ids, nil
		}
		if err != nil {
			return ids, core.WrapBPF("BPF_PROG_GET_NEXT_ID", err)
		}
		if next <= id {
			return ids, fmt.Errorf("BPF_PROG_GET_NEXT_ID went backwards (%d after %d)", next, id)
		}
		ids = append(ids, uint32(next))
		id = next
	}
}

// EnumerateMapIDs is EnumerateProgIDs for maps (BPF_MAP_GET_NEXT_ID).
func EnumerateMapIDs() ([]uint32, error) {
	var ids []uint32
	var id ebpf.MapID
	for {
		next, err := ebpf.MapGetNextID(id)
		if errors.Is(err, unix.ENOENT) {
			return ids, nil
		}
		if err != nil {
			return ids, core.WrapBPF("BPF_MAP_GET_NEXT_ID", err)
		}
		if next <= id {
			return ids, fmt.Errorf("BPF_MAP_GET_NEXT_ID went backwards (%d after %d)", next, id)
		}
		ids = append(ids, uint32(next))
		id = next
	}
}

// ProgramID returns the kernel ID of a loaded program.
func ProgramID(p *ebpf.Program) (uint32, error) {
	info, err := p.Info()
	if err != nil {
		return 0, core.WrapBPF("BPF_OBJ_GET_INFO_BY_FD", err)
	}
	id, ok := info.ID()
	if !ok {
		return 0, errors.New("kernel did not report a program ID")
	}
	return uint32(id), nil
}

// CString converts a NUL-padded byte array to a string.
func CString(b []byte) string {
	if i := bytes.IndexByte(b, 0); i >= 0 {
		b = b[:i]
	}
	return string(b)
}

// Int8String converts a NUL-padded int8 array (as generated by bpf2go for
// C char arrays) to a string.
func Int8String(a []int8) string {
	b := make([]byte, 0, len(a))
	for _, c := range a {
		if c == 0 {
			break
		}
		b = append(b, byte(c))
	}
	return string(b)
}
