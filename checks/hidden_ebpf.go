package checks

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io/fs"
	"log"
	"path/filepath"
	"syscall"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
)

// SysBpfInterferenceCheck detects attempts to hide BPF programs/maps/links
// by forcing premature -ENOENT returns on *GET_NEXT_ID sys_bpf commands while
// objects remain accessible via pinned paths. It correlates syscall events
// (captured with tracepoints) with an independent walk of bpffs pinned objects.
type SysBpfInterferenceCheck struct {
	objs   *bpfObjects
	links  []link.Link
	reader *ringbuf.Reader
	debug  bool
}

// NewSysBpfInterferenceCheck creates a new sys_bpf interference detection check.
func NewSysBpfInterferenceCheck() *SysBpfInterferenceCheck {
	return &SysBpfInterferenceCheck{}
}

// SetDebug toggles debug output.
func (c *SysBpfInterferenceCheck) SetDebug(d bool) { c.debug = d }

// debugLog prints only when debug enabled.
func (c *SysBpfInterferenceCheck) debugLog(format string, args ...any) {
	if c.debug {
		timestamp := time.Now().Format("15:04:05.000")
		log.Printf("[HIDDEN-EBPF %s] "+format, append([]any{timestamp}, args...)...)
	}
}

// Name returns the Cell name.
func (c *SysBpfInterferenceCheck) Name() string { return "sys_bpf Interference" }

// Description explains the purpose of the Cell.
func (c *SysBpfInterferenceCheck) Description() string {
	return "Detects hidden BPF objects by correlating sys_bpf NEXT_ID enumeration with pinned program IDs"
}

// bpfEnumEvent mirrors struct bpf_enum_event in BPF program
type bpfEnumEvent struct {
	PID     uint32
	Cmd     uint32
	StartID uint32
	Ret     int32
	NextID  uint32
}

// Run performs detection of enumeration interference.
func (c *SysBpfInterferenceCheck) Run() (Result, error) {
	start := time.Now()
	res := Result{Status: StatusOK, Findings: []Finding{}}

	// Load BPF spec (already contains programs) and assign.
	spec, err := loadBpf()
	if err != nil {
		res.Status = StatusError
		res.Error = fmt.Errorf("failed to load BPF spec: %w", err)
		res.Duration = time.Since(start)
		return res, err
	}
	objs := &bpfObjects{}
	if err := spec.LoadAndAssign(objs, nil); err != nil {
		res.Status = StatusError
		res.Error = fmt.Errorf("failed to load BPF objects: %w", err)
		res.Duration = time.Since(start)
		return res, err
	}
	c.objs = objs

	// Attach tracepoints.
	tp1, err := link.Tracepoint("syscalls", "sys_enter_bpf", objs.TraceSysEnterBpf, nil)
	if err != nil {
		res.Status = StatusError
		res.Error = fmt.Errorf("failed to attach sys_enter_bpf: %w", err)
		res.Duration = time.Since(start)
		return res, err
	}
	tp2, err := link.Tracepoint("syscalls", "sys_exit_bpf", objs.TraceSysExitBpf, nil)
	if err != nil {
		tp1.Close()
		res.Status = StatusError
		res.Error = fmt.Errorf("failed to attach sys_exit_bpf: %w", err)
		res.Duration = time.Since(start)
		return res, err
	}
	c.links = []link.Link{tp1, tp2}

	rd, err := ringbuf.NewReader(objs.BpfEnumEvents)
	if err != nil {
		res.Status = StatusError
		res.Error = fmt.Errorf("failed to open ringbuf: %w", err)
		res.Duration = time.Since(start)
		return res, err
	}
	c.reader = rd

	// Collect events concurrently while we enumerate programs.
	events := make([]bpfEnumEvent, 0, 128)
	done := make(chan struct{})
	go func() {
		for {
			select {
			case <-done:
				return
			default:
			}

			rec, err := rd.Read()
			if err != nil {
				if errors.Is(err, ringbuf.ErrClosed) {
					return
				}
				continue
			}
			var ev bpfEnumEvent
			if err := binary.Read(bytes.NewReader(rec.RawSample), binary.LittleEndian, &ev); err == nil {
				events = append(events, ev)
			}
		}
	}()

	// Enumerate program IDs via syscalls (may be interfered).
	enumerated := make(map[uint32]bool)
	var startID ebpf.ProgramID = 0
	if c.debug {
		c.debugLog("Starting ProgramGetNextID enumeration")
	}
	for {
		nextID, err := ebpf.ProgramGetNextID(startID)
		if err != nil {
			if errors.Is(err, syscall.ENOENT) {
				// Enumeration ended.
				if c.debug {
					c.debugLog("Enumeration completed at start_id=%d (ENOENT)", startID)
				}
				break
			}
			// Unexpected error.
			res.Status = StatusError
			res.Error = fmt.Errorf("program enumeration failed: %w", err)
			close(done)
			rd.Close()
			res.Duration = time.Since(start)
			return res, err
		}
		enumerated[uint32(nextID)] = true
		startID = nextID
	}

	// Brief sleep to allow final events to be captured.
	time.Sleep(50 * time.Millisecond)

	// If debug: fetch info for each enumerated program.
	if c.debug {
		c.debugLog("Enumerated %d program IDs", len(enumerated))
		count := 0
		for id := range enumerated {
			prog, err := ebpf.NewProgramFromID(ebpf.ProgramID(id))
			if err != nil {
				c.debugLog("[ID=%d] failed to open program: %v", id, err)
				continue
			}
			info, err := prog.Info()
			prog.Close()
			if err != nil {
				c.debugLog("[ID=%d] failed to get info: %v", id, err)
				continue
			}
			ptype := info.Type
			name := info.Name
			c.debugLog("Prog ID=%d Type=%s Name=%s (enumerated)", id, ptype.String(), name)
			count++
			if count >= 200 { // cap verbose output
				c.debugLog("Output truncated after 200 programs...")
				break
			}
		}
	}

	// Stop event reader.
	close(done)
	time.Sleep(100 * time.Millisecond)

	// Gather pinned program IDs by traversing bpffs.
	pinnedProgIDs := make(map[uint32]string)
	filepath.WalkDir("/sys/fs/bpf", func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		// Try load as program.
		prog, perr := ebpf.LoadPinnedProgram(path, nil)
		if perr != nil {
			return nil
		}
		defer prog.Close()
		info, ierr := prog.Info()
		if ierr != nil {
			return nil
		}
		id, ok := info.ID()
		if ok {
			pinnedProgIDs[uint32(id)] = path
			if c.debug {
				ptype := info.Type
				name := info.Name
				c.debugLog("Pinned Prog ID=%d Path=%s Type=%s Name=%s", uint32(id), path, ptype.String(), name)
			}
		}
		return nil
	})

	// Identify hidden programs: pinned IDs not in enumerated set.
	hidden := make(map[uint32]string)
	for id, path := range pinnedProgIDs {
		if !enumerated[id] {
			hidden[id] = path
		}
	}
	if c.debug {
		c.debugLog("Pinned programs=%d Hidden (not enumerated)=%d", len(pinnedProgIDs), len(hidden))
		for id, path := range hidden {
			c.debugLog("HIDDEN Prog ID=%d Path=%s", id, path)
		}
	}

	// Analyze events for premature ENOENT.
	enoentCount := 0
	for _, ev := range events {
		if ev.Ret == -int32(syscall.ENOENT) { // usually -2
			enoentCount++
		}
	}

	if len(hidden) > 0 {
		res.Status = StatusSuspicious
		for id, path := range hidden {
			res.Findings = append(res.Findings, Finding{
				Description: fmt.Sprintf("BPF program ID %d pinned at %s not returned by ProgramGetNextID enumeration", id, path),
				Details: map[string]string{
					"program_id":    fmt.Sprintf("%d", id),
					"pinned_path":   path,
					"enum_size":     fmt.Sprintf("%d", len(enumerated)),
					"enoent_events": fmt.Sprintf("%d", enoentCount),
				},
			})
		}
		res.Message = fmt.Sprintf("Detected %d hidden BPF program(s); enumeration returned %d IDs", len(hidden), len(enumerated))
	} else {
		res.Message = fmt.Sprintf("Enumerated %d BPF program(s); no pinned hidden programs (ENOENT events=%d)", len(enumerated), enoentCount)
	}

	res.Duration = time.Since(start)
	return res, nil
}

// Cleanup releases all allocated resources (ringbuffer reader, tracepoint links, BPF objects).
func (c *SysBpfInterferenceCheck) Cleanup() error {
	if c.reader != nil {
		c.reader.Close()
	}
	for _, l := range c.links {
		if l != nil {
			l.Close()
		}
	}
	if c.objs != nil {
		c.objs.Close()
	}
	return nil
}
