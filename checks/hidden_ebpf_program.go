package checks

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log"
	"path/filepath"
	"syscall"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
)

// HiddenEbpfProgramCheck detects attempts to hide BPF programs/maps/links
// by forcing premature -ENOENT returns on *GET_NEXT_ID sys_bpf commands while
// objects remain accessible via pinned paths. It correlates syscall events
// (captured with tracepoints) with an independent walk of bpffs pinned objects.
type HiddenEbpfProgramCheck struct {
	objs   *bpfObjects
	links  []link.Link
	reader *ringbuf.Reader
	debug  bool
}

// NewHiddenEbpfProgramCheck creates a new sys_bpf interference detection check.
func NewHiddenEbpfProgramCheck() *HiddenEbpfProgramCheck {
	return &HiddenEbpfProgramCheck{}
}

// SetDebug toggles debug output.
func (c *HiddenEbpfProgramCheck) SetDebug(d bool) { c.debug = d }

// debugLog prints only when debug enabled.
func (c *HiddenEbpfProgramCheck) debugLog(format string, args ...any) {
	if c.debug {
		timestamp := time.Now().Format("15:04:05.000")
		log.Printf("[HIDDEN-EBPF %s] "+format, append([]any{timestamp}, args...)...)
	}
}

// Name returns the Cell name.
func (c *HiddenEbpfProgramCheck) Name() string { return "Hidden eBPF Program Detection" }

// Description explains the purpose of the Cell.
func (c *HiddenEbpfProgramCheck) Description() string {
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

// bpfProgKernelInfo mirrors struct bpf_prog_kernel_info in BPF program
type bpfProgKernelInfo struct {
	ID       uint32
	ProgType uint32
	Name     [16]byte
}

// Run performs detection of enumeration interference.
func (c *HiddenEbpfProgramCheck) Run() (Result, error) {
	start := time.Now()
	res := Result{
		Cell:       "hidden_ebpf_program",
		Status:     StatusOK,
		Suspicious: []Finding{},
	}

	// Load BPF spec (already contains programs) and assign.
	spec, err := loadBpf()
	if err != nil {
		res.Status = StatusError
		res.SetError(fmt.Errorf("failed to load BPF spec: %w", err))
		res.SetDuration(time.Since(start))
		return res, err
	}
	objs := &bpfObjects{}
	if err := spec.LoadAndAssign(objs, nil); err != nil {
		res.Status = StatusError
		res.SetError(fmt.Errorf("failed to load BPF objects: %w", err))
		res.SetDuration(time.Since(start))
		return res, err
	}
	c.objs = objs

	// Step 1: Get ground truth from kernel via BPF iterator
	if c.debug {
		c.debugLog("Step 1: Collecting ground truth from kernel BPF iterator...")
	}
	kernelProgs, err := c.getKernelPrograms()
	if err != nil {
		res.Status = StatusError
		res.SetError(fmt.Errorf("failed to read kernel programs via iterator: %w", err))
		res.SetDuration(time.Since(start))
		return res, err
	}
	if c.debug {
		c.debugLog("Kernel ground truth: %d BPF programs", len(kernelProgs))
		count := 0
		for id, info := range kernelProgs {
			c.debugLog("  Kernel Prog ID=%d Type=%d Name=%s", id, info.ProgType, string(bytes.TrimRight(info.Name[:], "\x00")))
			count++
			if count >= 10 {
				c.debugLog("  ... (%d more programs)", len(kernelProgs)-10)
				break
			}
		}
	}

	// Step 2: Attach tracepoints (optional - may not be available on all kernels).
	tracepointsAvailable := false
	tp1, err := link.Tracepoint("syscalls", "sys_enter_bpf", objs.TraceSysEnterBpf, nil)
	if err != nil {
		if c.debug {
			c.debugLog("Warning: Could not attach sys_enter_bpf tracepoint: %v", err)
			c.debugLog("Continuing without syscall monitoring (detection still functional)")
		}
	} else {
		tp2, err := link.Tracepoint("syscalls", "sys_exit_bpf", objs.TraceSysExitBpf, nil)
		if err != nil {
			if c.debug {
				c.debugLog("Warning: Could not attach sys_exit_bpf tracepoint: %v", err)
				c.debugLog("Continuing without syscall monitoring (detection still functional)")
			}
			tp1.Close()
		} else {
			c.links = []link.Link{tp1, tp2}
			tracepointsAvailable = true
			if c.debug {
				c.debugLog("Successfully attached to sys_bpf tracepoints")
			}
		}
	}

	// Open ringbuf only if tracepoints are available
	if tracepointsAvailable {
		rd, err := ringbuf.NewReader(objs.BpfEnumEvents)
		if err != nil {
			res.Status = StatusError
			res.SetError(fmt.Errorf("failed to open ringbuf: %w", err))
			res.SetDuration(time.Since(start))
			return res, err
		}
		c.reader = rd
	}

	// Collect events concurrently while we enumerate programs (only if tracepoints available).
	events := make([]bpfEnumEvent, 0, 128)
	done := make(chan struct{})
	if c.reader != nil {
		go func() {
			for {
				select {
				case <-done:
					return
				default:
				}

				rec, err := c.reader.Read()
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
	}

	// Enumerate program IDs via syscalls (may be interfered).
	// We compare against kernel ground truth to detect premature ENOENT attacks.
	enumerated := make(map[uint32]bool)
	var startID ebpf.ProgramID = 0
	consecutiveErrors := 0
	maxConsecutiveErrors := 5
	totalAttempts := 0

	if c.debug {
		c.debugLog("Starting ProgramGetNextID enumeration (will validate against kernel ground truth)")
	}

	// Continue enumeration until we've tried enough or found all kernel programs
	for {
		totalAttempts++
		nextID, err := ebpf.ProgramGetNextID(startID)
		if err != nil {
			if errors.Is(err, syscall.ENOENT) {
				consecutiveErrors++
				if c.debug {
					c.debugLog("Got ENOENT at start_id=%d (consecutive: %d/%d)", startID, consecutiveErrors, maxConsecutiveErrors)
				}

				// If we've tried multiple times and kernel shows more programs exist,
				// this is likely interference. Try incrementing ID manually.
				if len(enumerated) < len(kernelProgs) && consecutiveErrors < maxConsecutiveErrors {
					// Skip to next ID and keep trying
					startID++
					if totalAttempts > len(kernelProgs)*2 {
						// Safety limit: tried enough times
						if c.debug {
							c.debugLog("Reached attempt limit (%d attempts), stopping enumeration", totalAttempts)
						}
						break
					}
					continue
				}

				// Multiple ENOENTs in a row or found all programs - stop
				if c.debug {
					c.debugLog("Enumeration completed: found %d/%d programs after %d attempts",
						len(enumerated), len(kernelProgs), totalAttempts)
				}
				break
			}
			// Unexpected error.
			res.Status = StatusError
			res.SetError(fmt.Errorf("program enumeration failed: %w", err))
			close(done)
			if c.reader != nil {
				c.reader.Close()
			}
			res.SetDuration(time.Since(start))
			return res, err
		}

		// Success - reset error counter
		consecutiveErrors = 0
		enumerated[uint32(nextID)] = true
		startID = nextID

		// If we've found all kernel programs, make one more call to get legitimate ENOENT
		if len(enumerated) >= len(kernelProgs) {
			if c.debug {
				c.debugLog("Found all %d kernel programs, making final call to verify enumeration end", len(kernelProgs))
			}
			// One more call should return ENOENT (natural end of enumeration)
			_, err := ebpf.ProgramGetNextID(startID)
			if err != nil && errors.Is(err, syscall.ENOENT) {
				totalAttempts++
				if c.debug {
					c.debugLog("Received expected ENOENT at end of enumeration")
				}
			}
			break
		}
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

	// Identify hidden programs using three-way comparison:
	// 1. Kernel ground truth (from BPF iterator) - cannot be hidden
	// 2. Userspace enumeration (ProgramGetNextID) - can be manipulated
	// 3. Pinned objects (/sys/fs/bpf) - filesystem view

	hiddenFromEnum := make(map[uint32]bpfProgKernelInfo) // In kernel but not in enumeration
	for id, info := range kernelProgs {
		if !enumerated[id] {
			hiddenFromEnum[id] = info
		}
	}

	hiddenPinned := make(map[uint32]string) // Pinned but not enumerated
	for id, path := range pinnedProgIDs {
		if !enumerated[id] {
			hiddenPinned[id] = path
		}
	}

	if c.debug {
		c.debugLog("Analysis Results:")
		c.debugLog("  Kernel ground truth: %d programs", len(kernelProgs))
		c.debugLog("  Userspace enumeration: %d programs", len(enumerated))
		c.debugLog("  Pinned programs: %d programs", len(pinnedProgIDs))
		c.debugLog("  Hidden from enumeration: %d programs", len(hiddenFromEnum))
		c.debugLog("  Pinned but hidden: %d programs", len(hiddenPinned))
		for id, info := range hiddenFromEnum {
			name := string(bytes.TrimRight(info.Name[:], "\x00"))
			c.debugLog("  HIDDEN: Prog ID=%d Type=%d Name=%s (in kernel, not in syscall enum)", id, info.ProgType, name)
		}
	}

	// Analyze events for premature/suspicious ENOENT.
	enoentCount := 0
	enoentBeforeCompletion := 0
	for _, ev := range events {
		if ev.Ret == -int32(syscall.ENOENT) {
			enoentCount++
			// ENOENT when start_id is low but programs still exist = suspicious
			if ev.StartID < uint32(len(kernelProgs)) {
				enoentBeforeCompletion++
			}
		}
	}

	// Calculate interference indicators
	coveragePercent := 0.0
	if len(kernelProgs) > 0 {
		coveragePercent = float64(len(enumerated)) / float64(len(kernelProgs)) * 100.0
	}
	suspiciousEnoent := enoentCount > 1 || (enoentCount == 1 && len(enumerated) < len(kernelProgs))

	if c.debug {
		c.debugLog("BPF Syscall Interference Analysis:")
		c.debugLog("  Total ENOENT events: %d", enoentCount)
		c.debugLog("  Suspicious ENOENTs (before completion): %d", enoentBeforeCompletion)
		c.debugLog("  Enumeration coverage: %.1f%% (%d/%d)", coveragePercent, len(enumerated), len(kernelProgs))
		c.debugLog("  Total enumeration attempts: %d", totalAttempts)
		if suspiciousEnoent {
			c.debugLog("  SUSPICIOUS: ENOENT pattern indicates interference!")
		}
	}

	if len(hiddenFromEnum) > 0 {
		res.Status = StatusSuspicious
		for id, info := range hiddenFromEnum {
			name := string(bytes.TrimRight(info.Name[:], "\x00"))
			pinnedPath := hiddenPinned[id]
			if pinnedPath == "" {
				pinnedPath = "not pinned"
			}

			res.Suspicious = append(res.Suspicious, Finding{
				Description: fmt.Sprintf("BPF program ID %d (%s) exists in kernel but hidden from ProgramGetNextID enumeration", id, name),
				Details: map[string]string{
					"program_id":        fmt.Sprintf("%d", id),
					"program_name":      name,
					"program_type":      fmt.Sprintf("%d", info.ProgType),
					"pinned_path":       pinnedPath,
					"kernel_count":      fmt.Sprintf("%d", len(kernelProgs)),
					"enum_count":        fmt.Sprintf("%d", len(enumerated)),
					"enum_coverage":     fmt.Sprintf("%.1f%%", coveragePercent),
					"enoent_total":      fmt.Sprintf("%d", enoentCount),
					"enoent_suspicious": fmt.Sprintf("%d", enoentBeforeCompletion),
					"enum_attempts":     fmt.Sprintf("%d", totalAttempts),
					"detection_method":  "BPF iterator (kernel ground truth)",
				},
			})
		}
		res.Message = fmt.Sprintf("ALERT: %d BPF program(s) hidden from userspace enumeration (kernel:%d vs enum:%d, coverage:%.1f%%, ENOENT:%d suspicious:%d)",
			len(hiddenFromEnum), len(kernelProgs), len(enumerated), coveragePercent, enoentCount, enoentBeforeCompletion)
	} else {
		res.Message = fmt.Sprintf("No hidden programs detected (kernel:%d, enum:%d, pinned:%d, ENOENT:%d)",
			len(kernelProgs), len(enumerated), len(pinnedProgIDs), enoentCount)
	}

	res.SetDuration(time.Since(start))
	return res, nil
}

// getKernelPrograms reads all BPF programs from the kernel using a BPF iterator.
// This provides the ground truth that cannot be hidden by syscall manipulation.
func (c *HiddenEbpfProgramCheck) getKernelPrograms() (map[uint32]bpfProgKernelInfo, error) {
	// Create iterator link
	iter, err := link.AttachIter(link.IterOptions{
		Program: c.objs.DumpBpfProg,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to attach BPF prog iterator: %w", err)
	}
	defer iter.Close()

	// Open the iterator file
	iterFile, err := iter.Open()
	if err != nil {
		return nil, fmt.Errorf("failed to open iterator: %w", err)
	}
	defer iterFile.Close()

	// Read all program info from iterator
	programs := make(map[uint32]bpfProgKernelInfo)
	buf := make([]byte, 4096)

	for {
		n, err := iterFile.Read(buf)
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("failed to read from iterator: %w", err)
		}

		// Parse the binary data
		reader := bytes.NewReader(buf[:n])
		for reader.Len() > 0 {
			var info bpfProgKernelInfo
			if err := binary.Read(reader, binary.LittleEndian, &info); err != nil {
				if err == io.EOF {
					break
				}
				return nil, fmt.Errorf("failed to parse program info: %w", err)
			}
			if info.ID > 0 { // Valid program ID
				programs[info.ID] = info
			}
		}
	}

	return programs, nil
}

// Cleanup releases all allocated resources (ringbuffer reader, tracepoint links, BPF objects).
func (c *HiddenEbpfProgramCheck) Cleanup() error {
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
