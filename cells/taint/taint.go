// Package taint checks that the kernel's module-related taint flags are
// explained by the modules that are visible.
package taint

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/waldh4ri/zygarde/internal/core"
)

// flag is a taint bit that the kernel charges to a module
// (add_taint_module() in kernel/module/main.c; letters from kernel/panic.c).
type flag struct {
	bit    uint
	letter byte
	desc   string
}

var moduleFlags = []flag{
	{0, 'P', "proprietary module"},
	{1, 'F', "module force-loaded"},
	{10, 'C', "staging driver"},
	{12, 'O', "out-of-tree module"},
	{13, 'E', "unsigned module"},
	{15, 'K', "live patch"},
	{18, 'N', "test module"},
}

// Cell compares /proc/sys/kernel/tainted with /sys/module/*/taint.
//
// Loading a module sets its taint flags both on the module and on the
// kernel, and the kernel's flags stay set until reboot. A rootkit module
// that hides itself still leaves its taint behind: an out-of-tree (O) or
// unsigned (E) taint that no visible module carries points to a hidden
// module, or to one that was loaded and later unloaded.
type Cell struct {
	tainted   string
	sysModule string
}

// New returns the kernel taint Cell.
func New() *Cell { return &Cell{tainted: "/proc/sys/kernel/tainted", sysModule: "/sys/module"} }

func (*Cell) ID() string                    { return "kernel_taint" }
func (*Cell) Name() string                  { return "Kernel Taint Consistency" }
func (*Cell) Timeout() time.Duration        { return 15 * time.Second }
func (*Cell) Supported(env *core.Env) error { return nil }
func (*Cell) Description() string {
	return "Checks that module-related kernel taint flags are carried by a visible module"
}

func (c *Cell) Run(ctx context.Context, env *core.Env, rec *core.Recorder) error {
	data, err := os.ReadFile(c.tainted)
	if err != nil {
		return fmt.Errorf("reading %s: %w", c.tainted, err)
	}
	mask, err := strconv.ParseUint(strings.TrimSpace(string(data)), 10, 64)
	if err != nil {
		return fmt.Errorf("parsing %s: %w", c.tainted, err)
	}

	carriers, err := moduleTaints(c.sysModule)
	if err != nil {
		return err
	}

	var unexplained []flag
	for _, f := range moduleFlags {
		if mask&(1<<f.bit) == 0 {
			continue
		}
		if len(carriers[f.letter]) == 0 {
			unexplained = append(unexplained, f)
		}
	}

	for _, f := range unexplained {
		rec.Suspicious(fmt.Sprintf("Kernel is tainted '%c' (%s) but no visible module carries that taint", f.letter, f.desc),
			map[string]string{
				"taint":       string(f.letter),
				"meaning":     f.desc,
				"kernel_mask": strconv.FormatUint(mask, 10),
				"note":        "a module hiding itself, or one that was loaded and later unloaded (taint persists until reboot)",
			})
	}

	if len(unexplained) == 0 {
		rec.Message("%s", summary(mask, carriers))
	} else {
		rec.Message("%d module taint flag(s) not explained by any visible module", len(unexplained))
	}
	return nil
}

// moduleTaints maps each taint letter to the modules carrying it.
func moduleTaints(root string) (map[byte][]string, error) {
	entries, err := os.ReadDir(root)
	if err != nil {
		return nil, fmt.Errorf("listing %s: %w", root, err)
	}
	carriers := make(map[byte][]string)
	for _, e := range entries {
		data, err := os.ReadFile(filepath.Join(root, e.Name(), "taint"))
		if err != nil {
			continue // built-in modules have no taint attribute
		}
		for _, l := range []byte(strings.TrimSpace(string(data))) {
			carriers[l] = append(carriers[l], e.Name())
		}
	}
	return carriers, nil
}

func summary(mask uint64, carriers map[byte][]string) string {
	if mask == 0 {
		return "Kernel is not tainted"
	}
	var parts []string
	for _, f := range moduleFlags {
		if mask&(1<<f.bit) != 0 {
			mods := carriers[f.letter]
			sort.Strings(mods)
			parts = append(parts, fmt.Sprintf("%c: %s", f.letter, strings.Join(mods, ", ")))
		}
	}
	if len(parts) == 0 {
		return fmt.Sprintf("Kernel taint %d has no module-related flags", mask)
	}
	return "Module taints explained by visible modules (" + strings.Join(parts, "; ") + ")"
}
