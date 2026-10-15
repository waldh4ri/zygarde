// Command fixture attaches benign BPF programs where eBPF rootkits attach
// theirs, and opens a TCP listener, so the kernel matrix can check that
// zygarde inventories them and attributes them to this process.
//
// It attaches: a tracepoint on syscalls/sys_enter_getdents64, a kprobe on
// getppid's handler, an XDP program on lo and a tc egress program on lo
// (tcx on Linux 6.6+, otherwise a clsact filter through tc(8)). Every
// program does nothing. It also starts a child process disguised as a
// kernel thread ("[kworker/0:7]"). It prints "ready" once set up and runs
// until stdin closes or it receives SIGTERM.
//
// usage: fixture [-port 34567]
package main

import (
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"syscall"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
	"golang.org/x/sys/unix"
)

const pinPath = "/sys/fs/bpf/zyg_fixture_tc"

// kthreadName is the disguise of the masquerading child.
const kthreadName = "kworker/0:7"

const roleEnv = "ZYG_FIXTURE_ROLE"

// init runs on the main thread, whose name is the process name.
func init() {
	if os.Getenv(roleEnv) != "kthread" {
		return
	}
	name := append([]byte(kthreadName), 0)
	unix.Prctl(unix.PR_SET_NAME, uintptr(unsafe.Pointer(&name[0])), 0, 0, 0)
	io.Copy(io.Discard, os.Stdin)
	os.Exit(0)
}

func program(name string, typ ebpf.ProgramType, ret int32) (*ebpf.Program, error) {
	return ebpf.NewProgram(&ebpf.ProgramSpec{
		Name:         name,
		Type:         typ,
		License:      "GPL",
		Instructions: asm.Instructions{asm.Mov.Imm(asm.R0, ret), asm.Return()},
	})
}

func main() {
	port := flag.Int("port", 34567, "TCP port to listen on (127.0.0.1)")
	flag.Parse()
	_ = rlimit.RemoveMemlock()

	var closers []io.Closer
	defer func() {
		for _, c := range closers {
			c.Close()
		}
		exec.Command("tc", "qdisc", "del", "dev", "lo", "clsact").Run()
		os.Remove(pinPath)
	}()
	warn := func(what string, err error) { fmt.Fprintf(os.Stderr, "fixture: %s: %v\n", what, err) }

	if p, err := program("zyg_fx_tp", ebpf.TracePoint, 0); err != nil {
		warn("load tracepoint program", err)
	} else if l, err := link.Tracepoint("syscalls", "sys_enter_getdents64", p, nil); err != nil {
		warn("attach tracepoint", err)
	} else {
		closers = append(closers, p, l)
	}

	if p, err := program("zyg_fx_kprobe", ebpf.Kprobe, 0); err != nil {
		warn("load kprobe program", err)
	} else if l, err := link.Kprobe("sys_getppid", p, nil); err != nil {
		warn("attach kprobe", err)
	} else {
		closers = append(closers, p, l)
	}

	lo, err := net.InterfaceByName("lo")
	if err != nil {
		warn("lo", err)
		os.Exit(1)
	}
	if p, err := program("zyg_fx_xdp", ebpf.XDP, 2 /* XDP_PASS */); err != nil {
		warn("load XDP program", err)
	} else if l, err := link.AttachXDP(link.XDPOptions{Program: p, Interface: lo.Index, Flags: link.XDPGenericMode}); err != nil {
		warn("attach XDP", err)
	} else {
		closers = append(closers, p, l)
	}

	if p, err := program("zyg_fx_tc", ebpf.SchedCLS, -1 /* TC_ACT_UNSPEC / TCX_NEXT */); err != nil {
		warn("load tc program", err)
	} else if l, err := link.AttachTCX(link.TCXOptions{Program: p, Interface: lo.Index, Attach: ebpf.AttachTCXEgress}); err == nil {
		closers = append(closers, p, l)
	} else {
		// Before tcx: a clsact egress filter, through tc(8) and a pin.
		closers = append(closers, p)
		os.Remove(pinPath)
		if err := p.Pin(pinPath); err != nil {
			warn("pin tc program", err)
		} else {
			exec.Command("tc", "qdisc", "add", "dev", "lo", "clsact").Run()
			if out, err := exec.Command("tc", "filter", "add", "dev", "lo", "egress", "bpf", "da", "pinned", pinPath).CombinedOutput(); err != nil {
				warn("tc filter add", fmt.Errorf("%v: %s", err, out))
			}
		}
	}

	kt := exec.Command("/proc/self/exe")
	kt.Args[0] = "[" + kthreadName + "]"
	kt.Env = append(os.Environ(), roleEnv+"=kthread")
	if stdin, err := kt.StdinPipe(); err != nil {
		warn("masquerading child", err)
	} else if err := kt.Start(); err != nil {
		warn("masquerading child", err)
	} else {
		closers = append(closers, stdin) // the child exits when this closes
	}

	ln, err := net.Listen("tcp4", fmt.Sprintf("127.0.0.1:%d", *port))
	if err != nil {
		warn("listen", err)
	} else {
		closers = append(closers, ln)
	}

	fmt.Println("ready")
	done := make(chan struct{})
	go func() { io.Copy(io.Discard, os.Stdin); close(done) }()
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGTERM, syscall.SIGINT)
	select {
	case <-done:
	case <-sig:
	}
}
