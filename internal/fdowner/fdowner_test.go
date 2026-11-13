package fdowner

import (
	"fmt"
	"testing"
	"time"
)

func TestHolders(t *testing.T) {
	tab := &Table{FDs: []FD{
		{TGID: 10, Kind: Prog, ID: 5, Comm: "loader"},
		{TGID: 11, Kind: Link, ID: 7, ProgID: 5, Comm: "agent"},
		{TGID: 12, Kind: Perf, ProgID: 5, Comm: "tracer"},
		{TGID: 10, Kind: Prog, ID: 5, Comm: "loader"}, // second descriptor
		{TGID: 13, Kind: Socket, Inode: 999, Comm: "sshd"},
		{TGID: 0, Kind: Socket, Inode: 999, Comm: "untranslatable"},
		{TGID: 14, Kind: Map, ID: 5, Comm: "mapper"},
	}}
	if got := Describe(tab.Holders(Prog, 5)); got != "10 (loader), 11 (agent), 12 (tracer)" {
		t.Errorf("program holders = %s", got)
	}
	if got := Describe(tab.Holders(Link, 7)); got != "11 (agent)" {
		t.Errorf("link holders = %s", got)
	}
	if got := Describe(tab.Holders(Socket, 999)); got != "13 (sshd)" {
		t.Errorf("socket holders = %s", got)
	}
	if got := Describe(tab.Holders(Map, 5)); got != "14 (mapper)" {
		t.Errorf("map holders = %s", got)
	}
	if len(tab.Holders(Socket, 1)) != 0 {
		t.Error("unknown socket has holders")
	}
}

// Ownership of every socket on a busy host must stay fast.
func TestHoldersScale(t *testing.T) {
	tab := &Table{}
	for i := 0; i < 200000; i++ {
		tab.FDs = append(tab.FDs, FD{TGID: uint32(i%500 + 1), Kind: Socket, Inode: uint64(i), Comm: fmt.Sprint(i % 500)})
	}
	start := time.Now()
	for i := 0; i < 100000; i++ {
		tab.Holders(Socket, uint64(i))
	}
	if d := time.Since(start); d > 5*time.Second {
		t.Fatalf("100k lookups took %v", d)
	}
}
