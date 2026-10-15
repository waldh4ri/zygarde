// Command zygarde detects Linux rootkits by comparing what the kernel knows
// (read with eBPF) with what userspace is shown.
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"slices"
	"strings"
	"syscall"

	"github.com/waldh4ri/zygarde/cells/bpfprog"
	"github.com/waldh4ri/zygarde/cells/file"
	"github.com/waldh4ri/zygarde/cells/hooks"
	"github.com/waldh4ri/zygarde/cells/integrity"
	"github.com/waldh4ri/zygarde/cells/kmodule"
	"github.com/waldh4ri/zygarde/cells/process"
	"github.com/waldh4ri/zygarde/cells/syscalltable"
	"github.com/waldh4ri/zygarde/cells/taint"
	"github.com/waldh4ri/zygarde/internal/canary"
	"github.com/waldh4ri/zygarde/internal/core"
	"github.com/waldh4ri/zygarde/internal/report"
	"github.com/waldh4ri/zygarde/internal/supervisor"
)

const version = "0.1.0"

type options struct {
	debug      bool
	json       bool
	verbose    bool
	noColor    bool
	output     string
	noIsolate  bool
	list       bool
	cells      string
	settings   core.Settings
	versionOut bool
}

func parseFlags(args []string) (options, error) {
	var o options
	fs := flag.NewFlagSet("zygarde", flag.ContinueOnError)
	fs.BoolVar(&o.debug, "d", false, "enable debug logging (shorthand)")
	fs.BoolVar(&o.debug, "debug", false, "enable debug logging on stderr")
	fs.BoolVar(&o.json, "json", false, "print the full report as JSON on stdout instead of text")
	fs.BoolVar(&o.verbose, "v", false, "also show what each check does, its observations and canaries")
	fs.BoolVar(&o.noColor, "no-color", false, "disable colors (also disabled when NO_COLOR is set or output is not a terminal)")
	fs.StringVar(&o.output, "o", "", "also save the JSON report to this file")
	fs.StringVar(&o.output, "output", "", "also save the JSON report to this file")
	fs.BoolVar(&o.noIsolate, "no-isolation", false, "run Cells in this process instead of a supervised worker")
	fs.BoolVar(&o.list, "list", false, "list available Cells and exit")
	fs.StringVar(&o.cells, "cells", "", "comma-separated Cell IDs to run (default: all)")
	fs.StringVar(&o.settings.BTFPath, "btf", "", "external BTF file for kernels without /sys/kernel/btf/vmlinux")
	fs.BoolVar(&o.versionOut, "version", false, "print the version and exit")
	return o, fs.Parse(args)
}

func allCells(o options) []core.Cell {
	return []core.Cell{
		integrity.New(), // first: later Cells' results depend on bpf() working
		syscalltable.New(),
		hooks.New(),
		kmodule.New(),
		taint.New(),
		process.New(),
		file.New(),
		bpfprog.New(),
	}
}

func selectCells(all []core.Cell, list string) ([]core.Cell, error) {
	if list == "" {
		return all, nil
	}
	var out []core.Cell
	for _, id := range strings.Split(list, ",") {
		i := slices.IndexFunc(all, func(c core.Cell) bool { return c.ID() == strings.TrimSpace(id) })
		if i < 0 {
			return nil, fmt.Errorf("unknown cell %q (see --list)", id)
		}
		out = append(out, all[i])
	}
	return out, nil
}

func main() {
	if os.Getenv(canary.RoleEnv) == canary.RoleProcess {
		canary.RunProcess()
	}
	os.Exit(run())
}

func run() int {
	o, err := parseFlags(os.Args[1:])
	if err != nil {
		return 1
	}
	level := slog.LevelWarn
	if o.debug {
		level = slog.LevelDebug
	}
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level}))

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	cells := allCells(o)
	if os.Getenv(canary.RoleEnv) == supervisor.RoleWorker {
		env := core.ProbeEnv(o.settings, log.With("pid", os.Getpid()))
		if err := supervisor.Worker(ctx, cells, env); err != nil {
			log.Error("worker failed", "err", err)
			return 1
		}
		return 0
	}

	switch {
	case o.versionOut:
		fmt.Println("zygarde", version)
		return 0
	case o.list:
		for _, c := range cells {
			fmt.Printf("%-24s %s\n", c.ID(), c.Description())
		}
		return 0
	}

	selected, err := selectCells(cells, o.cells)
	if err != nil {
		fmt.Fprintln(os.Stderr, "zygarde:", err)
		return 1
	}

	out := newPrinter(os.Stdout, o.json, o.verbose, colorEnabled(os.Stdout, o.noColor), termWidth(os.Stdout))
	if os.Geteuid() != 0 {
		return out.fatal("zygarde must run as root to load eBPF programs (try: sudo zygarde)")
	}
	rep := report.New(version)
	out.header(rep, selected)

	var results []core.Result
	cb := supervisor.Callbacks{Start: out.start, Result: out.result}
	if o.noIsolate {
		env := core.ProbeEnv(o.settings, log)
		for _, c := range selected {
			cb.Start(c)
			r := core.RunCell(ctx, env, c)
			cb.Result(r)
			results = append(results, r)
		}
	} else {
		results = supervisor.Supervise(ctx, selected, os.Args[1:], log, cb)
	}

	rep.Finish(results)
	saved := ""
	if o.output != "" {
		if err := saveReport(rep, o.output); err != nil {
			fmt.Fprintf(os.Stderr, "zygarde: saving report: %v\n", err)
		} else {
			saved = o.output
		}
	}
	out.summary(rep, saved)
	return rep.ExitCode()
}
