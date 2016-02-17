package main

import (
	"errors"
	"fmt"
	"os"
	"strconv"
	"sync"
	"syscall"
	"time"

	"github.com/apuigsech/netlink/protocols/audit"
	"github.com/jessevdk/go-flags"
	"github.com/jroimartin/syscallinfo"
	"github.com/jroimartin/syscallinfo/linux_amd64"
)

type Atrace struct {
	al           *audit.AuditNLSocket
	key          string
	l_processes  sync.RWMutex
	processes    map[int]*Process
	processesRun int
}

type Process struct {
	scList    []int
	recursive bool
	running   bool
	sccList   []*syscallinfo.SyscallCall
}

func NewATrace(cb audit.EventCallback) (*Atrace, error) {
	al, err := audit.OpenLink(0, 0)
	if err != nil {
		return nil, err
	}

	err = al.GetAuditEvents(true)
	if err != nil {
		return nil, err
	}

	at := &Atrace{
		al: al,
		// TODO: Randomise
		key: "atrace-xxxxxxxx",
	}

	at.processes = map[int]*Process{}

	// TODO:
	// need runtime.LockOSThread()?
	al.StartEventMonitor(cb, nil, at)

	return at, nil
}

func (at *Atrace) AddProcess(pid int, scList []int, recursive bool) {
	rule := &audit.AuditRuleData{
		Flags:  audit.AUDIT_FILTER_EXIT,
		Action: audit.AUDIT_ALWAYS,
	}

	for _, sc := range scList {
		rule.SetSyscall(sc)
	}

	if recursive {
		rule.SetSyscall(syscall.SYS_FORK)
		rule.SetSyscall(syscall.SYS_VFORK)
		rule.SetSyscall(syscall.SYS_CLONE)
		rule.SetSyscall(syscall.SYS_EXIT)
	}

	rule.SetField(audit.AUDIT_PID, pid, audit.AUDIT_EQUAL)
	rule.SetField(audit.AUDIT_FILTERKEY, at.key, audit.AUDIT_EQUAL)

	at.al.AddRule(rule)

	process := &Process{
		scList:    scList,
		recursive: recursive,
		running:   true,
	}
	process.sccList = make([]*syscallinfo.SyscallCall, 0)

	at.l_processes.Lock()
	at.processes[pid] = process
	at.processesRun++
	at.l_processes.Unlock()
}

func (at *Atrace) DelProcess(pid int) {
	at.l_processes.Lock()
	//delete(at.processes, pid)
	at.processesRun--
	at.l_processes.Unlock()
}

func (at *Atrace) TracePid(pid int, scList []int, recursive bool) {
	at.AddProcess(pid, scList, recursive)
}

func (at *Atrace) TraceCommand(argv []string, scList []int, recursive bool) int {
	pid, err := Fork()
	if err != nil {
		panic(err)
	}

	if pid == 0 {
		syscall.Kill(os.Getpid(), syscall.SIGSTOP)
		syscall.Exec(opts.Command.Argv[0], opts.Command.Argv, []string{})
	} else {
		var wstatus syscall.WaitStatus
		syscall.Wait4(pid, &wstatus, syscall.WUNTRACED, nil)
		at.AddProcess(pid, scList, recursive)
		syscall.Kill(pid, syscall.SIGCONT)
	}

	return pid
}


type TimestampType int

const (
	TSNone TimestampType = iota
	TSRelative
	TSAbsolute
	TSAbsoluteMS
)


type Options struct {
	Count             bool   `short:"c" description:"count time, calls, and errors for each syscall and report summary"`
	CountOutput       bool   `short:"C" description:"like -c but also print regular output"`
	Debug             bool   `short:"d" description:"enable debug output to stderr"`
	FollowForks       bool `short:"f" description:"follow forks"`
	TimestampRelative bool   `short:"r" description:"print relative timestamp"`
	TimestampAbsolute []bool   `short:"t" description:"print absolute timestamp, -tt with usecs"`
	ShowPaths        bool   `short:"y" description:"print paths associated with file descriptor arguments"`
	Version           bool   `short:"V" description:"print version"`
	AlignmentColumn   uint   `short:"a" description:"alignment COLUMN for printing syscall results" value-name:"column" default:"40"`
	OutputFile        string `short:"o" description:"send trace output to FILE instead of stderr" value-name:"file"`
	Pid 			  []int
	TracePid          []bool `short:"p" description:"trace a PID instead of new COMMAND" value-name:"pid"`

	Command struct {
		Argv []string `description:"Command to execute" positional-arg-name:"COMMAND/PIDs"`
	} `positional-args:"yes" required:"yes"`

	OutputItem struct {
		SyscallsList  bool
		SyscallsCount bool
	}

	Processed struct {
		ShowHelp    bool
		ShowVersion bool
		ShowCalls   bool
		ShowCount   bool
		Debug       bool
		FollowForks bool
		Timestamp   TimestampType
		ShowPaths   bool
		TracePid	bool
		TraceCommand bool
	}
}

var opts Options
var parser = flags.NewParser(&opts, flags.Default)

func ProcessOptions() {
	opts.Processed.ShowVersion = opts.Version

	opts.Processed.ShowCalls = true
	if opts.Count || opts.CountOutput {
		opts.Processed.ShowCount = true
		if !opts.CountOutput {
			opts.Processed.ShowCalls = false
		}
	}

	opts.Processed.Debug = opts.Debug 

	opts.Processed.FollowForks = opts.FollowForks

	opts.Processed.Timestamp = TSNone
	if opts.TimestampRelative {
		opts.Processed.Timestamp = TSRelative
	} else if len(opts.TimestampAbsolute) == 1 {
		opts.Processed.Timestamp = TSAbsolute
		} else if len(opts.TimestampAbsolute) > 1 {
			opts.Processed.Timestamp = TSAbsoluteMS
	}

	opts.Processed.ShowPaths = opts.ShowPaths 

	if len(opts.TracePid) > 0 {
		opts.Processed.TracePid = true
		for i := 0; i < len(opts.TracePid); i++ {
			pid, _ := strconv.ParseUint(opts.Command.Argv[i], 10, 32)
			opts.Pid = append(opts.Pid, int(pid))
			opts.Command.Argv = opts.Command.Argv[1:]
		}
	}

	if len(opts.Command.Argv) > 0 {
		opts.Processed.TraceCommand = true
	}

}

func Fork() (int, error) {
	//runtime_BeforeFork()
	pid, _, err := syscall.RawSyscall6(syscall.SYS_CLONE, uintptr(syscall.SIGCHLD), 0, 0, 0, 0, 0)
	if err != 0 {
		//runtime_AfterFork()
		return 0, errors.New("Fork Error")
	}
	if pid != 0 {
		//runtime_AfterFork()
		return int(pid), nil

	}
	return 0, nil
}

func EventCallback(ae *audit.AuditEvent, ce chan error, args ...interface{}) {
	at, _ := args[0].(*Atrace)

	pid, _ := ae.GetValueInt("pid", 10)
	scNR, _ := ae.GetValueInt("syscall", 10)
	a0, _ := ae.GetValueInt("a0", 16)
	a1, _ := ae.GetValueInt("a1", 16)
	a2, _ := ae.GetValueInt("a2", 16)
	a3, _ := ae.GetValueInt("a3", 16)
	a4, _ := ae.GetValueInt("a4", 16)
	a5, _ := ae.GetValueInt("a5", 16)
	exit, _ := ae.GetValueInt("exit", 10)

	r := syscallinfo.NewResolver(linux_amd64.SyscallTable)
	sc, err := r.SyscallN(scNR)
	if err != nil {
		return
	}

	scc, err := syscallinfo.NewSyscallCall(sc, uint64(exit), uint64(a0), uint64(a1), uint64(a2), uint64(a3), uint64(a4), uint64(a5))
	if err != nil {
		return
	}

	at.l_processes.Lock()
	process := at.processes[pid]
	process.sccList = append(process.sccList, scc)
	//fmt.Println(">", process.sccList)
	at.l_processes.Unlock()

	switch scNR {
	case syscall.SYS_EXIT:
		at.l_processes.Lock()
		//delete(at.processes, pid)
		at.l_processes.Unlock()
	case syscall.SYS_CLONE, syscall.SYS_FORK, syscall.SYS_VFORK:
		//if process.recursive {
		at.AddProcess(exit, process.scList, process.recursive)
		//}
	}

	fmt.Printf("[%v] %v\n", pid, scc)
	os.Stdout.Sync()
}

func main() {
	if _, err := parser.Parse(); err != nil {
		os.Exit(1)
	}

	ProcessOptions()

	at, _ := NewATrace(EventCallback)

	scList := []int{
		syscall.SYS_WRITE,
		syscall.SYS_CLONE,
		syscall.SYS_FORK,
		syscall.SYS_EXIT,
		syscall.SYS_EXECVE,
	}


	fmt.Println(opts.Processed)

	if opts.Processed.TracePid  {
		for _, pid := range opts.Pid {
			at.TracePid(pid, scList, opts.Processed.FollowForks)
		}
	}

	if opts.Processed.TraceCommand {
		at.TraceCommand(opts.Command.Argv, scList, opts.Processed.FollowForks)
	}

	// TODO: Reliable cleanup.
	//select{}
	time.Sleep(5 * time.Second)

	for _, v := range at.processes {
		for _, scc := range v.sccList {
			fmt.Println(scc.Syscall().Entry)
		}
	}
}
