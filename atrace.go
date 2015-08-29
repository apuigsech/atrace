package main

import (
	"fmt"
	"os"
	"strconv"
	"errors"
	"sync"
	"syscall"
	"github.com/jessevdk/go-flags"
	"github.com/apuigsech/netlink/protocols/audit"
	"github.com/jroimartin/syscallinfo"
	"github.com/jroimartin/syscallinfo/linux_amd64"
)


type Atrace struct {
	al			*audit.AuditNLSocket
	key			string
	l_processes	sync.RWMutex
	processes	map[int]Process
}

type Process struct {
	syscalls	[]int
	recursive	bool
}


func NewATrace(cb audit.EventCallback) (*Atrace, error) {
	al,err := audit.OpenLink(0, 0)
	if err != nil {
		return nil,err
	}

	err = al.GetAuditEvents(true)
	if err  != nil {
		return nil,err
	}

	at := &Atrace{
		al: al,
		// TODO: Randomise
		key: "atrace-xxxxxxxx",
	}


	at.processes = map[int]Process{}

	// TODO:
	// need runtime.LockOSThread()?
	al.StartEventMonitor(cb, nil, at)

	return at,nil	
}


func (at *Atrace) AddProcess(pid int, scList []int, recursive bool) {
	rule := &audit.AuditRuleData{
		Flags:  audit.AUDIT_FILTER_EXIT,
		Action:	audit.AUDIT_ALWAYS,
	}

	for _,sc := range scList {
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

	process := Process{
		syscalls:	scList,
		recursive:	recursive,
	}

	at.l_processes.Lock()
	at.processes[pid] = process
	at.l_processes.Unlock()
}


func (at *Atrace) DelProcess(pid int) {
	at.l_processes.Lock()
	delete(at.processes, pid)
	at.l_processes.Unlock()
}


func (at *Atrace) TracePid(pid int, scList []int, recursive bool) {
	at.AddProcess(pid, scList, recursive)
}


func (at *Atrace) TraceCommand(argv []string, scList []int, recursive bool) (int) {
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



type Options struct {
	Count bool `short:"c" description:"count time, calls, and errors for each syscall and report summary"`
	CountOutput bool `short:"C" description:"like -c but also print regular output"`
	Debug bool `short:"d" description:"enable debug output to stderr"`
	FollowForks []bool `short:"f" description:"follow forks, -ff with output into separate files"`
	TimestampRelative bool `short:"r" description:"print relative timestamp"`
	TimestampAbsolute bool `short:"t" description:"print absolute timestamp, -tt with usecs"`
	PrintPaths bool `short:"y" description:"print paths associated with file descriptor arguments"`
	Version bool `short:"V" description:"print version"`
	AlignmentColumn uint `short:"a" description:"alignment COLUMN for printing syscall results" value-name:"column" default:"40"`
	OutputFile string `short:"o" description:"send trace output to FILE instead of stderr" value-name:"file"`
	Pid []int
	TracePid []bool `short:"p" description:"trace a PID instead of new COMMAND" value-name:"pid"`
    Command struct {
        Argv  []string `description:"Command to execute" positional-arg-name:"COMMAND/PIDs"`
    } `positional-args:"yes" required:"yes"`
}

var opts Options
var parser = flags.NewParser(&opts, flags.Default)

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
	pid,_ := ae.GetValueInt("pid", 10)
	syscallid,_ := ae.GetValueInt("syscall", 10)
	a0,_ := ae.GetValueInt("a0", 16)
	a1,_ := ae.GetValueInt("a1", 16)
	a2,_ := ae.GetValueInt("a2", 16)
	a3,_ := ae.GetValueInt("a3", 16)
	a4,_ := ae.GetValueInt("a4", 16)
	a5,_ := ae.GetValueInt("a5", 16)
	exit,_ := ae.GetValueInt("exit", 10)

	at,_ := args[0].(*Atrace)

	at.l_processes.Lock()
	process := at.processes[pid]
	at.l_processes.Unlock()

	// TODO: Review "task" auditd messages.
	switch syscallid {
	case syscall.SYS_EXIT:
		at.l_processes.Lock()
		delete(at.processes, pid)
		at.l_processes.Unlock()
	case syscall.SYS_CLONE, syscall.SYS_FORK, syscall.SYS_VFORK:
		fmt.Println(process)
		if process.recursive {
			at.AddProcess(exit, process.syscalls, process.recursive)
		}
	}

	scRes := syscallinfo.NewResolver(linux_amd64.SyscallTable)
	str,_ := scRes.Repr(syscallid, uint64(exit), uint64(a0), uint64(a1), uint64(a2), uint64(a3), uint64(a4), uint64(a5))

	fmt.Printf("[%d] %s\n", pid, str)
	os.Stdout.Sync()
}


func main() {
	if _, err := parser.Parse(); err != nil {
		os.Exit(1)
	}

	for i := 0 ; i < len(opts.TracePid); i++ {
			pid,_ := strconv.ParseUint(opts.Command.Argv[i], 10, 32)
			opts.Pid = append(opts.Pid, int(pid))
			opts.Command.Argv = opts.Command.Argv[1:]
	}

	recursive := false
	if len(opts.FollowForks) > 0 {
		recursive = true
	}

	at,_ := NewATrace(EventCallback)

	scList := []int{
		syscall.SYS_OPEN,
		syscall.SYS_READ,
		syscall.SYS_CLOSE,
		syscall.SYS_WRITE,
	}

	for _,pid := range opts.Pid {
		at.TracePid(pid, scList, recursive)
	} 
	if len(opts.Command.Argv) > 0 {
		at.TraceCommand(opts.Command.Argv, scList, recursive)
	}

	// TODO: Reliable cleanup.
	select{}
}