package main

import (
	"fmt"
	"os"
	"github.com/jessevdk/go-flags"
)

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
//	Expression map[string][]string
//	ExpressionCallback func(string) `short:"e" description:"a qualifying expression: option=[!]all or option=[!]val1[,val2]..." value-name:"expr"`
	OutputFile string `short:"o" description:"send trace output to FILE instead of stderr" value-name:"file"`
	Pid []uint `short:"p" description:"trace process with process id PID, may be repeated" value-name:"pid"`
    Program struct {
        Command   string  `description:"Command to execute" positional-arg-name:"PROG" required:"yes"`
        Arguments []string `description:"Arguments for the command" positional-arg-name:"ARGS"`
    } `positional-args:"yes"`
}

var opts Options

var parser = flags.NewParser(&opts, flags.Default)

func main() {
	if _, err := parser.Parse(); err != nil {
		os.Exit(1)
	}
	fmt.Println(opts)
}