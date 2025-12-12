//go:build linux
// +build linux

package main

import (
	"os"
	"syscall"
)

// conditionalC2FailNotify tells the parent (stager/loader) to recycle us.
func conditionalC2FailNotify() {
	ppid := os.Getppid()
	_ = syscall.Kill(ppid, syscall.SIGTRAP)
}
