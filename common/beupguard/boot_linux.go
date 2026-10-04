//go:build linux

package beupguard

import (
	"errors"
	"golang.org/x/sys/unix"
	"os"
	"strings"
)

func KernelBootStamp() (BootStamp, error) {
	b, e := os.ReadFile("/proc/sys/kernel/random/boot_id")
	if e != nil {
		return BootStamp{}, e
	}
	id := strings.TrimSpace(string(b))
	if len(id) != 36 {
		return BootStamp{}, errors.New("invalid kernel boot identity")
	}
	var stamp unix.Timespec
	if e = unix.ClockGettime(unix.CLOCK_BOOTTIME, &stamp); e != nil {
		return BootStamp{}, e
	}
	return BootStamp{ID: id, Nanos: stamp.Nano()}, nil
}
