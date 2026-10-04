//go:build !linux

package beupguard

import "errors"

func KernelBootStamp() (BootStamp, error) {
	return BootStamp{}, errors.New("production isolation runtime requires Linux boot clock")
}
