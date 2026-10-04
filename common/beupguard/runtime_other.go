//go:build !linux && !darwin

package beupguard

import (
	"errors"
	"os"
)

func StartFromEnvironment() (func(), error) {
	if os.Getenv("BEUP_GUARD_CONFIG") != "" {
		return func() {}, errors.New("isolation unsupported on this OS")
	}
	return func() {}, nil
}
