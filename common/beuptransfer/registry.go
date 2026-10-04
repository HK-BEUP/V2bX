package beuptransfer

import (
	"errors"
	"sync"
)

var adapters sync.Map

// Install is called only before loading users for a specifically opted-in
// inbound. No environment variable or default path enables this candidate.
func Install(tag string, a *GuardAdapter) error {
	if a == nil || a.tag != tag {
		return ErrCoverage
	}
	if _, exists := adapters.LoadOrStore(tag, a); exists {
		return errors.New("transfer adapter already installed")
	}
	return nil
}
func ForTag(tag string) *GuardAdapter {
	if v, ok := adapters.Load(tag); ok {
		return v.(*GuardAdapter)
	}
	return nil
}
func Remove(tag string, a *GuardAdapter) {
	if a == nil {
		return
	}
	a.NoteCoverageFailure()
	adapters.CompareAndDelete(tag, a)
}
