package session

import (
	"context"
	"errors"
	"sync"
)

// Opt-in hook owned by the embedding node. No default registration exists.
// It starts immediately after authentication, before payload/sniffing/Mux can
// block, and completes only when the inbound handler has returned.
type CredentialTracker struct {
	Begin func(context.Context, byte) (context.Context, func(), error)
}

var credentialTrackers sync.Map

func InstallCredentialTracker(tag string, tracker *CredentialTracker) (func(), error) {
	if tag == "" || tracker == nil || tracker.Begin == nil {
		return nil, errors.New("invalid credential tracker")
	}
	if _, exists := credentialTrackers.LoadOrStore(tag, tracker); exists {
		return nil, errors.New("credential tracker already installed")
	}
	return func() { credentialTrackers.CompareAndDelete(tag, tracker) }, nil
}

func BeginCredentialTracking(ctx context.Context, command byte) (context.Context, func(), error) {
	in := InboundFromContext(ctx)
	if in != nil {
		if tracker, exists := credentialTrackers.Load(in.Tag); exists {
			return tracker.(*CredentialTracker).Begin(ctx, command)
		}
	}
	return ctx, func() {}, nil
}
