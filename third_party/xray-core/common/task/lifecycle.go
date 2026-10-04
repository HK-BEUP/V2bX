package task

import "context"

// Lifecycle is an optional accounting observer. A caller's return does not
// imply every child has finished; each child registers before being started.
type Lifecycle interface{ Begin() (func(), error) }
type lifecycleKey struct{}

func WithLifecycle(ctx context.Context, observer Lifecycle) context.Context {
	return context.WithValue(ctx, lifecycleKey{}, observer)
}
func beginLifecycle(ctx context.Context) (func(), error) {
	if observer, ok := ctx.Value(lifecycleKey{}).(Lifecycle); ok && observer != nil {
		return observer.Begin()
	}
	return func() {}, nil
}

// BeginLifecycle reserves completion before an asynchronous child is launched.
// Callers must release it after the last possible accounting write.
func BeginLifecycle(ctx context.Context) (func(), error) { return beginLifecycle(ctx) }
func HasLifecycle(ctx context.Context) bool {
	v, ok := ctx.Value(lifecycleKey{}).(Lifecycle)
	return ok && v != nil
}
func StartLifecycle(ctx context.Context, run func()) error {
	finished, err := beginLifecycle(ctx)
	if err != nil {
		return err
	}
	go func() { defer finished(); run() }()
	return nil
}
