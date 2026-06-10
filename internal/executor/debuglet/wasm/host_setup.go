package wasm

import (
	"context"
	"fmt"

	"github.com/wasmerio/wasmer-go/wasmer"
)

// HostEnvironment carries the execution context for the current debuglet
// session. It is passed by value to each host function.
type HostEnvironment struct {
	ctx          context.Context
	sessionID    string
	handleToAddr map[int32]string
}

func NewHostEnvironment(debugletID string) *HostEnvironment {
	return &HostEnvironment{
		sessionID:    debugletID,
		handleToAddr: make(map[int32]string),
	}
}

func (h *HostEnvironment) SetContext(ctx context.Context) {
	h.ctx = ctx
}

// checkContextExpired returns a descriptive error if the HostEnvironment's
// context has been cancelled or has exceeded its deadline.
func checkContextExpired(env *HostEnvironment) error {
	if env == nil {
		return nil
	}
	select {
	case <-env.ctx.Done():
	default:
		return nil
	}
	switch err := env.ctx.Err(); err {
	case context.DeadlineExceeded:
		return fmt.Errorf("debuglet exceeded maximum allowed runtime")
	default:
		return fmt.Errorf("debuglet context cancelled: %w", err)
	}
}

// hostFunction is the function signature expected by wasmer's import mechanism, but with stricter typing for the environment
type hostFunction func(environment *HostEnvironment, args []wasmer.Value) ([]wasmer.Value, error)

// wrapHostFn wraps a hostFunction with the session's HostEnvironment and
// converts it into a *wasmer.Function ready for registration.
func (host *HostEnvironment) WrapHostFn(store *wasmer.Store, input, output []*wasmer.ValueType, fn hostFunction) *wasmer.Function {
	fnTyped := func(environment interface{}, args []wasmer.Value) ([]wasmer.Value, error) {
		return fn(environment.(*HostEnvironment), args)
	}
	return wasmer.NewFunctionWithEnvironment(store, wasmer.NewFunctionType(input, output), host, fnTyped)
}
