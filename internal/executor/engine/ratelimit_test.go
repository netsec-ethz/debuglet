package engine

import (
	"debuglet/internal/executor/resource"
	"fmt"
	"testing"

	"go.uber.org/zap"
)

func BenchmarkRatelimit(b *testing.B) {
	sugar := zap.NewNop().Sugar()

	registerMany := func(manager *resource.LimitManager) {
		for i := range 1_000_000 {
			manager.RegisterAssignment(fmt.Sprintf("other-%d", i), int64(i%5+1), int64(i%5+1))
		}
	}

	benchmark := func(direction resource.TransferDirection) func(b *testing.B) {
		env := newHostEnv(b.Context())
		env.manager = resource.New(1e15)
		env.manager.RegisterAssignment("session-1", 1e9, 1e9)
		env.handleToAddr[0] = "1.1.1.1"
		registerMany(env.manager)
		env.manager.Fairshare()

		return func(b *testing.B) {
			disableRatelimit = false
			for b.Loop() {
				if err := ratelimit(env, direction, 0, 1, sugar); err != nil {
					b.Fatalf("Expected no error, got %v", err)
				}
			}
		}
	}

	b.Run("Up", benchmark(resource.TransferOut))
	b.Run("Down", benchmark(resource.TransferIn))
}
