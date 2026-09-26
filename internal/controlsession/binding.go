// Package controlsession defines the nonsecret, immutable identity persisted
// with a run. Possession tokens and transport admission belong elsewhere.
package controlsession

import (
	"crypto/rand"
	"errors"
	"fmt"
	"io"

	"github.com/google/uuid"

	"github.com/netsec-ethz/debuglet/internal/ids"
)

// Binding identifies one session in one dispatcher incarnation. Both fields
// must be canonical lowercase, nonzero UUID strings. The value has no token.
type Binding struct {
	Incarnation string
	SessionID   string
}

func (b Binding) Valid() bool {
	return canonicalID(b.Incarnation) && canonicalID(b.SessionID)
}

func ParseBinding(incarnation, sessionID string) (Binding, error) {
	binding := Binding{Incarnation: incarnation, SessionID: sessionID}
	if !binding.Valid() {
		return Binding{}, errors.New("invalid control session binding")
	}
	return binding, nil
}

func NewIncarnation() (string, error) {
	return newIdentity(rand.Reader)
}

func NewBinding(incarnation string) (Binding, error) {
	return newBinding(incarnation, rand.Reader)
}

func newBinding(incarnation string, random io.Reader) (Binding, error) {
	if !canonicalID(incarnation) {
		return Binding{}, errors.New("invalid dispatcher incarnation")
	}
	sessionID, err := newIdentity(random)
	if err != nil {
		return Binding{}, err
	}
	return Binding{Incarnation: incarnation, SessionID: sessionID}, nil
}

// The reader is per call, so tests can exercise entropy failure without
// replacing crypto/rand.Reader or the UUID package's process-wide source.
func newIdentity(random io.Reader) (string, error) {
	id, err := uuid.NewRandomFromReader(random)
	if err != nil {
		return "", fmt.Errorf("generate control session identity: %w", err)
	}
	return id.String(), nil
}

func canonicalID(value string) bool {
	_, ok := ids.ParseCanonical(value)
	return ok
}
