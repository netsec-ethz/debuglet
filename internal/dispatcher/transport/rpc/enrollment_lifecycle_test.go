package rpc

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/netsec-ethz/debuglet/internal/dispatcher/database"
	"github.com/netsec-ethz/debuglet/internal/dispatcher/enrollment"
	"github.com/netsec-ethz/debuglet/internal/testtls"
	pb "github.com/netsec-ethz/debuglet/protocol"
	"github.com/pressly/goose/v3"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/status"
	_ "modernc.org/sqlite"
)

// enrolledControl runs both control listeners over real TLS, with the
// production enrollment store deciding node identities.
func enrolledControl(t *testing.T) (*controlTLS, *enrollment.Store, *countedNodes) {
	t.Helper()
	db, err := sql.Open("sqlite", filepath.Join(t.TempDir(), "dispatcher.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	db.SetMaxOpenConns(1)
	provider, err := goose.NewProvider(goose.DialectSQLite3, db, database.MigrationFS(),
		goose.WithDisableGlobalRegistry(true), goose.WithLogger(goose.NopLogger()))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := provider.Up(t.Context()); err != nil {
		t.Fatal(err)
	}
	store := enrollment.NewStore(db)
	nodes := &countedNodes{inner: store, refused: make(map[string]int), changed: make(chan struct{})}
	return newControlTLS(t, controlTLSOptions{requireClientIdentity: true, nodes: nodes}), store, nodes
}

// countedNodes reports each refusal, so a negative assertion waits for the
// decision rather than for a timeout to pass.
type countedNodes struct {
	inner   NodeAuthority
	mu      sync.Mutex
	refused map[string]int
	changed chan struct{}
}

func (n *countedNodes) Admit(ctx context.Context, executorID, fingerprint, token string) error {
	return n.record(executorID, n.inner.Admit(ctx, executorID, fingerprint, token))
}

func (n *countedNodes) Bound(ctx context.Context, executorID, fingerprint string) error {
	return n.record(executorID, n.inner.Bound(ctx, executorID, fingerprint))
}

func (n *countedNodes) record(executorID string, err error) error {
	if err != nil {
		n.mu.Lock()
		n.refused[executorID]++
		close(n.changed)
		n.changed = make(chan struct{})
		n.mu.Unlock()
	}
	return err
}

func (n *countedNodes) count(executorID string) int {
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.refused[executorID]
}

func (n *countedNodes) await(t *testing.T, executorID string, want int) {
	t.Helper()
	deadline := time.After(sessionTestWait)
	for {
		n.mu.Lock()
		refused, changed := n.refused[executorID], n.changed
		n.mu.Unlock()
		if refused >= want {
			return
		}
		select {
		case <-changed:
		case <-deadline:
			t.Fatalf("the authority refused %q %d times, want %d", executorID, refused, want)
		}
	}
}

// directCall places one direct-channel request over its own TLS connection,
// carrying the control metadata of an existing session. With another identity
// it is the peer that holds a session's token but not its node credential.
func (f *controlTLS) directCall(identity *testtls.Identity, owner *SessionOwner, call func(context.Context, pb.DispatcherServiceClient) error) error {
	f.t.Helper()
	gconn, err := grpc.NewClient(f.direct.Addr().String(),
		grpc.WithTransportCredentials(credentials.NewTLS(f.ca.ClientConfig(identity, ""))))
	if err != nil {
		f.t.Fatal(err)
	}
	defer gconn.Close()
	f.b.mu.RLock()
	offer := f.b.offers[owner.Binding().SessionID]
	f.b.mu.RUnlock()
	if offer == nil {
		f.t.Fatal("the session has no published offer")
	}
	ctx, cancel := context.WithTimeout(context.Background(), sessionTestWait)
	defer cancel()
	return call(offer.credentials.Outgoing(ctx), pb.NewDispatcherServiceClient(gconn))
}

// fingerprintOf names an issued identity the way the transport names the
// certificate it verified.
func fingerprintOf(identity *testtls.Identity) string {
	sum := sha256.Sum256(identity.Certificate.Certificate[0])
	return hex.EncodeToString(sum[:])
}

func heartbeat(ctx context.Context, client pb.DispatcherServiceClient) error {
	_, err := client.Heartbeat(ctx, &pb.HeartbeatRequest{ExecutorId: "executor"})
	return err
}

func issueToken(t *testing.T, store *enrollment.Store, executorID string) string {
	t.Helper()
	token, err := store.Issue(t.Context(), executorID, time.Hour)
	if err != nil {
		t.Fatalf("issue enrollment token: %v", err)
	}
	return token
}

// TestEnrollmentBindsBothControlChannels enrols one node with a single-use
// token and uses the session it opened in both directions. Its next session
// presents no token and is admitted by the recorded binding alone.
func TestEnrollmentBindsBothControlChannels(t *testing.T) {
	f, store, _ := enrolledControl(t)
	cfg := f.ca.ClientConfig(f.client, "")
	owned := f.connectedPeer(&lifecyclePeer{id: "executor", version: "A", token: issueToken(t, store, "executor")}, cfg)
	owner := f.registered("A")

	ctx, cancel := context.WithTimeout(context.Background(), sessionTestWait)
	defer cancel()
	if err := owned.client.WaitReadyContext(ctx); err != nil {
		t.Fatalf("bind acknowledgement for an enrolled node: %v", err)
	}
	if err := f.directCall(f.client, owner, heartbeat); err != nil {
		t.Fatalf("direct call from the enrolled node: %v", err)
	}
	reverse, ok := f.b.GetClientFor(owner)
	if !ok {
		t.Fatal("reverse client unavailable for an enrolled owner")
	}
	if _, err := reverse.Abort(ctx, &pb.AbortRequest{DebugletId: "fixture"}); err != nil {
		t.Fatalf("reverse call to the enrolled node: %v", err)
	}
	f.connectedPeer(&lifecyclePeer{id: "executor", version: "B"}, cfg)
	f.registered("B")
}

// TestEnrollmentRefusesUnenrolledNodes keeps a peer holding a certificate the
// authority issued, but no enrollment names, out of the control plane on both
// channels: under an ID nobody enrolled, and under the ID of a live node it is
// not the credential for. Neither evicts the healthy session.
func TestEnrollmentRefusesUnenrolledNodes(t *testing.T) {
	f, store, nodes := enrolledControl(t)
	f.connectedPeer(&lifecyclePeer{id: "executor", version: "A", token: issueToken(t, store, "executor")}, f.ca.ClientConfig(f.client, ""))
	owner := f.registered("A")
	other, err := f.ca.Issue("other", testtls.Options{Client: true})
	if err != nil {
		t.Fatalf("issue a second executor identity: %v", err)
	}

	f.connectedPeer(&lifecyclePeer{id: "stranger", version: "S"}, f.ca.ClientConfig(other, ""))
	nodes.await(t, "stranger", 1)
	f.connectedPeer(&lifecyclePeer{id: "executor", version: "D"}, f.ca.ClientConfig(other, ""))
	nodes.await(t, "executor", 1)
	if count := f.state.connectedCount(); count != 1 {
		t.Fatalf("connections that reached registration: %d", count)
	}
	if !owner.Available() {
		t.Fatal("a duplicate ID from an unenrolled certificate evicted the healthy node")
	}

	if err := f.directCall(other, owner, heartbeat); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("direct call carrying the session token from an unenrolled node: %v", err)
	}
	if err := f.directCall(f.client, owner, heartbeat); err != nil {
		t.Fatalf("direct call from the enrolled node: %v", err)
	}
}

// TestEnrollmentRotationAndRevocation replaces the credential bound to a live
// executor ID while its session is open, and then deletes the binding. The old
// session keeps the authority of the lease it holds and the messages its token
// fences, loses the lease at the next renewal, and is replaced when the node
// holding the new credential connects.
func TestEnrollmentRotationAndRevocation(t *testing.T) {
	f, store, nodes := enrolledControl(t)
	f.connectedPeer(&lifecyclePeer{id: "executor", version: "A", token: issueToken(t, store, "executor")}, f.ca.ClientConfig(f.client, ""))
	owner := f.registered("A")
	renew := func(identity *testtls.Identity, owner *SessionOwner, sequence uint64) error {
		return f.directCall(identity, owner, func(ctx context.Context, client pb.DispatcherServiceClient) error {
			_, err := client.RenewLease(ctx, &pb.RenewLeaseRequest{Sequence: sequence})
			return err
		})
	}
	if err := renew(f.client, owner, 1); err != nil {
		t.Fatalf("lease renewal for the enrolled node: %v", err)
	}

	rotated, err := f.ca.Issue("rotated", testtls.Options{Client: true})
	if err != nil {
		t.Fatalf("issue the replacement identity: %v", err)
	}
	if err := store.Admit(t.Context(), "executor", fingerprintOf(rotated), issueToken(t, store, "executor")); err != nil {
		t.Fatalf("rotate the node credential: %v", err)
	}
	if err := f.directCall(f.client, owner, heartbeat); err != nil {
		t.Fatalf("ordinary call on the lease the old session still holds: %v", err)
	}
	if err := renew(f.client, owner, 2); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("lease renewal after rotation: %v", err)
	}

	// Both sessions exist at this point: the old one is open on the credential
	// that was rotated out, and the new node registers over it.
	f.connectedPeer(&lifecyclePeer{id: "executor", version: "N"}, f.ca.ClientConfig(rotated, ""))
	current := f.registered("N")
	awaitSessionSignal(t, owner.Done())
	if !current.Available() {
		t.Fatal("the rotated-in node did not take the session over")
	}

	if removed, err := store.Revoke(t.Context(), "executor"); err != nil || !removed.Binding {
		t.Fatalf("revoke the enrollment: removed=%+v err=%v", removed, err)
	}
	if err := renew(rotated, current, 1); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("lease renewal after revocation: %v", err)
	}
	refusals := nodes.count("executor")
	f.connectedPeer(&lifecyclePeer{id: "executor", version: "R"}, f.ca.ClientConfig(rotated, ""))
	nodes.await(t, "executor", refusals+1)
	if count := f.state.connectedCount(); count != 2 {
		t.Fatalf("connections that reached registration: %d", count)
	}
}
