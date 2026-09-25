package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/netsec-ethz/debuglet/pkg/client"
)

// logPage builds a wire log page; entries are (id, bytes) pairs.
func logPage(state string, after int64, hasMore bool, entries ...any) map[string]any {
	logs := []map[string]any{}
	for i := 0; i+1 < len(entries); i += 2 {
		logs = append(logs, map[string]any{
			"id":        entries[i],
			"timestamp": "2026-09-08T12:00:00Z",
			"output":    base64.StdEncoding.EncodeToString(entries[i+1].([]byte)),
		})
	}
	return map[string]any{"state": state, "error": "", "after": after, "logs": logs, "has_more": hasMore}
}

// logScript serves successive pages keyed by request number; the last page
// repeats. It returns the fixture and a request counter.
func logScript(t *testing.T, pages ...any) (*fixture, *atomic.Int64) {
	t.Helper()
	var n atomic.Int64
	mux := http.NewServeMux()
	mux.HandleFunc("GET /debuglet/{id}/logs", func(w http.ResponseWriter, r *http.Request) {
		i := int(n.Add(1)) - 1
		if i >= len(pages) {
			i = len(pages) - 1
		}
		switch p := pages[i].(type) {
		case string:
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(p))
		default:
			writeJSONResponse(w, http.StatusOK, p)
		}
	})
	return newFixture(t, mux), &n
}

// fakePages is an in-process page source for followLogs. Its pages honour the
// cursor contract the SDK guarantees, and it fails after a small call budget so
// a follow loop that does not stop fails on an assertion instead of spinning.
func fakePages(pages ...client.LogPage) (logFetcher, *[]client.LogOptions) {
	var requests []client.LogOptions
	return func(ctx context.Context, o client.LogOptions) (client.LogPage, error) {
		if len(requests) >= 16 {
			return client.LogPage{}, errors.New("fake page source: call budget exhausted (follow loop did not stop)")
		}
		requests = append(requests, o)
		i := len(requests) - 1
		if i >= len(pages) {
			i = len(pages) - 1
		}
		return pages[i], nil
	}, &requests
}

func entry(id int64, output string) client.LogEntry {
	return client.LogEntry{ID: id, Timestamp: "t", Output: []byte(output)}
}

func TestCLILogFollow(t *testing.T) {
	bg := context.Background()
	bin1 := []byte{0, 255, '\n', 'a'}
	bin2 := []byte{'b', 0, 0, '\r'}
	bin3 := []byte("tail")

	t.Run("single page without follow", func(t *testing.T) {
		fx, count := logScript(t, logPage("RunStateStarted", 2, true, 1, bin1, 2, bin2))
		code, stdout, stderr := runCLI(bg, "--endpoint", fx.endpoint(), "logs", "--limit", "2", fixJobID)
		assertCode(t, code, exitOK, stdout, stderr)
		if stdout != string(append(append([]byte{}, bin1...), bin2...)) {
			t.Fatalf("human stdout %q is not the exact guest bytes", stdout)
		}
		if !strings.Contains(stderr, "after=2") || !strings.Contains(stderr, "state=RunStateStarted") || !strings.Contains(stderr, "has_more=true") {
			t.Fatalf("cursor/state info missing from stderr: %q", stderr)
		}
		if count.Load() != 1 {
			t.Fatalf("%d requests, want exactly one page", count.Load())
		}
		req, _ := fx.last("GET", "/debuglet/")
		if req.Query != "after=0&limit=2" {
			t.Fatalf("query %q", req.Query)
		}
		code, stdout, stderr = runCLI(bg, "--endpoint", fx.endpoint(), "--output", "json", "logs", "--after", "2", fixJobID)
		// The scripted page repeats: entries 1,2 for cursor 2 do not advance.
		assertCode(t, code, exitFailure, stdout, stderr)
		if stdout != "" {
			t.Fatalf("invalid page must not be printed: %q", stdout)
		}
	})

	t.Run("single page JSON prints the LogPage", func(t *testing.T) {
		fx, _ := logScript(t, logPage("RunStateExited", 1, false, 1, bin1))
		code, stdout, stderr := runCLI(bg, "--endpoint", fx.endpoint(), "--output", "json", "logs", fixJobID)
		assertCode(t, code, exitOK, stdout, stderr)
		if stderr != "" {
			t.Fatalf("JSON mode wrote progress to stderr: %q", stderr)
		}
		var page client.LogPage
		if err := json.Unmarshal([]byte(stdout), &page); err != nil {
			t.Fatal(err)
		}
		if page.State != client.StateExited || page.After != 1 || len(page.Logs) != 1 || !bytes.Equal(page.Logs[0].Output, bin1) {
			t.Fatalf("unexpected page %+v", page)
		}
		oneJSONDocument(t, stdout)
	})

	t.Run("follow drains has_more pages and the trailing empty page", func(t *testing.T) {
		fx, count := logScript(t,
			logPage("RunStateStarted", 2, true, 1, bin1, 2, bin2),
			logPage("RunStateExited", 3, true, 3, bin3), // full terminal page claims more
			logPage("RunStateExited", 3, false),         // permitted empty page ends the follow
		)
		code, stdout, stderr := runCLI(bg, "--endpoint", fx.endpoint(), "logs", "--follow", "--limit", "2", fixJobID)
		assertCode(t, code, exitOK, stdout, stderr)
		want := append(append(append([]byte{}, bin1...), bin2...), bin3...)
		if !bytes.Equal([]byte(stdout), want) {
			t.Fatalf("stdout %q, want %q", stdout, want)
		}
		if count.Load() != 3 {
			t.Fatalf("%d requests, want 3", count.Load())
		}
		req, _ := fx.last("GET", "/debuglet/")
		if req.Query != "after=3&limit=2" {
			t.Fatalf("last query %q, cursor must resume from the last delivered ID", req.Query)
		}
	})

	t.Run("follow polls empty nonterminal pages until terminal", func(t *testing.T) {
		shortPoll(t)
		fx, count := logScript(t,
			logPage("RunStateStarted", 0, false),
			logPage("RunStateStarted", 0, false),
			logPage("RunStateExited", 5, false, 5, bin3),
		)
		code, stdout, stderr := runCLI(bg, "--endpoint", fx.endpoint(), "logs", "--follow", fixJobID)
		assertCode(t, code, exitOK, stdout, stderr)
		if stdout != "tail" {
			t.Fatalf("stdout %q", stdout)
		}
		if count.Load() != 3 {
			t.Fatalf("%d requests, want 3 (two empty polls then the terminal page)", count.Load())
		}
	})

	t.Run("follow JSON emits NDJSON only", func(t *testing.T) {
		fx, _ := logScript(t,
			logPage("RunStateStarted", 1, true, 1, bin1),
			logPage("RunStateExited", 2, false, 2, bin2),
		)
		code, stdout, stderr := runCLI(bg, "--endpoint", fx.endpoint(), "--output", "json", "logs", "--follow", fixJobID)
		assertCode(t, code, exitOK, stdout, stderr)
		if stderr != "" {
			t.Fatalf("JSON follow wrote to stderr: %q", stderr)
		}
		lines := strings.Split(strings.TrimSuffix(stdout, "\n"), "\n")
		if len(lines) != 2 {
			t.Fatalf("want 2 NDJSON lines, got %d: %q", len(lines), stdout)
		}
		for i, line := range lines {
			var page client.LogPage
			if err := json.Unmarshal([]byte(line), &page); err != nil {
				t.Fatalf("line %d is not a LogPage: %v", i, err)
			}
			if page.After != int64(i+1) || len(page.Logs) != 1 {
				t.Fatalf("line %d unexpected page %+v", i, page)
			}
		}
	})

	t.Run("backward or non-progressing cursors fail explicitly", func(t *testing.T) {
		cases := map[string][]any{
			"backward id":         {logPage("RunStateStarted", 6, true, 5, bin1, 6, bin2), logPage("RunStateStarted", 4, true, 4, bin3)},
			"repeated id":         {logPage("RunStateStarted", 6, true, 5, bin1, 6, bin2), logPage("RunStateStarted", 6, true, 6, bin3)},
			"cursor below last":   {logPage("RunStateStarted", 5, true, 5, bin1, 6, bin2)},
			"empty cursor moved":  {logPage("RunStateStarted", 3, false)},
			"empty with has_more": {logPage("RunStateStarted", 0, true)},
			"unordered in page":   {logPage("RunStateStarted", 2, false, 2, bin1, 1, bin2)},
		}
		for name, pages := range cases {
			fx, _ := logScript(t, pages...)
			code, stdout, stderr := runCLI(bg, "--endpoint", fx.endpoint(), "--output", "json", "logs", "--follow", fixJobID)
			if code != exitFailure {
				t.Errorf("%s: exit %d, want %d\nstderr: %q", name, code, exitFailure, stderr)
			}
			if stderr == "" {
				t.Errorf("%s: failure not explained", name)
			}
			_ = stdout
		}
	})

	t.Run("the follow loop resumes its cursor, stops and propagates failures", func(t *testing.T) {
		shortPoll(t)
		// Drain a has_more page, poll an empty nonterminal one, drain the
		// full terminal page and stop on the permitted empty page after it.
		// Each page's cursor is one the SDK delivers, and the loop resumes
		// from the last ID it was given.
		fetch, requests := fakePages(
			client.LogPage{State: "RunStateStarted", After: 2, HasMore: true, Logs: []client.LogEntry{entry(1, "a"), entry(2, "b")}},
			client.LogPage{State: "RunStateStarted", After: 2},
			client.LogPage{State: client.StateExited, After: 3, HasMore: true, Logs: []client.LogEntry{entry(3, "c")}},
			client.LogPage{State: client.StateExited, After: 3},
		)
		var emitted []client.LogPage
		emit := func(p client.LogPage) error { emitted = append(emitted, p); return nil }
		if err := followLogs(bg, fetch, 0, 7, emit); err != nil {
			t.Fatal(err)
		}
		if len(*requests) != 4 || len(emitted) != 4 {
			t.Fatalf("requests %d emitted %d", len(*requests), len(emitted))
		}
		for i, want := range []int64{0, 2, 2, 3} {
			if (*requests)[i].After != want || (*requests)[i].Limit != 7 {
				t.Fatalf("request %d %+v, want after %d limit 7", i, (*requests)[i], want)
			}
		}
		// Fetch errors propagate and the context classifies them.
		expired, cancel := context.WithDeadline(bg, time.Now().Add(-time.Second))
		defer cancel()
		err := followLogs(expired, func(context.Context, client.LogOptions) (client.LogPage, error) {
			return client.LogPage{}, context.DeadlineExceeded
		}, 0, 0, emit)
		if !errors.Is(err, context.DeadlineExceeded) || failureExit(expired) != exitDeadline {
			t.Fatalf("deadline during follow: %v", err)
		}
	})

	t.Run("corrupt base64 fails", func(t *testing.T) {
		fx, _ := logScript(t, `{"state":"RunStateExited","error":"","after":1,"logs":[{"id":1,"timestamp":"t","output":"!!!notbase64"}],"has_more":false}`)
		for _, args := range [][]string{{"logs", fixJobID}, {"logs", "--follow", fixJobID}} {
			code, stdout, stderr := runCLI(bg, append([]string{"--endpoint", fx.endpoint()}, args...)...)
			if code != exitFailure {
				t.Errorf("%q: exit %d, want %d\nstderr: %q", args, code, exitFailure, stderr)
			}
			if stdout != "" {
				t.Errorf("%q: corrupt output must not be printed: %q", args, stdout)
			}
		}
	})

	t.Run("follow deadline and interruption map to 124 and 130", func(t *testing.T) {
		fx, _ := logScript(t, logPage("RunStateStarted", 0, false))
		mux := http.NewServeMux()
		mux.HandleFunc("GET /debuglet/{id}/logs", blockUntilGone)
		blocking := newFixture(t, mux)
		code, stdout, stderr := runCLI(bg, "--endpoint", blocking.endpoint(), "--timeout", "300ms", "logs", "--follow", fixJobID)
		assertCode(t, code, exitDeadline, stdout, stderr)

		parent, interrupt := context.WithCancel(bg)
		defer interrupt()
		interrupt()
		code, stdout, stderr = runCLI(parent, "--endpoint", fx.endpoint(), "logs", "--follow", fixJobID)
		assertCode(t, code, exitInterrupted, stdout, stderr)
		if n := fx.count("DELETE", "/debuglet") + blocking.count("DELETE", "/debuglet"); n != 0 {
			t.Fatalf("%d cancellations sent by logs", n)
		}
	})
}
