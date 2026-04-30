package resource_test

import (
	"debuglet/internal/executor/resource"
	"maps"
	"testing"
)

func TestRegisterSimple(t *testing.T) {
	e := resource.New(1000)

	fairshareReq, err := e.RegisterAssignment("1", 100, 1000)
	if fairshareReq || err != nil {
		t.Fatalf("Expected no fairshare or error, got fairshare=%v, err=%v", fairshareReq, err)
	}
	fairshareReq, err = e.RegisterAssignment("2", 300, 1000)
	if !fairshareReq || err != nil {
		t.Fatalf("Expected fairshare and no error, got fairshare=%v, err=%v", fairshareReq, err)
	}

	fairshares := maps.Collect(e.Fairshare())
	if len(fairshares) != 2 {
		t.Fatalf("Expected fairshare to update both jobs, got len=%d", len(fairshares))
	}
	for id, newCeil := range fairshares {
		if id == "1" && newCeil != 400 {
			t.Fatalf("Expected job '1' to get 400, got %d", newCeil)
		}
		if id == "2" && newCeil != 600 {
			t.Fatalf("Expected job '2' to get 600, got %d", newCeil)
		}
	}
}

func TestMinimalUpdates(t *testing.T) {
	e := resource.New(1000)
	if req, err := e.RegisterAssignment("1", 100, 100); req || err != nil {
		t.Fatalf("Expected no fairshare or error, got fairshare=%v, err=%v", req, err)
	}
	if req, err := e.RegisterAssignment("2", 100, 500); req || err != nil {
		t.Fatalf("Expected no fairshare or error, got fairshare=%v, err=%v", req, err)
	}
	if req, err := e.RegisterAssignment("3", 100, 500); !req || err != nil {
		t.Fatalf("Expected fairshare and no error, got fairshare=%v, err=%v", req, err)
	}
	fairshares := maps.Collect(e.Fairshare())
	if len(fairshares) != 2 {
		t.Fatalf("Expected fairshare to only update two jobs, got len=%d", len(fairshares))
	}

}

func TestRemove(t *testing.T) {
	e := resource.New(1000)
	if req, err := e.RegisterAssignment("1", 100, 100); req || err != nil {
		t.Fatalf("Expected no fairshare or error, got fairshare=%v, err=%v", req, err)
	}
	if req := e.RemoveAssignment("1"); req {
		t.Fatalf("Expected no fairshare, got fairshare=%v", req)
	}
	if req, err := e.RegisterAssignment("2", 1000, 1000); req || err != nil {
		t.Fatalf("Expected no fairshare or error, got fairshare=%v, err=%v", req, err)
	}
}
