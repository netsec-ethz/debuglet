package resource_test

import (
	"debuglet/internal/executor/resource"
	"testing"
)

func TestRegisterSimple(t *testing.T) {
	e := resource.New(1000)

	err := e.RegisterAssignment("1", 100, 1000)
	if err != nil {
		t.Fatalf("Expected no fairshare or error, got err=%v", err)
	}
	err = e.RegisterAssignment("2", 300, 1000)
	if err != nil {
		t.Fatalf("Expected fairshare and no error, got err=%v", err)
	}
	e.Fairshare()

	first := e.GetAllowedExecutor("1")
	second := e.GetAllowedExecutor("2")
	if first != 400 {
		t.Fatalf("Expected job '1' to get 400, got %d", first)
	}
	if second != 600 {
		t.Fatalf("Expected job '2' to get 600, got %d", second)
	}
}

func TestMinimalUpdates(t *testing.T) {
	e := resource.New(1000)
	if err := e.RegisterAssignment("1", 100, 100); err != nil {
		t.Fatalf("Expected no fairshare or error, got err=%v", err)
	}
	if err := e.RegisterAssignment("2", 100, 500); err != nil {
		t.Fatalf("Expected no fairshare or error, got err=%v", err)
	}
	if err := e.RegisterAssignment("3", 100, 500); err != nil {
		t.Fatalf("Expected fairshare and no error, got err=%v", err)
	}
	e.Fairshare()

	first := e.GetAllowedExecutor("1")
	second := e.GetAllowedExecutor("2")
	third := e.GetAllowedExecutor("3")
	if first != 100 {
		t.Fatalf("Expected job '1' to get 100, got %d", first)
	}
	if second != 450 {
		t.Fatalf("Expected job '2' to get 450, got %d", second)
	}
	if third != 450 {
		t.Fatalf("Expected job '3' to get 450, got %d", third)
	}
}

func TestRemove(t *testing.T) {
	e := resource.New(1000)
	if err := e.RegisterAssignment("1", 100, 100); err != nil {
		t.Fatalf("Expected no fairshare or error, got err=%v", err)
	}
	if req := e.RemoveAssignment("1"); req {
		t.Fatalf("Expected no fairshare, got fairshare=%v", req)
	}
	if err := e.RegisterAssignment("2", 1000, 1000); err != nil {
		t.Fatalf("Expected no fairshare or error, got err=%v", err)
	}
	e.Fairshare()

	first := e.GetAllowedExecutor("1")
	second := e.GetAllowedExecutor("2")
	if first != 0 {
		t.Fatalf("Expected job '1' to get 0, got %d", first)
	}
	if second != 1000 {
		t.Fatalf("Expected job '2' to get 1000, got %d", second)
	}
}
