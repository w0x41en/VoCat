package qmiport

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"
)

func TestLeaseKeepsPortOpenAndSerializesUsers(t *testing.T) {
	path := filepath.Join(t.TempDir(), "wwan0qmi0")
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	var opens atomic.Int32
	coordinator := newCoordinator(func(path string) (portHandle, error) {
		opens.Add(1)
		return os.OpenFile(path, os.O_RDWR, 0)
	})
	t.Cleanup(func() { _ = coordinator.close() })

	first, err := coordinator.acquire(context.Background(), path, "first")
	if err != nil {
		t.Fatalf("first acquire: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if _, err := coordinator.acquire(ctx, path, "second"); err == nil {
		t.Fatal("second acquire succeeded before the first lease was released")
	}
	first.Release()

	second, err := coordinator.acquire(context.Background(), path, "second")
	if err != nil {
		t.Fatalf("second acquire: %v", err)
	}
	second.Release()
	if got := opens.Load(); got != 1 {
		t.Fatalf("keepalive opens = %d, want 1", got)
	}
}

// A waiter that gives up must learn that the port is owned rather than dead:
// the SMS sync loop and VoWiFi AKA both use short deadlines and would otherwise
// report a bare timeout while an eSIM install legitimately holds the card.
func TestAcquireReportsBusyHolderOnTimeout(t *testing.T) {
	path := filepath.Join(t.TempDir(), "wwan0qmi0")
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	coordinator := newCoordinator(func(path string) (portHandle, error) {
		return os.OpenFile(path, os.O_RDWR, 0)
	})
	t.Cleanup(func() { _ = coordinator.close() })

	holder, err := coordinator.acquire(context.Background(), path, "esim-uim")
	if err != nil {
		t.Fatalf("first acquire: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	_, err = coordinator.acquire(ctx, path, "sms-uim-wms")
	if err == nil {
		t.Fatal("acquire succeeded while the port was held")
	}
	var busy *BusyError
	if !errors.As(err, &busy) {
		t.Fatalf("error = %v, want a *BusyError", err)
	}
	if busy.Holder != "esim-uim" {
		t.Fatalf("holder = %q, want %q", busy.Holder, "esim-uim")
	}
	if busy.Path != path {
		t.Fatalf("path = %q, want %q", busy.Path, path)
	}
	if busy.HeldFor <= 0 {
		t.Fatalf("held for = %v, want a positive duration", busy.HeldFor)
	}
	// Callers that only classify transport timeouts must keep working.
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("error %v does not unwrap to context.DeadlineExceeded", err)
	}

	// A released lease must not leave its label behind for the next waiter.
	holder.Release()
	blocker, err := coordinator.acquire(context.Background(), path, "")
	if err != nil {
		t.Fatalf("second acquire: %v", err)
	}
	defer blocker.Release()
	lateCtx, cancelLate := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancelLate()
	_, err = coordinator.acquire(lateCtx, path, "sms-uim-wms")
	if !errors.As(err, &busy) {
		t.Fatalf("error = %v, want a *BusyError", err)
	}
	if busy.Holder != "" {
		t.Fatalf("holder = %q, want it cleared on release", busy.Holder)
	}
}

// Cancellation (process shutdown) must stay distinguishable from a deadline.
func TestAcquireBusyErrorPreservesCancellation(t *testing.T) {
	path := filepath.Join(t.TempDir(), "wwan0qmi0")
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	coordinator := newCoordinator(func(path string) (portHandle, error) {
		return os.OpenFile(path, os.O_RDWR, 0)
	})
	t.Cleanup(func() { _ = coordinator.close() })

	holder, err := coordinator.acquire(context.Background(), path, "esim-uim")
	if err != nil {
		t.Fatal(err)
	}
	defer holder.Release()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err = coordinator.acquire(ctx, path, "sms-uim-wms")
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("error = %v, want context.Canceled", err)
	}
	if errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("error = %v, must not report a deadline", err)
	}
}

func TestLeaseReopensReplacedDeviceNode(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "wwan0qmi0")
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	var opens atomic.Int32
	coordinator := newCoordinator(func(path string) (portHandle, error) {
		opens.Add(1)
		return os.OpenFile(path, os.O_RDWR, 0)
	})
	t.Cleanup(func() { _ = coordinator.close() })

	first, err := coordinator.acquire(context.Background(), path, "first")
	if err != nil {
		t.Fatal(err)
	}
	first.Release()
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	second, err := coordinator.acquire(context.Background(), path, "second")
	if err != nil {
		t.Fatal(err)
	}
	second.Release()
	if got := opens.Load(); got != 2 {
		t.Fatalf("keepalive opens = %d, want 2 after node replacement", got)
	}
}
