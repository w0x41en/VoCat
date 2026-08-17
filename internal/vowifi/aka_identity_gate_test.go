package vowifi

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"
)

type gateTestAKA struct {
	mu          sync.Mutex
	checkCalls  int
	authCalls   int
	serviceCent string
}

func (fake *gateTestAKA) CheckReady(context.Context, SIMIdentity) (AKAEvidence, error) {
	fake.mu.Lock()
	fake.checkCalls++
	fake.mu.Unlock()
	return AKAEvidence{Ready: true}, nil
}

func (fake *gateTestAKA) Authenticate(context.Context, SIMIdentity, AKAChallenge) (AKAResult, error) {
	fake.mu.Lock()
	fake.authCalls++
	fake.mu.Unlock()
	return AKAResult{RES: []byte{1}, CK: make([]byte, 16), IK: make([]byte, 16)}, nil
}

func (fake *gateTestAKA) ReadSMSCenter(context.Context, string) (string, error) {
	return fake.serviceCent, nil
}

type gateTestSIM struct {
	mu       sync.Mutex
	identity SIMIdentity
	reads    int
}

func (fake *gateTestSIM) ReadIdentity(context.Context, string) (SIMIdentity, error) {
	fake.mu.Lock()
	defer fake.mu.Unlock()
	fake.reads++
	return fake.identity, nil
}

func (fake *gateTestSIM) setIdentity(identity SIMIdentity) {
	fake.mu.Lock()
	fake.identity = identity
	fake.mu.Unlock()
}

func (fake *gateTestSIM) readCount() int {
	fake.mu.Lock()
	defer fake.mu.Unlock()
	return fake.reads
}

func gateTestIdentity(imsi string) SIMIdentity {
	return SIMIdentity{ICCID: "8944100000000000000", IMSI: imsi}
}

func TestAKAIdentityGateWaitsForBaselineBeforeAuthenticate(t *testing.T) {
	want := gateTestIdentity("234150000000000")
	sim := &gateTestSIM{identity: gateTestIdentity("204047495061889")}
	aka := &gateTestAKA{serviceCent: "+447700900000"}
	provider := newAKAIdentityGate(aka, sim, "wwan0", time.Millisecond, nil)

	result := make(chan error, 1)
	go func() {
		_, err := provider.Authenticate(context.Background(), want, AKAChallenge{})
		result <- err
	}()

	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) && sim.readCount() < 2 {
		time.Sleep(time.Millisecond)
	}
	if sim.readCount() < 2 {
		t.Fatal("AKA gate did not poll the drifting identity")
	}
	sim.setIdentity(want)
	select {
	case err := <-result:
		if err != nil {
			t.Fatalf("gated Authenticate() error = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("gated Authenticate() did not resume after the baseline returned")
	}
	aka.mu.Lock()
	authCalls := aka.authCalls
	aka.mu.Unlock()
	if authCalls != 1 {
		t.Fatalf("underlying Authenticate calls = %d, want 1", authCalls)
	}
}

func TestAKAIdentityGateCancelsWithoutAuthenticatingDriftedIMSI(t *testing.T) {
	want := gateTestIdentity("234150000000000")
	sim := &gateTestSIM{identity: gateTestIdentity("204047495061889")}
	aka := &gateTestAKA{}
	provider := newAKAIdentityGate(aka, sim, "wwan0", time.Millisecond, nil)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()

	_, err := provider.Authenticate(ctx, want, AKAChallenge{})
	if err == nil || !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("gated Authenticate() error = %v, want context deadline", err)
	}
	aka.mu.Lock()
	authCalls := aka.authCalls
	aka.mu.Unlock()
	if authCalls != 0 {
		t.Fatalf("underlying Authenticate calls = %d, want 0", authCalls)
	}
}

func TestAKAIdentityGatePreservesSMSCenterReader(t *testing.T) {
	aka := &gateTestAKA{serviceCent: "+447700900000"}
	provider := newAKAIdentityGate(aka, &gateTestSIM{identity: gateTestIdentity("234150000000000")}, "wwan0", time.Millisecond, nil)
	reader, ok := provider.(interface {
		ReadSMSCenter(context.Context, string) (string, error)
	})
	if !ok {
		t.Fatal("gated AKA provider lost the SMS-centre reader capability")
	}
	got, err := reader.ReadSMSCenter(context.Background(), "wwan0")
	if err != nil || got != "+447700900000" {
		t.Fatalf("ReadSMSCenter() = %q/%v", got, err)
	}
}
