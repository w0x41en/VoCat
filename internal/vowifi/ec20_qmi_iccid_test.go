package vowifi

import (
	"context"
	"errors"
	"testing"

	"vocat/internal/modem"
)

type nativeICCIDTestExecutor struct {
	readCalls int
	qmiCalls  int
}

func (executor *nativeICCIDTestExecutor) ExecuteAT(context.Context, string, string) (modem.Response, error) {
	executor.readCalls++
	return modem.Response{}, errors.New("AT ICCID path must not be used")
}

func (executor *nativeICCIDTestExecutor) ReadNativeQMIICCID(context.Context, string) (string, error) {
	executor.qmiCalls++
	return "89441000400316034372", nil
}

func TestEC20AdapterPrefersNativeQMIICCID(t *testing.T) {
	executor := &nativeICCIDTestExecutor{}
	adapter, err := NewEC20Adapter(executor, EC20AdapterOptions{})
	if err != nil {
		t.Fatal(err)
	}

	got, err := adapter.readICCID(context.Background(), "wwan0")
	if err != nil {
		t.Fatalf("readICCID: %v", err)
	}
	if got != "89441000400316034372" {
		t.Fatalf("ICCID = %q", got)
	}
	if executor.qmiCalls != 1 || executor.readCalls != 0 {
		t.Fatalf("reader calls = QMI %d, AT %d; want QMI 1 and AT 0", executor.qmiCalls, executor.readCalls)
	}
}
