package entitlement

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"vocat/internal/vowifi"
)

type fakeAKA struct{}

func (fakeAKA) CheckReady(context.Context, vowifi.SIMIdentity) (vowifi.AKAEvidence, error) {
	return vowifi.AKAEvidence{Ready: true, Application: "USIM"}, nil
}

func (fakeAKA) Authenticate(context.Context, vowifi.SIMIdentity, vowifi.AKAChallenge) (vowifi.AKAResult, error) {
	return vowifi.AKAResult{}, nil
}

func testIdentity() vowifi.SIMIdentity {
	return vowifi.SIMIdentity{
		IMSI:    "515031234567890",
		HomeMCC: "515",
		HomeMNC: "003",
	}
}

func TestProbeParsesVoWiFiXMLWithoutLoggingBody(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodGet {
			t.Fatalf("method = %s, want GET", request.Method)
		}
		if request.URL.Query().Get("app") != "ap2004" {
			t.Fatalf("app = %q", request.URL.Query().Get("app"))
		}
		if request.URL.Query().Get("EAP_ID") == "" {
			t.Fatal("EAP_ID is missing")
		}
		writer.Header().Set("Content-Type", xmlContentType)
		_, _ = writer.Write([]byte(`<?xml version="1.0"?><wap-provisioningdoc><characteristic type="APPLICATION"><characteristic type="ap2004"><parm name="EntitlementStatus" value="1"/><parm name="ProvStatus" value="1"/><parm name="TC_Status" value="2"/><parm name="AddrStatus" value="2"/></characteristic></characteristic></wap-provisioningdoc>`))
	}))
	defer server.Close()

	client := server.Client()
	result, err := Probe(context.Background(), Config{
		Endpoint:      server.URL,
		Identity:      testIdentity(),
		AKA:           fakeAKA{},
		HTTPClient:    client,
		InitialMethod: http.MethodGet,
	})
	if err != nil {
		t.Fatalf("Probe() error = %v", err)
	}
	if result.EntitlementStatus != "1" || result.ProvisioningStatus != "1" ||
		result.TermsStatus != "2" || result.AddressStatus != "2" {
		t.Fatalf("result statuses = %#v", result)
	}
	if result.EAPIdentitySHA256 == "" || result.ResponseBodySHA256 == "" {
		t.Fatalf("redacted hashes missing: %#v", result)
	}
}

func TestProbeRelaysEAPIdentityThenParsesJSON(t *testing.T) {
	identitySeen := ""
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Method == http.MethodGet {
			identitySeen = request.URL.Query().Get("EAP_ID")
			packet, _ := json.Marshal(relayEnvelope{Packet: base64.StdEncoding.EncodeToString([]byte{1, 9, 0, 5, 1})})
			writer.Header().Set("Content-Type", relayContentType)
			_, _ = writer.Write(packet)
			return
		}
		var relay relayEnvelope
		if err := json.NewDecoder(request.Body).Decode(&relay); err != nil {
			t.Fatalf("decode relay request: %v", err)
		}
		response, err := base64.StdEncoding.DecodeString(relay.Packet)
		if err != nil || len(response) < 5 || response[0] != 2 || response[1] != 9 || response[4] != 1 {
			t.Fatalf("relayed EAP response = %x, err=%v", response, err)
		}
		writer.Header().Set("Content-Type", "application/json")
		_, _ = writer.Write([]byte(`{"ap2004":{"EntitlementStatus":"2","ProvStatus":"0"}}`))
	}))
	defer server.Close()

	result, err := Probe(context.Background(), Config{
		Endpoint:      server.URL,
		Identity:      testIdentity(),
		AKA:           fakeAKA{},
		HTTPClient:    server.Client(),
		InitialMethod: http.MethodGet,
	})
	if err != nil {
		t.Fatalf("Probe() error = %v", err)
	}
	if result.EAPRounds != 1 || result.EntitlementStatus != "2" || result.ProvisioningStatus != "0" {
		t.Fatalf("result = %#v", result)
	}
	if !strings.Contains(identitySeen, "@nai.epc.mnc003.mcc515.3gppnetwork.org") {
		t.Fatalf("EAP_ID = %q", identitySeen)
	}
}

func TestProbeRejectsPlainHTTPEndpoint(t *testing.T) {
	_, err := Probe(context.Background(), Config{
		Endpoint: "http://127.0.0.1:1/",
		Identity: testIdentity(),
		AKA:      fakeAKA{},
	})
	if err == nil || !strings.Contains(err.Error(), "https URL") {
		t.Fatalf("Probe() error = %v, want HTTPS validation", err)
	}
}
