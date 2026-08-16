package ike

import (
	"encoding/hex"
	"strings"
	"testing"

	"vocat/internal/vowifi"
)

func TestIKEAuthTraceRedactsIDiAndParsesInitialPayloads(t *testing.T) {
	identity := "051502123456789@nai.epc.mnc002.mcc515.3gppnetwork.org"
	idi := payload{Type: payloadIDi, Body: append([]byte{3, 0, 0, 0}, []byte(identity)...)}
	idr := payload{Type: payloadIDr, Body: append([]byte{2, 0, 0, 0}, []byte("ims")...)}
	childOffer, err := marshalProposals([]proposal{espOffer([]byte{1, 2, 3, 4}, false, false)})
	if err != nil {
		t.Fatalf("marshal child offer: %v", err)
	}
	event := traceIKEAuthPayloads(
		"tx",
		1,
		buildInitialEAPOnlyAuth(
			idi,
			idr,
			childOffer,
			dualStackTrafficSelectors(payloadTSi),
			dualStackTrafficSelectors(payloadTSr),
		),
	)
	if event.Direction != "tx" || event.Exchange != "IKE_AUTH" || event.MessageID != 1 {
		t.Fatalf("trace envelope = %#v", event)
	}
	if len(event.Payloads) != 9 {
		t.Fatalf("trace payload count = %d, want 9", len(event.Payloads))
	}

	tracedIDi := event.Payloads[0]
	if tracedIDi.Name != "IDi" || tracedIDi.IdentityType != 3 || tracedIDi.IdentityLength != len(identity) ||
		tracedIDi.WireLength != 8+len(identity) {
		t.Fatalf("IDi trace = %#v", tracedIDi)
	}
	if tracedIDi.IdentityPrefix != "051502" {
		t.Fatalf("IDi prefix = %q, want 051502", tracedIDi.IdentityPrefix)
	}
	if tracedIDi.IdentityRealm != "nai.epc.mnc002.mcc515.3gppnetwork.org" {
		t.Fatalf("IDi realm = %q", tracedIDi.IdentityRealm)
	}
	if tracedIDi.IdentityValue != "" || tracedIDi.IdentitySHA256 == "" {
		t.Fatalf("IDi retained identity or omitted digest: %#v", tracedIDi)
	}
	if strings.Contains(tracedIDi.RawHexRedacted, hex.EncodeToString([]byte(identity))) {
		t.Fatal("IDi raw trace retained the unredacted identity")
	}
	if wantPrefix := "03000000aaaaaaaaaaaa"; !strings.HasPrefix(tracedIDi.RawHexRedacted, wantPrefix) {
		t.Fatalf("IDi redacted raw = %q, want prefix %q", tracedIDi.RawHexRedacted, wantPrefix)
	}

	tracedIDr := event.Payloads[1]
	if tracedIDr.Name != "IDr" || tracedIDr.IdentityType != 2 || tracedIDr.IdentityValue != "ims" {
		t.Fatalf("IDr trace = %#v", tracedIDr)
	}
	if tracedIDr.RawHexRedacted != "02000000696d73" {
		t.Fatalf("IDr raw = %q", tracedIDr.RawHexRedacted)
	}

	tracedSA := event.Payloads[5]
	if tracedSA.Name != "SA" || tracedSA.ProposalCount != 1 || tracedSA.ParseError != "" {
		t.Fatalf("SA trace = %#v", tracedSA)
	}
	for _, index := range []int{6, 7} {
		if event.Payloads[index].TrafficSelectorCount != 2 || event.Payloads[index].ParseError != "" {
			t.Fatalf("traffic selector trace[%d] = %#v", index, event.Payloads[index])
		}
	}
	configuration := event.Payloads[8]
	if configuration.ConfigurationType != configRequest || len(configuration.ConfigurationAttributes) != 7 {
		t.Fatalf("CFG trace = %#v", configuration)
	}
	for _, attribute := range configuration.ConfigurationAttributes {
		if attribute.ValueLength != 0 || attribute.WireLength != 4 {
			t.Fatalf("CFG attribute = %#v", attribute)
		}
	}
}

func TestIKEAuthTraceReportsMalformedIdentityWithoutPanicking(t *testing.T) {
	event := traceIKEAuthPayloads("tx", 1, []payload{{Type: payloadIDi, Body: []byte{3}}})
	if len(event.Payloads) != 1 || event.Payloads[0].ParseError == "" {
		t.Fatalf("malformed IDi trace = %#v", event)
	}
}

func TestAKAIdentityTraceAuditMatchesSourceIMSIAndExpectedNAI(t *testing.T) {
	identity := vowifi.SIMIdentity{
		IMSI:    "515027106574535",
		HomeMCC: "515",
		HomeMNC: "02",
	}
	permanent, err := permanentAKAIdentityForType(identity, eapTypeAKA)
	if err != nil {
		t.Fatalf("permanentAKAIdentityForType() error = %v", err)
	}
	audit := traceAKAIdentityAudit(identity, permanent, eapTypeAKA)
	if !audit.SameIMSI || !audit.PermanentIdentityMatchesExpected {
		t.Fatalf("matching audit = %#v", audit)
	}
	if audit.ModemIMSILength != 15 || audit.EAPIMSILength != 15 || audit.ExpectedIdentityLength != 54 {
		t.Fatalf("matching audit lengths = %#v", audit)
	}
	if audit.ModemIMSIHash == "" || audit.ModemIMSIHash != audit.EAPIMSIHash {
		t.Fatalf("matching audit hashes = %#v", audit)
	}

	wrong := append([]byte(nil), permanent...)
	wrong[8] = '8'
	wrongAudit := traceAKAIdentityAudit(identity, wrong, eapTypeAKA)
	if wrongAudit.SameIMSI || wrongAudit.PermanentIdentityMatchesExpected {
		t.Fatalf("mismatched audit = %#v", wrongAudit)
	}
}
