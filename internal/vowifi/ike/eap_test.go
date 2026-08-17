package ike

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"strings"
	"testing"

	"vocat/internal/vowifi"
)

type testAKAProvider struct {
	result    vowifi.AKAResult
	err       error
	challenge vowifi.AKAChallenge
	calls     int
}

func mustHex(t *testing.T, value string) []byte {
	t.Helper()
	decoded, err := hex.DecodeString(strings.ReplaceAll(value, " ", ""))
	if err != nil {
		t.Fatalf("decode test vector: %v", err)
	}
	return decoded
}

func TestEAPAKAPrimeRFC9048Case3KeyVector(t *testing.T) {
	keys, err := deriveAKAPrimeKeys(
		[]byte("0555444333222111"),
		mustHex(t, "b0b0 b0b0 b0b0 b0b0 b0b0 b0b0 b0b0 b0b0"),
		mustHex(t, "c0c0 c0c0 c0c0 c0c0 c0c0 c0c0 c0c0 c0c0"),
		mustHex(t, "a0a0 a0a0 a0a0 a0a0 a0a0 a0a0 a0a0 a0a0"),
		[]byte("WLAN"),
	)
	if err != nil {
		t.Fatalf("deriveAKAPrimeKeys() error = %v", err)
	}
	for name, result := range map[string]struct {
		got  []byte
		want string
	}{
		"K_encr": {keys.KEncr, "897d302fa2847416488c28e20dcb7be4"},
		"K_aut":  {keys.KAut, "c40700e7722483ae3dc7139eb0b88bb558cb3081eccd057f9207d1286ee7dd53"},
		"MSK":    {keys.MSK, "9f7dca9e37bb22029ed986e7cd09d4a70d1ac76d95535c5cac40a7504699bb8961a29ef6f3e90f183de5861ad1bedc81ce9916391b401aa006c98785a5756df7"},
		"EMSK":   {keys.EMSK, "724de00bdb9e568187be3fe746114557d5018779537ee37f4d3c6c738cb97b9dc651bc19bfadc344ffe2b52ca78bd8316b51dacc5f2b1440cb9515521cc7ba23"},
	} {
		if want := mustHex(t, result.want); !bytes.Equal(result.got, want) {
			t.Errorf("%s = %x, want %x", name, result.got, want)
		}
	}
}

func TestEAPAKAPrimeUsesType50Prefix6AndSHA256MAC(t *testing.T) {
	result := vowifi.AKAResult{
		RES: bytes.Repeat([]byte{0xd0}, 8),
		CK:  bytes.Repeat([]byte{0xc0}, 16),
		IK:  bytes.Repeat([]byte{0xb0}, 16),
	}
	provider := &testAKAProvider{result: result}
	client, err := newAKAClientWithMethod(testSIMIdentity(), provider, "aka-prime")
	if err != nil {
		t.Fatalf("newAKAClientWithMethod() error = %v", err)
	}
	if got := string(client.identity); got != "6234150123456789@nai.epc.mnc015.mcc234.3gppnetwork.org" {
		t.Fatalf("AKA' permanent identity = %q", got)
	}

	randValue := bytes.Repeat([]byte{0xe0}, 16)
	autnValue := bytes.Repeat([]byte{0xa0}, 16) // AMF separation bit is set.
	randAttribute, _ := marshalAKAAttribute(akaAttrRAND, append([]byte{0, 0}, randValue...))
	autnAttribute, _ := marshalAKAAttribute(akaAttrAUTN, append([]byte{0, 0}, autnValue...))
	kdfAttribute, _ := marshalAKAAttribute(akaAttrKDF, []byte{0, akaPrimeKDF})
	kdfInputAttribute, _ := marshalAKAAttribute(akaAttrKDFInput, append([]byte{0, 4}, []byte("WLAN")...))
	macAttribute, _ := marshalAKAAttribute(akaAttrMAC, make([]byte, 18))
	data := []byte{akaSubtypeChallenge, 0, 0}
	data = append(data, randAttribute...)
	data = append(data, autnAttribute...)
	data = append(data, kdfAttribute...)
	data = append(data, kdfInputAttribute...)
	data = append(data, macAttribute...)
	request, _ := marshalEAPPacket(eapPacket{Code: eapRequest, Identifier: 31, Type: eapTypeAKAPrime, Data: data})
	keys, err := deriveAKAPrimeKeys(client.identity, result.IK, result.CK, autnValue, []byte("WLAN"))
	if err != nil {
		t.Fatal(err)
	}
	attributes, _ := parseAKAAttributes(data[3:])
	mac, _ := oneAKAAttribute(attributes, akaAttrMAC)
	macOffset := 5 + 3 + mac.Offset
	copy(request[macOffset+4:macOffset+20], akaPrimeMAC(keys.KAut, request))

	action, err := client.handle(context.Background(), request)
	if err != nil {
		t.Fatalf("handle AKA' challenge error = %v", err)
	}
	response, err := parseEAPPacket(action.Response)
	if err != nil {
		t.Fatal(err)
	}
	if response.Type != eapTypeAKAPrime || response.Data[0] != akaSubtypeChallenge {
		t.Fatalf("AKA' response = %#v", response)
	}
	responseAttributes, err := parseAKAAttributes(response.Data[3:])
	if err != nil {
		t.Fatal(err)
	}
	responseMAC, err := oneAKAAttribute(responseAttributes, akaAttrMAC)
	if err != nil {
		t.Fatal(err)
	}
	zeroed := append([]byte(nil), action.Response...)
	responseOffset := 5 + 3 + responseMAC.Offset
	actualMAC := append([]byte(nil), zeroed[responseOffset+4:responseOffset+20]...)
	for index := responseOffset + 4; index < responseOffset+20; index++ {
		zeroed[index] = 0
	}
	if !bytes.Equal(actualMAC, akaPrimeMAC(keys.KAut, zeroed)) {
		t.Fatal("AKA' response AT_MAC does not use HMAC-SHA-256-128")
	}
	replayed, err := client.handle(context.Background(), request)
	if err != nil || !bytes.Equal(replayed.Response, action.Response) {
		t.Fatalf("replayed AKA' challenge = %x, %v", replayed.Response, err)
	}
	if provider.calls != 1 {
		t.Fatalf("replayed AKA' challenge accessed the USIM %d times, want once", provider.calls)
	}
	keysBeforeMismatch := append([]byte(nil), client.keys.KAut...)
	mismatchedRetransmission := append([]byte(nil), request...)
	mismatchedRetransmission[len(mismatchedRetransmission)-1] ^= 0x01
	mismatchedAction, err := client.handle(context.Background(), mismatchedRetransmission)
	if err != nil || len(mismatchedAction.Response) != 0 {
		t.Fatalf("same-Identifier changed request was not discarded: response=%x err=%v", mismatchedAction.Response, err)
	}
	if provider.calls != 1 || !bytes.Equal(client.keys.KAut, keysBeforeMismatch) {
		t.Fatalf("same-Identifier changed request altered AKA state: calls=%d KAut=%x", provider.calls, client.keys.KAut)
	}
	successAfterMismatch, _ := marshalEAPPacket(eapPacket{Code: eapSuccess, Identifier: 31})
	if action, err := client.handle(context.Background(), successAfterMismatch); err == nil || action.Success {
		t.Fatalf("success after changed same-Identifier request = %#v err=%v", action, err)
	}
}

func TestEAPAKAPrimeExplicitPolicyRejectsType23Downgrade(t *testing.T) {
	client, err := newAKAClientWithMethod(testSIMIdentity(), &testAKAProvider{}, "aka-prime")
	if err != nil {
		t.Fatal(err)
	}
	notificationRequest, _ := marshalEAPPacket(eapPacket{
		Code: eapRequest, Identifier: 30, Type: eapTypeNotification, Data: []byte("notice"),
	})
	notificationAction, err := client.handle(context.Background(), notificationRequest)
	if err != nil {
		t.Fatalf("pre-method EAP notification error = %v", err)
	}
	notificationResponse, err := parseEAPPacket(notificationAction.Response)
	if err != nil || notificationResponse.Type != eapTypeNotification || len(notificationResponse.Data) != 0 || client.methodStarted {
		t.Fatalf("pre-method EAP notification response = %#v parseErr=%v methodStarted=%v", notificationResponse, err, client.methodStarted)
	}
	request, err := marshalEAPPacket(eapPacket{
		Code:       eapRequest,
		Identifier: 32,
		Type:       eapTypeAKA,
		Data:       []byte{akaSubtypeIdentity, 0, 0},
	})
	if err != nil {
		t.Fatal(err)
	}
	action, err := client.handle(context.Background(), request)
	if err != nil {
		t.Fatalf("type 23 negotiation error = %v", err)
	}
	response, err := parseEAPPacket(action.Response)
	if err != nil {
		t.Fatal(err)
	}
	if response.Code != eapResponse || response.Identifier != 32 || response.Type != eapTypeNak ||
		!bytes.Equal(response.Data, []byte{eapTypeAKAPrime}) {
		t.Fatalf("type 23 downgrade response = %#v, want legacy Nak selecting type 50", response)
	}
	biddingClient, err := newAKAClientWithMethod(testSIMIdentity(), &testAKAProvider{}, "aka-prime")
	if err != nil {
		t.Fatal(err)
	}
	bidding, err := marshalAKAAttribute(akaAttrBidding, []byte{0x80, 0})
	if err != nil {
		t.Fatal(err)
	}
	biddingRequest, err := marshalEAPPacket(eapPacket{
		Code:       eapRequest,
		Identifier: 34,
		Type:       eapTypeAKA,
		Data:       append([]byte{akaSubtypeChallenge, 0, 0}, bidding...),
	})
	if err != nil {
		t.Fatal(err)
	}
	biddingAction, err := biddingClient.handle(context.Background(), biddingRequest)
	if err != nil {
		t.Fatalf("AT_BIDDING downgrade error = %v", err)
	}
	biddingResponse, err := parseEAPPacket(biddingAction.Response)
	if err != nil || biddingResponse.Type != eapTypeAKA || len(biddingResponse.Data) < 3 || biddingResponse.Data[0] != akaSubtypeAuthReject {
		t.Fatalf("AT_BIDDING downgrade response = %#v parseErr=%v, want EAP-AKA Authentication-Reject", biddingResponse, err)
	}
	for index, unsupportedType := range []uint8{254, 255} {
		unsupportedRequest, _ := marshalEAPPacket(eapPacket{
			Code:       eapRequest,
			Identifier: uint8(33 + index),
			Type:       unsupportedType,
			Data:       []byte{0},
		})
		unsupportedAction, handleErr := client.handle(context.Background(), unsupportedRequest)
		if handleErr != nil {
			t.Fatalf("type %d negotiation error = %v", unsupportedType, handleErr)
		}
		unsupportedResponse, parseErr := parseEAPPacket(unsupportedAction.Response)
		if parseErr != nil || unsupportedResponse.Type != eapTypeNak ||
			!bytes.Equal(unsupportedResponse.Data, []byte{eapTypeAKAPrime}) {
			t.Fatalf("type %d negotiation response = %#v parseErr=%v", unsupportedType, unsupportedResponse, parseErr)
		}
	}

	identityRequest, _ := marshalAKAAttribute(akaAttrPermanentIDReq, []byte{0, 0})
	methodRequest, _ := marshalEAPPacket(eapPacket{
		Code:       eapRequest,
		Identifier: 35,
		Type:       eapTypeAKAPrime,
		Data:       append([]byte{akaSubtypeIdentity, 0, 0}, identityRequest...),
	})
	if methodAction, handleErr := client.handle(context.Background(), methodRequest); handleErr != nil || len(methodAction.Response) == 0 {
		t.Fatalf("configured method did not start: response=%x err=%v", methodAction.Response, handleErr)
	}

	notificationRequest, _ = marshalEAPPacket(eapPacket{
		Code: eapRequest, Identifier: 36, Type: eapTypeNotification, Data: []byte("notice again"),
	})
	notificationAction, err = client.handle(context.Background(), notificationRequest)
	if err != nil {
		t.Fatalf("in-method EAP notification error = %v", err)
	}
	notificationResponse, err = parseEAPPacket(notificationAction.Response)
	if err != nil || notificationResponse.Type != eapTypeNotification || len(notificationResponse.Data) != 0 {
		t.Fatalf("in-method EAP notification response = %#v parseErr=%v", notificationResponse, err)
	}

	requery, _ := marshalEAPPacket(eapPacket{Code: eapRequest, Identifier: 37, Type: eapTypeIdentity, Data: []byte("again")})
	if requeryAction, handleErr := client.handle(context.Background(), requery); handleErr != nil || len(requeryAction.Response) != 0 {
		t.Fatalf("identity re-query after type 50 start was not silently discarded: response=%x err=%v", requeryAction.Response, handleErr)
	}

	request[1] = 38
	action, err = client.handle(context.Background(), request)
	if err != nil || len(action.Response) != 0 {
		t.Fatalf("method switch after type 50 start was not silently discarded: response=%x err=%v", action.Response, err)
	}
}

func TestEAPAKAPrimeNegotiatesOnlySupportedKDFBeforeSIMAccess(t *testing.T) {
	provider := &testAKAProvider{}
	client, err := newAKAClientWithMethod(testSIMIdentity(), provider, "aka-prime")
	if err != nil {
		t.Fatal(err)
	}
	randAttribute, _ := marshalAKAAttribute(akaAttrRAND, append([]byte{0, 0}, bytes.Repeat([]byte{1}, 16)...))
	autnAttribute, _ := marshalAKAAttribute(akaAttrAUTN, append([]byte{0, 0}, bytes.Repeat([]byte{0xa0}, 16)...))
	unsupported, _ := marshalAKAAttribute(akaAttrKDF, []byte{0, 2})
	supported, _ := marshalAKAAttribute(akaAttrKDF, []byte{0, akaPrimeKDF})
	input, _ := marshalAKAAttribute(akaAttrKDFInput, append([]byte{0, 4}, []byte("WLAN")...))
	macAttribute, _ := marshalAKAAttribute(akaAttrMAC, make([]byte, 18))
	data := append([]byte{akaSubtypeChallenge, 0, 0}, randAttribute...)
	data = append(data, autnAttribute...)
	data = append(data, unsupported...)
	data = append(data, supported...)
	data = append(data, input...)
	data = append(data, macAttribute...)
	request, _ := marshalEAPPacket(eapPacket{Code: eapRequest, Identifier: 33, Type: eapTypeAKAPrime, Data: data})
	action, err := client.handle(context.Background(), request)
	if err != nil {
		t.Fatalf("KDF selection error = %v", err)
	}
	if provider.calls != 0 {
		t.Fatalf("SIM accessed %d times before KDF negotiation completed", provider.calls)
	}
	response, err := parseEAPPacket(action.Response)
	if err != nil {
		t.Fatal(err)
	}
	attributes, err := parseAKAAttributes(response.Data[3:])
	if err != nil {
		t.Fatal(err)
	}
	if len(attributes) != 1 || attributes[0].Type != akaAttrKDF ||
		binary.BigEndian.Uint16(attributes[0].Raw[2:4]) != akaPrimeKDF {
		t.Fatalf("KDF selection response = %#v", response)
	}
}

func TestEAPAKAPrimeRejectsUnsupportedKDFWithoutRequiringKDFInput(t *testing.T) {
	client, err := newAKAClientWithMethod(testSIMIdentity(), &testAKAProvider{}, "aka-prime")
	if err != nil {
		t.Fatal(err)
	}
	unsupported, _ := marshalAKAAttribute(akaAttrKDF, []byte{0, 2})
	attributes, err := parseAKAAttributes(unsupported)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := client.prepareAKAPrimeKDF(34, attributes); !errors.Is(err, errAKAPrimeKDFUnsupported) {
		t.Fatalf("unsupported KDF without AT_KDF_INPUT error = %v", err)
	}
}

func TestEAPAKAPrimeSelectsAlternativeBeforeProcessingKDFInput(t *testing.T) {
	unsupported, _ := marshalAKAAttribute(akaAttrKDF, []byte{0, 2})
	supported, _ := marshalAKAAttribute(akaAttrKDF, []byte{0, akaPrimeKDF})
	malformedInput, _ := marshalAKAAttribute(akaAttrKDFInput, []byte{0, 10})
	for _, test := range []struct {
		name  string
		input []byte
	}{
		{name: "missing input"},
		{name: "malformed input", input: malformedInput},
	} {
		t.Run(test.name, func(t *testing.T) {
			client, err := newAKAClientWithMethod(testSIMIdentity(), &testAKAProvider{}, "aka-prime")
			if err != nil {
				t.Fatal(err)
			}
			encoded := append(append(append([]byte(nil), unsupported...), supported...), test.input...)
			attributes, err := parseAKAAttributes(encoded)
			if err != nil {
				t.Fatal(err)
			}
			_, _, selection, err := client.prepareAKAPrimeKDF(35, attributes)
			if err != nil || selection == nil {
				t.Fatalf("alternative KDF selection = %v err=%v", selection, err)
			}
			response, err := parseEAPPacket(selection.Response)
			if err != nil {
				t.Fatal(err)
			}
			selectedAttributes, err := parseAKAAttributes(response.Data[3:])
			if err != nil || len(selectedAttributes) != 1 || selectedAttributes[0].Type != akaAttrKDF ||
				binary.BigEndian.Uint16(selectedAttributes[0].Raw[2:4]) != akaPrimeKDF {
				t.Fatalf("alternative KDF response = %#v attrs=%#v err=%v", response, selectedAttributes, err)
			}
		})
	}
}

func TestEAPAKAPrimeRejectsExcessKDFInputPadding(t *testing.T) {
	client, err := newAKAClientWithMethod(testSIMIdentity(), &testAKAProvider{}, "aka-prime")
	if err != nil {
		t.Fatal(err)
	}
	kdf, _ := marshalAKAAttribute(akaAttrKDF, []byte{0, akaPrimeKDF})
	inputValue := append([]byte{0, 4}, []byte("WLAN")...)
	inputValue = append(inputValue, make([]byte, 4)...)
	input, _ := marshalAKAAttribute(akaAttrKDFInput, inputValue)
	attributes, err := parseAKAAttributes(append(kdf, input...))
	if err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := client.prepareAKAPrimeKDF(36, attributes); err == nil || !strings.Contains(err.Error(), "excessive padding") {
		t.Fatalf("excess KDF input padding error = %v", err)
	}
}

func TestEAPAKAPrimeKeepsNegotiatedKDFForSyncRetry(t *testing.T) {
	client, err := newAKAClientWithMethod(testSIMIdentity(), &testAKAProvider{}, "aka-prime")
	if err != nil {
		t.Fatal(err)
	}
	input, _ := marshalAKAAttribute(akaAttrKDFInput, append([]byte{0, 4}, []byte("WLAN")...))
	makeAttributes := func(values ...byte) []akaAttribute {
		encoded := append([]byte(nil), input...)
		for _, value := range values {
			attribute, _ := marshalAKAAttribute(akaAttrKDF, []byte{0, value})
			encoded = append(encoded, attribute...)
		}
		attributes, parseErr := parseAKAAttributes(encoded)
		if parseErr != nil {
			t.Fatal(parseErr)
		}
		return attributes
	}
	if _, _, selection, err := client.prepareAKAPrimeKDF(10, makeAttributes(2, akaPrimeKDF)); err != nil || selection == nil {
		t.Fatalf("initial KDF negotiation selection=%v err=%v", selection, err)
	}
	accepted := makeAttributes(akaPrimeKDF, 2, akaPrimeKDF)
	if _, _, selection, err := client.prepareAKAPrimeKDF(11, accepted); err != nil || selection != nil {
		t.Fatalf("negotiated KDF acceptance selection=%v err=%v", selection, err)
	}
	if _, _, selection, err := client.prepareAKAPrimeKDF(12, accepted); err != nil || selection != nil {
		t.Fatalf("sync retry with identical KDF selection=%v err=%v", selection, err)
	}
	if _, _, _, err := client.prepareAKAPrimeKDF(13, makeAttributes(akaPrimeKDF, 3, akaPrimeKDF)); err == nil {
		t.Fatal("accepted negotiated KDF list changed without rejection")
	}
}

func TestEAPAKAPrimeFailsClosedWithoutKDFOrSeparationBit(t *testing.T) {
	provider := &testAKAProvider{result: vowifi.AKAResult{
		RES: bytes.Repeat([]byte{1}, 8), CK: bytes.Repeat([]byte{2}, 16), IK: bytes.Repeat([]byte{3}, 16),
	}}
	build := func(autn []byte, withKDF bool, networkName []byte) []byte {
		randAttribute, _ := marshalAKAAttribute(akaAttrRAND, append([]byte{0, 0}, bytes.Repeat([]byte{1}, 16)...))
		autnAttribute, _ := marshalAKAAttribute(akaAttrAUTN, append([]byte{0, 0}, autn...))
		macAttribute, _ := marshalAKAAttribute(akaAttrMAC, make([]byte, 18))
		data := append([]byte{akaSubtypeChallenge, 0, 0}, randAttribute...)
		data = append(data, autnAttribute...)
		if withKDF {
			kdf, _ := marshalAKAAttribute(akaAttrKDF, []byte{0, akaPrimeKDF})
			data = append(data, kdf...)
		}
		if networkName != nil {
			inputValue := binary.BigEndian.AppendUint16(nil, uint16(len(networkName)))
			inputValue = append(inputValue, networkName...)
			input, _ := marshalAKAAttribute(akaAttrKDFInput, inputValue)
			data = append(data, input...)
		}
		data = append(data, macAttribute...)
		request, _ := marshalEAPPacket(eapPacket{Code: eapRequest, Identifier: 41, Type: eapTypeAKAPrime, Data: data})
		return request
	}
	for _, test := range []struct {
		name        string
		request     []byte
		wantSubtype byte
	}{
		{name: "missing KDF", request: build(bytes.Repeat([]byte{0xa0}, 16), false, []byte("WLAN")), wantSubtype: akaSubtypeAuthReject},
		{name: "missing KDF and KDF input", request: build(bytes.Repeat([]byte{0xa0}, 16), false, nil), wantSubtype: akaSubtypeAuthReject},
		{name: "empty KDF input", request: build(bytes.Repeat([]byte{0xa0}, 16), true, []byte{}), wantSubtype: akaSubtypeAuthReject},
		{name: "AMF separation bit clear", request: build(make([]byte, 16), true, []byte("WLAN")), wantSubtype: akaSubtypeAuthReject},
	} {
		t.Run(test.name, func(t *testing.T) {
			client, err := newAKAClientWithMethod(testSIMIdentity(), provider, "aka-prime")
			if err != nil {
				t.Fatal(err)
			}
			action, err := client.handle(context.Background(), test.request)
			if err != nil {
				t.Fatalf("handle() returned transport error instead of fail-closed response: %v", err)
			}
			response, parseErr := parseEAPPacket(action.Response)
			if parseErr != nil || response.Type != eapTypeAKAPrime || response.Data[0] != test.wantSubtype {
				t.Fatalf("fail-closed response = %#v parseErr=%v", response, parseErr)
			}
		})
	}
}

func (provider *testAKAProvider) CheckReady(context.Context, vowifi.SIMIdentity) (vowifi.AKAEvidence, error) {
	return vowifi.AKAEvidence{Ready: true, Application: "USIM"}, nil
}

func (provider *testAKAProvider) Authenticate(
	_ context.Context,
	_ vowifi.SIMIdentity,
	challenge vowifi.AKAChallenge,
) (vowifi.AKAResult, error) {
	provider.calls++
	provider.challenge = challenge
	return provider.result, provider.err
}

func testSIMIdentity() vowifi.SIMIdentity {
	return vowifi.SIMIdentity{
		IMSI:    "234150123456789",
		HomeMCC: "234",
		HomeMNC: "15",
	}
}

func TestEAPAKAIdentityRequiresExactlyOneRequestAttribute(t *testing.T) {
	client, err := newAKAClient(testSIMIdentity(), &testAKAProvider{})
	if err != nil {
		t.Fatalf("newAKAClient() error = %v", err)
	}
	request, err := marshalEAPPacket(eapPacket{
		Code:       eapRequest,
		Identifier: 9,
		Type:       eapTypeAKA,
		Data:       []byte{akaSubtypeIdentity, 0, 0},
	})
	if err != nil {
		t.Fatal(err)
	}
	action, err := client.handle(context.Background(), request)
	if err != nil {
		t.Fatalf("handle malformed identity error = %v", err)
	}
	response, err := parseEAPPacket(action.Response)
	if err != nil {
		t.Fatal(err)
	}
	if response.Code != eapResponse || response.Identifier != 9 ||
		response.Type != eapTypeAKA || len(response.Data) < 1 ||
		response.Data[0] != akaSubtypeClientError {
		t.Fatalf("malformed identity response = %#v", response)
	}
	client, err = newAKAClient(testSIMIdentity(), &testAKAProvider{})
	if err != nil {
		t.Fatal(err)
	}

	permanent, _ := marshalAKAAttribute(akaAttrPermanentIDReq, []byte{0, 0})
	validRequest, _ := marshalEAPPacket(eapPacket{
		Code:       eapRequest,
		Identifier: 10,
		Type:       eapTypeAKA,
		Data:       append([]byte{akaSubtypeIdentity, 0, 0}, permanent...),
	})
	action, err = client.handle(context.Background(), validRequest)
	if err != nil {
		t.Fatalf("handle valid identity error = %v", err)
	}
	response, _ = parseEAPPacket(action.Response)
	if response.Data[0] != akaSubtypeIdentity {
		t.Fatalf("valid identity response subtype = %d", response.Data[0])
	}
	attributes, err := parseAKAAttributes(response.Data[3:])
	if err != nil {
		t.Fatal(err)
	}
	identity, err := oneAKAAttribute(attributes, akaAttrIdentity)
	if err != nil {
		t.Fatal(err)
	}
	length := int(identity.Raw[2])<<8 | int(identity.Raw[3])
	if got := string(identity.Raw[4 : 4+length]); got != "0234150123456789@nai.epc.mnc015.mcc234.3gppnetwork.org" {
		t.Fatalf("permanent AKA identity = %q", got)
	}
}

func TestEAPAKAIdentityWireEncodingHasExactLengthAndPadding(t *testing.T) {
	client, err := newAKAClient(testSIMIdentity(), &testAKAProvider{})
	if err != nil {
		t.Fatalf("newAKAClient() error = %v", err)
	}
	permanent, _ := marshalAKAAttribute(akaAttrPermanentIDReq, []byte{0, 0})
	request, _ := marshalEAPPacket(eapPacket{
		Code:       eapRequest,
		Identifier: 11,
		Type:       eapTypeAKA,
		Data:       append([]byte{akaSubtypeIdentity, 0, 0}, permanent...),
	})
	action, err := client.handle(context.Background(), request)
	if err != nil {
		t.Fatalf("identity response error = %v", err)
	}
	response, err := parseEAPPacket(action.Response)
	if err != nil {
		t.Fatalf("parse identity response = %v", err)
	}
	attributes, err := parseAKAAttributes(response.Data[3:])
	if err != nil {
		t.Fatalf("parse identity attributes = %v", err)
	}
	identity, err := oneAKAAttribute(attributes, akaAttrIdentity)
	if err != nil {
		t.Fatal(err)
	}
	if len(identity.Raw) != ((4 + len(client.identity) + 3) &^ 3) {
		t.Fatalf("wire attribute length = %d, want padded length for %d identity bytes", len(identity.Raw), len(client.identity))
	}
	actualLength := int(binary.BigEndian.Uint16(identity.Raw[2:4]))
	if actualLength != len(client.identity) {
		t.Fatalf("actual identity length = %d, want %d", actualLength, len(client.identity))
	}
	if !bytes.Equal(identity.Raw[4:4+actualLength], client.identity) {
		t.Fatalf("identity bytes = %x, want %x", identity.Raw[4:4+actualLength], client.identity)
	}
	if bytes.Contains(identity.Raw[4:4+actualLength], []byte{0}) {
		t.Fatal("identity bytes contain an unexpected NUL")
	}
	if !bytes.Equal(identity.Raw[4+actualLength:], make([]byte, len(identity.Raw)-4-actualLength)) {
		t.Fatalf("identity padding is not all zero: %x", identity.Raw[4+actualLength:])
	}
	trace := traceEAPPacket("tx", action.Response)
	if trace.ParseError != "" || !trace.TypePresent || !trace.SubtypePresent || trace.Subtype != akaSubtypeIdentity {
		t.Fatalf("identity trace = %#v", trace)
	}
	if len(trace.Attributes) != 1 || trace.Attributes[0].IdentityLength != len(client.identity) ||
		trace.Attributes[0].IdentityHasNUL || trace.Attributes[0].PaddingHasNonZero {
		t.Fatalf("identity trace attributes = %#v", trace.Attributes)
	}
	if trace.RawHexRedacted == hex.EncodeToString(action.Response) {
		t.Fatal("identity trace did not redact subscriber identity bytes")
	}
}

func TestEAPFailureIsAcceptedOnlyAfterAMethodFailureResponse(t *testing.T) {
	client, err := newAKAClient(testSIMIdentity(), &testAKAProvider{})
	if err != nil {
		t.Fatal(err)
	}
	failure, err := marshalEAPPacket(eapPacket{Code: eapFailure, Identifier: 3})
	if err != nil {
		t.Fatal(err)
	}
	if action, err := client.handle(context.Background(), failure); err != nil || len(action.Response) != 0 {
		t.Fatalf("pre-response EAP failure was not silently discarded: response=%x err=%v", action.Response, err)
	}
	identityRequest, _ := marshalEAPPacket(eapPacket{
		Code: eapRequest, Identifier: 3, Type: eapTypeIdentity, Data: []byte("identity"),
	})
	if action, err := client.handle(context.Background(), identityRequest); err != nil || len(action.Response) == 0 {
		t.Fatalf("identity response = %x err=%v", action.Response, err)
	}
	if action, err := client.handle(context.Background(), failure); err != nil || len(action.Response) != 0 || client.terminalFailure {
		t.Fatalf("failure after ordinary identity response was not silently discarded: action=%#v err=%v terminal=%v", action, err, client.terminalFailure)
	}

	malformedRequest, _ := marshalEAPPacket(eapPacket{
		Code: eapRequest, Identifier: 4, Type: eapTypeAKA, Data: []byte{akaSubtypeChallenge},
	})
	action, err := client.handle(context.Background(), malformedRequest)
	if err != nil || len(action.Response) == 0 {
		t.Fatalf("malformed AKA request response = %x err=%v", action.Response, err)
	}
	response, parseErr := parseEAPPacket(action.Response)
	if parseErr != nil || len(response.Data) == 0 || response.Data[0] != akaSubtypeClientError {
		t.Fatalf("malformed AKA request did not produce Client-Error: response=%#v err=%v", response, parseErr)
	}
	clientErrorFailure, _ := marshalEAPPacket(eapPacket{Code: eapFailure, Identifier: 4})
	_, err = client.handle(context.Background(), clientErrorFailure)
	if !errors.Is(err, vowifi.ErrEAPAuthenticationRejected) || !strings.Contains(err.Error(), "before the SIM AKA challenge") {
		t.Fatalf("failure after Client-Error = %v", err)
	}

	postChallenge, err := newAKAClient(testSIMIdentity(), &testAKAProvider{})
	if err != nil {
		t.Fatal(err)
	}
	postChallenge.challengeComplete = true
	postChallenge.hasLastResponseID = true
	postChallenge.lastResponseID = 5
	postFailure, _ := marshalEAPPacket(eapPacket{Code: eapFailure, Identifier: 5})
	if action, err := postChallenge.handle(context.Background(), postFailure); err != nil || len(action.Response) != 0 || postChallenge.terminalFailure {
		t.Fatalf("failure after ordinary Challenge response was not silently discarded: action=%#v err=%v terminal=%v", action, err, postChallenge.terminalFailure)
	}
	postSuccess, _ := marshalEAPPacket(eapPacket{Code: eapSuccess, Identifier: 5})
	if action, err := postChallenge.handle(context.Background(), postSuccess); err != nil || !action.Success {
		t.Fatalf("discarded Failure poisoned later Success: action=%#v err=%v", action, err)
	}

	protected, err := newAKAClient(testSIMIdentity(), &testAKAProvider{})
	if err != nil {
		t.Fatal(err)
	}
	protected.challengeComplete = true
	protected.protectedSuccess = true
	protected.hasLastResponseID = true
	protected.lastResponseID = 6
	protectedFailure, _ := marshalEAPPacket(eapPacket{Code: eapFailure, Identifier: 6})
	if action, err := protected.handle(context.Background(), protectedFailure); err != nil || action.Success || len(action.Response) != 0 || protected.terminalFailure {
		t.Fatalf("failure after protected success was not silently discarded: action=%#v err=%v terminal=%v", action, err, protected.terminalFailure)
	}
}

func TestEAPAKARejectsNewIdentityOrChallengeAfterCompletedChallenge(t *testing.T) {
	permanent, _ := marshalAKAAttribute(akaAttrPermanentIDReq, []byte{0, 0})
	for index, test := range []struct {
		name string
		data []byte
	}{
		{name: "identity", data: append([]byte{akaSubtypeIdentity, 0, 0}, permanent...)},
		{name: "challenge", data: []byte{akaSubtypeChallenge, 0, 0}},
	} {
		t.Run(test.name, func(t *testing.T) {
			provider := &testAKAProvider{}
			client, err := newAKAClient(testSIMIdentity(), provider)
			if err != nil {
				t.Fatal(err)
			}
			client.challengeComplete = true
			client.methodStarted = true
			client.keys.KAut = bytes.Repeat([]byte{0x77}, 16)
			keysBefore := append([]byte(nil), client.keys.KAut...)
			identifier := uint8(90 + index)
			request, _ := marshalEAPPacket(eapPacket{
				Code: eapRequest, Identifier: identifier, Type: eapTypeAKA, Data: test.data,
			})
			action, err := client.handle(context.Background(), request)
			if err != nil {
				t.Fatalf("unexpected post-challenge request error = %v", err)
			}
			response, parseErr := parseEAPPacket(action.Response)
			if parseErr != nil || response.Data[0] != akaSubtypeClientError {
				t.Fatalf("post-challenge response = %#v parseErr=%v", response, parseErr)
			}
			if provider.calls != 0 || !bytes.Equal(client.keys.KAut, keysBefore) {
				t.Fatalf("post-challenge request altered AKA state: calls=%d KAut=%x", provider.calls, client.keys.KAut)
			}
			success, _ := marshalEAPPacket(eapPacket{Code: eapSuccess, Identifier: identifier})
			if successAction, successErr := client.handle(context.Background(), success); successErr == nil || successAction.Success {
				t.Fatalf("success after post-challenge %s = %#v err=%v", test.name, successAction, successErr)
			}
		})
	}
}

func TestEAPAKAIdentityRoundAndTypeLimits(t *testing.T) {
	request := func(t *testing.T, client *akaClient, identifier, kind uint8) eapPacket {
		t.Helper()
		attribute, err := marshalAKAAttribute(kind, []byte{0, 0})
		if err != nil {
			t.Fatal(err)
		}
		return eapPacket{
			Code: eapRequest, Identifier: identifier, Type: eapTypeAKA,
			Data: append([]byte{akaSubtypeIdentity, 0, 0}, attribute...),
		}
	}
	handle := func(t *testing.T, client *akaClient, packet eapPacket) eapPacket {
		t.Helper()
		encoded, err := marshalEAPPacket(packet)
		if err != nil {
			t.Fatal(err)
		}
		action, err := client.handle(context.Background(), encoded)
		if err != nil {
			t.Fatalf("identity round error = %v", err)
		}
		response, err := parseEAPPacket(action.Response)
		if err != nil {
			t.Fatal(err)
		}
		return response
	}

	client, _ := newAKAClient(testSIMIdentity(), &testAKAProvider{})
	if response := handle(t, client, request(t, client, 101, akaAttrAnyIDReq)); response.Data[0] != akaSubtypeIdentity {
		t.Fatalf("first identity response = %#v", response)
	}
	if response := handle(t, client, request(t, client, 102, akaAttrAnyIDReq)); response.Data[0] != akaSubtypeClientError {
		t.Fatalf("repeated identity type response = %#v", response)
	}

	client, _ = newAKAClient(testSIMIdentity(), &testAKAProvider{})
	client.identityRounds = 3
	if response := handle(t, client, request(t, client, 103, akaAttrPermanentIDReq)); response.Data[0] != akaSubtypeClientError {
		t.Fatalf("fourth identity round response = %#v", response)
	}

	client, _ = newAKAClient(testSIMIdentity(), &testAKAProvider{})
	if response := handle(t, client, request(t, client, 104, akaAttrPermanentIDReq)); response.Data[0] != akaSubtypeIdentity {
		t.Fatalf("permanent identity response = %#v", response)
	}
	if response := handle(t, client, request(t, client, 105, akaAttrFullAuthIDReq)); response.Data[0] != akaSubtypeClientError {
		t.Fatalf("full-auth after permanent response = %#v", response)
	}

	client, _ = newAKAClient(testSIMIdentity(), &testAKAProvider{})
	for index, kind := range []uint8{akaAttrAnyIDReq, akaAttrFullAuthIDReq, akaAttrPermanentIDReq} {
		response := handle(t, client, request(t, client, uint8(106+index), kind))
		if response.Data[0] != akaSubtypeIdentity {
			t.Fatalf("valid identity round %d response = %#v", index+1, response)
		}
	}
}

func TestEAPAKAChallengeTypedSIMAndMAC(t *testing.T) {
	result := vowifi.AKAResult{
		RES: bytes.Repeat([]byte{0x91}, 8),
		CK:  bytes.Repeat([]byte{0x92}, 16),
		IK:  bytes.Repeat([]byte{0x93}, 16),
	}
	provider := &testAKAProvider{result: result}
	client, err := newAKAClient(testSIMIdentity(), provider)
	if err != nil {
		t.Fatal(err)
	}
	keys, err := deriveAKAKeys(client.identity, result.IK, result.CK)
	if err != nil {
		t.Fatal(err)
	}
	randValue := bytes.Repeat([]byte{0xa1}, 16)
	autnValue := bytes.Repeat([]byte{0xa2}, 16)
	randAttribute, _ := marshalAKAAttribute(akaAttrRAND, append([]byte{0, 0}, randValue...))
	autnAttribute, _ := marshalAKAAttribute(akaAttrAUTN, append([]byte{0, 0}, autnValue...))
	macAttribute, _ := marshalAKAAttribute(akaAttrMAC, make([]byte, 18))
	data := []byte{akaSubtypeChallenge, 0, 0}
	data = append(data, randAttribute...)
	data = append(data, autnAttribute...)
	data = append(data, macAttribute...)
	request, _ := marshalEAPPacket(eapPacket{
		Code:       eapRequest,
		Identifier: 21,
		Type:       eapTypeAKA,
		Data:       data,
	})
	attributes, _ := parseAKAAttributes(data[3:])
	mac, _ := oneAKAAttribute(attributes, akaAttrMAC)
	macOffset := 5 + 3 + mac.Offset
	copy(request[macOffset+4:macOffset+20], akaMAC(keys.KAut, request))

	action, err := client.handle(context.Background(), request)
	if err != nil {
		t.Fatalf("handle challenge error = %v", err)
	}
	if provider.calls != 1 || !bytes.Equal(provider.challenge.RAND[:], randValue) ||
		!bytes.Equal(provider.challenge.AUTN[:], autnValue) {
		t.Fatalf("typed SIM challenge = %#v calls=%d", provider.challenge, provider.calls)
	}
	response, err := parseEAPPacket(action.Response)
	if err != nil {
		t.Fatal(err)
	}
	if response.Data[0] != akaSubtypeChallenge {
		t.Fatalf("challenge response subtype = %d", response.Data[0])
	}
	responseAttributes, err := parseAKAAttributes(response.Data[3:])
	if err != nil {
		t.Fatal(err)
	}
	res, err := oneAKAAttribute(responseAttributes, akaAttrRES)
	if err != nil {
		t.Fatal(err)
	}
	if bits := int(res.Raw[2])<<8 | int(res.Raw[3]); bits != len(result.RES)*8 {
		t.Fatalf("AT_RES bits = %d", bits)
	}
	responseMAC, err := oneAKAAttribute(responseAttributes, akaAttrMAC)
	if err != nil {
		t.Fatal(err)
	}
	zeroed := append([]byte(nil), action.Response...)
	responseOffset := 5 + 3 + responseMAC.Offset
	actualMAC := append([]byte(nil), zeroed[responseOffset+4:responseOffset+20]...)
	for index := responseOffset + 4; index < responseOffset+20; index++ {
		zeroed[index] = 0
	}
	if !bytes.Equal(actualMAC, akaMAC(keys.KAut, zeroed)) {
		t.Fatal("response AT_MAC does not authenticate the complete EAP packet")
	}
	mismatchedSuccess, _ := marshalEAPPacket(eapPacket{Code: eapSuccess, Identifier: 22})
	if mismatchedAction, mismatchedErr := client.handle(context.Background(), mismatchedSuccess); mismatchedErr != nil || mismatchedAction.Success || len(mismatchedAction.Response) != 0 {
		t.Fatalf("mismatched EAP success = %#v err=%v", mismatchedAction, mismatchedErr)
	}
	success, _ := marshalEAPPacket(eapPacket{Code: eapSuccess, Identifier: 21})
	finalAction, err := client.handle(context.Background(), success)
	if err != nil || !finalAction.Success {
		t.Fatalf("authenticated EAP success = %#v err=%v", finalAction, err)
	}
}

func TestEAPAKAFailureNotificationIsTerminal(t *testing.T) {
	client, err := newAKAClient(testSIMIdentity(), &testAKAProvider{})
	if err != nil {
		t.Fatal(err)
	}
	request := testAKANotificationRequest(t, client, 51, 0x4000, false)
	action, err := client.handle(context.Background(), request)
	if err != nil {
		t.Fatalf("pre-authentication failure notification error = %v", err)
	}
	response, err := parseEAPPacket(action.Response)
	if err != nil || response.Type != eapTypeAKA || response.Data[0] != akaSubtypeNotification {
		t.Fatalf("failure notification response = %#v parseErr=%v", response, err)
	}
	replayed, err := client.handle(context.Background(), request)
	if err != nil || !bytes.Equal(replayed.Response, action.Response) {
		t.Fatalf("failure notification retransmission = %x err=%v", replayed.Response, err)
	}
	failure, _ := marshalEAPPacket(eapPacket{Code: eapFailure, Identifier: 51})
	if _, err := client.handle(context.Background(), failure); !errors.Is(err, vowifi.ErrEAPAuthenticationRejected) {
		t.Fatalf("failure after failure notification error = %v", err)
	}
	success, _ := marshalEAPPacket(eapPacket{Code: eapSuccess, Identifier: 51})
	if _, err := client.handle(context.Background(), success); !errors.Is(err, vowifi.ErrEAPAuthenticationRejected) {
		t.Fatalf("success after failure notification error = %v", err)
	}
	requestAfterFailure, _ := marshalEAPPacket(eapPacket{Code: eapRequest, Identifier: 52, Type: eapTypeIdentity, Data: []byte("retry")})
	if _, err := client.handle(context.Background(), requestAfterFailure); !errors.Is(err, vowifi.ErrEAPAuthenticationRejected) {
		t.Fatalf("request after failure notification error = %v", err)
	}

	postAuthClient, err := newAKAClient(testSIMIdentity(), &testAKAProvider{})
	if err != nil {
		t.Fatal(err)
	}
	postAuthClient.challengeComplete = true
	postAuthClient.keys.KAut = bytes.Repeat([]byte{0x33}, 16)
	postAuthFailure := testAKANotificationRequest(t, postAuthClient, 53, 0, true)
	if action, err := postAuthClient.handle(context.Background(), postAuthFailure); err != nil || len(action.Response) == 0 {
		t.Fatalf("post-authentication failure notification = %x err=%v", action.Response, err)
	}
	postAuthSuccess, _ := marshalEAPPacket(eapPacket{Code: eapSuccess, Identifier: 53})
	if _, err := postAuthClient.handle(context.Background(), postAuthSuccess); !errors.Is(err, vowifi.ErrEAPAuthenticationRejected) {
		t.Fatalf("success after post-authentication failure error = %v", err)
	}
}

func TestEAPAKANotificationPhaseAndRoundValidation(t *testing.T) {
	for _, test := range []struct {
		name              string
		challengeComplete bool
		code              uint16
		withMAC           bool
	}{
		{name: "post-auth before challenge", code: 0, withMAC: true},
		{name: "pre-auth after challenge", challengeComplete: true, code: 0x4000},
		{name: "success bit in pre-auth phase", code: 0xc000},
	} {
		t.Run(test.name, func(t *testing.T) {
			client, err := newAKAClient(testSIMIdentity(), &testAKAProvider{})
			if err != nil {
				t.Fatal(err)
			}
			client.challengeComplete = test.challengeComplete
			client.keys.KAut = bytes.Repeat([]byte{0x44}, 16)
			request := testAKANotificationRequest(t, client, 61, test.code, test.withMAC)
			action, err := client.handle(context.Background(), request)
			if err != nil {
				t.Fatalf("phase validation returned transport error: %v", err)
			}
			response, parseErr := parseEAPPacket(action.Response)
			if parseErr != nil || response.Data[0] != akaSubtypeClientError {
				t.Fatalf("phase validation response = %#v parseErr=%v", response, parseErr)
			}
		})
	}

	client, err := newAKAClient(testSIMIdentity(), &testAKAProvider{})
	if err != nil {
		t.Fatal(err)
	}
	client.challengeComplete = true
	client.resultIndication = true
	client.keys.KAut = bytes.Repeat([]byte{0x55}, 16)
	first := testAKANotificationRequest(t, client, 71, 32768, true)
	if action, err := client.handle(context.Background(), first); err != nil || len(action.Response) == 0 {
		t.Fatalf("protected success notification = %x err=%v", action.Response, err)
	}
	second := testAKANotificationRequest(t, client, 72, 32768, true)
	action, err := client.handle(context.Background(), second)
	if err != nil {
		t.Fatalf("second notification returned transport error: %v", err)
	}
	response, parseErr := parseEAPPacket(action.Response)
	if parseErr != nil || response.Data[0] != akaSubtypeClientError {
		t.Fatalf("second notification response = %#v parseErr=%v", response, parseErr)
	}

	informationalClient, err := newAKAClient(testSIMIdentity(), &testAKAProvider{})
	if err != nil {
		t.Fatal(err)
	}
	informationalClient.challengeComplete = true
	informationalClient.keys.KAut = bytes.Repeat([]byte{0x66}, 16)
	informational := testAKANotificationRequest(t, informationalClient, 73, 0x8001, true)
	action, err = informationalClient.handle(context.Background(), informational)
	if err != nil {
		t.Fatalf("informational success notification error = %v", err)
	}
	response, parseErr = parseEAPPacket(action.Response)
	if parseErr != nil || response.Data[0] != akaSubtypeNotification || informationalClient.terminalFailure {
		t.Fatalf("informational success notification response = %#v parseErr=%v terminal=%v", response, parseErr, informationalClient.terminalFailure)
	}
}

func TestEAPAKAClientErrorAfterChallengeRejectsSuccess(t *testing.T) {
	client, err := newAKAClient(testSIMIdentity(), &testAKAProvider{})
	if err != nil {
		t.Fatal(err)
	}
	client.challengeComplete = true
	reauth, _ := marshalEAPPacket(eapPacket{
		Code: eapRequest, Identifier: 81, Type: eapTypeAKA, Data: []byte{akaSubtypeReauth, 0, 0},
	})
	action, err := client.handle(context.Background(), reauth)
	if err != nil {
		t.Fatalf("unsupported reauthentication response error = %v", err)
	}
	response, err := parseEAPPacket(action.Response)
	if err != nil || response.Data[0] != akaSubtypeClientError {
		t.Fatalf("unsupported reauthentication response = %#v parseErr=%v", response, err)
	}
	success, _ := marshalEAPPacket(eapPacket{Code: eapSuccess, Identifier: 81})
	if _, err := client.handle(context.Background(), success); !errors.Is(err, vowifi.ErrEAPAuthenticationRejected) {
		t.Fatalf("success after client error = %v", err)
	}
}

func testAKANotificationRequest(t *testing.T, client *akaClient, identifier uint8, code uint16, withMAC bool) []byte {
	t.Helper()
	notification, err := marshalAKAAttribute(akaAttrNotification, binary.BigEndian.AppendUint16(nil, code))
	if err != nil {
		t.Fatal(err)
	}
	data := append([]byte{akaSubtypeNotification, 0, 0}, notification...)
	if withMAC {
		mac, err := marshalAKAAttribute(akaAttrMAC, make([]byte, 18))
		if err != nil {
			t.Fatal(err)
		}
		data = append(data, mac...)
	}
	request, err := marshalEAPPacket(eapPacket{Code: eapRequest, Identifier: identifier, Type: client.method, Data: data})
	if err != nil {
		t.Fatal(err)
	}
	if withMAC {
		attributes, err := parseAKAAttributes(data[3:])
		if err != nil {
			t.Fatal(err)
		}
		mac, err := oneAKAAttribute(attributes, akaAttrMAC)
		if err != nil {
			t.Fatal(err)
		}
		offset := 5 + 3 + mac.Offset
		copy(request[offset+4:offset+20], client.packetMAC(client.keys.KAut, request))
	}
	return request
}

func TestEAPAKAUSIMNetworkAuthenticationFailureSendsReject(t *testing.T) {
	provider := &testAKAProvider{err: vowifi.ErrEC20AKAMACFailure}
	client, err := newAKAClient(testSIMIdentity(), provider)
	if err != nil {
		t.Fatal(err)
	}
	randAttribute, _ := marshalAKAAttribute(akaAttrRAND, append([]byte{0, 0}, bytes.Repeat([]byte{1}, 16)...))
	autnAttribute, _ := marshalAKAAttribute(akaAttrAUTN, append([]byte{0, 0}, bytes.Repeat([]byte{2}, 16)...))
	macAttribute, _ := marshalAKAAttribute(akaAttrMAC, make([]byte, 18))
	data := append([]byte{akaSubtypeChallenge, 0, 0}, randAttribute...)
	data = append(data, autnAttribute...)
	data = append(data, macAttribute...)
	request, _ := marshalEAPPacket(eapPacket{Code: eapRequest, Identifier: 5, Type: eapTypeAKA, Data: data})
	action, err := client.handle(context.Background(), request)
	if err != nil {
		t.Fatalf("handle USIM MAC failure error = %v", err)
	}
	response, _ := parseEAPPacket(action.Response)
	if len(response.Data) != 3 || response.Data[0] != akaSubtypeAuthReject {
		t.Fatalf("USIM MAC failure response = %#v", response)
	}
	if !errors.Is(provider.err, vowifi.ErrEC20AKAMACFailure) {
		t.Fatal("test provider lost the MAC failure sentinel")
	}
	failure, _ := marshalEAPPacket(eapPacket{Code: eapFailure, Identifier: 5})
	if _, err := client.handle(context.Background(), failure); !errors.Is(err, vowifi.ErrEAPAuthenticationRejected) {
		t.Fatalf("failure after Authentication-Reject error = %v", err)
	}
}

// The vector is a live capture from Smart Philippines (515/03) on 2026-08-17:
// its AKA-Challenge carried AT_CHECKCODE 2862b445..., which is SHA-1 over the
// AKA-Identity round exactly as this client transmits it.  Reproducing the
// operator's own value proves the hash input, not just the hash.
func TestEAPAKACheckcodeMatchesSmartCapture(t *testing.T) {
	const (
		wireIdentityRequest  = "0101000c170500000a010000"
		wireIdentityResponse = "02010044170500000e0f003630353135303339323437343832343433406e" +
			"61692e6570632e6d6e633030332e6d63633531352e336770706e6574776f726b2e6f72670000"
		wireCheckcode = "2862b44541d2de929a35332ac3c076f7bd43da52"
	)
	result := vowifi.AKAResult{
		RES: bytes.Repeat([]byte{0x91}, 8),
		CK:  bytes.Repeat([]byte{0x92}, 16),
		IK:  bytes.Repeat([]byte{0x93}, 16),
	}
	provider := &testAKAProvider{result: result}
	client, err := newAKAClient(vowifi.SIMIdentity{
		IMSI:    "515039247482443",
		HomeMCC: "515",
		HomeMNC: "03",
	}, provider)
	if err != nil {
		t.Fatal(err)
	}
	action, err := client.handle(context.Background(), mustHex(t, wireIdentityRequest))
	if err != nil {
		t.Fatalf("identity round error = %v", err)
	}
	if got := hex.EncodeToString(action.Response); got != wireIdentityResponse {
		t.Fatalf("identity response = %s, want %s", got, wireIdentityResponse)
	}
	if got := hex.EncodeToString(client.checkcode()); got != wireCheckcode {
		t.Fatalf("checkcode = %s, want %s", got, wireCheckcode)
	}

	request := testAKAChallengeRequest(t, client, result, 2, mustHex(t, wireCheckcode))
	action, err = client.handle(context.Background(), request)
	if err != nil {
		t.Fatalf("challenge error = %v", err)
	}
	if provider.calls != 1 {
		t.Fatalf("SIM authenticate calls = %d", provider.calls)
	}
	response, err := parseEAPPacket(action.Response)
	if err != nil {
		t.Fatal(err)
	}
	responseAttributes, err := parseAKAAttributes(response.Data[3:])
	if err != nil {
		t.Fatal(err)
	}
	checkcode, err := oneAKAAttribute(responseAttributes, akaAttrCheckcode)
	if err != nil {
		t.Fatalf("response AT_CHECKCODE: %v", err)
	}
	if len(checkcode.Raw) != 24 || checkcode.Raw[1] != 6 ||
		checkcode.Raw[2] != 0 || checkcode.Raw[3] != 0 {
		t.Fatalf("AT_CHECKCODE wire encoding = %x", checkcode.Raw)
	}
	if got := hex.EncodeToString(checkcode.Raw[4:]); got != wireCheckcode {
		t.Fatalf("response checkcode = %s, want %s", got, wireCheckcode)
	}
	// AT_MAC has to cover the attribute, otherwise the checkcode is unprotected
	// and buys nothing.
	keys, err := deriveAKAKeys(client.identity, result.IK, result.CK)
	if err != nil {
		t.Fatal(err)
	}
	responseMAC, err := oneAKAAttribute(responseAttributes, akaAttrMAC)
	if err != nil {
		t.Fatal(err)
	}
	zeroed := append([]byte(nil), action.Response...)
	macOffset := 5 + 3 + responseMAC.Offset
	actualMAC := append([]byte(nil), zeroed[macOffset+4:macOffset+20]...)
	for index := macOffset + 4; index < macOffset+20; index++ {
		zeroed[index] = 0
	}
	if !bytes.Equal(actualMAC, akaMAC(keys.KAut, zeroed)) {
		t.Fatal("response AT_MAC does not cover AT_CHECKCODE")
	}
}

func TestEAPAKACheckcodeMismatchIsRejectedBeforeSIMAccess(t *testing.T) {
	result := vowifi.AKAResult{
		RES: bytes.Repeat([]byte{0x91}, 8),
		CK:  bytes.Repeat([]byte{0x92}, 16),
		IK:  bytes.Repeat([]byte{0x93}, 16),
	}
	provider := &testAKAProvider{result: result}
	client, err := newAKAClient(testSIMIdentity(), provider)
	if err != nil {
		t.Fatal(err)
	}
	anyID, _ := marshalAKAAttribute(akaAttrAnyIDReq, []byte{0, 0})
	identityRequest, _ := marshalEAPPacket(eapPacket{
		Code:       eapRequest,
		Identifier: 1,
		Type:       eapTypeAKA,
		Data:       append([]byte{akaSubtypeIdentity, 0, 0}, anyID...),
	})
	if _, err := client.handle(context.Background(), identityRequest); err != nil {
		t.Fatalf("identity round error = %v", err)
	}
	tampered := append([]byte(nil), client.checkcode()...)
	tampered[0] ^= 0xff
	request := testAKAChallengeRequest(t, client, result, 2, tampered)
	action, err := client.handle(context.Background(), request)
	if err != nil {
		t.Fatalf("checkcode mismatch error = %v", err)
	}
	if provider.calls != 0 {
		t.Fatalf("SIM was accessed on a mismatched checkcode: calls=%d", provider.calls)
	}
	response, err := parseEAPPacket(action.Response)
	if err != nil {
		t.Fatal(err)
	}
	if response.Data[0] != akaSubtypeClientError {
		t.Fatalf("mismatch response subtype = %d, want client error", response.Data[0])
	}
}

// Without an AKA-Identity round there is nothing to protect, so the attribute is
// only mirrored — empty, as RFC 4187 Section 10.13 defines it — when the
// responder itself sent one.
func TestEAPAKACheckcodeWithoutIdentityRound(t *testing.T) {
	result := vowifi.AKAResult{
		RES: bytes.Repeat([]byte{0x91}, 8),
		CK:  bytes.Repeat([]byte{0x92}, 16),
		IK:  bytes.Repeat([]byte{0x93}, 16),
	}
	for _, test := range []struct {
		name             string
		responder        []byte
		responderPresent bool
		wantPresent      bool
	}{
		{name: "responder silent", wantPresent: false},
		{name: "responder empty", responder: nil, responderPresent: true, wantPresent: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			provider := &testAKAProvider{result: result}
			client, err := newAKAClient(testSIMIdentity(), provider)
			if err != nil {
				t.Fatal(err)
			}
			checkcode := test.responder
			if !test.responderPresent {
				checkcode = nil
			}
			request := testAKAChallengeRequestWithOptions(t, client, result, 3, checkcode, test.responderPresent)
			action, err := client.handle(context.Background(), request)
			if err != nil {
				t.Fatalf("challenge error = %v", err)
			}
			response, err := parseEAPPacket(action.Response)
			if err != nil {
				t.Fatal(err)
			}
			if response.Data[0] != akaSubtypeChallenge {
				t.Fatalf("response subtype = %d", response.Data[0])
			}
			attributes, err := parseAKAAttributes(response.Data[3:])
			if err != nil {
				t.Fatal(err)
			}
			attribute, err := oneAKAAttribute(attributes, akaAttrCheckcode)
			if test.wantPresent {
				if err != nil {
					t.Fatalf("expected mirrored AT_CHECKCODE: %v", err)
				}
				if len(attribute.Raw) != 4 {
					t.Fatalf("mirrored AT_CHECKCODE = %x, want empty", attribute.Raw)
				}
				return
			}
			if err == nil {
				t.Fatalf("unexpected AT_CHECKCODE = %x", attribute.Raw)
			}
		})
	}
}

func testAKAChallengeRequest(
	t *testing.T,
	client *akaClient,
	result vowifi.AKAResult,
	identifier uint8,
	checkcode []byte,
) []byte {
	t.Helper()
	return testAKAChallengeRequestWithOptions(t, client, result, identifier, checkcode, true)
}

func testAKAChallengeRequestWithOptions(
	t *testing.T,
	client *akaClient,
	result vowifi.AKAResult,
	identifier uint8,
	checkcode []byte,
	withCheckcode bool,
) []byte {
	t.Helper()
	keys, err := deriveAKAKeys(client.identity, result.IK, result.CK)
	if err != nil {
		t.Fatal(err)
	}
	randAttribute, _ := marshalAKAAttribute(akaAttrRAND, append([]byte{0, 0}, bytes.Repeat([]byte{0xa1}, 16)...))
	autnAttribute, _ := marshalAKAAttribute(akaAttrAUTN, append([]byte{0, 0}, bytes.Repeat([]byte{0xa2}, 16)...))
	macAttribute, _ := marshalAKAAttribute(akaAttrMAC, make([]byte, 18))
	data := []byte{akaSubtypeChallenge, 0, 0}
	data = append(data, randAttribute...)
	data = append(data, autnAttribute...)
	if withCheckcode {
		checkcodeAttribute, err := marshalAKAAttribute(akaAttrCheckcode, append([]byte{0, 0}, checkcode...))
		if err != nil {
			t.Fatal(err)
		}
		data = append(data, checkcodeAttribute...)
	}
	data = append(data, macAttribute...)
	request, err := marshalEAPPacket(eapPacket{
		Code:       eapRequest,
		Identifier: identifier,
		Type:       eapTypeAKA,
		Data:       data,
	})
	if err != nil {
		t.Fatal(err)
	}
	attributes, err := parseAKAAttributes(data[3:])
	if err != nil {
		t.Fatal(err)
	}
	mac, err := oneAKAAttribute(attributes, akaAttrMAC)
	if err != nil {
		t.Fatal(err)
	}
	macOffset := 5 + 3 + mac.Offset
	copy(request[macOffset+4:macOffset+20], akaMAC(keys.KAut, request))
	return request
}
