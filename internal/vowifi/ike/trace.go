package ike

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strings"

	"vocat/internal/vowifi"
)

// IKEAuthTraceAttribute describes one configuration attribute in the
// plaintext CFG_REQUEST. Values are intentionally not retained because the
// request attributes used here have no subscriber data.
type IKEAuthTraceAttribute struct {
	Type        uint16 `json:"type"`
	WireLength  int    `json:"wire_length"`
	ValueLength int    `json:"value_length"`
}

// IKEAuthTracePayload describes one plaintext IKE_AUTH payload before it is
// encrypted. IDi identity bytes are replaced with 0xaa in RawHexRedacted;
// only a short PLMN prefix, realm, length, and digest are retained.
type IKEAuthTracePayload struct {
	Type                    uint8                   `json:"type"`
	Name                    string                  `json:"name"`
	BodyLength              int                     `json:"body_length"`
	WireLength              int                     `json:"wire_length"`
	RawHexRedacted          string                  `json:"raw_hex_redacted"`
	ParseError              string                  `json:"parse_error,omitempty"`
	IdentityType            uint8                   `json:"identity_type,omitempty"`
	IdentityLength          int                     `json:"identity_length,omitempty"`
	IdentityPrefix          string                  `json:"identity_prefix,omitempty"`
	IdentityRealm           string                  `json:"identity_realm,omitempty"`
	IdentityValue           string                  `json:"identity_value,omitempty"`
	IdentitySHA256          string                  `json:"identity_sha256,omitempty"`
	IdentityHasNUL          bool                    `json:"identity_has_nul,omitempty"`
	NotifyType              uint16                  `json:"notify_type,omitempty"`
	NotifyDataLength        int                     `json:"notify_data_length,omitempty"`
	ConfigurationType       uint8                   `json:"configuration_type,omitempty"`
	ConfigurationAttributes []IKEAuthTraceAttribute `json:"configuration_attributes,omitempty"`
	ProposalCount           int                     `json:"proposal_count,omitempty"`
	TrafficSelectorCount    int                     `json:"traffic_selector_count,omitempty"`
}

// IKEAuthTraceEvent is emitted for the first IKE_AUTH request while its
// payloads are still available in plaintext. It is diagnostic data only and
// must not be used as an authentication input.
type IKEAuthTraceEvent struct {
	Direction                        string                `json:"direction"`
	Exchange                         string                `json:"exchange"`
	MessageID                        uint32                `json:"message_id"`
	ModemIMSIHash                    string                `json:"modem_imsi_sha256,omitempty"`
	EAPIMSIHash                      string                `json:"eap_imsi_sha256,omitempty"`
	ModemIMSILength                  int                   `json:"modem_imsi_length,omitempty"`
	EAPIMSILength                    int                   `json:"eap_imsi_length,omitempty"`
	SameIMSI                         bool                  `json:"same_imsi"`
	PermanentIdentityMatchesExpected bool                  `json:"permanent_identity_matches_expected"`
	ExpectedIdentityLength           int                   `json:"expected_permanent_identity_length,omitempty"`
	Payloads                         []IKEAuthTracePayload `json:"payloads"`
}

// IKETraceCallback receives redacted plaintext IKE_AUTH diagnostics.
type IKETraceCallback func(IKEAuthTraceEvent)

type akaIdentityTrace struct {
	ModemIMSIHash                    string
	EAPIMSIHash                      string
	ModemIMSILength                  int
	EAPIMSILength                    int
	SameIMSI                         bool
	PermanentIdentityMatchesExpected bool
	ExpectedIdentityLength           int
}

func traceAKAIdentityAudit(identity vowifi.SIMIdentity, akaIdentity []byte, method uint8) akaIdentityTrace {
	modemIMSI := strings.TrimSpace(identity.IMSI)
	eapIMSI, extracted := extractAKAIMSI(akaIdentity, method)
	result := akaIdentityTrace{
		ModemIMSILength: modemIMSITraceLength(modemIMSI),
		EAPIMSILength:   modemIMSITraceLength(eapIMSI),
		SameIMSI:        extracted && modemIMSI != "" && modemIMSI == eapIMSI,
	}
	if modemIMSI != "" {
		digest := sha256.Sum256([]byte(modemIMSI))
		result.ModemIMSIHash = hex.EncodeToString(digest[:])
	}
	if eapIMSI != "" {
		digest := sha256.Sum256([]byte(eapIMSI))
		result.EAPIMSIHash = hex.EncodeToString(digest[:])
	}
	if expected, err := permanentAKAIdentityForType(identity, method); err == nil {
		result.ExpectedIdentityLength = len(expected)
		result.PermanentIdentityMatchesExpected = bytes.Equal(expected, akaIdentity)
	}
	return result
}

func modemIMSITraceLength(value string) int {
	if value == "" {
		return 0
	}
	return len(value)
}

func extractAKAIMSI(akaIdentity []byte, method uint8) (string, bool) {
	prefix := byte('0')
	if method == eapTypeAKAPrime {
		prefix = '6'
	}
	if len(akaIdentity) < 3 || akaIdentity[0] != prefix {
		return "", false
	}
	at := bytes.IndexByte(akaIdentity, '@')
	if at <= 1 {
		return "", false
	}
	value := akaIdentity[1:at]
	for _, digit := range value {
		if digit < '0' || digit > '9' {
			return "", false
		}
	}
	return string(value), true
}

func traceIKEAuthPayloads(direction string, messageID uint32, payloads []payload) IKEAuthTraceEvent {
	event := IKEAuthTraceEvent{
		Direction: direction,
		Exchange:  "IKE_AUTH",
		MessageID: messageID,
		Payloads:  make([]IKEAuthTracePayload, 0, len(payloads)),
	}
	for _, item := range payloads {
		trace := IKEAuthTracePayload{
			Type:           item.Type,
			Name:           ikePayloadName(item.Type),
			BodyLength:     len(item.Body),
			WireLength:     4 + len(item.Body),
			RawHexRedacted: hex.EncodeToString(item.Body),
		}
		switch item.Type {
		case payloadIDi:
			traceIdentityPayload(&trace, item.Body, true)
		case payloadIDr:
			traceIdentityPayload(&trace, item.Body, false)
		case payloadNotify:
			traceNotifyPayload(&trace, item)
		case payloadCP:
			traceConfigurationPayload(&trace, item.Body)
		case payloadSA:
			proposals, err := parseProposals(item.Body)
			if err != nil {
				trace.ParseError = err.Error()
			} else {
				trace.ProposalCount = len(proposals)
			}
		case payloadTSi, payloadTSr:
			selectors, err := parseTrafficSelectors(item)
			if err != nil {
				trace.ParseError = err.Error()
			} else {
				trace.TrafficSelectorCount = len(selectors)
			}
		}
		event.Payloads = append(event.Payloads, trace)
	}
	return event
}

func ikePayloadName(kind uint8) string {
	switch kind {
	case payloadSA:
		return "SA"
	case payloadKE:
		return "KE"
	case payloadIDi:
		return "IDi"
	case payloadIDr:
		return "IDr"
	case payloadCert:
		return "CERT"
	case payloadAuth:
		return "AUTH"
	case payloadNonce:
		return "NONCE"
	case payloadNotify:
		return "NOTIFY"
	case payloadDelete:
		return "DELETE"
	case payloadTSi:
		return "TSi"
	case payloadTSr:
		return "TSr"
	case payloadEncrypted:
		return "ENCRYPTED"
	case payloadCP:
		return "CP"
	case payloadEAP:
		return "EAP"
	default:
		return fmt.Sprintf("PAYLOAD_%d", kind)
	}
}

func traceIdentityPayload(trace *IKEAuthTracePayload, body []byte, redact bool) {
	if len(body) < 4 {
		trace.ParseError = "ike: identity payload body is shorter than four-byte header"
		return
	}
	value := body[4:]
	trace.IdentityType = body[0]
	trace.IdentityLength = len(value)
	trace.IdentityHasNUL = bytes.Contains(value, []byte{0})
	digest := sha256.Sum256(value)
	trace.IdentitySHA256 = hex.EncodeToString(digest[:])
	if redact {
		// The first six bytes cover the leading 0 and the five PLMN digits,
		// which is enough to distinguish 51502 from an accidental 515002
		// normalization without retaining subscriber digits.
		prefixLength := len(value)
		if prefixLength > 6 {
			prefixLength = 6
		}
		trace.IdentityPrefix = string(value[:prefixLength])
		if at := bytes.IndexByte(value, '@'); at >= 0 && at+1 < len(value) {
			trace.IdentityRealm = string(value[at+1:])
		}
		redacted := append([]byte(nil), body...)
		for index := 4; index < len(redacted); index++ {
			redacted[index] = 0xaa
		}
		trace.RawHexRedacted = hex.EncodeToString(redacted)
		return
	}
	trace.IdentityValue = string(value)
}

func traceNotifyPayload(trace *IKEAuthTracePayload, item payload) {
	kind, data, err := parseNotify(item)
	if err != nil {
		trace.ParseError = err.Error()
		return
	}
	trace.NotifyType = kind
	trace.NotifyDataLength = len(data)
}

func traceConfigurationPayload(trace *IKEAuthTracePayload, body []byte) {
	if len(body) < 4 {
		trace.ParseError = "ike: configuration payload body is shorter than four-byte header"
		return
	}
	trace.ConfigurationType = body[0]
	for offset := 4; offset < len(body); {
		if offset+4 > len(body) {
			trace.ParseError = "ike: configuration attribute header is truncated"
			return
		}
		kind := binary.BigEndian.Uint16(body[offset : offset+2])
		length := int(binary.BigEndian.Uint16(body[offset+2 : offset+4]))
		offset += 4
		if offset+length > len(body) {
			trace.ParseError = fmt.Sprintf("ike: configuration attribute %d exceeds payload", kind)
			return
		}
		trace.ConfigurationAttributes = append(trace.ConfigurationAttributes, IKEAuthTraceAttribute{
			Type:        kind,
			WireLength:  4 + length,
			ValueLength: length,
		})
		offset += length
	}
}
