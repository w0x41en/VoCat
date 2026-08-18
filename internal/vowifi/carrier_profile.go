package vowifi

import (
	"fmt"
	"strings"
)

// CarrierProfile is the small, protocol-facing portion of a carrier policy
// that VoCat needs while starting a session.  It deliberately contains no
// subscriber secret or operator credential.  The profile is resolved from the
// live home PLMN, not from the serving network name.
//
// The preset name is kept compatible with VoHive so diagnostics from the two
// implementations can be compared directly (for example O2_de_26203).
type CarrierProfile struct {
	MCC               string `json:"mcc,omitempty"`
	MNC               string `json:"mnc,omitempty"`
	PLMN              string `json:"plmn,omitempty"`
	PresetID          string `json:"preset_id,omitempty"`
	Source            string `json:"source,omitempty"`
	EPDG              string `json:"epdg,omitempty"`
	EPDGIdentity      string `json:"epdg_identity,omitempty"`
	IKEIdentityType   uint8  `json:"ike_identity_type,omitempty"`
	IMSAPN            string `json:"ims_apn,omitempty"`
	EAPMethod         string `json:"eap_method,omitempty"`
	IMSTransport      string `json:"ims_transport,omitempty"`
	AllowSHA1         bool   `json:"allow_sha1,omitempty"`
	UseMODP1024       bool   `json:"use_modp1024,omitempty"`
	LegacyIKEOnly     bool   `json:"legacy_ike_only,omitempty"`
	IMSIdentitySource string `json:"ims_identity_source,omitempty"`
	// AllowMissingResponderAUTH tolerates an initial IKE_AUTH response that
	// omits AUTH even though this client did not request RFC 5998 EAP-only
	// authentication.  RFC 5998 Section 3 requires such a responder to send
	// AUTH, so this is a per-carrier deviation and never a global default: the
	// final MSK AUTH check stays mandatory either way.
	AllowMissingResponderAUTH bool `json:"allow_missing_responder_auth,omitempty"`
}

const (
	CarrierSourceBuiltin  = "builtin"
	CarrierSourceFallback = "standard_fallback"
	IMSIdentityDerived    = "imsi_derived"
	IMSIdentityExplicit   = "explicit"
)

// ResolveCarrierProfile applies the same MCC/MNC matching rule as VoHive's
// carrier resolver.  The explicit home PLMN supplied by the SIM reader wins;
// no MNC length is guessed from a display/operator name.
func ResolveCarrierProfile(identity SIMIdentity) CarrierProfile {
	mcc := strings.TrimSpace(identity.HomeMCC)
	mnc := strings.TrimSpace(identity.HomeMNC)
	if !isNDigits(mcc, 3, 3) || !isNDigits(mnc, 2, 3) {
		return CarrierProfile{
			Source:            CarrierSourceFallback,
			IMSAPN:            "ims",
			EAPMethod:         "aka",
			IMSTransport:      "tcp",
			IMSIdentitySource: IMSIdentityDerived,
		}
	}
	canonicalMNC := mnc
	for len(canonicalMNC) < 3 {
		canonicalMNC = "0" + canonicalMNC
	}
	plmn := mcc + canonicalMNC
	profile := CarrierProfile{
		MCC:      mcc,
		MNC:      canonicalMNC,
		PLMN:     plmn,
		PresetID: plmn,
		Source:   CarrierSourceFallback,
		// The ePDG names itself in IKE IDr with the TS 23.003 PLMN FQDN, which
		// is an identity and not an address: operators such as Globe publish a
		// separate vanity hostname for dialling and leave this name
		// unresolvable on the public internet.  Keep the two apart so IDr is
		// checked against the identity and the certificate against the host.
		EPDGIdentity:      derivedEPDGIdentity(mcc, canonicalMNC),
		IMSAPN:            "ims",
		EAPMethod:         "aka",
		IMSTransport:      "tcp",
		IMSIdentitySource: IMSIdentityDerived,
	}
	switch plmn {
	case "262003":
		// O2 Germany / Telefónica Germany.  The network currently requires the
		// SHA-1 compatibility offer in addition to the strong-first proposal.
		profile.PresetID = "O2_de_26203"
		profile.Source = CarrierSourceBuiltin
		profile.AllowSHA1 = true
		// Observed 2026-08-17: this ePDG rejects an explicit RFC 5998 EAP-only
		// notification and then omits AUTH from the initial IKE_AUTH response
		// anyway, which RFC 5998 Section 3 does not permit.  The two facts are
		// one behaviour -- the network does EAP-only authentication but will not
		// negotiate it -- so suppressing the notify and tolerating the missing
		// AUTH have to be set together or the exchange cannot complete.
		profile.AllowMissingResponderAUTH = true
	case "234015":
		profile.PresetID = "Vodafone_uk_23415"
		profile.Source = CarrierSourceBuiltin
	case "515003":
		// Smart Philippines uses the bare IMS APN in the Apple carrier bundle.
		// The canonical APN-FQDN form was rejected by Smart's ePDG before
		// EAP-AKA started; keep the network-facing IDr as "ims".
		profile.PresetID = "Smart_PH_51503"
		profile.Source = CarrierSourceBuiltin
		profile.IMSAPN = "ims"
	case "515066":
		// DITO Philippines accepts a single IKE suite on its ePDG:
		// AES-CBC-128 with HMAC-SHA1 and MODP-1024. Every stronger offer is
		// answered with NO_PROPOSAL_CHOSEN, so the legacy transforms are not
		// a preference here but the only way to negotiate at all.
		profile.PresetID = "DITO_PH_515066"
		profile.Source = CarrierSourceBuiltin
		profile.AllowSHA1 = true
		profile.UseMODP1024 = true
		profile.LegacyIKEOnly = true
	case "515002":
		// Globe Philippines publishes a dedicated static ePDG hostname rather
		// than the standard PLMN-derived name. Keep the hostname here so DNS
		// resolution follows the operator profile and remains dynamic.
		profile.PresetID = "Globe_PH_51502"
		profile.Source = CarrierSourceBuiltin
		profile.EPDG = "weconnect.globe.com.ph"
		// Globe owns mnc002.mcc515.pub.3gppnetwork.org (SOA g-net1.globe.com.ph)
		// but all three of its authoritative servers answer NXDOMAIN for the
		// epdg.epc label, so the identity below never resolves publicly.  It is
		// still what the ePDG puts in IDr, which is all it is used for.
		profile.EPDGIdentity = "epdg.epc.mnc002.mcc515.pub.3gppnetwork.org"
		// The permanent EAP-AKA NAI is carried in IKE IDi as
		// ID_RFC822_ADDR (type 3). ID_FQDN (type 2) is reserved for the
		// requested APN in IDr below.
		profile.IKEIdentityType = 3 // ID_RFC822_ADDR / NAI
		// Globe is the other PLMN whose ePDG refuses the RFC 5998 EAP-only
		// notification.  Set precautionarily rather than from an observed
		// response: this network is reached only far enough to fail at
		// EAP-AKA, and requiring an initial AUTH it may not send would stop
		// that investigation at IKE instead.  Drop it once a capture shows the
		// ePDG does send AUTH.
		profile.AllowMissingResponderAUTH = true
	}
	return profile
}

// derivedEPDGIdentity builds the TS 23.003 ePDG FQDN.  The MNC is already
// zero-padded to three digits by the caller: Globe's own DNS zone is named
// mnc002, so the padded form is the operator-recognised one even though the
// unpadded mnc02 label is what a public resolver answers (with a 127.0.0.1
// wildcard sinkhole that is not an ePDG).
func derivedEPDGIdentity(mcc string, canonicalMNC string) string {
	return fmt.Sprintf("epdg.epc.mnc%s.mcc%s.pub.3gppnetwork.org", canonicalMNC, mcc)
}

func (profile CarrierProfile) String() string {
	if profile.PresetID == "" {
		return "standard_fallback"
	}
	return fmt.Sprintf("%s (%s)", profile.PresetID, profile.Source)
}
