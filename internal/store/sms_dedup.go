package store

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"time"
)

// SMSInboundDedupKey returns the stable cross-transport identity for one
// single-part SMS-DELIVER. The originating address, TP-SCTS and raw TP-UD are
// shared by IMS and modem storage copies; transport-specific wrappers,
// Call-IDs and storage indexes are deliberately excluded.
//
// TP-SCTS has one-second precision, so including TP-UD prevents two different
// messages from the same sender in the same second from colliding.
func SMSInboundDedupKey(peer string, serviceCenterTimestamp *time.Time, rawUserData string) string {
	peer = strings.ToUpper(strings.TrimSpace(peer))
	rawUserData = strings.ToUpper(strings.TrimSpace(rawUserData))
	if peer == "" || serviceCenterTimestamp == nil || serviceCenterTimestamp.IsZero() || rawUserData == "" {
		return ""
	}
	if _, err := hex.DecodeString(rawUserData); err != nil {
		return ""
	}
	digest := sha256.Sum256([]byte(strings.Join([]string{
		peer,
		serviceCenterTimestamp.UTC().Truncate(time.Second).Format(time.RFC3339),
		rawUserData,
	}, "\x00")))
	return "sha256:" + hex.EncodeToString(digest[:])
}
