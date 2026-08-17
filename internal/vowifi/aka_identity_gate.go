package vowifi

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"
)

const defaultAKAIdentityGateInterval = 2 * time.Second

// akaIdentityGate prevents a USIM AUTHENTICATE APDU from running while a
// multi-IMSI card is temporarily advertising another subscriber identity.
// The watcher may tolerate that flap for the lifetime of the session, but AKA
// itself must use the same IMSI that built the IKE/IMS identity.
type akaIdentityGate struct {
	inner         AKAProvider
	sim           SIMIdentityReader
	deviceID      string
	checkInterval time.Duration
	logger        *slog.Logger
}

func newAKAIdentityGate(
	inner AKAProvider,
	sim SIMIdentityReader,
	deviceID string,
	checkInterval time.Duration,
	logger *slog.Logger,
) AKAProvider {
	if inner == nil || sim == nil || strings.TrimSpace(deviceID) == "" {
		return inner
	}
	if checkInterval <= 0 {
		checkInterval = defaultAKAIdentityGateInterval
	}
	return &akaIdentityGate{
		inner:         inner,
		sim:           sim,
		deviceID:      strings.TrimSpace(deviceID),
		checkInterval: checkInterval,
		logger:        logger,
	}
}

func (gate *akaIdentityGate) CheckReady(
	ctx context.Context,
	identity SIMIdentity,
) (AKAEvidence, error) {
	return gate.inner.CheckReady(ctx, identity)
}

func (gate *akaIdentityGate) Authenticate(
	ctx context.Context,
	identity SIMIdentity,
	challenge AKAChallenge,
) (AKAResult, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := gate.waitForBaseline(ctx, identity); err != nil {
		return AKAResult{}, err
	}
	return gate.inner.Authenticate(ctx, identity, challenge)
}

// ReadSMSCenter keeps the optional QMI/AT service-centre reader visible after
// the AKA provider is wrapped. IMS EnableSMS uses this capability on devices
// where the initial orchestrator probe could not populate SIMIdentity.SMSC.
func (gate *akaIdentityGate) ReadSMSCenter(ctx context.Context, deviceID string) (string, error) {
	reader, ok := gate.inner.(interface {
		ReadSMSCenter(context.Context, string) (string, error)
	})
	if !ok {
		return "", errors.New("vowifi: wrapped AKA provider has no SMS-centre reader")
	}
	return reader.ReadSMSCenter(ctx, deviceID)
}

func (gate *akaIdentityGate) waitForBaseline(ctx context.Context, want SIMIdentity) error {
	if strings.TrimSpace(want.ICCID) == "" || strings.TrimSpace(want.IMSI) == "" {
		return gate.innerIdentityUnavailable("session baseline is missing ICCID or IMSI")
	}
	loggedWait := false
	for {
		current, err := gate.sim.ReadIdentity(ctx, gate.deviceID)
		if err == nil && sameAKAIdentity(want, current) {
			if loggedWait && gate.logger != nil {
				gate.logger.Info("VoWiFi AKA identity gate released",
					"category", "vowifi", "event", "aka_identity_gate_released",
					"device_id", gate.deviceID)
			}
			return nil
		}
		if ctx.Err() != nil {
			return fmt.Errorf("vowifi: wait for SIM identity baseline before AKA: %w", ctx.Err())
		}
		if !loggedWait && gate.logger != nil {
			attrs := []any{
				"category", "vowifi", "event", "aka_identity_gate_waiting",
				"device_id", gate.deviceID,
				"identity_read_failed", err != nil,
			}
			if err == nil {
				attrs = append(attrs,
					"iccid_match", strings.EqualFold(strings.TrimSpace(want.ICCID), strings.TrimSpace(current.ICCID)),
					"imsi_match", strings.TrimSpace(want.IMSI) == strings.TrimSpace(current.IMSI),
				)
			}
			gate.logger.Warn("VoWiFi AKA authentication gated until the session SIM identity returns",
				attrs...)
			loggedWait = true
		}
		timer := time.NewTimer(gate.checkInterval)
		select {
		case <-ctx.Done():
			if !timer.Stop() {
				<-timer.C
			}
			return fmt.Errorf("vowifi: wait for SIM identity baseline before AKA: %w", ctx.Err())
		case <-timer.C:
		}
	}
}

func (gate *akaIdentityGate) innerIdentityUnavailable(reason string) error {
	return fmt.Errorf("vowifi: AKA identity gate unavailable: %s", reason)
}

func sameAKAIdentity(want, current SIMIdentity) bool {
	return strings.TrimSpace(want.ICCID) != "" &&
		strings.TrimSpace(want.IMSI) != "" &&
		strings.EqualFold(strings.TrimSpace(want.ICCID), strings.TrimSpace(current.ICCID)) &&
		strings.TrimSpace(want.IMSI) == strings.TrimSpace(current.IMSI)
}
