package device

import (
	"context"
	"errors"
	"fmt"

	"vocat/internal/modem"
)

// readNativeQMIICCID reads the authoritative ICCID from the UIM service on
// native WWAN devices.  OpenStick 410 firmware does not implement the usual
// AT+CCID/AT+QCCID commands, while QMI UIM still exposes EF_ICCID.
func (manager *Manager) readNativeQMIICCID(ctx context.Context, candidate modem.Candidate) (string, error) {
	if manager == nil || manager.qmiRadioOpener == nil {
		return "", errors.New("QMI UIM ICCID reader is unavailable")
	}
	if candidate.QMIControl == "" {
		return "", errors.New("QMI UIM control device is unavailable")
	}
	session, err := manager.qmiRadioOpener(ctx, candidate.QMIControl)
	if err != nil {
		return "", fmt.Errorf("open QMI UIM control: %w", err)
	}
	if session == nil {
		return "", errors.New("QMI UIM control returned an empty session")
	}
	defer session.Close()
	reader, ok := session.(nativeQMIICCIDSession)
	if !ok {
		return "", errors.New("QMI session does not expose UIM ICCID reading")
	}
	value, err := reader.GetICCID(ctx)
	if err != nil {
		return "", fmt.Errorf("read EF_ICCID: %w", err)
	}
	iccid := parseICCIDIdentifier(modem.Response{Lines: []string{value}}, nil, 18, 22)
	if iccid == "" {
		return "", errors.New("QMI UIM returned an invalid ICCID")
	}
	return iccid, nil
}

// ReadNativeQMIICCID exposes the native WWAN identity path to integrations
// such as VoWiFi that need to verify the active SIM independently of a full
// device snapshot. Non-native modems return an error so their existing AT
// identity path remains the fallback.
func (manager *Manager) ReadNativeQMIICCID(ctx context.Context, id string) (string, error) {
	if manager == nil {
		return "", errors.New("QMI UIM ICCID reader is unavailable")
	}
	state, err := manager.lookup(id)
	if err != nil {
		return "", err
	}
	candidate := manager.candidateFor(state)
	if !isNativeQMICandidate(candidate) {
		return "", errors.New("device does not expose native QMI UIM ICCID")
	}
	queryContext, cancel := manager.withTimeout(ctx, manager.commandTimeout*5)
	defer cancel()
	return manager.readNativeQMIICCID(queryContext, candidate)
}

func (manager *Manager) readNativeQMIIMEI(ctx context.Context, candidate modem.Candidate) (string, error) {
	if manager == nil || manager.qmiRadioOpener == nil {
		return "", errors.New("QMI DMS IMEI reader is unavailable")
	}
	if !isNativeQMICandidate(candidate) || candidate.QMIControl == "" {
		return "", errors.New("device does not expose native QMI DMS IMEI")
	}
	session, err := manager.qmiRadioOpener(ctx, candidate.QMIControl)
	if err != nil {
		return "", fmt.Errorf("open QMI DMS control: %w", err)
	}
	if session == nil {
		return "", errors.New("QMI DMS control returned an empty session")
	}
	defer session.Close()
	reader, ok := session.(nativeQMIIMEISession)
	if !ok {
		return "", errors.New("QMI session does not expose DMS IMEI reading")
	}
	value, err := reader.GetIMEI(ctx)
	if err != nil {
		return "", fmt.Errorf("read DMS IMEI: %w", err)
	}
	imei := parseIdentifier(modem.Response{Lines: []string{value}}, nil, 14, 17)
	if imei == "" {
		return "", errors.New("QMI DMS returned an invalid IMEI")
	}
	return imei, nil
}

// ReadNativeQMIIMEI exposes the native DMS identity path to integrations that
// cannot rely on AT+CGSN on Qualcomm 410 firmware.
func (manager *Manager) ReadNativeQMIIMEI(ctx context.Context, id string) (string, error) {
	if manager == nil {
		return "", errors.New("QMI DMS IMEI reader is unavailable")
	}
	state, err := manager.lookup(id)
	if err != nil {
		return "", err
	}
	candidate := manager.candidateFor(state)
	queryContext, cancel := manager.withTimeout(ctx, manager.commandTimeout*5)
	defer cancel()
	return manager.readNativeQMIIMEI(queryContext, candidate)
}
