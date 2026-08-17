package server

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"vocat/internal/device"
	"vocat/internal/store"
	"vocat/internal/vowifi"
)

func esimUnavailable(w http.ResponseWriter) {
	writeError(w, http.StatusNotImplemented, "esim_operation_unavailable", "This specific eSIM operation is not implemented.")
}

// handleESIM routes every /devices/{id}/esim* path.
func (s *Server) handleESIM(w http.ResponseWriter, r *http.Request, rest []string, configID string, physicalID string, physicalPresent bool) bool {
	if len(rest) == 0 || (len(rest) == 1 && strings.TrimSpace(rest[0]) == "") {
		if !requireMethod(w, r, http.MethodGet) {
			return true
		}
		s.writeEsimOverview(w, r, physicalID, physicalPresent)
		return true
	}

	switch rest[0] {
	case "profiles":
		if len(rest) == 1 {
			if !requireMethod(w, r, http.MethodGet) {
				return true
			}
			s.writeEsimGroups(w, r, physicalID, physicalPresent)
			return true
		}
		if len(rest) == 2 && r.Method == http.MethodDelete {
			s.handleEsimDelete(w, r, physicalID, physicalPresent, rest[1])
			return true
		}
		if len(rest) == 2 && r.Method == http.MethodPatch {
			s.handleEsimRename(w, r, physicalID, physicalPresent, rest[1])
			return true
		}
		esimUnavailable(w)
		return true
	case "notifications":
		if len(rest) == 1 {
			if !requireMethod(w, r, http.MethodGet) {
				return true
			}
			// No LPA download backend, so there are never pending notifications.
			writeJSON(w, http.StatusOK, map[string]any{"data": map[string]any{"items": []any{}}})
			return true
		}
		// notifications/{id}/actions/retry
		esimUnavailable(w)
		return true
	case "actions":
		if len(rest) == 3 && rest[1] == "switch" && rest[2] == "stream" {
			if !requireMethod(w, r, http.MethodGet) {
				return true
			}
			s.handleEsimSwitchStream(w, r, configID, physicalID, physicalPresent)
			return true
		}
		if len(rest) == 2 && rest[1] == "switch" {
			if !requireMethod(w, r, http.MethodPost) {
				return true
			}
			s.handleEsimSwitch(w, r, configID, physicalID, physicalPresent)
			return true
		}
		if len(rest) == 2 && rest[1] == "disable" {
			if !requireMethod(w, r, http.MethodPost) {
				return true
			}
			s.handleEsimDisable(w, r, configID, physicalID, physicalPresent)
			return true
		}
		if len(rest) == 2 && rest[1] == "download" {
			if !requireMethod(w, r, http.MethodGet) {
				return true
			}
			s.handleEsimDownload(w, r, configID, physicalID, physicalPresent)
			return true
		}
		// Any other provisioning action is not implemented.
		esimUnavailable(w)
		return true
	default:
		return false
	}
}

// esimInfo loads the eUICC profile list. The string result is "ok" (use info),
// "empty" (no usable eUICC — render the empty state), or "error" (an error
// response has already been written).
func (s *Server) esimInfo(w http.ResponseWriter, r *http.Request, physicalID string, physicalPresent bool) (string, []device.EsimInventoryEntry) {
	if s.devices == nil || !physicalPresent {
		return "empty", nil
	}
	info, err := s.devices.ESIMInventory(r.Context(), physicalID)
	if err != nil {
		if errors.Is(err, device.ErrNoEUICC) {
			return "empty", nil
		}
		s.writeDeviceError(w, err)
		return "error", nil
	}
	return "ok", info
}

// writeEsimOverview returns { chipInfo, profiles } for the eSIM tab.
func (s *Server) writeEsimOverview(w http.ResponseWriter, r *http.Request, physicalID string, physicalPresent bool) {
	status, info := s.esimInfo(w, r, physicalID, physicalPresent)
	switch status {
	case "error":
		return
	case "empty":
		writeJSON(w, http.StatusOK, map[string]any{"data": map[string]any{"chipInfo": nil, "profiles": []any{}}})
		return
	}
	chipInfo := esimInventoryChipInfo(info)
	groups := esimInventoryGroups(info)
	writeJSON(w, http.StatusOK, map[string]any{
		"data": map[string]any{
			"chipInfo": chipInfo,
			"profiles": groups,
		},
	})
}

func esimInventoryChipInfo(entries []device.EsimInventoryEntry) map[string]any {
	eids := make([]any, 0, len(entries))
	firmware := ""
	for _, entry := range entries {
		chip := entry.Chip
		eid := map[string]any{"eid": chip.EID, "aid": chip.AID}
		if chip.HasFreeNvram {
			eid["freeNvramBytes"] = chip.FreeNvramBytes
			eid["freeNvram"] = fmt.Sprintf("%.2f KB", float64(chip.FreeNvramBytes)/1024)
		}
		if chip.Manufacturer != "" {
			eid["manufacturer"] = chip.Manufacturer
		}
		if len(chip.Certificates) > 0 {
			eid["certificates"] = chip.Certificates
		}
		if len(chip.TrustedCIs) > 0 {
			eid["trustedCiKeyIds"] = chip.TrustedCIs
		}
		if chip.DefaultSmdpAddress != "" {
			eid["defaultSmdpAddress"] = chip.DefaultSmdpAddress
		}
		if chip.RootDsAddress != "" {
			eid["rootDsAddress"] = chip.RootDsAddress
		}
		if chip.SAS != "" {
			eid["sasAccreditationNumber"] = chip.SAS
		}
		eids = append(eids, eid)
		if firmware == "" {
			firmware = chip.FirmwareVer
		}
	}
	result := map[string]any{"eids": eids}
	if firmware != "" {
		result["firmware"] = firmware
	}
	return result
}

func esimInventoryGroups(entries []device.EsimInventoryEntry) []map[string]any {
	groups := make([]map[string]any, 0, len(entries))
	for _, entry := range entries {
		groups = append(groups, esimGroups(entry.Info)...)
	}
	return groups
}

// esimChipInfo reads the eUICC chip header (EID, firmware, free NVRAM,
// manufacturer, CI certificates, SM-DP+/Root SM-DS addresses, SAS, info source)
// for the eSIM tab. On any read failure it returns a sparse object so the
// profile list still renders.
func (s *Server) esimChipInfo(r *http.Request, physicalID string) map[string]any {
	chip, err := s.devices.ESIMChipInfo(r.Context(), physicalID)
	if err != nil || chip == nil {
		return map[string]any{}
	}
	eid := map[string]any{
		"eid": chip.EID,
		"aid": chip.AID,
	}
	if chip.HasFreeNvram {
		eid["freeNvramBytes"] = chip.FreeNvramBytes
		eid["freeNvram"] = fmt.Sprintf("%.2f KB", float64(chip.FreeNvramBytes)/1024)
	}
	if chip.Manufacturer != "" {
		eid["manufacturer"] = chip.Manufacturer
	}
	if len(chip.Certificates) > 0 {
		eid["certificates"] = chip.Certificates
	}
	if len(chip.TrustedCIs) > 0 {
		eid["trustedCiKeyIds"] = chip.TrustedCIs
	}
	if chip.DefaultSmdpAddress != "" {
		eid["defaultSmdpAddress"] = chip.DefaultSmdpAddress
	}
	if chip.RootDsAddress != "" {
		eid["rootDsAddress"] = chip.RootDsAddress
	}
	if chip.SAS != "" {
		eid["sasAccreditationNumber"] = chip.SAS
	}
	chipMap := map[string]any{
		"eids": []any{eid},
	}
	if chip.FirmwareVer != "" {
		chipMap["firmware"] = chip.FirmwareVer
	}
	return chipMap
}

// writeEsimGroups returns just the profile groups for the /esim/profiles call.
func (s *Server) writeEsimGroups(w http.ResponseWriter, r *http.Request, physicalID string, physicalPresent bool) {
	status, info := s.esimInfo(w, r, physicalID, physicalPresent)
	switch status {
	case "error":
		return
	case "empty":
		writeJSON(w, http.StatusOK, map[string]any{"data": []any{}})
		return
	}
	groups := esimInventoryGroups(info)
	writeJSON(w, http.StatusOK, map[string]any{"data": groups})
}

// GetProfilesInfo does not include an EID on every eUICC implementation. The
// EC20 hosts one physical eUICC, so associate the separately-read chip identity
// with that sole profile group. Without this, the SPA cannot match the group to
// its manufacturer/certificate/production metadata even though it was read.
func attachSingleEUICCIdentity(groups []map[string]any, chipInfo map[string]any) {
	if len(groups) != 1 {
		return
	}
	eids, ok := chipInfo["eids"].([]any)
	if !ok || len(eids) != 1 {
		return
	}
	identity, ok := eids[0].(map[string]any)
	if !ok {
		return
	}
	groupEID, _ := groups[0]["eid"].(string)
	chipEID, _ := identity["eid"].(string)
	if strings.TrimSpace(groupEID) == "" && strings.TrimSpace(chipEID) != "" {
		groups[0]["eid"] = strings.TrimSpace(chipEID)
	}
	groupAID, _ := groups[0]["aidHex"].(string)
	chipAID, _ := identity["aid"].(string)
	if strings.TrimSpace(groupAID) == "" && strings.TrimSpace(chipAID) != "" {
		groups[0]["aidHex"] = strings.TrimSpace(chipAID)
	}
}

// esimGroups flattens the eUICC profile list into the SPA's per-eUICC groups
// (the EC20 hosts a single eUICC, so this is normally one group).
func esimGroups(info device.EsimInfo) []map[string]any {
	profiles := make([]map[string]any, 0, len(info.Profiles))
	for _, p := range info.Profiles {
		profiles = append(profiles, map[string]any{
			"iccid":               p.ICCID,
			"name":                firstNonEmpty(p.Nickname, p.Name),
			"serviceProviderName": p.ServiceProvider,
			"state":               p.State,
			"stateText":           p.StateText,
			"classText":           p.Class,
		})
	}
	return []map[string]any{
		{
			"eid":      info.EID,
			"aidHex":   info.AID,
			"profiles": profiles,
		},
	}
}

func (s *Server) handleEsimRename(w http.ResponseWriter, r *http.Request, physicalID string, physicalPresent bool, iccid string) {
	if s.devices == nil {
		writeError(w, http.StatusServiceUnavailable, "device_manager_unavailable", "device manager is unavailable")
		return
	}
	if !physicalPresent {
		writeError(w, http.StatusServiceUnavailable, "physical_device_missing", "the configured modem is not present on this Linux host")
		return
	}
	iccid = strings.TrimSpace(iccid)
	if iccid == "" {
		writeError(w, http.StatusBadRequest, "invalid_request", "iccid is required")
		return
	}
	var request struct {
		Name   string `json:"name"`
		AIDHex string `json:"aid_hex"` // accepted for the multi-eUICC SPA contract; ICCID addresses the profile
	}
	if err := s.decodeJSON(w, r, &request); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	nickname := strings.TrimSpace(request.Name)
	if nickname == "" {
		writeError(w, http.StatusBadRequest, "invalid_request", "profile nickname is required")
		return
	}
	if err := s.devices.ESIMRenameProfile(r.Context(), physicalID, iccid, nickname, request.AIDHex); err != nil {
		s.writeDeviceError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"data": map[string]any{"status": "renamed", "iccid": iccid, "name": nickname}})
}

// handleEsimSwitch enables one already-installed profile by ICCID (切卡). The
// eUICC EnableProfile command needs no authentication key.
func (s *Server) handleEsimSwitch(w http.ResponseWriter, r *http.Request, configID string, physicalID string, physicalPresent bool) {
	if s.devices == nil {
		writeError(w, http.StatusServiceUnavailable, "device_manager_unavailable", "device manager is unavailable")
		return
	}
	if !physicalPresent {
		writeError(w, http.StatusServiceUnavailable, "physical_device_missing", "the configured modem is not present on this Linux host")
		return
	}
	var request struct {
		ICCID  string `json:"iccid"`
		AIDHex string `json:"aid_hex"` // accepted for contract compatibility; switching keys off iccid
	}
	if err := s.decodeJSON(w, r, &request); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	iccid := strings.TrimSpace(request.ICCID)
	if iccid == "" {
		writeError(w, http.StatusBadRequest, "invalid_request", "iccid is required")
		return
	}
	// A confirmed profile switch includes the EC20 reset and a live ICCID read,
	// which normally takes longer than the server's ordinary response deadline.
	controller := http.NewResponseController(w)
	_ = controller.SetWriteDeadline(time.Time{})
	if err := s.runESIMSwitch(r.Context(), configID, physicalID, iccid, request.AIDHex, nil); err != nil {
		s.writeESIMSwitchError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"data": map[string]any{"status": "switched", "iccid": iccid, "verified": true}})
}

// esimCardOperationFailure tags which stage of a guarded card transaction
// failed. Both the profile switch and the profile download run the same
// quiesce/guard/restore sequence, so both report through this type.
type esimCardOperationFailure struct {
	stage string
	err   error
}

func (failure *esimCardOperationFailure) Error() string { return failure.err.Error() }
func (failure *esimCardOperationFailure) Unwrap() error { return failure.err }

// runESIMSwitch is the single transaction used by both the legacy JSON POST
// and the progress SSE endpoint. progress is invoked only by the device layer;
// quiesce, subscriber guarding, rollback and per-card policy are identical.
func (s *Server) runESIMSwitch(
	ctx context.Context,
	configID string,
	physicalID string,
	iccid string,
	aidHex string,
	progress func(device.EsimProgress),
) error {
	transaction, err := s.quiesceVoWiFiForESIMTransaction(ctx, configID)
	if err != nil {
		return &esimCardOperationFailure{stage: "quiesce", err: err}
	}
	if transaction != nil && transaction.physicalID == "" {
		transaction.physicalID = physicalID
	}
	releaseSubscriberChange, err := s.beginVoWiFiSubscriberChange(ctx, configID)
	if err != nil {
		if restoreErr := s.restoreESIMVoWiFiTransaction(transaction); restoreErr != nil {
			s.logger.Error("restore VoWiFi after subscriber guard failure", "device_id", configID, "error", restoreErr)
		}
		return &esimCardOperationFailure{stage: "subscriber_guard", err: err}
	}
	released := false
	defer func() {
		if !released {
			releaseSubscriberChange()
		}
	}()
	var switchErr error
	if progressController, ok := s.devices.(esimProgressDeviceController); ok && progress != nil {
		switchErr = progressController.ESIMSwitchProfileWithProgress(ctx, physicalID, iccid, aidHex, progress)
	} else {
		switchErr = s.devices.ESIMSwitchProfile(ctx, physicalID, iccid, aidHex)
	}
	if switchErr != nil {
		// The runtime guard blocks all new VoWiFi work, so release it before
		// restoring the old card. A failed preflight must be invisible to users.
		releaseSubscriberChange()
		released = true
		if restoreErr := s.restoreESIMVoWiFiTransaction(transaction); restoreErr != nil {
			s.logger.Error("restore VoWiFi after failed eSIM switch", "device_id", configID, "error", restoreErr)
		}
		return &esimCardOperationFailure{stage: "device", err: switchErr}
	}
	// The device layer verifies the requested ICCID before returning. Reconcile
	// the target card's stored policy only after that proof is available.
	releaseSubscriberChange()
	released = true
	if err := s.applyESIMCardPolicy(ctx, configID, physicalID, iccid); err != nil {
		s.logger.Error("apply target card policy after eSIM switch", "device_id", configID, "iccid", iccid, "error", err)
		return &esimCardOperationFailure{stage: "policy", err: err}
	}
	return nil
}

// runESIMDownload writes one profile to the eUICC inside the same VoWiFi
// quiesce/guard transaction a switch uses. A download holds the eUICC -- and
// therefore the QMI control port -- for the whole SGP.22 exchange, and on the
// native 410 VoWiFi keeps the radio in RF-off while it owns the subscriber,
// which the download preflight (ensureNativeQMIOnlineForESIM) rejects outright.
// Quiescing turns both problems into a planned, reversible pause.
//
// Unlike a switch this never changes the active subscriber, so the previous
// card's policy is restored on every outcome rather than only on failure.
func (s *Server) runESIMDownload(
	ctx context.Context,
	configID string,
	physicalID string,
	params device.EsimDownloadParams,
	progress func(device.EsimProgress),
) (*device.EsimDownloadResult, error) {
	report := func(step, msg string, pct int) {
		if progress != nil {
			progress(device.EsimProgress{Step: step, Msg: msg, Pct: pct})
		}
	}
	// Announce the pause before quiescing: waiting for the runtime to stop can
	// take up to 30 seconds, and the operator is watching a progress bar.
	if s.vowifi != nil && strings.TrimSpace(configID) != "" {
		if state, err := s.vowifi.State(configID); err == nil && (state.Enabled || state.Active) {
			report("vowifi_pause", "正在暂停 VoWiFi 以释放 SIM 卡（下载完成后自动恢复）...", 5)
		}
	}
	transaction, err := s.quiesceVoWiFiForESIMTransaction(ctx, configID)
	if err != nil {
		return nil, &esimCardOperationFailure{stage: "quiesce", err: err}
	}
	if transaction != nil && transaction.physicalID == "" {
		transaction.physicalID = physicalID
	}
	releaseSubscriberChange, err := s.beginVoWiFiSubscriberChange(ctx, configID)
	if err != nil {
		if restoreErr := s.restoreESIMVoWiFiTransaction(transaction); restoreErr != nil {
			s.logger.Error("restore VoWiFi after subscriber guard failure",
				"device_id", configID, "error", restoreErr)
		}
		return nil, &esimCardOperationFailure{stage: "subscriber_guard", err: err}
	}

	result, downloadErr := s.devices.ESIMDownloadProfile(ctx, physicalID, params, progress)

	// Restore on every path, including a cancelled request: the guard rejects
	// RequestEnabled while held, so release it first. Neither call takes the
	// request context, so a disconnected browser still gets VoWiFi back.
	releaseSubscriberChange()
	if transaction != nil && transaction.runtimeKnown &&
		(transaction.previousRuntime.Enabled || transaction.previousRuntime.Active) {
		report("vowifi_restore", "正在恢复 VoWiFi...", 95)
	}
	if restoreErr := s.restoreESIMVoWiFiTransaction(transaction); restoreErr != nil {
		s.logger.Error("restore VoWiFi after eSIM profile download",
			"device_id", configID, "error", restoreErr)
	}
	if downloadErr != nil {
		return nil, &esimCardOperationFailure{stage: "device", err: downloadErr}
	}
	return result, nil
}

func (s *Server) writeESIMSwitchError(w http.ResponseWriter, err error) {
	var failure *esimCardOperationFailure
	if errors.As(err, &failure) {
		switch failure.stage {
		case "quiesce":
			writeError(w, http.StatusConflict, "vowifi_quiesce_failed", failure.Error())
			return
		case "subscriber_guard":
			writeError(w, http.StatusConflict, "vowifi_subscriber_change_failed", failure.Error())
			return
		case "policy":
			writeError(w, http.StatusConflict, "card_policy_apply_failed", failure.Error())
			return
		case "device":
			s.writeDeviceError(w, failure.err)
			return
		}
	}
	s.writeDeviceError(w, err)
}

// handleEsimSwitchStream is the interactive GET+SSE variant. The operation
// context is detached from the HTTP request so closing the browser does not
// cancel the card-side reset/verification transaction.
func (s *Server) handleEsimSwitchStream(w http.ResponseWriter, r *http.Request, configID, physicalID string, physicalPresent bool) {
	if s.devices == nil {
		writeError(w, http.StatusServiceUnavailable, "device_manager_unavailable", "device manager is unavailable")
		return
	}
	if !physicalPresent {
		writeError(w, http.StatusServiceUnavailable, "physical_device_missing", "the configured modem is not present on this Linux host")
		return
	}
	iccid := strings.TrimSpace(r.URL.Query().Get("iccid"))
	if iccid == "" {
		writeError(w, http.StatusBadRequest, "invalid_request", "iccid is required")
		return
	}
	aidHex := r.URL.Query().Get("aid_hex")
	controller := beginSSE(w)
	if err := writeSSEEvent(w, controller, "connected", map[string]any{}); err != nil {
		return
	}
	sawDone := false
	emit := func(p device.EsimProgress) {
		if p.Step == "done" {
			sawDone = true
		}
		_ = writeSSEEvent(w, controller, "progress", map[string]any{"step": p.Step, "msg": p.Msg, "pct": p.Pct})
	}
	operationContext := context.WithoutCancel(r.Context())
	if err := s.runESIMSwitch(operationContext, configID, physicalID, iccid, aidHex, emit); err != nil {
		_ = writeSSEEvent(w, controller, "progress", map[string]any{
			"step": "error", "msg": "切卡失败: " + err.Error(), "pct": -1, "code": "esim_switch_failed",
		})
		return
	}
	// The device manager emits done; emit a fallback for legacy controller
	// implementations that only expose the original DeviceController method.
	if !sawDone {
		_ = writeSSEEvent(w, controller, "progress", map[string]any{"step": "done", "msg": "Profile 切换完成", "pct": 100})
	}
}

// esimVoWiFiTransaction captures the state changed while a profile switch is
// being prepared.  Quiescing VoWiFi is deliberately temporary: a failed
// EnableProfile/preflight must put the old subscriber back exactly where it
// was, while a successful switch receives the target card's stored policy.
type esimVoWiFiTransaction struct {
	configID             string
	physicalID           string
	previousConfig       store.Device
	configLoaded         bool
	configChanged        bool
	previousICCID        string
	previousPolicy       store.CardPolicy
	previousPolicyExists bool
	previousRuntime      vowifi.State
	runtimeKnown         bool
}

// quiesceVoWiFiForESIM is kept for profile disable/delete and the Telegram
// command paths.  Those operations intentionally leave VoWiFi disabled; only
// a switch gets the transaction/rollback semantics below.
func (s *Server) quiesceVoWiFiForESIM(ctx context.Context, configID string) error {
	_, err := s.quiesceVoWiFiForESIMTransaction(ctx, configID)
	return err
}

func (s *Server) quiesceVoWiFiForESIMTransaction(ctx context.Context, configID string) (*esimVoWiFiTransaction, error) {
	configID = strings.TrimSpace(configID)
	transaction := &esimVoWiFiTransaction{configID: configID}
	if configID == "" || s.vowifi == nil {
		return transaction, nil
	}
	state, stateErr := s.vowifi.State(configID)
	if stateErr != nil {
		return nil, fmt.Errorf("stop VoWiFi before subscriber change: %w", stateErr)
	}
	transaction.previousRuntime = state
	transaction.runtimeKnown = true
	transaction.previousICCID = strings.TrimSpace(state.ICCID)

	if s.store != nil {
		config, err := s.store.Device(ctx, configID)
		if err != nil && !errors.Is(err, store.ErrNotFound) {
			return nil, fmt.Errorf("load device policy before subscriber change: %w", err)
		}
		if err == nil {
			transaction.previousConfig = config
			transaction.configLoaded = true
			entry, physicalID, present := s.physicalForConfig(config)
			if present {
				transaction.physicalID = physicalID
			}
			if present && entry.Snapshot != nil {
				transaction.previousICCID = strings.TrimSpace(entry.Snapshot.ICCID)
			}
			if transaction.previousICCID != "" {
				policy, policyErr := s.store.CardPolicy(ctx, transaction.previousICCID)
				if policyErr == nil {
					transaction.previousPolicy = policy
					transaction.previousPolicyExists = true
				} else if !errors.Is(policyErr, store.ErrNotFound) {
					return nil, fmt.Errorf("load card policy before subscriber change: %w", policyErr)
				}
			}
			if config.VoWiFiEnabled {
				transaction.configChanged = true
				config.VoWiFiEnabled = false
				if err := s.store.UpsertDevice(ctx, config); err != nil {
					return nil, fmt.Errorf("disable VoWiFi policy before subscriber change: %w", err)
				}
			}
		}
	}

	restoreOnFailure := func(operationErr error) (*esimVoWiFiTransaction, error) {
		if transaction.configChanged && transaction.configLoaded {
			if restoreErr := s.store.UpsertDevice(context.Background(), transaction.previousConfig); restoreErr != nil {
				s.logger.Error("restore temporary VoWiFi policy after quiesce failure", "device_id", configID, "error", restoreErr)
			}
		}
		// If stopping failed before the guard was acquired, request the old
		// desired state again.  The runtime may still be finishing its cleanup;
		// an asynchronous retry is safer than leaving the card permanently off.
		if transaction.runtimeKnown && (transaction.previousRuntime.Enabled || transaction.previousRuntime.Active || transaction.previousConfig.VoWiFiEnabled) {
			if current, currentErr := s.vowifi.State(configID); currentErr == nil && !current.Enabled && !current.Active {
				if _, restoreErr := s.vowifi.RequestEnabled(configID, true); restoreErr != nil {
					s.logger.Error("restore VoWiFi runtime after quiesce failure", "device_id", configID, "error", restoreErr)
				}
			}
		}
		return nil, operationErr
	}

	needsStop := state.Enabled || state.Active ||
		(state.Phase != vowifi.PhaseIdle && state.Phase != vowifi.PhaseFailed)
	if needsStop {
		if _, err := s.vowifi.RequestEnabled(configID, false); err != nil {
			return restoreOnFailure(fmt.Errorf("stop VoWiFi before subscriber change: %w", err))
		}
	}

	waitContext, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	for {
		state, err := s.vowifi.State(configID)
		if err != nil {
			return restoreOnFailure(fmt.Errorf("confirm VoWiFi stopped before subscriber change: %w", err))
		}
		if !state.Enabled && !state.Active &&
			(state.Phase == vowifi.PhaseIdle || state.Phase == vowifi.PhaseFailed) {
			return transaction, nil
		}
		select {
		case <-waitContext.Done():
			return restoreOnFailure(fmt.Errorf("wait for VoWiFi to stop before subscriber change: %w", waitContext.Err()))
		case <-ticker.C:
		}
	}
}

// restoreESIMVoWiFiTransaction restores the pre-switch policy and runtime.
// It is called after releasing the subscriber guard because RequestEnabled is
// intentionally rejected while that guard is held.
func (s *Server) restoreESIMVoWiFiTransaction(transaction *esimVoWiFiTransaction) error {
	if transaction == nil || !transaction.configLoaded || s.store == nil {
		return nil
	}
	config := transaction.previousConfig
	policy := transaction.previousPolicy
	if !transaction.previousPolicyExists {
		policy = defaultCardPolicy(transaction.previousICCID)
		policy.APN = config.APN
		policy.NetworkEnabled = config.NetworkEnabled
		policy.VoWiFiEnabled = config.VoWiFiEnabled || transaction.previousRuntime.Enabled || transaction.previousRuntime.Active
		policy.AirplaneEnabled = policy.VoWiFiEnabled
		policy.Source = "rollback"
	}
	if transaction.previousConfig.VoWiFiEnabled || transaction.previousRuntime.Enabled || transaction.previousRuntime.Active {
		// The live session is authoritative when an older build had a stale
		// per-card policy.  Do not reproduce the old build's permanent disable.
		policy.VoWiFiEnabled = true
		policy.AirplaneEnabled = true
		policy.NetworkEnabled = false
	}
	return s.applyESIMEnvironment(context.Background(), transaction.physicalID, config, policy)
}

func (s *Server) applyESIMCardPolicy(ctx context.Context, configID, physicalID, iccid string) error {
	if s.store == nil {
		return nil
	}
	config, err := s.store.Device(ctx, configID)
	if err != nil {
		return fmt.Errorf("load device after profile switch: %w", err)
	}
	policy, policyErr := s.store.CardPolicy(ctx, strings.TrimSpace(iccid))
	if errors.Is(policyErr, store.ErrNotFound) {
		policy = defaultCardPolicy(iccid)
		policy.APN = config.APN
		policy.Source = "default"
	} else if policyErr != nil {
		return fmt.Errorf("load target card policy: %w", policyErr)
	}
	return s.applyESIMEnvironment(ctx, physicalID, config, policy)
}

// applyESIMEnvironment persists one card's desired policy and reconciles the
// modem/runtime to it.  It is shared by switch success and switch rollback so
// both paths use identical VoWiFi/airplane/cellular ordering.
func (s *Server) applyESIMEnvironment(ctx context.Context, physicalID string, config store.Device, policy store.CardPolicy) error {
	if strings.TrimSpace(policy.ICCID) == "" {
		// A unit/test path can lack a live ICCID.  Still restore the device row and
		// runtime intent without manufacturing an invalid card-policy row.
		config.VoWiFiEnabled = policy.VoWiFiEnabled
		config.NetworkEnabled = policy.NetworkEnabled && !policy.VoWiFiEnabled && !policy.AirplaneEnabled
		if err := s.store.UpsertDevice(ctx, config); err != nil {
			return fmt.Errorf("persist device policy: %w", err)
		}
		if s.vowifi != nil {
			state, stateErr := s.vowifi.State(config.ID)
			if policy.VoWiFiEnabled {
				if stateErr == nil && state.Enabled {
					_, stateErr = s.vowifi.RequestReconnect(config.ID)
				} else {
					_, stateErr = s.vowifi.RequestEnabled(config.ID, true)
				}
			} else if stateErr == nil && (state.Enabled || state.Active) {
				_, stateErr = s.vowifi.RequestEnabled(config.ID, false)
			}
			if stateErr != nil {
				return fmt.Errorf("restore VoWiFi runtime: %w", stateErr)
			}
		}
		return nil
	}
	if policy.IPVersion == "" {
		policy.IPVersion = "IPV4V6"
	}
	if policy.VoWiFiEnabled {
		policy.AirplaneEnabled = true
		policy.NetworkEnabled = false
	}
	policy.Source = firstNonEmpty(policy.Source, "manual")
	config.APN = policy.APN
	config.VoWiFiEnabled = policy.VoWiFiEnabled
	config.NetworkEnabled = policy.NetworkEnabled && !policy.VoWiFiEnabled && !policy.AirplaneEnabled
	if err := s.store.UpsertCardPolicy(ctx, policy); err != nil {
		return fmt.Errorf("persist target card policy: %w", err)
	}
	if s.devices == nil {
		if err := s.store.UpsertDevice(ctx, config); err != nil {
			return fmt.Errorf("persist device policy: %w", err)
		}
		return nil
	}
	snapshot := automaticTaskEnvironmentSnapshot{config: config, policy: policy}
	if err := s.restoreAutomaticTaskEnvironment(physicalID, snapshot); err != nil {
		return fmt.Errorf("reconcile target card policy: %w", err)
	}
	return nil
}

type voWiFiSubscriberChangeGuard interface {
	BeginSubscriberChange(context.Context, string) (func(), error)
}

func (s *Server) beginVoWiFiSubscriberChange(ctx context.Context, configID string) (func(), error) {
	configID = strings.TrimSpace(configID)
	if configID == "" || s.vowifi == nil {
		return func() {}, nil
	}
	guard, ok := s.vowifi.(voWiFiSubscriberChangeGuard)
	if !ok {
		return nil, errors.New("VoWiFi controller does not support subscriber-change guards")
	}
	release, err := guard.BeginSubscriberChange(ctx, configID)
	if err != nil {
		return nil, fmt.Errorf("begin guarded VoWiFi subscriber change: %w", err)
	}
	if release == nil {
		return nil, errors.New("VoWiFi controller returned a nil subscriber-change release")
	}
	return release, nil
}

func (s *Server) handleEsimDisable(w http.ResponseWriter, r *http.Request, configID string, physicalID string, physicalPresent bool) {
	if s.devices == nil {
		writeError(w, http.StatusServiceUnavailable, "device_manager_unavailable", "device manager is unavailable")
		return
	}
	if !physicalPresent {
		writeError(w, http.StatusServiceUnavailable, "physical_device_missing", "the configured modem is not present on this Linux host")
		return
	}
	var request struct {
		ICCID  string `json:"iccid"`
		AIDHex string `json:"aid_hex"` // accepted for the multi-eUICC SPA contract; disabling keys off ICCID
	}
	if err := s.decodeJSON(w, r, &request); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	iccid := strings.TrimSpace(request.ICCID)
	if iccid == "" {
		writeError(w, http.StatusBadRequest, "invalid_request", "iccid is required")
		return
	}
	// Disabling a profile performs the same modem reset and live identity
	// verification as switching, so it must not inherit the normal API deadline.
	controller := http.NewResponseController(w)
	_ = controller.SetWriteDeadline(time.Time{})
	if err := s.quiesceVoWiFiForESIM(r.Context(), configID); err != nil {
		writeError(w, http.StatusConflict, "vowifi_quiesce_failed", err.Error())
		return
	}
	releaseSubscriberChange, err := s.beginVoWiFiSubscriberChange(r.Context(), configID)
	if err != nil {
		writeError(w, http.StatusConflict, "vowifi_subscriber_change_failed", err.Error())
		return
	}
	defer releaseSubscriberChange()
	if err := s.devices.ESIMDisableProfile(r.Context(), physicalID, iccid, request.AIDHex); err != nil {
		s.writeDeviceError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"data": map[string]any{"status": "disabled", "iccid": iccid, "recovering": true}})
}

func (s *Server) handleEsimDelete(w http.ResponseWriter, r *http.Request, physicalID string, physicalPresent bool, iccid string) {
	if s.devices == nil {
		writeError(w, http.StatusServiceUnavailable, "device_manager_unavailable", "device manager is unavailable")
		return
	}
	if !physicalPresent {
		writeError(w, http.StatusServiceUnavailable, "physical_device_missing", "the configured modem is not present on this Linux host")
		return
	}
	iccid = strings.TrimSpace(iccid)
	if iccid == "" {
		writeError(w, http.StatusBadRequest, "invalid_request", "iccid is required")
		return
	}
	result, err := s.devices.ESIMDeleteProfile(r.Context(), physicalID, iccid, r.URL.Query().Get("aid_hex"))
	if err != nil {
		s.writeDeviceError(w, err)
		return
	}
	data := map[string]any{
		"status":     "deleted",
		"iccid":      iccid,
		"spaceDelta": map[string]any{"direction": "reclaimed", "bytes": result.SpaceDelta},
	}
	if result.Warning != "" {
		data["warning"] = result.Warning
	}
	writeJSON(w, http.StatusOK, map[string]any{"data": data})
}

// handleEsimDownload streams one eSIM profile download (写卡) as Server-Sent
// Events. The SPA drives it with GET + query params (smdp/matching_id/
// confirmation_code/aid_hex/imei) and reads `data: {step,msg,pct,...}` lines.
// The event field names (step/msg/pct/code/space_delta/warning) match the
// reference contract byte-for-byte, so the frontend needs no changes.
func (s *Server) handleEsimDownload(w http.ResponseWriter, r *http.Request, configID string, physicalID string, physicalPresent bool) {
	if s.devices == nil {
		writeError(w, http.StatusServiceUnavailable, "device_manager_unavailable", "device manager is unavailable")
		return
	}
	if !physicalPresent {
		writeError(w, http.StatusServiceUnavailable, "physical_device_missing", "the configured modem is not present on this Linux host")
		return
	}
	query := r.URL.Query()
	params := device.EsimDownloadParams{
		SMDP:             query.Get("smdp"),
		MatchingID:       query.Get("matching_id"),
		ConfirmationCode: query.Get("confirmation_code"),
		AIDHex:           query.Get("aid_hex"),
		IMEI:             query.Get("imei"),
	}
	if strings.TrimSpace(params.SMDP) == "" {
		writeError(w, http.StatusBadRequest, "invalid_request", "smdp 为必填项")
		return
	}

	controller := beginSSE(w)
	emit := func(payload map[string]any) {
		// A failed write means the client went away; r.Context() is then already
		// cancelled, so the device layer stops the download on its own.
		_ = writeSSEEvent(w, controller, "progress", payload)
	}

	result, err := s.runESIMDownload(r.Context(), configID, physicalID, params, func(p device.EsimProgress) {
		emit(map[string]any{"step": p.Step, "msg": p.Msg, "pct": p.Pct})
	})
	if err != nil {
		// A quiesce/guard failure is about the VoWiFi runtime, not the card, so
		// it must not be reported as an SM-DP+/eUICC download error code.
		code := device.ESIMDownloadErrorCode(err)
		var failure *esimCardOperationFailure
		if errors.As(err, &failure) && failure.stage != "device" {
			code = "vowifi_quiesce_failed"
		}
		emit(map[string]any{
			"step": "error",
			"msg":  "下载失败: " + err.Error(),
			"pct":  -1,
			"code": code,
		})
		return
	}
	done := map[string]any{
		"step":        "done",
		"msg":         "Profile 下载完成",
		"pct":         100,
		"space_delta": map[string]any{"direction": "consumed", "bytes": result.SpaceDelta},
	}
	if result.Warning != "" {
		done["warning"] = result.Warning
	}
	emit(done)
}
