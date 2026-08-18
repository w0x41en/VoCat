// Command ts43probe performs a read-only GSMA TS.43 VoWiFi entitlement query.
// It is kept separate from the vocat service so an experimental carrier HTTP
// flow cannot change radio state or affect a live IKE/IMS session.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"vocat/internal/vowifi"
	"vocat/internal/vowifi/entitlement"
)

func main() {
	flags := flag.NewFlagSet("ts43probe", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	endpoint := flags.String("endpoint", entitlement.DefaultSmartEndpoint, "TS.43 entitlement endpoint (https URL)")
	imsi := flags.String("imsi", "", "subscriber IMSI (required; never printed)")
	mcc := flags.String("mcc", "515", "home MCC")
	mnc := flags.String("mnc", "003", "home MNC")
	imei := flags.String("imei", "", "terminal IMEI used as terminal_id when set")
	terminalID := flags.String("terminal-id", "", "TS.43 terminal_id (defaults to --imei)")
	vendor := flags.String("terminal-vendor", "VoCat", "TS.43 terminal_vendor")
	model := flags.String("terminal-model", "OpenStick-410", "TS.43 terminal_model")
	swVersion := flags.String("terminal-sw-version", "dev", "TS.43 terminal_sw_version")
	controlDevice := flags.String("control-device", "/dev/cdc-wdm0", "QMI control device used only if EAP-AKA challenge arrives")
	method := flags.String("http-method", "GET", "initial HTTP method: GET or POST")
	eapMethod := flags.String("eap-method", "aka", "EAP method: aka or aka-prime")
	version := flags.String("vers", entitlement.DefaultTS43Version, "TS.43 protocol version")
	entitlementVersion := flags.String("entitlement-version", "", "TS.43 entitlement version (defaults to --vers)")
	timeout := flags.Duration("timeout", 30*time.Second, "overall HTTP timeout")
	if err := flags.Parse(os.Args[1:]); err != nil {
		os.Exit(2)
	}

	if strings.TrimSpace(*imsi) == "" {
		printError(errors.New("--imsi is required; obtain it from the modem and pass it only to this local diagnostic"))
		os.Exit(2)
	}
	if strings.TrimSpace(*terminalID) == "" {
		*terminalID = strings.TrimSpace(*imei)
	}
	aka, err := vowifi.NewQMIUIMAKAProvider(*controlDevice)
	if err != nil {
		printError(err)
		os.Exit(2)
	}
	httpClient, err := entitlement.HTTPClientWithTimeout(*timeout)
	if err != nil {
		printError(err)
		os.Exit(2)
	}

	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()
	result, probeErr := entitlement.Probe(ctx, entitlement.Config{
		Endpoint:           *endpoint,
		Identity:           vowifi.SIMIdentity{IMSI: strings.TrimSpace(*imsi), IMEI: strings.TrimSpace(*imei), HomeMCC: strings.TrimSpace(*mcc), HomeMNC: strings.TrimSpace(*mnc)},
		AKA:                aka,
		EAPMethod:          *eapMethod,
		Version:            *version,
		EntitlementVersion: *entitlementVersion,
		TerminalID:         strings.TrimSpace(*terminalID),
		TerminalVendor:     strings.TrimSpace(*vendor),
		TerminalModel:      strings.TrimSpace(*model),
		TerminalSWVersion:  strings.TrimSpace(*swVersion),
		InitialMethod:      *method,
		HTTPClient:         httpClient,
	})
	if encodeErr := json.NewEncoder(os.Stdout).Encode(result); encodeErr != nil {
		printError(encodeErr)
		os.Exit(1)
	}
	if probeErr != nil {
		printError(probeErr)
		os.Exit(1)
	}
}

func printError(err error) {
	if err == nil {
		return
	}
	_, _ = fmt.Fprintf(os.Stderr, "ts43probe: %v\n", err)
}
