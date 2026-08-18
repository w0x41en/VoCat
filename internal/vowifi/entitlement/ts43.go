// Package entitlement implements the diagnostic part of GSMA TS.43/RCC.14
// used to query a carrier's VoWiFi service entitlement.  It is intentionally
// separate from the IKE tunnel: a failed entitlement query must never change
// radio state or prevent a normal VoWiFi attempt.
package entitlement

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strings"
	"time"

	"vocat/internal/vowifi"
	"vocat/internal/vowifi/ike"
)

const (
	// Smart's carrier bundle points to this endpoint.  It is a default only
	// for the diagnostic command; callers may override it for another PLMN.
	DefaultSmartEndpoint = "https://esim-pldt-es-prd.ipaas.amdocs.com/pldt/prd/executeAppleActions"
	DefaultVoWiFiApp     = "ap2004"
	DefaultTS43Version   = "1"

	relayContentType = "application/vnd.gsma.eap-relay.v1.0+json"
	xmlContentType   = "text/vnd.wap.connectivity-xml"
	maxResponseBody  = 2 << 20
)

// Config describes one read-only TS.43 entitlement request.  Endpoint and
// identity are required.  Terminal fields are sent when non-empty because
// carrier servers commonly use them for device policy, while the standard
// keeps their exact presence operator-configurable.
type Config struct {
	Endpoint           string
	Identity           vowifi.SIMIdentity
	AKA                vowifi.AKAProvider
	EAPMethod          string
	App                string
	Version            string
	EntitlementVersion string
	TerminalID         string
	TerminalVendor     string
	TerminalModel      string
	TerminalSWVersion  string
	InitialMethod      string
	HTTPClient         *http.Client
	UserAgent          string
}

// Result contains only redacted, actionable diagnostics.  ResponseBodyHash
// allows two attempts to be compared without persisting carrier tokens,
// IMSIs, EAP packets, or service-flow user data.
type Result struct {
	Endpoint               string `json:"endpoint"`
	App                    string `json:"app"`
	EAPIdentityLength      int    `json:"eap_identity_length"`
	EAPIdentitySHA256      string `json:"eap_identity_sha256"`
	HTTPMethod             string `json:"http_method"`
	HTTPStatus             int    `json:"http_status"`
	ContentType            string `json:"content_type"`
	ResponseBytes          int    `json:"response_bytes"`
	ResponseBodySHA256     string `json:"response_body_sha256"`
	EAPRounds              int    `json:"eap_rounds"`
	Authenticated          bool   `json:"authenticated"`
	EntitlementStatus      string `json:"entitlement_status,omitempty"`
	ProvisioningStatus     string `json:"provisioning_status,omitempty"`
	TermsStatus            string `json:"terms_status,omitempty"`
	AddressStatus          string `json:"address_status,omitempty"`
	ServiceFlowURL         string `json:"service_flow_url,omitempty"`
	MessageForIncompatible string `json:"message_for_incompatible,omitempty"`
	ServerErrorCode        string `json:"server_error_code,omitempty"`
	ServerErrorDescription string `json:"server_error_description,omitempty"`
}

type relayEnvelope struct {
	Packet string `json:"eap-relay-packet"`
}

// Probe performs the TS.43 embedded EAP-AKA relay and parses the returned
// entitlement document.  It does not alter modem state; the supplied AKA
// provider is called only if the server actually sends an EAP challenge.
func Probe(ctx context.Context, config Config) (Result, error) {
	config, err := normalizeConfig(config)
	if err != nil {
		return Result{}, err
	}
	identity, err := ike.PermanentAKAIdentity(config.Identity, config.EAPMethod)
	if err != nil {
		return Result{}, err
	}
	result := Result{
		Endpoint:          config.Endpoint,
		App:               config.App,
		EAPIdentityLength: len(identity),
		EAPIdentitySHA256: sha256Hex([]byte(identity)),
		HTTPMethod:        strings.ToUpper(config.InitialMethod),
	}

	client, err := ike.NewHTTPEmbeddedEAPClient(config.Identity, config.AKA, config.EAPMethod)
	if err != nil {
		return result, err
	}
	httpClient := config.HTTPClient
	if httpClient == nil {
		jar, jarErr := cookiejar.New(nil)
		if jarErr != nil {
			return result, fmt.Errorf("ts43: create cookie jar: %w", jarErr)
		}
		httpClient = &http.Client{Jar: jar}
	}

	requestURL, err := buildRequestURL(config, identity)
	if err != nil {
		return result, err
	}
	response, body, err := doInitialRequest(ctx, httpClient, config, requestURL)
	if err != nil {
		return result, err
	}
	result = recordHTTP(result, response, body)

	for round := 0; round < 10; round++ {
		packet, relay, relayErr := decodeRelayPacket(body)
		if relayErr != nil {
			return result, relayErr
		}
		if !relay {
			parseEntitlementBody(&result, body)
			if response.StatusCode < 200 || response.StatusCode >= 300 {
				return result, serverHTTPError(result)
			}
			return result, nil
		}

		result.EAPRounds++
		clientResponse, success, handleErr := client.Handle(ctx, packet)
		if handleErr != nil {
			return result, fmt.Errorf("ts43: EAP-AKA round %d: %w", result.EAPRounds, handleErr)
		}
		if success {
			result.Authenticated = true
			// The relay server normally returns the final XML in the same HTTP
			// response that carried EAP-Success.  If it instead requires a
			// follow-up empty request, the next iteration handles that response
			// only when a relay response was actually supplied.
			parseEntitlementBody(&result, body)
			return result, nil
		}
		if len(clientResponse) == 0 {
			return result, errors.New("ts43: EAP server packet produced no response")
		}

		response, body, err = doRelayPost(ctx, httpClient, config, requestURL, clientResponse)
		if err != nil {
			return result, err
		}
		result = recordHTTP(result, response, body)
	}
	return result, errors.New("ts43: embedded EAP-AKA exceeded ten HTTP rounds")
}

func normalizeConfig(config Config) (Config, error) {
	config.Endpoint = strings.TrimSpace(config.Endpoint)
	if config.Endpoint == "" {
		return Config{}, errors.New("ts43: endpoint is required")
	}
	parsed, err := url.Parse(config.Endpoint)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" {
		return Config{}, errors.New("ts43: endpoint must be an https URL")
	}
	if strings.TrimSpace(config.Identity.IMSI) == "" {
		return Config{}, errors.New("ts43: IMSI is required")
	}
	if config.AKA == nil {
		return Config{}, errors.New("ts43: AKA provider is required")
	}
	config.EAPMethod = strings.TrimSpace(config.EAPMethod)
	if config.EAPMethod == "" {
		config.EAPMethod = "aka"
	}
	config.App = strings.TrimSpace(config.App)
	if config.App == "" {
		config.App = DefaultVoWiFiApp
	}
	config.Version = strings.TrimSpace(config.Version)
	if config.Version == "" {
		config.Version = DefaultTS43Version
	}
	config.EntitlementVersion = strings.TrimSpace(config.EntitlementVersion)
	if config.EntitlementVersion == "" {
		config.EntitlementVersion = config.Version
	}
	config.InitialMethod = strings.ToUpper(strings.TrimSpace(config.InitialMethod))
	if config.InitialMethod == "" {
		config.InitialMethod = http.MethodGet
	}
	if config.InitialMethod != http.MethodGet && config.InitialMethod != http.MethodPost {
		return Config{}, fmt.Errorf("ts43: unsupported initial HTTP method %q", config.InitialMethod)
	}
	if config.UserAgent == "" {
		config.UserAgent = "VoCat-TS43-Probe/1"
	}
	return config, nil
}

func buildRequestURL(config Config, identity string) (*url.URL, error) {
	requestURL, err := url.Parse(config.Endpoint)
	if err != nil {
		return nil, fmt.Errorf("ts43: parse endpoint: %w", err)
	}
	query := requestURL.Query()
	query.Set("EAP_ID", identity)
	query.Set("vers", config.Version)
	query.Set("app", config.App)
	if config.TerminalID != "" {
		query.Set("terminal_id", config.TerminalID)
	}
	if config.TerminalVendor != "" {
		query.Set("terminal_vendor", config.TerminalVendor)
	}
	if config.TerminalModel != "" {
		query.Set("terminal_model", config.TerminalModel)
	}
	if config.TerminalSWVersion != "" {
		query.Set("terminal_sw_version", config.TerminalSWVersion)
	}
	query.Set("entitlement_version", config.EntitlementVersion)
	requestURL.RawQuery = query.Encode()
	return requestURL, nil
}

func doInitialRequest(
	ctx context.Context,
	client *http.Client,
	config Config,
	requestURL *url.URL,
) (*http.Response, []byte, error) {
	var body io.Reader
	method := config.InitialMethod
	if method == http.MethodPost {
		payload := map[string]string{
			"terminal_id":         config.TerminalID,
			"terminal_vendor":     config.TerminalVendor,
			"terminal_model":      config.TerminalModel,
			"terminal_sw_version": config.TerminalSWVersion,
			"entitlement_version": config.EntitlementVersion,
			"app":                 config.App,
			"vers":                config.Version,
			"EAP_ID":              requestURL.Query().Get("EAP_ID"),
		}
		encoded, err := json.Marshal(payload)
		if err != nil {
			return nil, nil, fmt.Errorf("ts43: encode initial request: %w", err)
		}
		body = strings.NewReader(string(encoded))
	}
	request, err := http.NewRequestWithContext(ctx, method, requestURL.String(), body)
	if err != nil {
		return nil, nil, fmt.Errorf("ts43: create initial request: %w", err)
	}
	prepareRequest(request, config, method == http.MethodPost)
	return executeHTTP(client, request)
}

func doRelayPost(
	ctx context.Context,
	client *http.Client,
	config Config,
	requestURL *url.URL,
	packet []byte,
) (*http.Response, []byte, error) {
	payload, err := json.Marshal(relayEnvelope{Packet: base64.StdEncoding.EncodeToString(packet)})
	if err != nil {
		return nil, nil, fmt.Errorf("ts43: encode EAP relay packet: %w", err)
	}
	request, err := http.NewRequestWithContext(
		ctx,
		http.MethodPost,
		requestURL.String(),
		strings.NewReader(string(payload)),
	)
	if err != nil {
		return nil, nil, fmt.Errorf("ts43: create EAP relay request: %w", err)
	}
	prepareRequest(request, config, true)
	return executeHTTP(client, request)
}

func prepareRequest(request *http.Request, config Config, jsonBody bool) {
	request.Header.Set("Accept", relayContentType+", "+xmlContentType)
	request.Header.Set("User-Agent", config.UserAgent)
	if jsonBody {
		request.Header.Set("Content-Type", "application/json")
	}
}

func executeHTTP(client *http.Client, request *http.Request) (*http.Response, []byte, error) {
	response, err := client.Do(request)
	if err != nil {
		return nil, nil, fmt.Errorf("ts43: HTTP request: %w", err)
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, maxResponseBody+1))
	if err != nil {
		return response, nil, fmt.Errorf("ts43: read HTTP response: %w", err)
	}
	if len(body) > maxResponseBody {
		return response, nil, errors.New("ts43: HTTP response exceeds 2 MiB")
	}
	return response, body, nil
}

func recordHTTP(result Result, response *http.Response, body []byte) Result {
	result.HTTPStatus = response.StatusCode
	result.ContentType = strings.TrimSpace(strings.Split(response.Header.Get("Content-Type"), ";")[0])
	result.ResponseBytes = len(body)
	result.ResponseBodySHA256 = sha256Hex(body)
	return result
}

func decodeRelayPacket(body []byte) ([]byte, bool, error) {
	var envelope relayEnvelope
	if err := json.Unmarshal(body, &envelope); err != nil {
		return nil, false, nil
	}
	if envelope.Packet == "" {
		return nil, false, nil
	}
	packet, err := base64.StdEncoding.DecodeString(envelope.Packet)
	if err != nil {
		return nil, true, fmt.Errorf("ts43: decode EAP relay packet: %w", err)
	}
	return packet, true, nil
}

func serverHTTPError(result Result) error {
	if result.ServerErrorCode != "" || result.ServerErrorDescription != "" {
		return fmt.Errorf("ts43: server returned HTTP %d: %s %s", result.HTTPStatus, result.ServerErrorCode, result.ServerErrorDescription)
	}
	return fmt.Errorf("ts43: server returned HTTP %d", result.HTTPStatus)
}

func parseEntitlementBody(result *Result, body []byte) {
	if len(body) == 0 {
		return
	}
	var jsonValue any
	if json.Unmarshal(body, &jsonValue) == nil {
		fields := make(map[string]string)
		collectJSONFields(jsonValue, fields)
		applyFields(result, fields)
		return
	}
	var document xmlNode
	if xml.Unmarshal(body, &document) == nil {
		fields := make(map[string]string)
		collectXMLFields(document, fields)
		applyFields(result, fields)
	}
}

type xmlNode struct {
	XMLName         xml.Name  `xml:""`
	Type            string    `xml:"type,attr"`
	Name            string    `xml:"name,attr"`
	Value           string    `xml:"value,attr"`
	Params          []xmlParm `xml:"parm"`
	Characteristics []xmlNode `xml:"characteristic"`
}

type xmlParm struct {
	Name  string `xml:"name,attr"`
	Value string `xml:"value,attr"`
}

func collectXMLFields(node xmlNode, fields map[string]string) {
	if node.Name != "" && node.Value != "" {
		fields[node.Name] = node.Value
	}
	if node.Type != "" && node.Value != "" {
		fields[node.Type] = node.Value
	}
	for _, parm := range node.Params {
		if parm.Name != "" {
			fields[parm.Name] = parm.Value
		}
	}
	for _, child := range node.Characteristics {
		collectXMLFields(child, fields)
	}
}

func collectJSONFields(value any, fields map[string]string) {
	switch typed := value.(type) {
	case map[string]any:
		for key, child := range typed {
			if stringValue, ok := child.(string); ok {
				fields[key] = stringValue
			} else if number, ok := child.(float64); ok {
				fields[key] = fmt.Sprintf("%g", number)
			}
			collectJSONFields(child, fields)
		}
	case []any:
		for _, child := range typed {
			collectJSONFields(child, fields)
		}
	}
}

func applyFields(result *Result, fields map[string]string) {
	lookup := func(names ...string) string {
		for _, name := range names {
			for key, value := range fields {
				if strings.EqualFold(key, name) {
					return strings.TrimSpace(value)
				}
			}
		}
		return ""
	}
	result.EntitlementStatus = lookup("EntitlementStatus")
	result.ProvisioningStatus = lookup("ProvStatus", "ProvisioningStatus")
	result.TermsStatus = lookup("TC_Status", "TermsStatus")
	result.AddressStatus = lookup("AddrStatus", "AddressStatus")
	result.ServiceFlowURL = lookup("ServiceFlow_URL", "ServiceFlowURL")
	result.MessageForIncompatible = lookup("MessageForIncompatible")
	result.ServerErrorCode = lookup("Number", "ErrorCode", "code")
	result.ServerErrorDescription = lookup("Description", "ErrorDescription", "message")
}

func sha256Hex(value []byte) string {
	digest := sha256.Sum256(value)
	return hex.EncodeToString(digest[:])
}

// HTTPClientWithTimeout returns a cookie-preserving client suitable for a
// bounded diagnostic run.  It is exported so the CLI and tests use the same
// timeout behaviour without sharing a global http.Client.
func HTTPClientWithTimeout(timeout time.Duration) (*http.Client, error) {
	if timeout <= 0 {
		return nil, errors.New("ts43: HTTP timeout must be positive")
	}
	jar, err := cookiejar.New(nil)
	if err != nil {
		return nil, fmt.Errorf("ts43: create cookie jar: %w", err)
	}
	return &http.Client{Timeout: timeout, Jar: jar}, nil
}
