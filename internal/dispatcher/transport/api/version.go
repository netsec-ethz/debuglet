package api

import (
	"net/http"
	"strconv"
	"strings"

	apispec "github.com/netsec-ethz/debuglet/api"
	"github.com/netsec-ethz/debuglet/internal/buildinfo"
	"github.com/netsec-ethz/debuglet/internal/controlsession"

	"github.com/labstack/echo/v4"
)

// VersionHeader carries the contract version a client requires on requests and
// the version this dispatcher implements on responses. It is re-exported so
// that a server assembling middleware can name it without importing the
// contract package.
const VersionHeader = apispec.VersionHeader

// maxVersionHeader bounds the request header value that is parsed. A longer
// value is rejected without being inspected further and is never echoed back.
const maxVersionHeader = 16

// discoveryRoutes answer regardless of the requested contract version so that
// a client which speaks a different contract can still learn what this
// dispatcher implements.
// The health routes answer too: a probe states no contract version and reads
// nothing this contract describes, so negotiation must never stop one.
var discoveryRoutes = map[string]bool{
	routeVersion:   true,
	routeOpenAPI:   true,
	routeLiveness:  true,
	routeReadiness: true,
	routeHealth:    true,
}

// VersionResponse identities. GetVersion answers GET /version.
func (h *Handler) GetVersion(c echo.Context) error {
	return c.JSON(http.StatusOK, h.VersionIdentities())
}

// GetOpenAPI answers GET /openapi.yaml with the contract this build implements.
func (h *Handler) GetOpenAPI(c echo.Context) error {
	return c.Blob(http.StatusOK, apispec.MediaType, apispec.OpenAPI)
}

// VersionIdentities reports the three independent identities of a running
// dispatcher: the HTTP API contract it serves, the binary it was built from
// and the executor control protocol it speaks. They are versioned separately
// and only the API contract is a promise to HTTP clients.
func (h *Handler) VersionIdentities() VersionResponse {
	var configured string
	if h.dispatcher != nil {
		configured = h.dispatcher.GetVersion()
	}
	binary := buildinfo.Version
	if binary == "" {
		// An unstamped build (go run, go install without ldflags) has no
		// distribution version; the configured string is the only identity.
		binary = configured
	}
	return VersionResponse{
		Version:         configured,
		APIVersion:      apispec.Version,
		APIVersions:     []string{strconv.Itoa(apispec.Major)},
		BinaryVersion:   binary,
		BinaryRevision:  buildinfo.Revision,
		ProtocolVersion: strconv.FormatUint(uint64(controlsession.ProtocolVersion), 10),
	}
}

// APIVersionMiddleware announces the implemented contract version on every
// response and answers a client that requires an incompatible one with an
// explicit error instead of a best-effort response. A request without the
// header is served unchanged, which keeps every client written before the
// contract was versioned working.
func APIVersionMiddleware() echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			c.Response().Header().Set(apispec.VersionHeader, apispec.Version)
			required := strings.TrimSpace(c.Request().Header.Get(apispec.VersionHeader))
			if required == "" || discoveryRoutes[c.Path()] {
				return next(c)
			}
			if !supportedAPIVersion(required) {
				// The rejected value is never echoed: it is unvalidated
				// request text and the caller already knows what it sent.
				return apiError(http.StatusBadRequest, CodeUnsupportedAPIVersion,
					"unsupported "+apispec.VersionHeader+" request header; this dispatcher implements "+apispec.Version)
			}
			return next(c)
		}
	}
}

// supportedAPIVersion reports whether this dispatcher satisfies a client that
// requires the given contract version. The major version must match exactly;
// a minor version above the implemented one asks for additions this build does
// not have.
func supportedAPIVersion(required string) bool {
	major, minor, ok := parseAPIVersion(required)
	return ok && major == apispec.Major && minor <= apispec.Minor
}

// parseAPIVersion accepts "major" or "major.minor" in decimal digits only.
func parseAPIVersion(value string) (major, minor int, ok bool) {
	if value == "" || len(value) > maxVersionHeader {
		return 0, 0, false
	}
	majorText, minorText, hasMinor := strings.Cut(value, ".")
	major, ok = parseVersionNumber(majorText)
	if !ok {
		return 0, 0, false
	}
	if !hasMinor {
		return major, 0, true
	}
	minor, ok = parseVersionNumber(minorText)
	if !ok {
		return 0, 0, false
	}
	return major, minor, true
}

func parseVersionNumber(text string) (int, bool) {
	if text == "" {
		return 0, false
	}
	for i := 0; i < len(text); i++ {
		if text[i] < '0' || text[i] > '9' {
			return 0, false
		}
	}
	number, err := strconv.Atoi(text)
	if err != nil {
		return 0, false
	}
	return number, true
}
