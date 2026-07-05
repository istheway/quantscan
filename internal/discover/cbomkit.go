package discover

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	cdx "github.com/CycloneDX/cyclonedx-go"
)

// CBOMkitClient retrieves source-code CBOMs from a running CBOMkit service.
//
// CBOMkit performs deep static analysis (via the Sonar Cryptography plugin) and
// stores results keyed by package URL. Scans are kicked off out-of-band (the
// service's WebSocket flow); this client retrieves an already-generated CBOM by
// purl over the REST API, which is the CI-friendly path: the repo is scanned on
// a schedule or by a prior step, and we pull the latest result.
type CBOMkitClient struct {
	BaseURL string       // e.g. http://localhost:8081
	HTTP    *http.Client // nil => a client with a sane timeout
}

// CBOMkitSource pairs a package URL with an optional commit for retrieval.
type CBOMkitSource struct {
	PURL   string // e.g. pkg:github/keycloak/keycloak
	Commit string // optional commit hash; empty retrieves the latest stored CBOM
}

// Name implements Scanner.
func (s CBOMkitSource) label() string { return "cbomkit " + s.PURL }

// scanner adapts a client + source into a Scanner.
type cbomkitScanner struct {
	client *CBOMkitClient
	src    CBOMkitSource
}

func (c *cbomkitScanner) Name() string { return c.src.label() }

func (c *cbomkitScanner) Scan(ctx context.Context) (*cdx.BOM, error) {
	return c.client.Fetch(ctx, c.src)
}

// NewScanner returns a Scanner that fetches the CBOM for src from the service.
func (c *CBOMkitClient) NewScanner(src CBOMkitSource) Scanner {
	return &cbomkitScanner{client: c, src: src}
}

// Fetch retrieves the stored CBOM for a purl (optionally pinned to a commit)
// via GET {BaseURL}/api/v1/cbom/{purl}[@{commit}].
func (c *CBOMkitClient) Fetch(ctx context.Context, src CBOMkitSource) (*cdx.BOM, error) {
	if strings.TrimSpace(src.PURL) == "" {
		return nil, fmt.Errorf("cbomkit: empty purl")
	}
	ref := src.PURL
	if src.Commit != "" {
		ref += "@" + src.Commit
	}
	endpoint := strings.TrimRight(c.BaseURL, "/") + "/api/v1/cbom/" + url.PathEscape(ref)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("cbomkit: %w", err)
	}
	req.Header.Set("Accept", "application/json")

	hc := c.HTTP
	if hc == nil {
		hc = &http.Client{Timeout: 30 * time.Second}
	}
	resp, err := hc.Do(req)
	if err != nil {
		return nil, fmt.Errorf("cbomkit: get %s: %w", ref, err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 64<<20))
	if err != nil {
		return nil, fmt.Errorf("cbomkit: read response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("cbomkit: get %s: status %d: %s", ref, resp.StatusCode, strings.TrimSpace(string(body)))
	}
	return decodeCBOMResponse(body)
}

// decodeCBOMResponse parses a CBOMkit retrieval response. CBOMkit stores CBOMs
// as records, so the CycloneDX document may be returned bare or wrapped in an
// envelope (a "bom" or "cbom" field). Unwrap when present; otherwise the body
// is assumed to be the CBOM itself.
func decodeCBOMResponse(body []byte) (*cdx.BOM, error) {
	var env struct {
		Bom  json.RawMessage `json:"bom"`
		CBOM json.RawMessage `json:"cbom"`
	}
	if err := json.Unmarshal(body, &env); err == nil {
		if len(env.Bom) > 0 {
			return decodeBOM(env.Bom)
		}
		if len(env.CBOM) > 0 {
			return decodeBOM(env.CBOM)
		}
	}
	return decodeBOM(body)
}
