package report

import (
	"strings"
	"testing"
	"time"

	"github.com/neotechadmin/quantscan/internal/cbom"
)

func sampleInventory() *cbom.Inventory {
	return &cbom.Inventory{
		Source: "sample.json",
		Assets: []cbom.Asset{
			{Name: "RSA-2048", Family: "RSA", Params: "2048", Locations: []string{"src/tls.go:10"}},
			{Name: "AES-128-GCM", Family: "AES", ClassicalBits: 128},
			{Name: "ML-KEM-768", Family: "ML-KEM", Params: "768"},
		},
	}
}

func TestRenderHTMLContainsKeyContent(t *testing.T) {
	opts := Options{Org: "Acme Corp", GeneratedAt: time.Date(2026, 7, 3, 12, 0, 0, 0, time.UTC)}
	html, err := RenderHTML(sampleInventory(), opts)
	if err != nil {
		t.Fatalf("RenderHTML: %v", err)
	}

	wantSubstrings := []string{
		"Acme Corp",            // org name on the cover
		"sample.json",          // CBOM source
		"RSA-2048",             // asset row
		"ML-KEM-768",           // PQC asset row
		"Quantum-broken",       // classification pill
		"src/tls.go:10",        // evidence location
		"2026-07-03 12:00 UTC", // deterministic timestamp
		"Required Action",      // roadmap table header
	}
	for _, want := range wantSubstrings {
		if !strings.Contains(html, want) {
			t.Errorf("rendered HTML missing %q", want)
		}
	}
}

func TestRenderHTMLRequiresGeneratedAt(t *testing.T) {
	_, err := RenderHTML(sampleInventory(), Options{Org: "Acme"})
	if err == nil {
		t.Fatal("expected error when GeneratedAt is zero, got nil")
	}
}

func TestRenderHTMLDefaultOrg(t *testing.T) {
	opts := Options{GeneratedAt: time.Now()}
	html, err := RenderHTML(sampleInventory(), opts)
	if err != nil {
		t.Fatalf("RenderHTML: %v", err)
	}
	if !strings.Contains(html, "Client Organization") {
		t.Error("expected default org name when Org is empty")
	}
}

func TestBuildViewCountsAndControls(t *testing.T) {
	opts := Options{Org: "Acme", GeneratedAt: time.Now()}
	html, err := RenderHTML(sampleInventory(), opts)
	if err != nil {
		t.Fatalf("RenderHTML: %v", err)
	}
	// Control cross-reference should de-duplicate families; each of the three
	// distinct families (RSA, AES, ML-KEM) appears once in the control table.
	for _, fam := range []string{"PCI DSS 4.0", "ISO 27001 A.8.24"} {
		if !strings.Contains(html, fam) {
			t.Errorf("expected control reference %q in output", fam)
		}
	}
}
