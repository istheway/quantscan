package discover

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestCBOMkitFetchBare(t *testing.T) {
	var gotPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(sampleCBOM))
	}))
	defer srv.Close()

	client := &CBOMkitClient{BaseURL: srv.URL}
	bom, err := client.Fetch(context.Background(), CBOMkitSource{PURL: "pkg:github/foo/bar", Commit: "abc123"})
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if !strings.Contains(gotPath, "/api/v1/cbom/") {
		t.Errorf("unexpected request path %q", gotPath)
	}
	if bom.Components == nil || len(*bom.Components) != 1 {
		t.Fatalf("expected 1 component, got %v", bom.Components)
	}
}

func TestCBOMkitFetchUnwrapsEnvelope(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"projectIdentifier":"pkg:github/foo/bar","bom":` + sampleCBOM + `}`))
	}))
	defer srv.Close()

	client := &CBOMkitClient{BaseURL: srv.URL}
	bom, err := client.Fetch(context.Background(), CBOMkitSource{PURL: "pkg:github/foo/bar"})
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if bom.Components == nil || len(*bom.Components) != 1 {
		t.Fatalf("expected 1 component from unwrapped envelope, got %v", bom.Components)
	}
}

func TestCBOMkitFetchErrorStatus(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "not found", http.StatusNotFound)
	}))
	defer srv.Close()

	client := &CBOMkitClient{BaseURL: srv.URL}
	_, err := client.Fetch(context.Background(), CBOMkitSource{PURL: "pkg:github/foo/bar"})
	if err == nil {
		t.Fatal("expected error on 404, got nil")
	}
	if !strings.Contains(err.Error(), "404") {
		t.Errorf("error should mention status: %v", err)
	}
}

func TestCBOMkitFetchEmptyPURL(t *testing.T) {
	client := &CBOMkitClient{BaseURL: "http://example.invalid"}
	if _, err := client.Fetch(context.Background(), CBOMkitSource{}); err == nil {
		t.Fatal("expected error for empty purl, got nil")
	}
}

func TestCBOMkitScannerName(t *testing.T) {
	client := &CBOMkitClient{BaseURL: "http://x"}
	s := client.NewScanner(CBOMkitSource{PURL: "pkg:github/foo/bar"})
	if s.Name() != "cbomkit pkg:github/foo/bar" {
		t.Errorf("Name() = %q", s.Name())
	}
}
