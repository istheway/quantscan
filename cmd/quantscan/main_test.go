package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"testing"

	"github.com/neotechadmin/quantscan/internal/cbom"
)

var timestampedCBOM = regexp.MustCompile(`^cbom-\d{8}-\d{6}\.json$`)

func TestCBOMOutputPath(t *testing.T) {
	t.Run("dash means stdout", func(t *testing.T) {
		got, err := cbomOutputPath("-", "")
		if err != nil || got != "" {
			t.Fatalf("cbomOutputPath(-) = %q, %v; want \"\", nil", got, err)
		}
	})

	t.Run("explicit out wins over out-dir", func(t *testing.T) {
		got, err := cbomOutputPath("cbom.json", "/somewhere")
		if err != nil || got != "cbom.json" {
			t.Fatalf("cbomOutputPath = %q, %v; want cbom.json", got, err)
		}
	})

	t.Run("default auto-name in cwd", func(t *testing.T) {
		got, err := cbomOutputPath("", "")
		if err != nil {
			t.Fatal(err)
		}
		if !timestampedCBOM.MatchString(got) {
			t.Errorf("auto-name %q does not match cbom-YYYYMMDD-HHMMSS.json", got)
		}
	})

	t.Run("out-dir is created and joined", func(t *testing.T) {
		dir := filepath.Join(t.TempDir(), "nested", "cboms")
		got, err := cbomOutputPath("", dir)
		if err != nil {
			t.Fatal(err)
		}
		if filepath.Dir(got) != dir {
			t.Errorf("path %q not under out-dir %q", got, dir)
		}
		if !timestampedCBOM.MatchString(filepath.Base(got)) {
			t.Errorf("filename %q does not match pattern", filepath.Base(got))
		}
		if info, err := os.Stat(dir); err != nil || !info.IsDir() {
			t.Errorf("out-dir was not created: %v", err)
		}
	})
}

func TestMarshalJSONProjection(t *testing.T) {
	inv := &cbom.Inventory{
		Source: "fixture.json",
		Assets: []cbom.Asset{
			{Name: "RSA-2048", Family: "RSA", Params: "2048", Locations: []string{"a.go:1"}},
			{Name: "AES-128", Family: "AES", ClassicalBits: 128},
			{Name: "ML-KEM-768", Family: "ML-KEM"},
		},
	}

	data, err := marshalJSON(inv)
	if err != nil {
		t.Fatalf("marshalJSON: %v", err)
	}

	var jr jsonReport
	if err := json.Unmarshal(data, &jr); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if jr.Source != "fixture.json" {
		t.Errorf("Source = %q", jr.Source)
	}
	if jr.Total != 3 {
		t.Errorf("Total = %d, want 3", jr.Total)
	}
	if jr.Score != 50 {
		t.Errorf("Score = %d, want 50", jr.Score)
	}
	if jr.Counts["Quantum-broken"] != 1 || jr.Counts["Quantum-weakened"] != 1 || jr.Counts["Quantum-ready"] != 1 {
		t.Errorf("Counts = %+v", jr.Counts)
	}
	if len(jr.Assets) != 3 {
		t.Fatalf("len(Assets) = %d, want 3", len(jr.Assets))
	}
	// Worst-first ordering carries through to the JSON output.
	if jr.Assets[0].Classification != "Quantum-broken" {
		t.Errorf("first asset classification = %q, want Quantum-broken", jr.Assets[0].Classification)
	}
	// Guidance must be attached.
	if jr.Assets[0].CNSA2Deadline == "" || jr.Assets[0].Action == "" {
		t.Errorf("first asset missing guidance: %+v", jr.Assets[0])
	}
}
