package scoring

import (
	"testing"

	"github.com/neotechadmin/quantscan/internal/cbom"
)

func TestClassify(t *testing.T) {
	tests := []struct {
		name  string
		asset cbom.Asset
		want  Class
	}{
		{"RSA broken by Shor", cbom.Asset{Family: "RSA"}, ClassBroken},
		{"ECC broken by Shor", cbom.Asset{Family: "ECC"}, ClassBroken},
		{"DH broken by Shor", cbom.Asset{Family: "DH"}, ClassBroken},
		{"DSA broken by Shor", cbom.Asset{Family: "DSA"}, ClassBroken},
		{"MD5 classically broken", cbom.Asset{Family: "MD5"}, ClassWeakened},
		{"DES classically broken", cbom.Asset{Family: "DES"}, ClassWeakened},
		{"ML-KEM ready", cbom.Asset{Family: "ML-KEM"}, ClassReady},
		{"ML-DSA ready", cbom.Asset{Family: "ML-DSA"}, ClassReady},
		{"SLH-DSA ready", cbom.Asset{Family: "SLH-DSA"}, ClassReady},
		{"ChaCha20 ready", cbom.Asset{Family: "CHACHA20"}, ClassReady},
		{"AES-256 by bits ready", cbom.Asset{Family: "AES", ClassicalBits: 256}, ClassReady},
		{"AES-256 by name ready", cbom.Asset{Family: "AES", Name: "AES-256-GCM"}, ClassReady},
		{"AES-128 weakened", cbom.Asset{Family: "AES", Name: "AES-128-GCM", ClassicalBits: 128}, ClassWeakened},
		{"SHA-384 ready", cbom.Asset{Family: "SHA", Name: "SHA-384"}, ClassReady},
		{"SHA-512 ready", cbom.Asset{Family: "SHA", Name: "SHA-512"}, ClassReady},
		{"SHA-256 weakened", cbom.Asset{Family: "SHA", Name: "SHA-256"}, ClassWeakened},
		{"SHA3-512 ready", cbom.Asset{Family: "SHA3", Name: "SHA3-512"}, ClassReady},
		{"unknown family", cbom.Asset{Family: "BLOWFISH"}, ClassUnknown},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := Classify(tt.asset)
			if got.Class != tt.want {
				t.Errorf("Classify(%+v).Class = %v, want %v", tt.asset, got.Class, tt.want)
			}
			if got.Reason == "" {
				t.Errorf("Classify(%+v) produced empty Reason", tt.asset)
			}
		})
	}
}

func TestScoreCountsAndRollup(t *testing.T) {
	inv := &cbom.Inventory{
		Source: "test.json",
		Assets: []cbom.Asset{
			{Name: "RSA-2048", Family: "RSA"},
			{Name: "AES-128", Family: "AES", ClassicalBits: 128},
			{Name: "ML-KEM-768", Family: "ML-KEM"},
		},
	}
	rep := Score(inv)

	if rep.Total != 3 {
		t.Fatalf("Total = %d, want 3", rep.Total)
	}
	if rep.Counts[ClassBroken] != 1 || rep.Counts[ClassWeakened] != 1 || rep.Counts[ClassReady] != 1 {
		t.Errorf("unexpected counts: %+v", rep.Counts)
	}
	// penalty = 1.0*1 + 0.5*1 = 1.5 over 3 => score = 100*(1-0.5) = 50.
	if rep.Score != 50 {
		t.Errorf("Score = %d, want 50", rep.Score)
	}
	if rep.RiskLabel != "Elevated" {
		t.Errorf("RiskLabel = %q, want Elevated", rep.RiskLabel)
	}
	// Worst-first ordering: broken must lead.
	if rep.Verdicts[0].Class != ClassBroken {
		t.Errorf("first verdict class = %v, want Quantum-broken", rep.Verdicts[0].Class)
	}
}

func TestScoreEmptyInventoryIsPerfect(t *testing.T) {
	rep := Score(&cbom.Inventory{})
	if rep.Score != 100 {
		t.Errorf("empty inventory Score = %d, want 100", rep.Score)
	}
	if rep.RiskLabel != "Low" {
		t.Errorf("empty inventory RiskLabel = %q, want Low", rep.RiskLabel)
	}
}

func TestRiskLabelBoundaries(t *testing.T) {
	tests := []struct {
		score int
		want  string
	}{
		{100, "Low"}, {90, "Low"}, {89, "Moderate"}, {70, "Moderate"},
		{69, "Elevated"}, {40, "Elevated"}, {39, "Critical"}, {0, "Critical"},
	}
	for _, tt := range tests {
		if got := riskLabel(tt.score); got != tt.want {
			t.Errorf("riskLabel(%d) = %q, want %q", tt.score, got, tt.want)
		}
	}
}

func TestClassString(t *testing.T) {
	cases := map[Class]string{
		ClassBroken:   "Quantum-broken",
		ClassWeakened: "Quantum-weakened",
		ClassReady:    "Quantum-ready",
		ClassUnknown:  "Unknown",
	}
	for c, want := range cases {
		if got := c.String(); got != want {
			t.Errorf("Class(%d).String() = %q, want %q", c, got, want)
		}
	}
}
