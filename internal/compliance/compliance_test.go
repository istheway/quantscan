package compliance

import (
	"testing"

	"github.com/neotechadmin/quantscan/internal/cbom"
	"github.com/neotechadmin/quantscan/internal/scoring"
)

func TestForKnownFamily(t *testing.T) {
	g := For("RSA")
	if g.Family != "RSA" {
		t.Errorf("Family = %q, want RSA", g.Family)
	}
	if g.CNSA2Deadline == "" || g.Action == "" {
		t.Errorf("expected populated guidance, got %+v", g)
	}
	if len(g.Controls) == 0 {
		t.Error("expected mapped controls for RSA")
	}
}

func TestForUnknownFamilyFallsBack(t *testing.T) {
	g := For("BLOWFISH")
	if g.Family != "BLOWFISH" {
		t.Errorf("Family = %q, want BLOWFISH (echoed back)", g.Family)
	}
	if g.Status != unknownGuidance.Status {
		t.Errorf("Status = %q, want %q", g.Status, unknownGuidance.Status)
	}
	if g.Action != unknownGuidance.Action {
		t.Errorf("Action = %q, want fallback action", g.Action)
	}
}

func TestBuildRoadmapPreservesOrderAndAttachesGuidance(t *testing.T) {
	verdicts := []scoring.AssetVerdict{
		{Asset: cbom.Asset{Name: "RSA-2048", Family: "RSA"}, Class: scoring.ClassBroken},
		{Asset: cbom.Asset{Name: "ML-KEM-768", Family: "ML-KEM"}, Class: scoring.ClassReady},
	}
	road := BuildRoadmap(verdicts)

	if len(road) != len(verdicts) {
		t.Fatalf("len(road) = %d, want %d", len(road), len(verdicts))
	}
	if road[0].Asset.Family != "RSA" || road[1].Asset.Family != "ML-KEM" {
		t.Errorf("order not preserved: %q, %q", road[0].Asset.Family, road[1].Asset.Family)
	}
	if road[0].Guidance.Family != "RSA" {
		t.Errorf("guidance mismatch for row 0: %q", road[0].Guidance.Family)
	}
	if road[1].Guidance.Status != "Quantum-ready" {
		t.Errorf("ML-KEM status = %q, want Quantum-ready", road[1].Guidance.Status)
	}
}
