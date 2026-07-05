// Package scoring classifies cryptographic assets by their resistance to a
// cryptographically-relevant quantum computer (CRQC) and rolls the per-asset
// classification up into an org-level quantum-readiness score.
//
// The classification is deterministic and table-driven so results are
// reproducible across scans (a hard requirement for audit artifacts).
package scoring

import (
	"sort"
	"strings"

	"github.com/neotechadmin/quantscan/internal/cbom"
)

// Class is the quantum-risk classification of a single asset.
type Class int

const (
	ClassUnknown  Class = iota // could not be classified
	ClassBroken                // fully broken by Shor's algorithm (RSA/ECC/DH/DSA)
	ClassWeakened              // Grover-weakened or otherwise deprecated (AES-128, SHA-1)
	ClassReady                 // PQC or quantum-resistant at current parameters
)

func (c Class) String() string {
	switch c {
	case ClassBroken:
		return "Quantum-broken"
	case ClassWeakened:
		return "Quantum-weakened"
	case ClassReady:
		return "Quantum-ready"
	default:
		return "Unknown"
	}
}

// families that Shor's algorithm breaks outright, regardless of key size.
var shorBroken = map[string]bool{
	"RSA": true, "ECC": true, "DH": true, "DSA": true,
}

// PQC / quantum-resistant families (NIST FIPS 203/204/205 and friends).
var pqcReady = map[string]bool{
	"ML-KEM": true, "ML-DSA": true, "SLH-DSA": true, "FN-DSA": true,
}

// classicallyBroken families are already weak irrespective of quantum threat.
var classicallyBroken = map[string]bool{
	"MD5": true, "DES": true,
}

// AssetVerdict is the classification plus rationale for one asset.
type AssetVerdict struct {
	Asset  cbom.Asset
	Class  Class
	Reason string
}

// Classify assigns a quantum-risk Class to a single asset.
func Classify(a cbom.Asset) AssetVerdict {
	fam := a.Family
	v := AssetVerdict{Asset: a}

	switch {
	case shorBroken[fam]:
		v.Class = ClassBroken
		v.Reason = fam + " is broken by Shor's algorithm on a CRQC"
	case classicallyBroken[fam]:
		v.Class = ClassWeakened
		v.Reason = fam + " is already cryptographically broken and must be replaced"
	case pqcReady[fam], fam == "CHACHA20":
		v.Class = ClassReady
		v.Reason = fam + " is quantum-resistant at standardized parameters"
	case fam == "AES":
		if symmetricAtLeast256(a) {
			v.Class = ClassReady
			v.Reason = "AES-256 retains a 128-bit post-Grover security margin"
		} else {
			v.Class = ClassWeakened
			v.Reason = "AES-128 falls to ~64-bit security under Grover; migrate to AES-256"
		}
	case fam == "SHA3", strings.HasPrefix(fam, "SHA"):
		if hashAtLeast384(a) {
			v.Class = ClassReady
			v.Reason = fam + " with >=384-bit output retains adequate post-Grover margin"
		} else {
			v.Class = ClassWeakened
			v.Reason = fam + " short-digest variants are Grover-weakened; prefer SHA-384+"
		}
	default:
		v.Class = ClassUnknown
		v.Reason = "family not recognized; manual review required"
	}
	return v
}

// symmetricAtLeast256 reports whether a symmetric asset offers >=256-bit keys.
func symmetricAtLeast256(a cbom.Asset) bool {
	if a.ClassicalBits >= 256 {
		return true
	}
	return containsAny(a.Params+" "+a.Name, "256")
}

// hashAtLeast384 reports whether a hash offers a >=384-bit digest.
func hashAtLeast384(a cbom.Asset) bool {
	if a.ClassicalBits >= 192 { // ~half of digest length as collision strength
		return true
	}
	return containsAny(a.Params+" "+a.Name, "384", "512", "-3")
}

func containsAny(s string, subs ...string) bool {
	for _, sub := range subs {
		if strings.Contains(s, sub) {
			return true
		}
	}
	return false
}

// Report is the org-level rollup: verdicts plus aggregate readiness metrics.
type Report struct {
	Source    string
	Verdicts  []AssetVerdict
	Counts    map[Class]int
	Total     int
	Score     int // 0-100 quantum-readiness score, higher is better
	RiskLabel string
}

// Score classifies every asset in the inventory and computes the org rollup.
func Score(inv *cbom.Inventory) *Report {
	r := &Report{Source: inv.Source, Counts: map[Class]int{}}
	for _, a := range inv.Assets {
		v := Classify(a)
		r.Verdicts = append(r.Verdicts, v)
		r.Counts[v.Class]++
	}
	r.Total = len(r.Verdicts)

	// Sort worst-first so the report leads with the highest-risk assets.
	sort.SliceStable(r.Verdicts, func(i, j int) bool {
		return classSeverity(r.Verdicts[i].Class) > classSeverity(r.Verdicts[j].Class)
	})

	r.Score = computeScore(r)
	r.RiskLabel = riskLabel(r.Score)
	return r
}

// classSeverity orders classes worst-to-best for sorting and weighting.
func classSeverity(c Class) int {
	switch c {
	case ClassBroken:
		return 3
	case ClassWeakened:
		return 2
	case ClassUnknown:
		return 1
	default:
		return 0
	}
}

// computeScore maps the class distribution to a 0-100 readiness score using
// per-class weights. Broken assets dominate the penalty.
func computeScore(r *Report) int {
	if r.Total == 0 {
		return 100
	}
	const (
		wBroken   = 1.0
		wWeakened = 0.5
		wUnknown  = 0.3
	)
	penalty := wBroken*float64(r.Counts[ClassBroken]) +
		wWeakened*float64(r.Counts[ClassWeakened]) +
		wUnknown*float64(r.Counts[ClassUnknown])
	score := 100.0 * (1.0 - penalty/float64(r.Total))
	if score < 0 {
		score = 0
	}
	return int(score + 0.5)
}

func riskLabel(score int) string {
	switch {
	case score >= 90:
		return "Low"
	case score >= 70:
		return "Moderate"
	case score >= 40:
		return "Elevated"
	default:
		return "Critical"
	}
}
