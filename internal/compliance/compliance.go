// Package compliance maps cryptographic families to migration guidance and
// regulatory deadlines. The tables encode NIST IR 8547 ("Transition to
// Post-Quantum Cryptography Standards") direction and CNSA 2.0 timelines so
// the audit report can state, per asset, what must change and by when.
//
// Dates reflect published CNSA 2.0 guidance as of mid-2026 and are kept in
// one place so they can be reviewed and updated as standards evolve.
package compliance

import "github.com/neotechadmin/quantscan/internal/scoring"

// Guidance is the migration direction and deadline for a crypto family.
type Guidance struct {
	Family        string
	Status        string   // short human status
	Action        string   // NIST IR 8547-aligned migration action
	CNSA2Deadline string   // CNSA 2.0 target, empty if not applicable
	Controls      []string // cross-referenced control frameworks
}

// deadlines reflect CNSA 2.0: software/firmware signing prefer PQC by 2025 and
// exclusively by 2030; most other uses transition by 2030-2033.
var table = map[string]Guidance{
	"RSA": {
		Family: "RSA", Status: "Quantum-broken",
		Action:        "Replace key-establishment with ML-KEM and signatures with ML-DSA (NIST IR 8547 §quantum-vulnerable asymmetric).",
		CNSA2Deadline: "2030 (exclusive PQC by 2033)",
		Controls:      []string{"PCI DSS 4.0 4.2.1", "SOC 2 CC6.1", "ISO 27001 A.8.24"},
	},
	"ECC": {
		Family: "ECC", Status: "Quantum-broken",
		Action:        "Replace ECDH/ECDSA/EdDSA with ML-KEM / ML-DSA; retire NIST P-curves and Curve25519 for confidentiality.",
		CNSA2Deadline: "2030 (exclusive PQC by 2033)",
		Controls:      []string{"PCI DSS 4.0 4.2.1", "SOC 2 CC6.1", "ISO 27001 A.8.24"},
	},
	"DH": {
		Family: "DH", Status: "Quantum-broken",
		Action:        "Replace finite-field Diffie-Hellman with ML-KEM key establishment.",
		CNSA2Deadline: "2030",
		Controls:      []string{"SOC 2 CC6.1", "ISO 27001 A.8.24"},
	},
	"DSA": {
		Family: "DSA", Status: "Quantum-broken",
		Action:        "Replace DSA signatures with ML-DSA (FIPS 204).",
		CNSA2Deadline: "2030",
		Controls:      []string{"SOC 2 CC6.1", "ISO 27001 A.8.24"},
	},
	"AES": {
		Family: "AES", Status: "Conditional",
		Action:        "Standardize on AES-256; deprecate AES-128 for data requiring long-term confidentiality.",
		CNSA2Deadline: "AES-256 by 2030",
		Controls:      []string{"PCI DSS 4.0 3.5.1", "ISO 27001 A.8.24"},
	},
	"SHA": {
		Family: "SHA", Status: "Conditional",
		Action:        "Use SHA-384/512; retire SHA-1 and SHA-256 for signatures under CNSA 2.0.",
		CNSA2Deadline: "SHA-384+ by 2030",
		Controls:      []string{"PCI DSS 4.0 4.2.1", "ISO 27001 A.8.24"},
	},
	"SHA3": {
		Family: "SHA3", Status: "Conditional",
		Action:        "Prefer SHA3-384/512 where SHA-3 is used.",
		CNSA2Deadline: "SHA-384+ equivalent by 2030",
		Controls:      []string{"ISO 27001 A.8.24"},
	},
	"MD5": {
		Family: "MD5", Status: "Broken",
		Action:        "Remove immediately; MD5/MD4 are cryptographically broken independent of quantum threat.",
		CNSA2Deadline: "Immediate",
		Controls:      []string{"PCI DSS 4.0 4.2.1", "SOC 2 CC6.1"},
	},
	"DES": {
		Family: "DES", Status: "Broken",
		Action:        "Remove immediately; DES/3DES are prohibited.",
		CNSA2Deadline: "Immediate",
		Controls:      []string{"PCI DSS 4.0 3.5.1"},
	},
	"ML-KEM":   {Family: "ML-KEM", Status: "Quantum-ready", Action: "Compliant target (FIPS 203). Confirm parameter set (ML-KEM-768+).", CNSA2Deadline: "Compliant", Controls: []string{"ISO 27001 A.8.24"}},
	"ML-DSA":   {Family: "ML-DSA", Status: "Quantum-ready", Action: "Compliant target (FIPS 204). Confirm parameter set (ML-DSA-65+).", CNSA2Deadline: "Compliant", Controls: []string{"ISO 27001 A.8.24"}},
	"SLH-DSA":  {Family: "SLH-DSA", Status: "Quantum-ready", Action: "Compliant stateless-hash signature target (FIPS 205).", CNSA2Deadline: "Compliant", Controls: []string{"ISO 27001 A.8.24"}},
	"CHACHA20": {Family: "CHACHA20", Status: "Quantum-ready", Action: "256-bit stream cipher retains post-Grover margin; acceptable.", CNSA2Deadline: "Compliant", Controls: []string{"ISO 27001 A.8.24"}},
}

var unknownGuidance = Guidance{
	Status:        "Unclassified",
	Action:        "Manual cryptographic review required to determine quantum exposure.",
	CNSA2Deadline: "Review",
	Controls:      []string{"ISO 27001 A.8.24"},
}

// For returns migration guidance for a normalized family token.
func For(family string) Guidance {
	if g, ok := table[family]; ok {
		return g
	}
	g := unknownGuidance
	g.Family = family
	return g
}

// Roadmap is one row of the audit report's migration roadmap.
type Roadmap struct {
	scoring.AssetVerdict
	Guidance Guidance
}

// BuildRoadmap attaches compliance guidance to each scored asset verdict,
// preserving the worst-first ordering produced by the scoring package.
func BuildRoadmap(verdicts []scoring.AssetVerdict) []Roadmap {
	out := make([]Roadmap, 0, len(verdicts))
	for _, v := range verdicts {
		out = append(out, Roadmap{AssetVerdict: v, Guidance: For(v.Asset.Family)})
	}
	return out
}
