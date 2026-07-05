// Package cbom loads CycloneDX 1.6 CBOM documents and flattens their
// cryptographic assets into a normalized internal model that the scoring,
// compliance, and report packages consume. It deliberately keeps only the
// fields those consumers need rather than re-exposing the full CycloneDX tree.
package cbom

import (
	"fmt"
	"io"
	"os"
	"strings"

	cdx "github.com/CycloneDX/cyclonedx-go"
)

// AssetType mirrors the CycloneDX crypto assetType values we care about.
type AssetType string

const (
	AssetAlgorithm   AssetType = "algorithm"
	AssetCertificate AssetType = "certificate"
	AssetProtocol    AssetType = "protocol"
	AssetMaterial    AssetType = "related-crypto-material"
)

// Asset is a normalized cryptographic asset extracted from a CBOM.
type Asset struct {
	Ref       string    // bom-ref
	Name      string    // component name, e.g. "RSA-2048"
	Type      AssetType // algorithm | certificate | protocol | related-crypto-material
	Family    string    // normalized family, e.g. RSA, ECDSA, AES, SHA, ML-KEM
	Primitive string    // CycloneDX primitive (signature, hash, pke, kem, ...)
	Params    string    // parameterSetIdentifier / curve / key length hint
	Locations []string  // source-code / file evidence, best effort

	ClassicalBits int // classicalSecurityLevel, 0 if unknown
	QuantumLevel  int // nistQuantumSecurityLevel, 0 if unknown

	// Certificate-only fields.
	Subject  string
	Issuer   string
	NotAfter string // RFC3339, notValidAfter
}

// Inventory is the flattened result of loading a CBOM.
type Inventory struct {
	Source string  // filename or origin the CBOM was read from
	Assets []Asset // one entry per cryptographic-asset component
}

// LoadFile reads and parses a CycloneDX CBOM JSON document from disk.
func LoadFile(path string) (*Inventory, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open cbom: %w", err)
	}
	defer f.Close()
	inv, err := Load(f)
	if err != nil {
		return nil, err
	}
	inv.Source = path
	return inv, nil
}

// Load parses a CycloneDX CBOM JSON document from r.
func Load(r io.Reader) (*Inventory, error) {
	var bom cdx.BOM
	if err := cdx.NewBOMDecoder(r, cdx.BOMFileFormatJSON).Decode(&bom); err != nil {
		return nil, fmt.Errorf("decode cbom: %w", err)
	}
	inv := &Inventory{}
	if bom.Components == nil {
		return inv, nil
	}
	comps := *bom.Components

	// A certificate's own name is its subject (e.g. a CA name), which carries no
	// algorithm information. Its cryptography lives in referenced components, so
	// we index every asset's family by bom-ref up front and resolve certificate
	// references in a second pass.
	idx := newRefIndex(comps)

	for _, c := range comps {
		if c.Type != cdx.ComponentTypeCryptographicAsset || c.CryptoProperties == nil {
			continue
		}
		a := fromComponent(c)
		if a.Type == AssetCertificate {
			if fam, params := idx.certKey(c); fam != "" {
				a.Family = fam
				if a.Params == "" {
					a.Params = params
				}
			}
		}
		inv.Assets = append(inv.Assets, a)
	}
	return inv, nil
}

// refIndex resolves a certificate's cryptography from the components it points
// at: subjectPublicKeyRef (the certificate's own key) and signatureAlgorithmRef
// (the issuer's signing algorithm), following the public-key material's
// algorithmRef one hop further when needed.
type refIndex struct {
	family  map[string]string // bom-ref -> normalized family
	params  map[string]string // bom-ref -> parameter/curve/key-length hint
	algoRef map[string]string // material bom-ref -> referenced algorithm bom-ref
}

func newRefIndex(comps []cdx.Component) *refIndex {
	ix := &refIndex{
		family:  map[string]string{},
		params:  map[string]string{},
		algoRef: map[string]string{},
	}
	for _, c := range comps {
		if c.BOMRef == "" || c.CryptoProperties == nil {
			continue
		}
		cp := c.CryptoProperties
		if ap := cp.AlgorithmProperties; ap != nil {
			ix.family[c.BOMRef] = normalizeFamily(firstNonEmpty(ap.AlgorithmFamily, c.Name))
			ix.params[c.BOMRef] = firstNonEmpty(ap.ParameterSetIdentifier, ap.EllipticCurve, ap.Curve)
		} else {
			ix.family[c.BOMRef] = normalizeFamily(c.Name)
		}
		if m := cp.RelatedCryptoMaterialProperties; m != nil {
			if ref := string(m.AlgorithmRef); ref != "" {
				ix.algoRef[c.BOMRef] = ref
			}
			// A public-key material's name often carries the key length (RSA-4096).
			if ix.params[c.BOMRef] == "" {
				ix.params[c.BOMRef] = c.Name
			}
		}
	}
	return ix
}

// certKey returns the family and parameter hint for a certificate, preferring
// the subject public key over the signature algorithm. It returns empty strings
// when nothing resolvable is referenced.
func (ix *refIndex) certKey(c cdx.Component) (family, params string) {
	cert := c.CryptoProperties.CertificateProperties
	if cert == nil {
		return "", ""
	}
	for _, ref := range []string{string(cert.SubjectPublicKeyRef), string(cert.SignatureAlgorithmRef)} {
		if fam := ix.resolveFamily(ref, 0); fam != "" && fam != "UNKNOWN" {
			return fam, ix.params[ref]
		}
	}
	return "", ""
}

// resolveFamily follows a bom-ref to a known family, chasing a material's
// algorithmRef when the material itself is unclassified. depth guards cycles.
func (ix *refIndex) resolveFamily(ref string, depth int) string {
	if ref == "" || depth > 4 {
		return ""
	}
	if fam, ok := ix.family[ref]; ok && fam != "" && fam != "UNKNOWN" {
		return fam
	}
	if next, ok := ix.algoRef[ref]; ok {
		return ix.resolveFamily(next, depth+1)
	}
	return ix.family[ref]
}

func fromComponent(c cdx.Component) Asset {
	cp := c.CryptoProperties
	a := Asset{
		Ref:       c.BOMRef,
		Name:      c.Name,
		Type:      AssetType(cp.AssetType),
		Locations: occurrences(c.Evidence),
	}

	if ap := cp.AlgorithmProperties; ap != nil {
		a.Primitive = string(ap.Primitive)
		a.Params = firstNonEmpty(ap.ParameterSetIdentifier, ap.EllipticCurve, ap.Curve)
		a.Family = normalizeFamily(firstNonEmpty(ap.AlgorithmFamily, c.Name))
		if ap.ClassicalSecurityLevel != nil {
			a.ClassicalBits = *ap.ClassicalSecurityLevel
		}
		if ap.NistQuantumSecurityLevel != nil {
			a.QuantumLevel = *ap.NistQuantumSecurityLevel
		}
	} else {
		a.Family = normalizeFamily(c.Name)
	}

	if cert := cp.CertificateProperties; cert != nil {
		a.Subject = cert.SubjectName
		a.Issuer = cert.IssuerName
		a.NotAfter = cert.NotValidAfter
	}
	return a
}

func occurrences(e *cdx.Evidence) []string {
	if e == nil || e.Occurrences == nil {
		return nil
	}
	var locs []string
	for _, o := range *e.Occurrences {
		if o.Location != "" {
			locs = append(locs, o.Location)
		}
	}
	return locs
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}

// normalizeFamily maps assorted spellings to a canonical family token that
// the scoring tables key on. It is intentionally forgiving: CBOM producers
// disagree on casing and naming ("EC" vs "ECDSA", "Kyber" vs "ML-KEM").
func normalizeFamily(s string) string {
	u := strings.ToUpper(strings.TrimSpace(s))
	if u == "" {
		return "UNKNOWN"
	}
	switch {
	case strings.Contains(u, "ML-KEM"), strings.Contains(u, "KYBER"):
		return "ML-KEM"
	case strings.Contains(u, "ML-DSA"), strings.Contains(u, "DILITHIUM"):
		return "ML-DSA"
	case strings.Contains(u, "SLH-DSA"), strings.Contains(u, "SPHINCS"):
		return "SLH-DSA"
	case strings.Contains(u, "FALCON"), strings.Contains(u, "FN-DSA"):
		return "FN-DSA"
	case strings.HasPrefix(u, "RSA"):
		return "RSA"
	case strings.HasPrefix(u, "ECDSA"), strings.HasPrefix(u, "ECDH"),
		strings.HasPrefix(u, "EC-"), u == "EC", strings.HasPrefix(u, "ED25519"),
		strings.HasPrefix(u, "ED448"), strings.HasPrefix(u, "X25519"),
		strings.HasPrefix(u, "X448"):
		return "ECC"
	case u == "DH", strings.HasPrefix(u, "DIFFIE"):
		return "DH"
	case strings.HasPrefix(u, "DSA"):
		return "DSA"
	case strings.HasPrefix(u, "AES"):
		return "AES"
	case strings.HasPrefix(u, "3DES"), strings.HasPrefix(u, "TRIPLEDES"),
		strings.HasPrefix(u, "DES"):
		return "DES"
	case strings.HasPrefix(u, "SHA3"):
		return "SHA3"
	case strings.HasPrefix(u, "SHA"):
		return "SHA"
	case strings.HasPrefix(u, "MD5"), strings.HasPrefix(u, "MD4"):
		return "MD5"
	case strings.HasPrefix(u, "CHACHA"):
		return "CHACHA20"
	}
	return u
}
