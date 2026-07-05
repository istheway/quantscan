package discover

import (
	"os"
	"path/filepath"
	"testing"

	cdx "github.com/CycloneDX/cyclonedx-go"
)

// algo builds a minimal cryptographic-asset component for tests.
func algo(ref, name, params string, locations ...string) cdx.Component {
	c := cdx.Component{
		BOMRef: ref,
		Type:   cdx.ComponentTypeCryptographicAsset,
		Name:   name,
		CryptoProperties: &cdx.CryptoProperties{
			AssetType:           cdx.CryptoAssetTypeAlgorithm,
			AlgorithmProperties: &cdx.CryptoAlgorithmProperties{ParameterSetIdentifier: params},
		},
	}
	if len(locations) > 0 {
		occ := make([]cdx.EvidenceOccurrence, 0, len(locations))
		for _, l := range locations {
			occ = append(occ, cdx.EvidenceOccurrence{Location: l})
		}
		c.Evidence = &cdx.Evidence{Occurrences: &occ}
	}
	return c
}

func bomOf(components ...cdx.Component) *cdx.BOM {
	b := cdx.NewBOM()
	b.Components = &components
	return b
}

func components(b *cdx.BOM) []cdx.Component {
	if b.Components == nil {
		return nil
	}
	return *b.Components
}

func TestMergeDeduplicatesByBOMRef(t *testing.T) {
	a := bomOf(algo("crypto/rsa", "RSA-2048", "2048", "a.go:1"))
	b := bomOf(algo("crypto/rsa", "RSA-2048", "2048", "b.go:2"))

	merged := components(Merge(a, b))
	if len(merged) != 1 {
		t.Fatalf("expected 1 merged component, got %d", len(merged))
	}
	if got := occurrences(merged[0]); len(got) != 2 {
		t.Errorf("expected 2 unioned occurrences, got %d (%v)", len(got), got)
	}
}

func TestMergeDeduplicatesByIdentityAcrossRefs(t *testing.T) {
	// Different bom-refs but the same assetType|name|params must collapse.
	a := bomOf(algo("theia/1", "AES-128", "128", "conf/openssl.cnf"))
	b := bomOf(algo("sonar/9", "AES-128", "128", "src/crypto.go:5"))

	merged := components(Merge(a, b))
	if len(merged) != 1 {
		t.Fatalf("expected identity dedup to 1 component, got %d", len(merged))
	}
	if got := occurrences(merged[0]); len(got) != 2 {
		t.Errorf("expected 2 unioned occurrences, got %d", len(got))
	}
}

func TestMergeKeepsDistinctAssets(t *testing.T) {
	a := bomOf(algo("crypto/rsa", "RSA-2048", "2048"))
	b := bomOf(algo("crypto/mlkem", "ML-KEM-768", "768"))

	merged := components(Merge(a, b))
	if len(merged) != 2 {
		t.Fatalf("expected 2 distinct components, got %d", len(merged))
	}
}

func TestMergeDoesNotMergeNonCryptoByIdentity(t *testing.T) {
	// Library components have no crypto identity and must never be folded.
	lib := func(name string) cdx.Component {
		return cdx.Component{Type: cdx.ComponentTypeLibrary, Name: name}
	}
	a := bomOf(lib("openssl"))
	b := bomOf(lib("openssl"))

	merged := components(Merge(a, b))
	if len(merged) != 2 {
		t.Fatalf("expected non-crypto components preserved (2), got %d", len(merged))
	}
}

func TestMergeUnionsOccurrencesWithoutDuplicates(t *testing.T) {
	a := bomOf(algo("crypto/rsa", "RSA-2048", "2048", "a.go:1", "shared.go:9"))
	b := bomOf(algo("crypto/rsa", "RSA-2048", "2048", "shared.go:9", "b.go:2"))

	merged := components(Merge(a, b))
	if len(merged) != 1 {
		t.Fatalf("expected 1 component, got %d", len(merged))
	}
	if got := occurrences(merged[0]); len(got) != 3 {
		t.Errorf("expected 3 de-duplicated occurrences, got %d (%v)", len(got), got)
	}
}

// certWithKey builds a certificate component referencing a public-key material.
func certWithKey(certRef, subject, keyRef string) cdx.Component {
	return cdx.Component{
		BOMRef: certRef,
		Type:   cdx.ComponentTypeCryptographicAsset,
		Name:   subject,
		CryptoProperties: &cdx.CryptoProperties{
			AssetType: cdx.CryptoAssetTypeCertificate,
			CertificateProperties: &cdx.CertificateProperties{
				SubjectName:         subject,
				SubjectPublicKeyRef: cdx.BOMReference(keyRef),
			},
		},
	}
}

// pubKey builds a public-key related-crypto-material component.
func pubKey(ref, name string) cdx.Component {
	return cdx.Component{
		BOMRef: ref,
		Type:   cdx.ComponentTypeCryptographicAsset,
		Name:   name,
		CryptoProperties: &cdx.CryptoProperties{
			AssetType:                       cdx.CryptoAssetTypeRelatedCryptoMaterial,
			RelatedCryptoMaterialProperties: &cdx.RelatedCryptoMaterialProperties{Type: cdx.RelatedCryptoMaterialTypePublicKey},
		},
	}
}

func TestMergeRewritesDanglingCertRef(t *testing.T) {
	// Bom A keeps public-key material "key-A". Bom B has an identical key
	// "key-B" (deduped away) and a cert pointing at it. After merge the cert's
	// ref must be redirected to the surviving "key-A".
	a := bomOf(pubKey("key-A", "RSA-4096"))
	b := bomOf(pubKey("key-B", "RSA-4096"), certWithKey("cert-1", "Example Root CA", "key-B"))

	merged := Merge(a, b)
	comps := components(merged)

	// key-A and key-B collapse to one material; plus the certificate => 2.
	if len(comps) != 2 {
		t.Fatalf("expected 2 components (1 key + 1 cert), got %d", len(comps))
	}

	var cert *cdx.Component
	for i := range comps {
		if comps[i].CryptoProperties.AssetType == cdx.CryptoAssetTypeCertificate {
			cert = &comps[i]
		}
	}
	if cert == nil {
		t.Fatal("certificate not found in merged BOM")
	}
	if got := string(cert.CryptoProperties.CertificateProperties.SubjectPublicKeyRef); got != "key-A" {
		t.Errorf("cert SubjectPublicKeyRef = %q, want key-A (redirected from dropped key-B)", got)
	}
}

func TestMergeConcatenatesDependencies(t *testing.T) {
	a := cdx.NewBOM()
	a.Dependencies = &[]cdx.Dependency{{Ref: "x"}}
	b := cdx.NewBOM()
	b.Dependencies = &[]cdx.Dependency{{Ref: "y"}}

	merged := Merge(a, b)
	if merged.Dependencies == nil || len(*merged.Dependencies) != 2 {
		t.Fatalf("expected 2 dependencies, got %v", merged.Dependencies)
	}
}

func TestMergeIgnoresNilBOMs(t *testing.T) {
	merged := Merge(nil, bomOf(algo("crypto/rsa", "RSA-2048", "2048")), nil)
	if len(components(merged)) != 1 {
		t.Fatalf("expected 1 component from non-nil BOM, got %d", len(components(merged)))
	}
}

// TestMergeRealFixtures exercises Merge against two downloaded bom-examples so
// the dedup logic is validated on real CBOM shapes, not just synthetic ones.
func TestMergeRealFixtures(t *testing.T) {
	root := filepath.Join("..", "..", "bom-examples", "CBOM")
	algoBOM := loadFixture(t, filepath.Join(root, "Algorithm", "bom.json"))
	certBOM := loadFixture(t, filepath.Join(root, "Certificate", "bom.json"))

	nAlgo := len(components(algoBOM))
	nCert := len(components(certBOM))

	// Merging a BOM with itself must not increase the asset count (full dedup).
	self := Merge(algoBOM, cloneBOM(t, filepath.Join(root, "Algorithm", "bom.json")))
	if len(components(self)) != nAlgo {
		t.Errorf("self-merge inflated components: got %d, want %d", len(components(self)), nAlgo)
	}

	// Merging two different BOMs yields at most the sum (fewer if they overlap).
	both := Merge(algoBOM, certBOM)
	if got := len(components(both)); got > nAlgo+nCert {
		t.Errorf("cross-merge produced %d components, want <= %d", got, nAlgo+nCert)
	}
}

func loadFixture(t *testing.T, path string) *cdx.BOM {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Skipf("fixture %s unavailable: %v", path, err)
	}
	bom, err := decodeBOM(data)
	if err != nil {
		t.Fatalf("decode %s: %v", path, err)
	}
	return bom
}

// cloneBOM reloads a fixture from disk to get an independent copy (Merge mutates
// component slices in place, so we must not reuse the same struct).
func cloneBOM(t *testing.T, path string) *cdx.BOM {
	t.Helper()
	return loadFixture(t, path)
}
