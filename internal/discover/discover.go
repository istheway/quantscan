// Package discover generates a CycloneDX 1.6 CBOM from real code and
// infrastructure by orchestrating the CBOMkit toolchain: cbomkit-theia for
// filesystem, container-image, and configuration crypto assets, and a CBOMkit
// service for deep source-code static analysis. Each backend already emits a
// CycloneDX CBOM, so this package's job is to run them and merge their output
// into a single document that the cbom/scoring/report pipeline consumes.
package discover

import (
	"context"
	"strings"

	cdx "github.com/CycloneDX/cyclonedx-go"
)

// Scanner produces a CycloneDX CBOM from a single source (a directory, a
// container image, or a source-code repository).
type Scanner interface {
	// Name is a short human label used in progress and error messages.
	Name() string
	// Scan runs the backend and returns the parsed CBOM.
	Scan(ctx context.Context) (*cdx.BOM, error)
}

// Merge combines several CBOMs into one, de-duplicating cryptographic assets.
//
// Two scanners (e.g. a source-code scan and a filesystem scan) frequently
// report the same algorithm, so a naive concatenation would inflate the asset
// count and skew the readiness score. Assets are considered the same when they
// share a bom-ref, or failing that when they share an identity of
// (assetType | name | parameterSetIdentifier). When assets collide, their
// evidence occurrences (source locations) are unioned so no provenance is lost.
func Merge(boms ...*cdx.BOM) *cdx.BOM {
	out := cdx.NewBOM()
	var components []cdx.Component
	var dependencies []cdx.Dependency

	byRef := map[string]int{}      // bom-ref -> index into components
	byIdentity := map[string]int{} // identity key -> index into components
	remap := map[string]string{}   // dropped duplicate bom-ref -> kept bom-ref

	for _, b := range boms {
		if b == nil {
			continue
		}
		if b.Components != nil {
			for _, c := range *b.Components {
				if idx, ok := existingIndex(c, byRef, byIdentity); ok {
					kept := components[idx]
					// The duplicate is discarded, so any reference to it (e.g. a
					// certificate's subjectPublicKeyRef) must be redirected to the
					// component we keep, or it would dangle.
					if c.BOMRef != "" && kept.BOMRef != "" && c.BOMRef != kept.BOMRef {
						remap[c.BOMRef] = kept.BOMRef
					}
					components[idx] = mergeComponent(kept, c)
					continue
				}
				components = append(components, c)
				idx := len(components) - 1
				if c.BOMRef != "" {
					byRef[c.BOMRef] = idx
				}
				if key := identityKey(c); key != "" {
					byIdentity[key] = idx
				}
			}
		}
		if b.Dependencies != nil {
			dependencies = append(dependencies, *b.Dependencies...)
		}
	}

	if len(remap) > 0 {
		for i := range components {
			rewriteRefs(&components[i], remap)
		}
	}

	if len(components) > 0 {
		out.Components = &components
	}
	if len(dependencies) > 0 {
		out.Dependencies = &dependencies
	}
	return out
}

// existingIndex reports whether an equivalent component is already present,
// matching first by bom-ref and then by identity.
func existingIndex(c cdx.Component, byRef, byIdentity map[string]int) (int, bool) {
	if c.BOMRef != "" {
		if idx, ok := byRef[c.BOMRef]; ok {
			return idx, true
		}
	}
	if key := identityKey(c); key != "" {
		if idx, ok := byIdentity[key]; ok {
			return idx, true
		}
	}
	return 0, false
}

// identityKey derives a content identity for a cryptographic asset so the same
// algorithm found by different scanners collapses to one entry. Non-crypto
// components have no identity key and are never merged by identity.
func identityKey(c cdx.Component) string {
	if c.CryptoProperties == nil {
		return ""
	}
	cp := c.CryptoProperties
	params := ""
	if cp.AlgorithmProperties != nil {
		params = cp.AlgorithmProperties.ParameterSetIdentifier
	}
	return strings.Join([]string{
		string(cp.AssetType),
		strings.ToUpper(strings.TrimSpace(c.Name)),
		strings.TrimSpace(params),
	}, "|")
}

// mergeComponent folds src into dst, currently unioning evidence occurrences.
// dst keeps its own bom-ref and properties; only provenance is accumulated.
func mergeComponent(dst, src cdx.Component) cdx.Component {
	srcOcc := occurrences(src)
	if len(srcOcc) == 0 {
		return dst
	}
	existing := map[string]bool{}
	merged := occurrences(dst)
	for _, o := range merged {
		existing[o.Location] = true
	}
	for _, o := range srcOcc {
		if o.Location != "" && existing[o.Location] {
			continue
		}
		existing[o.Location] = true
		merged = append(merged, o)
	}
	if dst.Evidence == nil {
		dst.Evidence = &cdx.Evidence{}
	}
	dst.Evidence.Occurrences = &merged
	return dst
}

func occurrences(c cdx.Component) []cdx.EvidenceOccurrence {
	if c.Evidence == nil || c.Evidence.Occurrences == nil {
		return nil
	}
	return *c.Evidence.Occurrences
}

// rewriteRefs redirects a component's cryptographic references through remap so
// they point at the kept component after de-duplication rather than a dropped
// duplicate. It covers the certificate → key/signature and material → algorithm
// links that the scoring pipeline follows.
func rewriteRefs(c *cdx.Component, remap map[string]string) {
	if c.CryptoProperties == nil {
		return
	}
	cp := c.CryptoProperties
	if cert := cp.CertificateProperties; cert != nil {
		cert.SubjectPublicKeyRef = cdx.BOMReference(resolveRemap(string(cert.SubjectPublicKeyRef), remap))
		cert.SignatureAlgorithmRef = cdx.BOMReference(resolveRemap(string(cert.SignatureAlgorithmRef), remap))
	}
	if m := cp.RelatedCryptoMaterialProperties; m != nil {
		m.AlgorithmRef = cdx.BOMReference(resolveRemap(string(m.AlgorithmRef), remap))
	}
}

// resolveRemap follows a chain of remapped refs to its final target, returning
// the input unchanged when it was never remapped. The bound guards cycles.
func resolveRemap(ref string, remap map[string]string) string {
	for i := 0; ref != "" && i < 16; i++ {
		next, ok := remap[ref]
		if !ok || next == ref {
			break
		}
		ref = next
	}
	return ref
}
