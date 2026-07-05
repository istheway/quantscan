package cbom

import (
	"strings"
	"testing"
)

func TestNormalizeFamily(t *testing.T) {
	tests := []struct {
		in, want string
	}{
		{"RSA-2048", "RSA"},
		{"rsa", "RSA"},
		{"ECDSA-P256", "ECC"},
		{"ECDH", "ECC"},
		{"Ed25519", "ECC"},
		{"X25519", "ECC"},
		{"EC", "ECC"},
		{"Diffie-Hellman", "DH"},
		{"DH", "DH"},
		{"DSA", "DSA"},
		{"AES-256-GCM", "AES"},
		{"3DES", "DES"},
		{"DES", "DES"},
		{"SHA-256", "SHA"},
		{"SHA3-512", "SHA3"},
		{"MD5", "MD5"},
		{"ChaCha20-Poly1305", "CHACHA20"},
		{"Kyber768", "ML-KEM"},
		{"ML-KEM-768", "ML-KEM"},
		{"Dilithium3", "ML-DSA"},
		{"ML-DSA-65", "ML-DSA"},
		{"SPHINCS+", "SLH-DSA"},
		{"Falcon-512", "FN-DSA"},
		{"", "UNKNOWN"},
		{"Blowfish", "BLOWFISH"},
	}
	for _, tt := range tests {
		if got := normalizeFamily(tt.in); got != tt.want {
			t.Errorf("normalizeFamily(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

func TestLoadFlattensCryptoAssets(t *testing.T) {
	const doc = `{
	  "bomFormat": "CycloneDX",
	  "specVersion": "1.6",
	  "version": 1,
	  "components": [
	    {
	      "type": "cryptographic-asset",
	      "bom-ref": "crypto/rsa-2048",
	      "name": "RSA-2048",
	      "cryptoProperties": {
	        "assetType": "algorithm",
	        "algorithmProperties": {
	          "primitive": "pke",
	          "parameterSetIdentifier": "2048",
	          "classicalSecurityLevel": 112
	        }
	      },
	      "evidence": { "occurrences": [ { "location": "src/tls.go:10" } ] }
	    },
	    {
	      "type": "library",
	      "name": "openssl",
	      "version": "3.0.0"
	    }
	  ]
	}`

	inv, err := Load(strings.NewReader(doc))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	// The library component must be ignored; only the crypto asset remains.
	if len(inv.Assets) != 1 {
		t.Fatalf("len(Assets) = %d, want 1", len(inv.Assets))
	}
	a := inv.Assets[0]
	if a.Family != "RSA" {
		t.Errorf("Family = %q, want RSA", a.Family)
	}
	if a.Primitive != "pke" {
		t.Errorf("Primitive = %q, want pke", a.Primitive)
	}
	if a.Params != "2048" {
		t.Errorf("Params = %q, want 2048", a.Params)
	}
	if a.ClassicalBits != 112 {
		t.Errorf("ClassicalBits = %d, want 112", a.ClassicalBits)
	}
	if len(a.Locations) != 1 || a.Locations[0] != "src/tls.go:10" {
		t.Errorf("Locations = %v, want [src/tls.go:10]", a.Locations)
	}
}

func TestLoadCertificateFields(t *testing.T) {
	const doc = `{
	  "bomFormat": "CycloneDX",
	  "specVersion": "1.6",
	  "version": 1,
	  "components": [
	    {
	      "type": "cryptographic-asset",
	      "bom-ref": "crypto/leaf-cert",
	      "name": "example.com TLS cert",
	      "cryptoProperties": {
	        "assetType": "certificate",
	        "certificateProperties": {
	          "subjectName": "CN=example.com",
	          "issuerName": "CN=Example CA",
	          "notValidAfter": "2027-01-01T00:00:00Z"
	        }
	      }
	    }
	  ]
	}`

	inv, err := Load(strings.NewReader(doc))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(inv.Assets) != 1 {
		t.Fatalf("len(Assets) = %d, want 1", len(inv.Assets))
	}
	a := inv.Assets[0]
	if a.Type != AssetCertificate {
		t.Errorf("Type = %q, want certificate", a.Type)
	}
	if a.Subject != "CN=example.com" || a.Issuer != "CN=Example CA" {
		t.Errorf("subject/issuer = %q / %q", a.Subject, a.Issuer)
	}
	if a.NotAfter != "2027-01-01T00:00:00Z" {
		t.Errorf("NotAfter = %q", a.NotAfter)
	}
}

func TestLoadCertificateResolvesKeyAlgorithm(t *testing.T) {
	// A certificate names its subject (a CA), not an algorithm; its cryptography
	// is reached via subjectPublicKeyRef -> public-key material -> family.
	const doc = `{
	  "bomFormat": "CycloneDX",
	  "specVersion": "1.6",
	  "version": 1,
	  "components": [
	    {
	      "type": "cryptographic-asset",
	      "bom-ref": "cert-1",
	      "name": "Buypass Class 3 Root CA",
	      "cryptoProperties": {
	        "assetType": "certificate",
	        "certificateProperties": {
	          "subjectName": "Buypass Class 3 Root CA",
	          "subjectPublicKeyRef": "key-1",
	          "signatureAlgorithmRef": "sig-1"
	        }
	      }
	    },
	    {
	      "type": "cryptographic-asset",
	      "bom-ref": "key-1",
	      "name": "RSA-4096",
	      "cryptoProperties": {
	        "assetType": "related-crypto-material",
	        "relatedCryptoMaterialProperties": { "type": "public-key", "algorithmRef": "sig-1" }
	      }
	    },
	    {
	      "type": "cryptographic-asset",
	      "bom-ref": "sig-1",
	      "name": "RSA",
	      "cryptoProperties": { "assetType": "algorithm", "algorithmProperties": { "primitive": "signature" } }
	    }
	  ]
	}`

	inv, err := Load(strings.NewReader(doc))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	var cert *Asset
	for i := range inv.Assets {
		if inv.Assets[i].Type == AssetCertificate {
			cert = &inv.Assets[i]
		}
	}
	if cert == nil {
		t.Fatal("certificate asset not found")
	}
	if cert.Family != "RSA" {
		t.Errorf("certificate Family = %q, want RSA (resolved from subject public key)", cert.Family)
	}
	if cert.Subject != "Buypass Class 3 Root CA" {
		t.Errorf("certificate Subject = %q", cert.Subject)
	}
}

func TestLoadCertificateFallsBackToSignatureAlgorithm(t *testing.T) {
	// No resolvable public key; family must come from signatureAlgorithmRef.
	const doc = `{
	  "bomFormat": "CycloneDX", "specVersion": "1.6", "version": 1,
	  "components": [
	    {
	      "type": "cryptographic-asset", "bom-ref": "cert-1", "name": "Some ECC Root CA",
	      "cryptoProperties": {
	        "assetType": "certificate",
	        "certificateProperties": { "subjectName": "Some ECC Root CA", "signatureAlgorithmRef": "sig-1" }
	      }
	    },
	    {
	      "type": "cryptographic-asset", "bom-ref": "sig-1", "name": "ECDSA",
	      "cryptoProperties": { "assetType": "algorithm", "algorithmProperties": { "primitive": "signature" } }
	    }
	  ]
	}`
	inv, err := Load(strings.NewReader(doc))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if inv.Assets[0].Family != "ECC" {
		t.Errorf("certificate Family = %q, want ECC (from signature algorithm)", inv.Assets[0].Family)
	}
}

func TestLoadCertificateWithoutResolvableRefsStaysUnknown(t *testing.T) {
	const doc = `{
	  "bomFormat": "CycloneDX", "specVersion": "1.6", "version": 1,
	  "components": [
	    {
	      "type": "cryptographic-asset", "bom-ref": "cert-1", "name": "Mystery CA",
	      "cryptoProperties": {
	        "assetType": "certificate",
	        "certificateProperties": { "subjectName": "Mystery CA", "subjectPublicKeyRef": "missing" }
	      }
	    }
	  ]
	}`
	inv, err := Load(strings.NewReader(doc))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	// Family stays the normalized subject name (unrecognized), never panics.
	if inv.Assets[0].Family == "RSA" {
		t.Errorf("did not expect a resolved family for a dangling ref, got %q", inv.Assets[0].Family)
	}
}

func TestLoadEmptyBOM(t *testing.T) {
	inv, err := Load(strings.NewReader(`{"bomFormat":"CycloneDX","specVersion":"1.6","version":1}`))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(inv.Assets) != 0 {
		t.Errorf("expected no assets, got %d", len(inv.Assets))
	}
}

func TestLoadInvalidJSON(t *testing.T) {
	if _, err := Load(strings.NewReader("not json")); err == nil {
		t.Fatal("expected error decoding invalid JSON, got nil")
	}
}
