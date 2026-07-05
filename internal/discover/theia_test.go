package discover

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/spf13/viper"
)

// sampleCBOM is a minimal CycloneDX CBOM shared by the discover tests.
const sampleCBOM = `{
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
        "algorithmProperties": { "primitive": "pke", "parameterSetIdentifier": "2048" }
      }
    }
  ]
}`

func TestTheiaScannerName(t *testing.T) {
	s := &TheiaScanner{Mode: TheiaImage, Target: "nginx:latest"}
	if got, want := s.Name(), "cbomkit-theia image:nginx:latest"; got != want {
		t.Errorf("Name() = %q, want %q", got, want)
	}
}

func TestTheiaScannerUnknownMode(t *testing.T) {
	s := &TheiaScanner{Mode: "bogus", Target: "."}
	if _, err := s.Scan(context.Background()); err == nil {
		t.Fatal("expected error for unknown mode, got nil")
	}
}

// TestTheiaScannerDirScan runs the vendored cbomkit-theia in-process against a
// directory holding a real certificate and asserts it is discovered. This
// exercises the full in-process path (no external binary).
func TestTheiaScannerDirScan(t *testing.T) {
	dir := t.TempDir()
	writeSelfSignedCert(t, filepath.Join(dir, "server.pem"))

	s := &TheiaScanner{Mode: TheiaDir, Target: dir}
	bom, err := s.Scan(context.Background())
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if bom.Components == nil || len(*bom.Components) == 0 {
		t.Fatal("expected the certificate to be discovered, got no components")
	}

	var sawCert bool
	for _, c := range *bom.Components {
		if c.CryptoProperties != nil && c.CryptoProperties.AssetType == "certificate" {
			sawCert = true
		}
	}
	if !sawCert {
		t.Errorf("expected a certificate asset among %d components", len(*bom.Components))
	}
}

// TestTheiaScannerMaxFileSize confirms a small MaxFileSize makes theia skip a
// file it would otherwise scan. It restores the global viper key afterwards so
// it does not leak into other in-process scans.
func TestTheiaScannerMaxFileSize(t *testing.T) {
	prev := viper.GetInt64("keys.max_file_size")
	defer viper.Set("keys.max_file_size", prev)

	dir := t.TempDir()
	writeSelfSignedCert(t, filepath.Join(dir, "server.pem")) // ~600 bytes

	s := &TheiaScanner{Mode: TheiaDir, Target: dir, MaxFileSize: 64}
	bom, err := s.Scan(context.Background())
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}

	if bom.Components != nil {
		for _, c := range *bom.Components {
			if c.CryptoProperties != nil && c.CryptoProperties.AssetType == "certificate" {
				t.Fatalf("certificate should have been skipped at a 64-byte limit")
			}
		}
	}
}

// TestTheiaScannerSkipPlugins confirms --skip-plugins removes a plugin from the
// scan: skipping "certificates" makes theia miss a certificate it otherwise
// finds (see TestTheiaScannerDirScan). It restores the global viper "plugins"
// key afterwards so it does not leak into other in-process scans.
func TestTheiaScannerSkipPlugins(t *testing.T) {
	prev := viper.GetStringSlice("plugins")
	defer viper.Set("plugins", prev)

	dir := t.TempDir()
	writeSelfSignedCert(t, filepath.Join(dir, "server.pem"))

	s := &TheiaScanner{Mode: TheiaDir, Target: dir, SkipPlugins: []string{"certificates"}}
	bom, err := s.Scan(context.Background())
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if bom.Components != nil {
		for _, c := range *bom.Components {
			if c.CryptoProperties != nil && c.CryptoProperties.AssetType == "certificate" {
				t.Fatal("certificate should have been skipped with certificates plugin disabled")
			}
		}
	}
}

// TestSelectedPlugins covers the plugin-filtering logic that backs
// --skip-plugins: no skips means no filtering, a valid skip drops exactly that
// plugin, and an unknown name is rejected.
func TestSelectedPlugins(t *testing.T) {
	t.Run("empty skip returns nil (no filtering)", func(t *testing.T) {
		got, err := (&TheiaScanner{}).selectedPlugins()
		if err != nil {
			t.Fatalf("selectedPlugins: %v", err)
		}
		if got != nil {
			t.Errorf("expected nil, got %v", got)
		}
	})

	t.Run("valid skip drops only that plugin", func(t *testing.T) {
		got, err := (&TheiaScanner{SkipPlugins: []string{"secrets"}}).selectedPlugins()
		if err != nil {
			t.Fatalf("selectedPlugins: %v", err)
		}
		if len(got) != len(TheiaPlugins())-1 {
			t.Fatalf("expected %d plugins, got %d: %v", len(TheiaPlugins())-1, len(got), got)
		}
		for _, name := range got {
			if name == "secrets" {
				t.Errorf("secrets should have been filtered out, got %v", got)
			}
		}
	})

	t.Run("unknown plugin is rejected", func(t *testing.T) {
		if _, err := (&TheiaScanner{SkipPlugins: []string{"bogus"}}).selectedPlugins(); err == nil {
			t.Error("expected error for unknown plugin, got nil")
		}
	})
}

// writeSelfSignedCert generates an ECDSA self-signed certificate and writes it
// as PEM to path.
func writeSelfSignedCert(t *testing.T, path string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "quantscan.test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	if err := os.WriteFile(path, pemBytes, 0o644); err != nil {
		t.Fatalf("write cert: %v", err)
	}
}
