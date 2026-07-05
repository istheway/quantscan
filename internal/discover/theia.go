package discover

import (
	"bytes"
	"context"
	"fmt"
	"sync"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/cbomkit/cbomkit-theia/provider/docker"
	"github.com/cbomkit/cbomkit-theia/provider/filesystem"
	theia "github.com/cbomkit/cbomkit-theia/scanner"
	"github.com/spf13/viper"
)

// TheiaMode selects what cbomkit-theia scans.
type TheiaMode string

const (
	// TheiaDir scans a local directory (source tree or unpacked filesystem).
	TheiaDir TheiaMode = "dir"
	// TheiaImage scans a container image reference.
	TheiaImage TheiaMode = "image"
)

// cbomkit-theia is vendored and run in-process rather than shelled out to, so
// the binary is not a runtime prerequisite. It is driven through uber/dig and
// spf13/viper globals internally; RunScan reads its plugin list from viper, so
// we seed sensible defaults once before the first scan.
var theiaInit sync.Once

func initTheia() {
	theiaInit.Do(func() {
		viper.SetDefault("docker_host", "unix:///var/run/docker.sock")
		viper.SetDefault("plugins", theia.GetAllPluginNames())
	})
}

// TheiaScanner runs cbomkit-theia in-process against a directory or container
// image and returns the CycloneDX CBOM it produces.
type TheiaScanner struct {
	Mode        TheiaMode // dir or image
	Target      string    // directory path or image reference
	Ignore      []string  // glob patterns excluded from the scan
	MaxFileSize int64     // per-file scan limit in bytes; 0 keeps theia's default (1 MiB)
}

// Name implements Scanner.
func (t *TheiaScanner) Name() string {
	return fmt.Sprintf("cbomkit-theia %s:%s", t.Mode, t.Target)
}

// Scan builds a filesystem view of the target and runs theia's plugin scan.
func (t *TheiaScanner) Scan(ctx context.Context) (*cdx.BOM, error) {
	initTheia()

	// theia's certificate and secrets plugins skip files larger than the
	// keys.max_file_size viper key (default 1 MiB when unset/<=0).
	if t.MaxFileSize > 0 {
		viper.Set("keys.max_file_size", t.MaxFileSize)
	}

	fs, cleanup, err := t.filesystem()
	if err != nil {
		return nil, err
	}
	if cleanup != nil {
		defer cleanup()
	}

	var buf bytes.Buffer
	if err := theia.RunScan(theia.ParameterStruct{Fs: fs, Target: &buf}); err != nil {
		return nil, fmt.Errorf("cbomkit-theia %s scan of %q: %w", t.Mode, t.Target, err)
	}
	return decodeBOM(buf.Bytes())
}

// filesystem constructs the theia filesystem view for the scanner's mode. The
// returned cleanup (may be nil) tears down any pulled/extracted image.
func (t *TheiaScanner) filesystem() (filesystem.Filesystem, func(), error) {
	switch t.Mode {
	case TheiaDir:
		plain := filesystem.NewPlainFilesystem(t.Target)
		patterns := filesystem.LoadIgnorePatterns(t.Target, nil, t.Ignore)
		return filesystem.NewFilteredFilesystem(plain, patterns), nil, nil

	case TheiaImage:
		image, err := docker.GetImage(t.Target)
		if err != nil {
			return nil, nil, fmt.Errorf("cbomkit-theia: fetch image %q: %w", t.Target, err)
		}
		inner := docker.GetSquashedFilesystem(image)
		patterns := filesystem.LoadIgnorePatterns("", nil, t.Ignore)
		return filesystem.NewFilteredFilesystem(inner, patterns), image.TearDown, nil

	default:
		return nil, nil, fmt.Errorf("cbomkit-theia: unknown mode %q", t.Mode)
	}
}

// decodeBOM parses CycloneDX JSON produced by a backend scanner.
func decodeBOM(data []byte) (*cdx.BOM, error) {
	bom := cdx.NewBOM()
	if err := cdx.NewBOMDecoder(bytes.NewReader(data), cdx.BOMFileFormatJSON).Decode(bom); err != nil {
		return nil, fmt.Errorf("decode cbom: %w", err)
	}
	return bom, nil
}
