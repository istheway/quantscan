// Command quantscan is the QuantScan CLI: it scans a CycloneDX CBOM,
// classifies each cryptographic asset by its resistance to a cryptographically
// relevant quantum computer, and emits an auditor-ready report (HTML, PDF, or
// machine-readable JSON) with NIST IR 8547 / CNSA 2.0 migration guidance.
package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	cdx "github.com/CycloneDX/cyclonedx-go"
	units "github.com/docker/go-units"
	"github.com/spf13/cobra"

	"github.com/neotechadmin/quantscan/internal/cbom"
	"github.com/neotechadmin/quantscan/internal/compliance"
	"github.com/neotechadmin/quantscan/internal/discover"
	"github.com/neotechadmin/quantscan/internal/report"
	"github.com/neotechadmin/quantscan/internal/scoring"
)

func main() {
	if err := rootCmd().Execute(); err != nil {
		fmt.Fprintln(os.Stderr, "quantscan:", err)
		os.Exit(1)
	}
}

// version is the CLI version, overridable at build time via
// -ldflags "-X main.version=v1.2.3".
var version = "dev"

// pipelineGroup groups the core discover/scan commands in the help listing.
const pipelineGroup = "pipeline"

func rootCmd() *cobra.Command {
	root := &cobra.Command{
		Use:     "quantscan",
		Version: version,
		Short:   "Post-quantum cryptography readiness auditor",
		Long: `QuantScan audits your cryptography for quantum readiness.

It runs as a pipeline: discover the cryptography in your code and
infrastructure, score every asset against the quantum threat (Shor/Grover),
and render an auditor-ready report mapped to NIST IR 8547 and CNSA 2.0.

  discover  ->  build a CBOM from directories, container images, and source code
  scan      ->  score a CBOM and render an HTML / PDF / JSON report

Commands compose over stdin (discover -o - streams the CBOM), so a one-shot audit is:

  quantscan discover --dir . -o - | quantscan scan -f pdf --org "Acme Corp" -o report.pdf -

CLASSIFICATIONS
  Quantum-broken     Broken by Shor's algorithm on a CRQC (RSA, ECC, DH, DSA)
  Quantum-weakened   Grover-weakened or deprecated (AES-128, SHA-256, MD5, DES)
  Quantum-ready      PQC or resistant at standard parameters (ML-KEM, ML-DSA, AES-256)
  Unknown            Family not recognized; manual review required

OUTPUT FORMATS (scan -f)
  html   Standalone branded HTML report
  pdf    Print-ready PDF via headless Chrome (needs a Chromium binary)
  json   Machine-readable summary for CI / dashboards

PREREQUISITES
  discover --dir           nothing external (cbomkit-theia is vendored, runs in-process)
  discover --image         a running Docker daemon (to pull/extract the image)
  discover --purl          a running CBOMkit service (--cbomkit-url)
  scan -f pdf              a Chromium/Chrome binary on PATH (or --chrome)

ENVIRONMENT
  DOCKER_HOST   Docker daemon used by cbomkit-theia for --image scans

EXIT CODES
  0   success (report written; readiness score at or above --fail-under)
  1   error, or readiness score below --fail-under`,
		Example: `  # Score an existing CBOM and print a JSON summary
  quantscan scan cbom.json -f json

  # Discover crypto in a container image, then render a branded PDF
  quantscan discover --image myapp:latest -o - | quantscan scan -f pdf --org "Acme Corp" -o report.pdf -

  # Full command/flag reference for a subcommand
  quantscan discover --help
  quantscan scan --help`,
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	root.AddGroup(&cobra.Group{ID: pipelineGroup, Title: "Pipeline Commands:"})

	scan := scanCmd()
	scan.GroupID = pipelineGroup
	discover := discoverCmd()
	discover.GroupID = pipelineGroup

	root.AddCommand(discover)
	root.AddCommand(scan)
	return root
}

func scanCmd() *cobra.Command {
	var (
		format    string
		out       string
		org       string
		chrome    string
		failUnder int
	)

	cmd := &cobra.Command{
		Use:   "scan <cbom.json | ->",
		Short: "Score a CBOM and render a quantum-readiness report",
		Long: `Score a CycloneDX CBOM and render a quantum-readiness report.

Each cryptographic asset is classified as Quantum-broken, Quantum-weakened,
Quantum-ready, or Unknown, and rolled up into a 0-100 readiness score with a
NIST IR 8547 / CNSA 2.0 migration roadmap.

Pass "-" as the path to read the CBOM from stdin (e.g. piped from ` + "`quantscan discover`" + `).

By default the report is saved to report-<YYYYMMDD-HHMMSS>.<format> in the same
directory as the CBOM. Use -o <file> for an explicit name, or -o - for stdout.`,
		Example: `  # Save a branded PDF to report-<timestamp>.pdf beside the CBOM
  quantscan scan cbom.json -f pdf --org "Acme Corp"

  # JSON summary to stdout
  quantscan scan cbom.json -f json -o -

  # CI gate: exit non-zero if readiness is below 80
  quantscan scan cbom.json -f json --fail-under 80 -o -

  # Read the CBOM from stdin, write the report to stdout
  quantscan discover --dir . -o - | quantscan scan -o - -`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			inv, err := loadInventory(args[0])
			if err != nil {
				return err
			}

			opts := report.Options{Org: org, GeneratedAt: time.Now(), ChromePath: chrome}

			var payload []byte
			switch format {
			case "json":
				payload, err = marshalJSON(inv)
			case "html":
				var s string
				s, err = report.RenderHTML(inv, opts)
				payload = []byte(s)
			case "pdf":
				payload, err = report.RenderPDF(inv, opts)
			default:
				return fmt.Errorf("unknown --format %q (want html, pdf, or json)", format)
			}
			if err != nil {
				return err
			}

			outPath := reportOutputPath(out, format, args[0])
			if err := write(outPath, payload); err != nil {
				return err
			}

			// Re-score once for the CI gate and human-readable summary; cheap
			// relative to rendering and keeps the exit-code logic explicit.
			rep := scoring.Score(inv)
			if outPath != "" {
				fmt.Fprintf(cmd.OutOrStdout(), "wrote %s (%d assets, score %d/100 — %s risk)\n",
					outPath, rep.Total, rep.Score, rep.RiskLabel)
			}
			if failUnder > 0 && rep.Score < failUnder {
				return fmt.Errorf("quantum-readiness score %d is below --fail-under threshold %d", rep.Score, failUnder)
			}
			return nil
		},
	}

	cmd.Flags().StringVarP(&format, "format", "f", "html", "output format: html, pdf, or json")
	cmd.Flags().StringVarP(&out, "out", "o", "", "output file, or \"-\" for stdout (default: report-<timestamp>.<format> beside the CBOM)")
	cmd.Flags().StringVar(&org, "org", "", "organization name for the report cover")
	cmd.Flags().StringVar(&chrome, "chrome", "", "path to chromium binary for PDF (default: auto-detect)")
	cmd.Flags().IntVar(&failUnder, "fail-under", 0, "exit non-zero if the readiness score is below this value (CI gate)")
	return cmd
}

// reportOutputPath decides where a scan report is written. An explicit --out
// wins ("-" means stdout); otherwise the report defaults to an auto-named,
// timestamped file (report-YYYYMMDD-HHMMSS.<format>) in the same directory as
// the input CBOM (the current directory when reading from stdin). An empty
// return means stdout.
func reportOutputPath(out, format, cbomPath string) string {
	if out == "-" {
		return ""
	}
	if out != "" {
		return out
	}
	name := "report-" + time.Now().Format("20060102-150405") + "." + format
	return filepath.Join(filepath.Dir(cbomPath), name)
}

// loadInventory loads a CBOM from a file, or from stdin when path is "-".
func loadInventory(path string) (*cbom.Inventory, error) {
	if path == "-" {
		return cbom.Load(os.Stdin)
	}
	return cbom.LoadFile(path)
}

func discoverCmd() *cobra.Command {
	var (
		dirs        []string
		images      []string
		purls       []string
		cbomkitURL  string
		ignore      []string
		skipPlugins []string
		out         string
		outDir      string
		maxFileSize string
	)

	cmd := &cobra.Command{
		Use:   "discover",
		Short: "Generate a CBOM from code and infrastructure via CBOMkit",
		Long: "Discover cryptographic assets by orchestrating the CBOMkit toolchain and\n" +
			"merge the results into a single CycloneDX CBOM.\n\n" +
			"  --dir/--image run the embedded cbomkit-theia over a directory or container image.\n" +
			"  --purl fetches a source-code CBOM from a running CBOMkit service (--cbomkit-url).\n\n" +
			"By default the CBOM is saved to a timestamped file, cbom-<YYYYMMDD-HHMMSS>.json, in the\n" +
			"current directory (or --out-dir). Use -o <file> for an explicit name, or -o - for stdout\n" +
			"to pipe into `quantscan scan -`.",
		Example: `  # Save to ./cbom-<timestamp>.json (default)
  quantscan discover --dir .

  # Save timestamped files into a chosen directory
  quantscan discover --dir . --image myapp:latest --out-dir ./cboms

  # Explicit filename
  quantscan discover --dir . -o cbom.json

  # Add a deep source-code scan from a running CBOMkit service
  quantscan discover --dir . --cbomkit-url http://localhost:8081 --purl pkg:github/myorg/myapp

  # One-shot: stream to a report without saving a file
  quantscan discover --dir . -o - | quantscan scan -f pdf --org "Acme Corp" -o report.pdf -`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			maxBytes, err := units.RAMInBytes(maxFileSize)
			if err != nil {
				return fmt.Errorf("invalid --max-file-size %q: %w", maxFileSize, err)
			}
			scanners, err := buildScanners(dirs, images, purls, cbomkitURL, ignore, skipPlugins, maxBytes)
			if err != nil {
				return err
			}
			if len(scanners) == 0 {
				return fmt.Errorf("no sources given; specify at least one of --dir, --image, or --purl")
			}

			boms := make([]*cdx.BOM, 0, len(scanners))
			for _, s := range scanners {
				fmt.Fprintf(cmd.ErrOrStderr(), "scanning %s ...\n", s.Name())
				b, err := s.Scan(cmd.Context())
				if err != nil {
					return fmt.Errorf("%s: %w", s.Name(), err)
				}
				boms = append(boms, b)
			}

			merged := discover.Merge(boms...)

			var buf []byte
			buf, err = encodeBOM(merged)
			if err != nil {
				return err
			}

			path, err := cbomOutputPath(out, outDir)
			if err != nil {
				return err
			}
			if err := write(path, buf); err != nil {
				return err
			}
			if path == "" { // stdout
				fmt.Fprintf(cmd.ErrOrStderr(), "discovered %d crypto assets from %d source(s)\n",
					componentCount(merged), len(scanners))
			} else {
				fmt.Fprintf(cmd.ErrOrStderr(), "wrote %s (%d crypto assets from %d source(s))\n",
					path, componentCount(merged), len(scanners))
			}
			return nil
		},
	}

	cmd.Flags().StringArrayVar(&dirs, "dir", nil, "directory to scan with cbomkit-theia (repeatable)")
	cmd.Flags().StringArrayVar(&images, "image", nil, "container image to scan with cbomkit-theia (repeatable)")
	cmd.Flags().StringArrayVar(&purls, "purl", nil, "package URL to fetch a source-code CBOM for (repeatable; needs --cbomkit-url)")
	cmd.Flags().StringVar(&cbomkitURL, "cbomkit-url", "", "base URL of a running CBOMkit service (e.g. http://localhost:8081)")
	cmd.Flags().StringArrayVar(&ignore, "ignore", nil, "glob pattern excluded from cbomkit-theia scans (repeatable)")
	cmd.Flags().StringSliceVar(&skipPlugins, "skip-plugins", nil,
		"cbomkit-theia plugins to skip for --dir/--image scans, e.g. --skip-plugins secrets (choices: "+strings.Join(discover.TheiaPlugins(), ", ")+")")
	cmd.Flags().StringVarP(&out, "out", "o", "", "explicit output file, or \"-\" for stdout (overrides --out-dir)")
	cmd.Flags().StringVar(&outDir, "out-dir", "", "directory to save the timestamped cbom-<ts>.json (default: current directory)")
	cmd.Flags().StringVar(&maxFileSize, "max-file-size", "1MB", "skip files larger than this during --dir/--image scans (e.g. 512KB, 10MB)")
	return cmd
}

// cbomOutputPath decides where a discovered CBOM is written. An explicit --out
// wins ("-" means stdout); otherwise the CBOM is saved to an auto-named,
// timestamped file (cbom-YYYYMMDD-HHMMSS.json) in --out-dir, or the current
// directory when --out-dir is empty. An empty return means stdout.
func cbomOutputPath(out, outDir string) (string, error) {
	if out == "-" {
		return "", nil
	}
	if out != "" {
		return out, nil
	}
	name := "cbom-" + time.Now().Format("20060102-150405") + ".json"
	if outDir == "" {
		return name, nil
	}
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		return "", fmt.Errorf("create --out-dir %q: %w", outDir, err)
	}
	return filepath.Join(outDir, name), nil
}

// buildScanners assembles the ordered list of scanners from the CLI flags,
// validating cross-flag requirements (a purl needs a CBOMkit service URL).
func buildScanners(dirs, images, purls []string, cbomkitURL string, ignore, skipPlugins []string, maxFileSize int64) ([]discover.Scanner, error) {
	var scanners []discover.Scanner
	for _, d := range dirs {
		scanners = append(scanners, &discover.TheiaScanner{
			Mode: discover.TheiaDir, Target: d, Ignore: ignore, MaxFileSize: maxFileSize, SkipPlugins: skipPlugins,
		})
	}
	for _, img := range images {
		scanners = append(scanners, &discover.TheiaScanner{
			Mode: discover.TheiaImage, Target: img, Ignore: ignore, MaxFileSize: maxFileSize, SkipPlugins: skipPlugins,
		})
	}
	if len(purls) > 0 {
		if cbomkitURL == "" {
			return nil, fmt.Errorf("--purl requires --cbomkit-url to reach a CBOMkit service")
		}
		client := &discover.CBOMkitClient{BaseURL: cbomkitURL}
		for _, p := range purls {
			scanners = append(scanners, client.NewScanner(discover.CBOMkitSource{PURL: p}))
		}
	}
	return scanners, nil
}

func encodeBOM(bom *cdx.BOM) ([]byte, error) {
	var buf bytes.Buffer
	enc := cdx.NewBOMEncoder(&buf, cdx.BOMFileFormatJSON)
	enc.SetPretty(true)
	if err := enc.Encode(bom); err != nil {
		return nil, fmt.Errorf("encode cbom: %w", err)
	}
	return buf.Bytes(), nil
}

func componentCount(bom *cdx.BOM) int {
	if bom.Components == nil {
		return 0
	}
	return len(*bom.Components)
}

// jsonReport is the machine-readable projection of a scored CBOM, suitable for
// CI pipelines and dashboards. It uses class names rather than the internal
// numeric Class so the output is stable and self-describing.
type jsonReport struct {
	Source    string         `json:"source"`
	Score     int            `json:"score"`
	RiskLabel string         `json:"riskLabel"`
	Total     int            `json:"total"`
	Counts    map[string]int `json:"counts"`
	Assets    []jsonAsset    `json:"assets"`
}

type jsonAsset struct {
	Name           string   `json:"name"`
	Family         string   `json:"family"`
	Params         string   `json:"params,omitempty"`
	Classification string   `json:"classification"`
	Reason         string   `json:"reason"`
	Action         string   `json:"action"`
	CNSA2Deadline  string   `json:"cnsa2Deadline"`
	Controls       []string `json:"controls,omitempty"`
	Locations      []string `json:"locations,omitempty"`
}

func marshalJSON(inv *cbom.Inventory) ([]byte, error) {
	rep := scoring.Score(inv)
	roadmap := compliance.BuildRoadmap(rep.Verdicts)

	jr := jsonReport{
		Source:    rep.Source,
		Score:     rep.Score,
		RiskLabel: rep.RiskLabel,
		Total:     rep.Total,
		Counts: map[string]int{
			scoring.ClassBroken.String():   rep.Counts[scoring.ClassBroken],
			scoring.ClassWeakened.String(): rep.Counts[scoring.ClassWeakened],
			scoring.ClassReady.String():    rep.Counts[scoring.ClassReady],
			scoring.ClassUnknown.String():  rep.Counts[scoring.ClassUnknown],
		},
	}
	for _, r := range roadmap {
		jr.Assets = append(jr.Assets, jsonAsset{
			Name:           r.Asset.Name,
			Family:         r.Asset.Family,
			Params:         r.Asset.Params,
			Classification: r.Class.String(),
			Reason:         r.Reason,
			Action:         r.Guidance.Action,
			CNSA2Deadline:  r.Guidance.CNSA2Deadline,
			Controls:       r.Guidance.Controls,
			Locations:      r.Asset.Locations,
		})
	}
	return json.MarshalIndent(jr, "", "  ")
}

func write(path string, data []byte) error {
	if path == "" {
		_, err := os.Stdout.Write(data)
		return err
	}
	return os.WriteFile(path, data, 0o644)
}
