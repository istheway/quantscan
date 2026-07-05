// Package report renders a scored CBOM into an auditor-ready HTML document and
// converts it to PDF via headless Chrome (chromedp). Keeping the HTML template
// as the single source of truth lets us match branded layout fidelity that
// native Go PDF libraries cannot, while staying in one language.
package report

import (
	"bytes"
	"context"
	"embed"
	"fmt"
	"html/template"
	"strings"
	"time"

	"github.com/chromedp/cdproto/page"
	"github.com/chromedp/chromedp"

	"github.com/neotechadmin/quantscan/internal/cbom"
	"github.com/neotechadmin/quantscan/internal/compliance"
	"github.com/neotechadmin/quantscan/internal/scoring"
)

//go:embed templates/report.html.tmpl
var templatesFS embed.FS

var tmpl = template.Must(template.ParseFS(templatesFS, "templates/report.html.tmpl"))

// view is the flattened template model.
type view struct {
	Org, Source, GeneratedAt         string
	Score                            int
	RiskLabel                        string
	Total                            int
	Broken, Weakened, Ready, Unknown int
	Rows                             []row
	Controls                         []controlRow
}

type row struct {
	Name, Family, Params, ClassName string
	Action, Reason, Deadline        string
	Locations                       []string
}

type controlRow struct {
	Family, Controls, Status string
}

// Options controls report generation.
type Options struct {
	Org         string
	GeneratedAt time.Time // injected for reproducibility in tests
	ChromePath  string    // override chromium binary; empty = auto-detect
}

func buildView(rep *scoring.Report, roadmap []compliance.Roadmap, opts Options) view {
	v := view{
		Org:         orDefault(opts.Org, "Client Organization"),
		Source:      rep.Source,
		GeneratedAt: opts.GeneratedAt.UTC().Format("2006-01-02 15:04 MST"),
		Score:       rep.Score,
		RiskLabel:   rep.RiskLabel,
		Total:       rep.Total,
		Broken:      rep.Counts[scoring.ClassBroken],
		Weakened:    rep.Counts[scoring.ClassWeakened],
		Ready:       rep.Counts[scoring.ClassReady],
		Unknown:     rep.Counts[scoring.ClassUnknown],
	}
	seen := map[string]bool{}
	for _, r := range roadmap {
		v.Rows = append(v.Rows, row{
			Name:      r.Asset.Name,
			Family:    r.Asset.Family,
			Params:    r.Asset.Params,
			ClassName: r.Class.String(),
			Action:    r.Guidance.Action,
			Reason:    r.Reason,
			Deadline:  r.Guidance.CNSA2Deadline,
			Locations: r.Asset.Locations,
		})
		if !seen[r.Guidance.Family] {
			seen[r.Guidance.Family] = true
			v.Controls = append(v.Controls, controlRow{
				Family:   r.Guidance.Family,
				Controls: strings.Join(r.Guidance.Controls, ", "),
				Status:   r.Guidance.Status,
			})
		}
	}
	return v
}

// RenderHTML produces the report as a standalone HTML document.
func RenderHTML(inv *cbom.Inventory, opts Options) (string, error) {
	if opts.GeneratedAt.IsZero() {
		return "", fmt.Errorf("report: GeneratedAt must be set")
	}
	rep := scoring.Score(inv)
	roadmap := compliance.BuildRoadmap(rep.Verdicts)
	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, buildView(rep, roadmap, opts)); err != nil {
		return "", fmt.Errorf("render html: %w", err)
	}
	return buf.String(), nil
}

// RenderPDF renders the report and prints it to PDF bytes via headless Chrome.
func RenderPDF(inv *cbom.Inventory, opts Options) ([]byte, error) {
	html, err := RenderHTML(inv, opts)
	if err != nil {
		return nil, err
	}
	return htmlToPDF(html, opts.ChromePath)
}

func htmlToPDF(html, chromePath string) ([]byte, error) {
	allocOpts := append([]chromedp.ExecAllocatorOption{},
		chromedp.Headless,
		chromedp.NoSandbox, // required when running as root / in containers
		chromedp.DisableGPU,
	)
	if chromePath != "" {
		allocOpts = append(allocOpts, chromedp.ExecPath(chromePath))
	}

	allocCtx, cancelAlloc := chromedp.NewExecAllocator(context.Background(), allocOpts...)
	defer cancelAlloc()
	ctx, cancel := chromedp.NewContext(allocCtx)
	defer cancel()
	ctx, cancelTimeout := context.WithTimeout(ctx, 60*time.Second)
	defer cancelTimeout()

	var pdf []byte
	err := chromedp.Run(ctx,
		chromedp.Navigate("about:blank"),
		chromedp.ActionFunc(func(ctx context.Context) error {
			frameTree, err := page.GetFrameTree().Do(ctx)
			if err != nil {
				return err
			}
			return page.SetDocumentContent(frameTree.Frame.ID, html).Do(ctx)
		}),
		chromedp.ActionFunc(func(ctx context.Context) error {
			buf, _, err := page.PrintToPDF().
				WithPrintBackground(true).
				WithPreferCSSPageSize(true).
				Do(ctx)
			pdf = buf
			return err
		}),
	)
	if err != nil {
		return nil, fmt.Errorf("chromedp print to pdf: %w", err)
	}
	return pdf, nil
}

func orDefault(s, def string) string {
	if strings.TrimSpace(s) == "" {
		return def
	}
	return s
}
