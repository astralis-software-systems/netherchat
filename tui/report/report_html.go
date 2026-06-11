package report

import (
	"fmt"
	"strings"

	"github.com/salehkreiner/netherchat/tui/record"
)

// verifyCmd is the command the footer (and its QR) tell a reader to run.
const verifyCmd = "netherchat verify record.json"

// css is the entire stylesheet, inlined — no @font-face, no CDN, no external fetch
// (§2.6). Space Grotesk is requested but falls back to the system sans stack.
const css = `
:root{--bg:#0a0a12;--panel:#14141f;--accent:#7c3aed;--soft:#a78bfa;--text:#e2e0f0;--muted:#7c6fa0;--ok:#4ade80;--bad:#f87171}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--text);font-family:'Space Grotesk',system-ui,-apple-system,Segoe UI,Roboto,sans-serif;line-height:1.5}
code,.fpr,.hash code{font-family:'JetBrains Mono',ui-monospace,Menlo,Consolas,monospace}
.wrap{max-width:860px;margin:0 auto;padding:32px 20px}
header h1{margin:0 0 8px;font-size:1.7rem;color:#fff}
.meta{display:flex;flex-wrap:wrap;gap:16px;color:var(--muted);font-size:.9rem}
.meta b{color:var(--soft)}
.chain{margin:20px 0;padding:12px 16px;border-left:4px solid var(--ok);background:var(--panel);border-radius:6px}
.chain .sym{font-weight:700;margin-right:6px}
details.exec{margin:16px 0;background:var(--panel);border-radius:8px;padding:6px 16px}
details.exec summary{cursor:pointer;color:var(--soft);font-weight:600;padding:8px 0}
.execbody h3{color:var(--soft);margin:14px 0 4px;font-size:1rem}
.execbody ul{margin:4px 0 8px;padding-left:20px}
.exectimeline{list-style:none;padding-left:0}
.exectimeline .ts{color:var(--muted);font-family:'JetBrains Mono',monospace;font-size:.85rem;margin-right:6px}
.resolution{color:var(--muted)}
h2{color:#fff;font-size:1.25rem;border-bottom:1px solid #262633;padding-bottom:6px;margin-top:28px}
ol.timeline{list-style:none;padding:0;margin:0}
ol.timeline li{display:flex;gap:12px;padding:12px 0;border-bottom:1px solid #1c1c28}
ol.timeline .icon{font-size:1.1rem}
ol.timeline .row{display:flex;gap:10px;align-items:baseline;flex-wrap:wrap}
ol.timeline .ts{color:var(--muted);font-family:'JetBrains Mono',monospace;font-size:.82rem}
ol.timeline .who{color:var(--soft);font-weight:600}
ol.timeline .body{margin-top:2px}
li.decision .body{color:#fff}
li.action .body{color:var(--soft)}
.ok{color:var(--ok);font-size:.82rem}
.bad{color:var(--bad);font-size:.82rem}
table{width:100%;border-collapse:collapse;margin-top:8px;font-size:.9rem}
th,td{text-align:left;padding:8px 10px;border-bottom:1px solid #1c1c28}
th{color:var(--muted);font-weight:600}
.fpr{color:var(--soft);word-break:break-all}
footer{margin-top:32px;padding-top:20px;border-top:1px solid #262633;display:flex;justify-content:space-between;gap:20px;align-items:center;flex-wrap:wrap}
footer code{color:var(--soft);background:var(--panel);padding:2px 6px;border-radius:4px}
.hash{color:var(--muted);font-size:.82rem;margin-top:6px;word-break:break-all}
.qr{background:#fff;padding:6px;border-radius:6px;line-height:0}
`

// RenderHTML renders a sealed record as a standalone HTML timeline (§2.6). With
// opts.Executive it renders ONLY the executive summary (decisions/actions/timeline,
// no fingerprints, hashes, or notes); otherwise it renders the full report with the
// executive summary collapsed in a <details> and the verification status shown.
func RenderHTML(rec *record.SealedRecord, res *record.VerifyResult, opts Options) string {
	var b strings.Builder
	b.WriteString("<!DOCTYPE html>\n<html lang=\"en\"><head>\n<meta charset=\"utf-8\">\n")
	b.WriteString("<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n")
	b.WriteString("<title>" + esc(opts.title(rec.Room)) + "</title>\n")
	b.WriteString("<style>" + css + "</style>\n</head><body>\n<main class=\"wrap\">\n")

	b.WriteString(`<header><h1>` + esc(opts.title(rec.Room)) + `</h1><div class="meta">`)
	b.WriteString(`<span>room <b>#` + esc(rec.Room) + `</b></span>`)
	b.WriteString(`<span>sealed <b>` + esc(rec.SealedAt) + `</b></span>`)
	b.WriteString(fmt.Sprintf(`<span>participants <b>%d</b></span>`, len(rec.Signatures)))
	if !opts.Executive {
		b.WriteString(fmt.Sprintf(`<span>entries <b>%d</b></span>`, len(rec.Entries)))
	}
	b.WriteString(`</div></header>` + "\n")

	if opts.Executive {
		b.WriteString(executiveSection(rec))
		b.WriteString(footerHTML(rec, true))
		b.WriteString("</main></body></html>\n")
		return b.String()
	}

	sym, text, col := chainStatus(res)
	b.WriteString(fmt.Sprintf(`<div class="chain" style="border-color:%s"><span class="sym" style="color:%s">%s</span> hash chain %s</div>`+"\n", col, col, sym, esc(text)))

	b.WriteString(`<details class="exec"><summary>Executive summary</summary>` + executiveSection(rec) + `</details>` + "\n")

	b.WriteString(`<section><h2>Timeline</h2><ol class="timeline">` + "\n")
	for _, e := range rec.Entries {
		body := esc(e.Body)
		if e.Kind == record.KindAction && e.Actionee != "" {
			body = `<b>@` + esc(e.Actionee) + `</b>: ` + body
		}
		badge := `<span class="bad">✗ unverified</span>`
		if res.Valid {
			badge = `<span class="ok">✓ signed</span>`
		}
		b.WriteString(fmt.Sprintf(
			`<li class="%s"><span class="icon">%s</span><div><div class="row"><span class="ts">%s</span><span class="who">%s</span>%s</div><div class="body">%s</div></div></li>`+"\n",
			esc(e.Kind), kindIcon(e.Kind), entryTime(e), esc(e.AuthorName), badge, body))
	}
	b.WriteString(`</ol></section>` + "\n")

	b.WriteString(`<section><h2>Seal signatures</h2><table><thead><tr><th>fingerprint</th><th>status</th></tr></thead><tbody>` + "\n")
	if len(res.Signers) > 0 {
		for _, fpr := range res.Signers {
			b.WriteString(`<tr><td class="fpr">` + esc(fpr) + `</td><td class="ok">✓ verified</td></tr>` + "\n")
		}
	} else {
		for fpr := range rec.Signatures {
			b.WriteString(`<tr><td class="fpr">` + esc(fpr) + `</td><td class="bad">✗ not verified</td></tr>` + "\n")
		}
	}
	b.WriteString(`</tbody></table></section>` + "\n")

	b.WriteString(footerHTML(rec, false))
	b.WriteString("</main></body></html>\n")
	return b.String()
}

// executiveSection renders the leadership summary: what happened, decisions,
// actions, a name-only timeline, and the resolution time. No fingerprints, hashes,
// or note entries (§2.6).
func executiveSection(rec *record.SealedRecord) string {
	var b strings.Builder
	b.WriteString(`<div class="execbody"><h3>What happened</h3><p>` + esc(whatHappened(rec)) + `</p>`)

	if ds := decisions(rec); len(ds) > 0 {
		b.WriteString(`<h3>Decisions</h3><ul>`)
		for _, e := range ds {
			b.WriteString(`<li>` + esc(e.Body) + `</li>`)
		}
		b.WriteString(`</ul>`)
	}
	if as := actions(rec); len(as) > 0 {
		b.WriteString(`<h3>Actions</h3><ul>`)
		for _, e := range as {
			owner := ""
			if e.Actionee != "" {
				owner = `<b>@` + esc(e.Actionee) + `</b>: `
			}
			b.WriteString(`<li>` + owner + esc(e.Body) + `</li>`)
		}
		b.WriteString(`</ul>`)
	}
	b.WriteString(`<h3>Timeline</h3><ul class="exectimeline">`)
	for _, e := range rec.Entries {
		if e.Kind == record.KindNote {
			continue
		}
		b.WriteString(`<li><span class="ts">` + entryTime(e) + `</span> ` + esc(e.AuthorName) + ` — ` + esc(e.Body) + `</li>`)
	}
	b.WriteString(`</ul>`)
	if r := resolution(rec); r != "" {
		b.WriteString(`<p class="resolution">Resolution time: <b>` + r + `</b> (first entry → seal)</p>`)
	}
	b.WriteString(`</div>`)
	return b.String()
}

// footerHTML renders the verify command and inline QR; the head hash is included
// only in the full (non-executive) report.
func footerHTML(rec *record.SealedRecord, executive bool) string {
	var b strings.Builder
	b.WriteString(`<footer><div><div class="vcmd">Verify with: <code>` + esc(verifyCmd) + `</code></div>`)
	if !executive {
		b.WriteString(`<div class="hash">head_hash: <code>` + esc(rec.HeadHash) + `</code></div>`)
	}
	b.WriteString(`</div><div class="qr" title="scan to verify">` + QRSVG(verifyCmd) + `</div></footer>`)
	return b.String()
}
