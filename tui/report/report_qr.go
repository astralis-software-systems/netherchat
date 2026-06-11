package report

import (
	"fmt"
	"strings"

	"rsc.io/qr"
)

// qrQuiet is the quiet-zone width (in modules) around the QR code.
const qrQuiet = 4

// QRSVG encodes data as a self-contained inline SVG QR code (§2.6): black squares
// on a white background, built directly from the module bitmap so there is no
// external library or font at render time and nothing is fetched. It returns "" on
// error — the report still renders, just without the scan-to-verify code.
//
// rsc.io/qr is already in the dependency tree (mdp/qrterminal uses it); using it
// here for the SVG avoids adding a second QR library.
func QRSVG(data string) string {
	code, err := qr.Encode(data, qr.M)
	if err != nil {
		return ""
	}
	const scale = 4
	n := code.Size
	dim := (n + 2*qrQuiet) * scale

	var b strings.Builder
	fmt.Fprintf(&b, `<svg xmlns="http://www.w3.org/2000/svg" width="%d" height="%d" viewBox="0 0 %d %d" shape-rendering="crispEdges" role="img" aria-label="scan to verify">`, dim, dim, dim, dim)
	fmt.Fprintf(&b, `<rect width="%d" height="%d" fill="#ffffff"/>`, dim, dim)
	for y := 0; y < n; y++ {
		for x := 0; x < n; x++ {
			if code.Black(x, y) {
				fmt.Fprintf(&b, `<rect x="%d" y="%d" width="%d" height="%d" fill="#000000"/>`,
					(x+qrQuiet)*scale, (y+qrQuiet)*scale, scale, scale)
			}
		}
	}
	b.WriteString(`</svg>`)
	return b.String()
}
