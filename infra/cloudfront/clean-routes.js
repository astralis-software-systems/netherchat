// CloudFront Function (viewer-request) — clean-URL routing for the hosted site.
//
// The link generators emit extensionless paths that are the public contract:
//
//   /join?room=<room>&token=<token>          (server/internal/api.go, tui/ui/app/commands.go,
//                                             cmd/netherchat-{slack,teams}-notify/main.go)
//   /beacon?room=<room>&ttl=<n>#key=<key>    (cmd/netherchat/beaconcmd.go:115)
//
// The files behind them are join.html and beacon.html. S3 website hosting does not
// rewrite extensionless paths, so without this function both requests fall through
// to the landing page. The beacon case fails SILENTLY: the key lives in the
// fragment, which never leaves the browser, so the recipient sees a marketing page
// and no error at all.
//
// Two properties make this a URI-only rewrite:
//   - event.request.uri never contains the query string (it is event.request.querystring,
//     a separate field this function does not touch), so ?room=…&token=… survives.
//   - the fragment never leaves the browser at all (RFC 3986 §3.5), so #key=… is
//     untouched by definition — CloudFront never sees it.
//
// This mirrors web/vite.config.ts's cleanRoutes plugin exactly, including what it
// deliberately does NOT rewrite: only the bare page paths match. "/beacon/<room>"
// is the relay's beacon REST API (PROTOCOL.md §1.2) and a trailing slash is not a
// page path, so neither is touched here — dev and hosted agree on the whole mapping,
// not just the happy case.
var PAGES = ["/join", "/beacon"];

function handler(event) {
  var request = event.request;
  for (var i = 0; i < PAGES.length; i++) {
    if (request.uri === PAGES[i]) {
      request.uri = PAGES[i] + ".html";
      break;
    }
  }
  return request;
}
