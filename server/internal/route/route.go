// Package route evaluates the [[route]] alert-routing rules (§1.3) against an
// inbound webhook payload. It is the matching half of auto-war-room: given the
// rules from netherchat.toml and a decoded JSON payload, it picks the first rule
// whose conditions all hold. Creating the room and minting links is the caller's
// job (server/internal/api) — this package is pure, side-effect-free, and unit
// tested, so the matching semantics can be pinned down precisely.
package route

import (
	"math"
	"regexp"
	"strconv"
	"strings"

	"github.com/salehkreiner/netherchat/server/config"
)

// regexMeta is the set of characters that, when present in a match value, make
// it an anchored regular expression (^value$) rather than an exact-equality
// string. A plain value like "critical" has none of these and is compared by
// equality; ".*database.*" has metacharacters and is compiled as a regex.
const regexMeta = `.*+?()[]{}|^$\`

// Match evaluates routes in order and returns the first one whose conditions all
// hold for the payload, along with its index (used as trigger_rule in the
// route_fired event). Only routes whose Action is "break-glass" are considered —
// the only supported action — so a misconfigured rule never fires by accident.
func Match(routes []config.RouteConfig, payload map[string]any) (idx int, matched config.RouteConfig, ok bool) {
	for i, r := range routes {
		if r.Action != "break-glass" {
			continue
		}
		if matches(r, payload) {
			return i, r, true
		}
	}
	return 0, config.RouteConfig{}, false
}

// matches reports whether every condition in r.Match holds for the payload. The
// conditions are AND-ed; an empty Match matches everything (a deliberate
// catch-all — "any alert spawns a room").
func matches(r config.RouteConfig, payload map[string]any) bool {
	for field, pattern := range r.Match {
		actual, found := lookup(payload, field)
		if !found {
			return false
		}
		s, ok := toString(actual)
		if !ok || !matchValue(pattern, s) {
			return false
		}
	}
	return true
}

// matchValue compares one field. A pattern with regex metacharacters is treated
// as an anchored regex; otherwise it is exact string equality. An invalid regex
// never matches (it is an operator misconfiguration, not a payload to admit).
func matchValue(pattern, actual string) bool {
	if strings.ContainsAny(pattern, regexMeta) {
		re, err := regexp.Compile("^(?:" + pattern + ")$")
		if err != nil {
			return false
		}
		return re.MatchString(actual)
	}
	return pattern == actual
}

// lookup resolves a (possibly nested) field from the payload using dot notation:
// "severity" is a top-level key, "labels.severity" descends into a nested object.
// In netherchat.toml the dotted form is written as a quoted key,
// match."labels.severity", so it arrives here as the single string
// "labels.severity".
func lookup(payload map[string]any, path string) (any, bool) {
	var cur any = payload
	for _, p := range strings.Split(path, ".") {
		m, ok := cur.(map[string]any)
		if !ok {
			return nil, false
		}
		cur, ok = m[p]
		if !ok {
			return nil, false
		}
	}
	return cur, true
}

// toString renders a scalar JSON value for comparison. JSON numbers decode to
// float64; integers are rendered without a trailing ".0" so match.code = "500"
// works against {"code": 500}. Non-scalar values (objects, arrays, null) cannot
// be matched and report ok=false.
func toString(v any) (string, bool) {
	switch t := v.(type) {
	case string:
		return t, true
	case bool:
		return strconv.FormatBool(t), true
	case float64:
		if !math.IsInf(t, 0) && !math.IsNaN(t) && t == math.Trunc(t) {
			return strconv.FormatInt(int64(t), 10), true
		}
		return strconv.FormatFloat(t, 'f', -1, 64), true
	default:
		return "", false
	}
}
