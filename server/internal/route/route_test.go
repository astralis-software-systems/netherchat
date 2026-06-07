package route

import (
	"encoding/json"
	"testing"

	"github.com/salehkreiner/netherchat/server/config"
)

// payload decodes a JSON object the way the webhook handler does (numbers ->
// float64), so the matcher is exercised on realistic input.
func payload(t *testing.T, s string) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal([]byte(s), &m); err != nil {
		t.Fatalf("bad test payload: %v", err)
	}
	return m
}

func bg(match map[string]string) config.RouteConfig {
	return config.RouteConfig{Match: match, Action: "break-glass"}
}

func TestExactEquality(t *testing.T) {
	routes := []config.RouteConfig{bg(map[string]string{"severity": "critical"})}

	if idx, _, ok := Match(routes, payload(t, `{"severity":"critical","text":"db down"}`)); !ok || idx != 0 {
		t.Fatalf("expected match at 0, got idx=%d ok=%v", idx, ok)
	}
	if _, _, ok := Match(routes, payload(t, `{"severity":"warning"}`)); ok {
		t.Fatal("warning should not match a critical rule")
	}
	// Exact means exact: a superstring must not match a non-regex value.
	if _, _, ok := Match(routes, payload(t, `{"severity":"critical-ish"}`)); ok {
		t.Fatal("exact equality must not match a superstring")
	}
}

func TestAnchoredRegex(t *testing.T) {
	routes := []config.RouteConfig{bg(map[string]string{"alertname": ".*database.*"})}

	if _, _, ok := Match(routes, payload(t, `{"alertname":"high-cpu-database-01"}`)); !ok {
		t.Error(`".*database.*" should match "high-cpu-database-01"`)
	}
	if _, _, ok := Match(routes, payload(t, `{"alertname":"disk-full"}`)); ok {
		t.Error(`".*database.*" should NOT match "disk-full"`)
	}
	// Anchoring: a regex must match the WHOLE value, not a substring with a
	// non-greedy fixed core.
	routes = []config.RouteConfig{bg(map[string]string{"env": "prod"})}
	if _, _, ok := Match(routes, payload(t, `{"env":"production"}`)); ok {
		t.Error("a non-regex value must be exact, not a prefix")
	}
	routes = []config.RouteConfig{bg(map[string]string{"code": "50[0-9]"})}
	if _, _, ok := Match(routes, payload(t, `{"code":"503"}`)); !ok {
		t.Error("character-class regex should match 503")
	}
	if _, _, ok := Match(routes, payload(t, `{"code":"5031"}`)); ok {
		t.Error("anchored regex must reject the trailing-digit superstring 5031")
	}
}

func TestFieldsAreANDed(t *testing.T) {
	routes := []config.RouteConfig{bg(map[string]string{
		"severity":  "critical",
		"alertname": ".*database.*",
	})}

	if _, _, ok := Match(routes, payload(t, `{"severity":"critical","alertname":"prod-database-1"}`)); !ok {
		t.Error("both conditions hold; should match")
	}
	if _, _, ok := Match(routes, payload(t, `{"severity":"critical","alertname":"disk-full"}`)); ok {
		t.Error("one condition fails; AND should reject")
	}
	if _, _, ok := Match(routes, payload(t, `{"severity":"warning","alertname":"prod-database-1"}`)); ok {
		t.Error("one condition fails; AND should reject")
	}
}

func TestDotNotationNestedField(t *testing.T) {
	routes := []config.RouteConfig{bg(map[string]string{"labels.severity": "critical"})}

	if _, _, ok := Match(routes, payload(t, `{"labels":{"severity":"critical"}}`)); !ok {
		t.Error("dot notation should descend into nested objects")
	}
	if _, _, ok := Match(routes, payload(t, `{"labels":{"severity":"warning"}}`)); ok {
		t.Error("nested mismatch should not match")
	}
	// Missing the nested path entirely fails the condition.
	if _, _, ok := Match(routes, payload(t, `{"severity":"critical"}`)); ok {
		t.Error("absent nested field should not match")
	}
}

func TestFirstMatchWins(t *testing.T) {
	routes := []config.RouteConfig{
		bg(map[string]string{"severity": "warning"}),  // 0: no
		bg(map[string]string{"severity": "critical"}), // 1: yes
		bg(map[string]string{"text": ".*"}),           // 2: also yes, but later
	}
	idx, r, ok := Match(routes, payload(t, `{"severity":"critical","text":"db down"}`))
	if !ok || idx != 1 {
		t.Fatalf("expected first matching rule at idx 1, got idx=%d ok=%v", idx, ok)
	}
	if r.Action != "break-glass" {
		t.Errorf("returned rule = %+v", r)
	}
}

func TestNonBreakGlassActionIgnored(t *testing.T) {
	routes := []config.RouteConfig{
		{Match: map[string]string{"severity": "critical"}, Action: "ignore-me"},
		bg(map[string]string{"severity": "critical"}),
	}
	idx, _, ok := Match(routes, payload(t, `{"severity":"critical"}`))
	if !ok || idx != 1 {
		t.Fatalf("non-break-glass rule should be skipped; got idx=%d ok=%v", idx, ok)
	}
}

func TestNoRulesNoMatch(t *testing.T) {
	if _, _, ok := Match(nil, payload(t, `{"severity":"critical"}`)); ok {
		t.Error("no rules should never match")
	}
}

func TestEmptyMatchIsCatchAll(t *testing.T) {
	routes := []config.RouteConfig{bg(map[string]string{})}
	if _, _, ok := Match(routes, payload(t, `{"anything":"goes"}`)); !ok {
		t.Error("a rule with no conditions is a catch-all and should match")
	}
}

func TestNonStringScalarsCoerce(t *testing.T) {
	// JSON numbers / bools are stringified for comparison.
	routes := []config.RouteConfig{bg(map[string]string{"code": "500"})}
	if _, _, ok := Match(routes, payload(t, `{"code":500}`)); !ok {
		t.Error(`match "500" should match the JSON number 500`)
	}
	routes = []config.RouteConfig{bg(map[string]string{"firing": "true"})}
	if _, _, ok := Match(routes, payload(t, `{"firing":true}`)); !ok {
		t.Error(`match "true" should match the JSON bool true`)
	}
	// A non-scalar (object) value can't be matched.
	routes = []config.RouteConfig{bg(map[string]string{"labels": "x"})}
	if _, _, ok := Match(routes, payload(t, `{"labels":{"a":"b"}}`)); ok {
		t.Error("an object-valued field should not match a scalar pattern")
	}
}
