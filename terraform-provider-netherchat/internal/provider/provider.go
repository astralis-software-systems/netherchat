// Package provider implements the Terraform provider for Netherchat (B1). It manages
// the room topology declared in netherchat.toml — rooms, routes, trust pins, and
// action quorums — as config-as-code, editing the file in place and leaving every
// unmanaged section untouched.
package provider

import (
	"context"
	"sync"

	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

// fileMu serializes every read-modify-write of netherchat.toml. Terraform may invoke
// resource CRUD concurrently within a graph walk; the config file is a single shared
// document, so all edits go through one lock.
var fileMu sync.Mutex

type providerMeta struct {
	path        string
	validateURL string
}

// New returns the Netherchat provider.
func New() *schema.Provider {
	return &schema.Provider{
		Schema: map[string]*schema.Schema{
			"config_path": {
				Type:        schema.TypeString,
				Optional:    true,
				DefaultFunc: schema.EnvDefaultFunc("NETHERCHAT_CONFIG", "netherchat.toml"),
				Description: "Path to the netherchat.toml this provider manages. Defaults to ./netherchat.toml or $NETHERCHAT_CONFIG.",
			},
			"validate_url": {
				Type:        schema.TypeString,
				Optional:    true,
				DefaultFunc: schema.EnvDefaultFunc("NETHERCHAT_VALIDATE_URL", ""),
				Description: "Optional URL of a running relay's POST /api/v1/config/validate endpoint (e.g. https://relay.example.com/api/v1/config/validate). When set, each change is checked against the relay before it is written, so an invalid topology fails the apply. Sends only the rendered netherchat.toml — never message content. Empty (the default) edits the file purely offline.",
			},
		},
		ResourcesMap: map[string]*schema.Resource{
			"netherchat_room":          resourceRoom(),
			"netherchat_route":         resourceRoute(),
			"netherchat_trust":         resourceTrust(),
			"netherchat_action_policy": resourceActionPolicy(),
		},
		ConfigureContextFunc: configure,
	}
}

func configure(_ context.Context, d *schema.ResourceData) (any, diag.Diagnostics) {
	return &providerMeta{
		path:        d.Get("config_path").(string),
		validateURL: d.Get("validate_url").(string),
	}, nil
}

func cfgPath(meta any) string       { return meta.(*providerMeta).path }
func validateURLOf(meta any) string { return meta.(*providerMeta).validateURL }
