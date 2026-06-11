// Command terraform-provider-netherchat is the Terraform plugin that manages a
// Netherchat room topology (rooms, routes, trust pins, action quorums) as
// config-as-code in netherchat.toml (B1).
package main

import (
	"github.com/hashicorp/terraform-plugin-sdk/v2/plugin"

	"github.com/salehkreiner/terraform-provider-netherchat/internal/provider"
)

func main() {
	plugin.Serve(&plugin.ServeOpts{
		ProviderFunc: provider.New,
	})
}
