package provider

import (
	"context"

	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"

	"github.com/salehkreiner/terraform-provider-netherchat/internal/tfconfig"
)

func resourceActionPolicy() *schema.Resource {
	return &schema.Resource{
		Description:   "A two-person-rule policy — an [action.<name>] quorum gate for a dangerous action. Keyed by action.",
		CreateContext: actionWrite,
		ReadContext:   actionRead,
		UpdateContext: actionWrite,
		DeleteContext: actionDelete,
		Importer:      &schema.ResourceImporter{StateContext: schema.ImportStatePassthroughContext},
		Schema: map[string]*schema.Schema{
			"action": {
				Type:        schema.TypeString,
				Required:    true,
				ForceNew:    true,
				Description: "The action being gated, e.g. \"scuttle\". The policy's identity.",
			},
			"quorum": {
				Type:        schema.TypeInt,
				Required:    true,
				Description: "Number of distinct signers required to authorize the action (N-of-M).",
			},
		},
	}
}

func actionWrite(ctx context.Context, d *schema.ResourceData, meta any) diag.Diagnostics {
	fileMu.Lock()
	defer fileMu.Unlock()
	path := cfgPath(meta)
	cfg, err := tfconfig.Load(path)
	if err != nil {
		return diag.FromErr(err)
	}
	cfg.SetActionQuorum(d.Get("action").(string), d.Get("quorum").(int))
	if err := validate(meta, cfg); err != nil {
		return diag.FromErr(err)
	}
	if err := cfg.Write(path); err != nil {
		return diag.FromErr(err)
	}
	d.SetId(d.Get("action").(string))
	return readAction(d, cfg)
}

func actionRead(ctx context.Context, d *schema.ResourceData, meta any) diag.Diagnostics {
	fileMu.Lock()
	defer fileMu.Unlock()
	cfg, err := tfconfig.Load(cfgPath(meta))
	if err != nil {
		return diag.FromErr(err)
	}
	return readAction(d, cfg)
}

func readAction(d *schema.ResourceData, cfg *tfconfig.Config) diag.Diagnostics {
	q, ok := cfg.GetActionQuorum(d.Id())
	if !ok {
		d.SetId("")
		return nil
	}
	d.Set("action", d.Id())
	d.Set("quorum", q)
	return nil
}

func actionDelete(ctx context.Context, d *schema.ResourceData, meta any) diag.Diagnostics {
	fileMu.Lock()
	defer fileMu.Unlock()
	path := cfgPath(meta)
	cfg, err := tfconfig.Load(path)
	if err != nil {
		return diag.FromErr(err)
	}
	cfg.DeleteAction(d.Id())
	if err := cfg.Write(path); err != nil {
		return diag.FromErr(err)
	}
	d.SetId("")
	return nil
}
