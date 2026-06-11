package provider

import (
	"context"

	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"

	"github.com/salehkreiner/terraform-provider-netherchat/internal/tfconfig"
)

func resourceTrust() *schema.Resource {
	return &schema.Resource{
		Description:   "A trust pin — a [[trust]] entry binding a handle to a fingerprint and/or a keys URL. Keyed by handle.",
		CreateContext: trustWrite,
		ReadContext:   trustRead,
		UpdateContext: trustWrite,
		DeleteContext: trustDelete,
		Importer:      &schema.ResourceImporter{StateContext: schema.ImportStatePassthroughContext},
		Schema: map[string]*schema.Schema{
			"handle": {
				Type:        schema.TypeString,
				Required:    true,
				ForceNew:    true,
				Description: "The handle being pinned; the entry's identity.",
			},
			"fpr": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Pinned fingerprint, e.g. \"SHA256:…\".",
			},
			"keys_url": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "URL to fetch the handle's public keys, e.g. https://github.com/<handle>.keys.",
			},
		},
	}
}

func trustWrite(ctx context.Context, d *schema.ResourceData, meta any) diag.Diagnostics {
	fileMu.Lock()
	defer fileMu.Unlock()
	path := cfgPath(meta)
	cfg, err := tfconfig.Load(path)
	if err != nil {
		return diag.FromErr(err)
	}
	cfg.SetTrust(tfconfig.Trust{
		Handle:  d.Get("handle").(string),
		Fpr:     d.Get("fpr").(string),
		KeysURL: d.Get("keys_url").(string),
	})
	if err := validate(meta, cfg); err != nil {
		return diag.FromErr(err)
	}
	if err := cfg.Write(path); err != nil {
		return diag.FromErr(err)
	}
	d.SetId(d.Get("handle").(string))
	return readTrust(d, cfg)
}

func trustRead(ctx context.Context, d *schema.ResourceData, meta any) diag.Diagnostics {
	fileMu.Lock()
	defer fileMu.Unlock()
	cfg, err := tfconfig.Load(cfgPath(meta))
	if err != nil {
		return diag.FromErr(err)
	}
	return readTrust(d, cfg)
}

func readTrust(d *schema.ResourceData, cfg *tfconfig.Config) diag.Diagnostics {
	t, ok := cfg.GetTrust(d.Id())
	if !ok {
		d.SetId("")
		return nil
	}
	d.Set("handle", t.Handle)
	d.Set("fpr", t.Fpr)
	d.Set("keys_url", t.KeysURL)
	return nil
}

func trustDelete(ctx context.Context, d *schema.ResourceData, meta any) diag.Diagnostics {
	fileMu.Lock()
	defer fileMu.Unlock()
	path := cfgPath(meta)
	cfg, err := tfconfig.Load(path)
	if err != nil {
		return diag.FromErr(err)
	}
	cfg.DeleteTrust(d.Id())
	if err := cfg.Write(path); err != nil {
		return diag.FromErr(err)
	}
	d.SetId("")
	return nil
}
