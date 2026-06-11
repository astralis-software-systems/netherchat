package provider

import (
	"context"

	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"

	"github.com/salehkreiner/terraform-provider-netherchat/internal/tfconfig"
)

func resourceRoom() *schema.Resource {
	return &schema.Resource{
		Description:   "A Netherchat room — a [rooms.<name>] section of netherchat.toml.",
		CreateContext: roomWrite,
		ReadContext:   roomRead,
		UpdateContext: roomWrite,
		DeleteContext: roomDelete,
		Importer:      &schema.ResourceImporter{StateContext: schema.ImportStatePassthroughContext},
		Schema: map[string]*schema.Schema{
			"name": {
				Type:        schema.TypeString,
				Required:    true,
				ForceNew:    true,
				Description: "Room name; the table key under [rooms].",
			},
			"invite_only": {
				Type:        schema.TypeBool,
				Optional:    true,
				Default:     false,
				Description: "Only invited members may join.",
			},
			"webhook": {
				Type:        schema.TypeBool,
				Optional:    true,
				Default:     false,
				Description: "Expose an inbound webhook for this room.",
			},
			"webhook_token": {
				Type:        schema.TypeString,
				Optional:    true,
				Sensitive:   true,
				Description: "Bearer token required on the room's webhook endpoint.",
			},
			"exec_enabled": {
				Type:        schema.TypeBool,
				Optional:    true,
				Default:     false,
				Description: "Advisory flag for /exec in this room. Enforcement is ultimately agent-side; the server ignores keys it does not recognize.",
			},
			"beacon_token": {
				Type:        schema.TypeString,
				Optional:    true,
				Sensitive:   true,
				Description: "Token for the room's out-of-band read-only status beacon.",
			},
			"beacon_ttl": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Lifetime of a published beacon snapshot, e.g. \"15m\".",
			},
			"ttl": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Hard lifetime of the room, e.g. \"24h\".",
			},
		},
	}
}

func roomFromData(d *schema.ResourceData) tfconfig.Room {
	return tfconfig.Room{
		InviteOnly:   d.Get("invite_only").(bool),
		Webhook:      d.Get("webhook").(bool),
		WebhookToken: d.Get("webhook_token").(string),
		ExecEnabled:  d.Get("exec_enabled").(bool),
		BeaconToken:  d.Get("beacon_token").(string),
		BeaconTTL:    d.Get("beacon_ttl").(string),
		TTL:          d.Get("ttl").(string),
	}
}

func roomWrite(ctx context.Context, d *schema.ResourceData, meta any) diag.Diagnostics {
	fileMu.Lock()
	defer fileMu.Unlock()
	path := cfgPath(meta)
	cfg, err := tfconfig.Load(path)
	if err != nil {
		return diag.FromErr(err)
	}
	name := d.Get("name").(string)
	cfg.SetRoom(name, roomFromData(d))
	if err := validate(meta, cfg); err != nil {
		return diag.FromErr(err)
	}
	if err := cfg.Write(path); err != nil {
		return diag.FromErr(err)
	}
	d.SetId(name)
	return readRoom(d, cfg)
}

func roomRead(ctx context.Context, d *schema.ResourceData, meta any) diag.Diagnostics {
	fileMu.Lock()
	defer fileMu.Unlock()
	cfg, err := tfconfig.Load(cfgPath(meta))
	if err != nil {
		return diag.FromErr(err)
	}
	return readRoom(d, cfg)
}

func readRoom(d *schema.ResourceData, cfg *tfconfig.Config) diag.Diagnostics {
	r, ok := cfg.GetRoom(d.Id())
	if !ok {
		d.SetId("") // removed out of band; let Terraform plan a re-create
		return nil
	}
	d.Set("name", d.Id())
	d.Set("invite_only", r.InviteOnly)
	d.Set("webhook", r.Webhook)
	d.Set("webhook_token", r.WebhookToken)
	d.Set("exec_enabled", r.ExecEnabled)
	d.Set("beacon_token", r.BeaconToken)
	d.Set("beacon_ttl", r.BeaconTTL)
	d.Set("ttl", r.TTL)
	return nil
}

func roomDelete(ctx context.Context, d *schema.ResourceData, meta any) diag.Diagnostics {
	fileMu.Lock()
	defer fileMu.Unlock()
	path := cfgPath(meta)
	cfg, err := tfconfig.Load(path)
	if err != nil {
		return diag.FromErr(err)
	}
	cfg.DeleteRoom(d.Id())
	if err := cfg.Write(path); err != nil {
		return diag.FromErr(err)
	}
	d.SetId("")
	return nil
}
