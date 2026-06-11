package provider

import (
	"context"

	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"

	"github.com/salehkreiner/terraform-provider-netherchat/internal/tfconfig"
)

func resourceRoute() *schema.Resource {
	return &schema.Resource{
		Description:   "A signal route — a [[route]] entry that spawns a room when an inbound signal matches. Keyed by room_prefix.",
		CreateContext: routeWrite,
		ReadContext:   routeRead,
		UpdateContext: routeWrite,
		DeleteContext: routeDelete,
		Importer:      &schema.ResourceImporter{StateContext: schema.ImportStatePassthroughContext},
		Schema: map[string]*schema.Schema{
			"room_prefix": {
				Type:        schema.TypeString,
				Required:    true,
				ForceNew:    true,
				Description: "Prefix for spawned room names (<prefix>-<8hex>). Must be unique; it is the route's identity.",
			},
			"action": {
				Type:        schema.TypeString,
				Optional:    true,
				Default:     "break-glass",
				Description: "Action to take on a match. Currently only \"break-glass\".",
			},
			"match": {
				Type:        schema.TypeMap,
				Optional:    true,
				Elem:        &schema.Schema{Type: schema.TypeString},
				Description: "Field=value conditions an inbound signal must satisfy.",
			},
			"invite": {
				Type:        schema.TypeList,
				Optional:    true,
				Elem:        &schema.Schema{Type: schema.TypeString},
				Description: "Display names or @handles to invite into the spawned room.",
			},
			"ttl": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Hard lifetime of the spawned room, e.g. \"24h\".",
			},
			"reply_url": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Optional URL to POST the generated room links back to.",
			},
		},
	}
}

func routeFromData(d *schema.ResourceData) tfconfig.Route {
	r := tfconfig.Route{
		RoomPrefix: d.Get("room_prefix").(string),
		Action:     d.Get("action").(string),
		TTL:        d.Get("ttl").(string),
		ReplyURL:   d.Get("reply_url").(string),
	}
	if m, ok := d.Get("match").(map[string]any); ok && len(m) > 0 {
		r.Match = map[string]string{}
		for k, v := range m {
			r.Match[k] = v.(string)
		}
	}
	for _, v := range d.Get("invite").([]any) {
		r.Invite = append(r.Invite, v.(string))
	}
	return r
}

func routeWrite(ctx context.Context, d *schema.ResourceData, meta any) diag.Diagnostics {
	fileMu.Lock()
	defer fileMu.Unlock()
	path := cfgPath(meta)
	cfg, err := tfconfig.Load(path)
	if err != nil {
		return diag.FromErr(err)
	}
	cfg.SetRoute(routeFromData(d))
	if err := validate(meta, cfg); err != nil {
		return diag.FromErr(err)
	}
	if err := cfg.Write(path); err != nil {
		return diag.FromErr(err)
	}
	d.SetId(d.Get("room_prefix").(string))
	return readRoute(d, cfg)
}

func routeRead(ctx context.Context, d *schema.ResourceData, meta any) diag.Diagnostics {
	fileMu.Lock()
	defer fileMu.Unlock()
	cfg, err := tfconfig.Load(cfgPath(meta))
	if err != nil {
		return diag.FromErr(err)
	}
	return readRoute(d, cfg)
}

func readRoute(d *schema.ResourceData, cfg *tfconfig.Config) diag.Diagnostics {
	r, ok := cfg.GetRoute(d.Id())
	if !ok {
		d.SetId("")
		return nil
	}
	d.Set("room_prefix", r.RoomPrefix)
	d.Set("action", r.Action)
	d.Set("match", r.Match)
	d.Set("invite", r.Invite)
	d.Set("ttl", r.TTL)
	d.Set("reply_url", r.ReplyURL)
	return nil
}

func routeDelete(ctx context.Context, d *schema.ResourceData, meta any) diag.Diagnostics {
	fileMu.Lock()
	defer fileMu.Unlock()
	path := cfgPath(meta)
	cfg, err := tfconfig.Load(path)
	if err != nil {
		return diag.FromErr(err)
	}
	cfg.DeleteRoute(d.Id())
	if err := cfg.Write(path); err != nil {
		return diag.FromErr(err)
	}
	d.SetId("")
	return nil
}
