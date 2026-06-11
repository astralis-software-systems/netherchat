// Package engagement implements "engagement-in-a-box" (C1): a turnkey, fully
// self-contained deployment package a security consultant can stand up per client,
// and a consolidated close report at the end.
//
// `Init` generates a directory holding everything needed to run a private,
// blind-relay deployment for one engagement:
//
//   - netherchat.toml      — rooms (invite-only, webhook, scuttle), the Two-Person
//     Rule action quorums, and the consultants' trust pins;
//   - docker-compose.yml    — the relay, ready to `docker compose up -d`;
//   - identities/           — one Ed25519 identity file per consultant (0600);
//   - trust-pins.txt        — handle → fingerprint, for out-of-band verification;
//   - records/              — a drop folder for the sealed records produced in-room;
//   - engagement.json       — a manifest describing the package;
//   - README.md             — how to deploy, distribute identities, and close out.
//
// `Close` reads the sealed records dropped into records/, re-verifies each one
// OFFLINE, and writes a single consolidated close report.
//
// Everything here is industry-neutral: it speaks of "engagements", "clients", and
// "consultants" as roles, never a specific vertical. It lives under tui/ so it may
// use the client crypto package; the blind relay neither links nor knows about it.
package engagement

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"time"

	"github.com/salehkreiner/netherchat/tui/internal/crypto"
)

// ManifestVersion is the engagement.json format version.
const ManifestVersion = "v1"

// DefaultRooms are provisioned when none are specified.
var DefaultRooms = []string{"ops", "findings"}

// Options configures Init.
type Options struct {
	Name        string   // engagement name; also the package directory name (filesystem-safe)
	Client      string   // optional client/org label (free text)
	Consultants []string // consultant handles; one identity is generated per handle
	Rooms       []string // rooms to provision (default DefaultRooms)
	OutDir      string   // parent directory for the package (default ".")
	Addr        string   // relay listen address (default ":3000")
	Image       string   // relay container image (default "salkreiner/netherchat:latest")
	Quorum      int      // Two-Person-Rule quorum for scuttle/break-glass (default 2)
	RoomTTL     string   // hard room lifetime (default "168h")
	IdleScuttle string   // room scuttle idle_after (default "2h")
}

func (o *Options) applyDefaults() {
	if len(o.Rooms) == 0 {
		o.Rooms = append([]string(nil), DefaultRooms...)
	}
	if o.OutDir == "" {
		o.OutDir = "."
	}
	if o.Addr == "" {
		o.Addr = ":3000"
	}
	if o.Image == "" {
		o.Image = "salkreiner/netherchat:latest"
	}
	if o.Quorum < 1 {
		o.Quorum = 2
	}
	if o.RoomTTL == "" {
		o.RoomTTL = "168h"
	}
	if o.IdleScuttle == "" {
		o.IdleScuttle = "2h"
	}
}

func (o *Options) validate() error {
	if err := safeIdent(o.Name); err != nil {
		return fmt.Errorf("engagement name: %w", err)
	}
	if len(o.Consultants) == 0 {
		return errors.New("engagement: at least one --consultant is required")
	}
	seen := map[string]bool{}
	for _, h := range o.Consultants {
		if err := safeIdent(h); err != nil {
			return fmt.Errorf("consultant handle %q: %w", h, err)
		}
		if seen[h] {
			return fmt.Errorf("engagement: duplicate consultant handle %q", h)
		}
		seen[h] = true
	}
	for _, r := range o.Rooms {
		if err := safeIdent(r); err != nil {
			return fmt.Errorf("room name %q: %w", r, err)
		}
	}
	return nil
}

// Manifest is the engagement.json describing a generated package. It carries no
// secrets — webhook tokens and identity private keys live only in netherchat.toml
// and the identity files, never here.
type Manifest struct {
	Version     string           `json:"netherchat_engagement"` // ManifestVersion
	Name        string           `json:"name"`
	Client      string           `json:"client,omitempty"`
	CreatedAt   string           `json:"created_at"` // RFC3339 UTC
	Relay       RelayInfo        `json:"relay"`
	Quorum      int              `json:"quorum"`
	RoomTTL     string           `json:"room_ttl,omitempty"`
	IdleScuttle string           `json:"idle_scuttle,omitempty"`
	Rooms       []string         `json:"rooms"`
	Consultants []ConsultantInfo `json:"consultants"`

	Dir string `json:"-"` // package directory (runtime only)
}

// RelayInfo describes the relay the package deploys.
type RelayInfo struct {
	Addr  string `json:"addr"`
	Image string `json:"image"`
	Port  string `json:"port"`
}

// ConsultantInfo is one consultant's public identity in the manifest.
type ConsultantInfo struct {
	Handle       string `json:"handle"`
	Fingerprint  string `json:"fingerprint"`
	IdentityFile string `json:"identity_file"`
}

// roomSpec pairs a room with its generated webhook token (kept out of the manifest).
type roomSpec struct {
	Name         string
	WebhookToken string
}

// Init generates the engagement package and returns its manifest. It refuses to
// overwrite an existing directory, so it never clobbers identity files.
func Init(opts Options) (*Manifest, error) {
	opts.applyDefaults()
	if err := opts.validate(); err != nil {
		return nil, err
	}

	pkgDir := filepath.Join(opts.OutDir, opts.Name)
	if _, err := os.Stat(pkgDir); err == nil {
		return nil, fmt.Errorf("engagement: %s already exists (refusing to overwrite)", pkgDir)
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	idDir := filepath.Join(pkgDir, "identities")
	recDir := filepath.Join(pkgDir, "records")
	for _, d := range []string{pkgDir, idDir, recDir} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			return nil, err
		}
	}

	// One identity per consultant; the file holds a private key, so id.Save writes 0600.
	consultants := make([]ConsultantInfo, 0, len(opts.Consultants))
	for _, handle := range opts.Consultants {
		id, err := crypto.GenerateIdentity()
		if err != nil {
			return nil, fmt.Errorf("engagement: generate identity for %q: %w", handle, err)
		}
		rel := filepath.Join("identities", "identity-"+handle+".json")
		if err := id.Save(filepath.Join(pkgDir, rel)); err != nil {
			return nil, fmt.Errorf("engagement: save identity for %q: %w", handle, err)
		}
		consultants = append(consultants, ConsultantInfo{
			Handle:       handle,
			Fingerprint:  id.Fingerprint(),
			IdentityFile: filepath.ToSlash(rel),
		})
	}

	rooms := make([]roomSpec, 0, len(opts.Rooms))
	for _, name := range opts.Rooms {
		tok, err := genToken()
		if err != nil {
			return nil, err
		}
		rooms = append(rooms, roomSpec{Name: name, WebhookToken: tok})
	}

	manifest := &Manifest{
		Version:     ManifestVersion,
		Name:        opts.Name,
		Client:      opts.Client,
		CreatedAt:   time.Now().UTC().Format(time.RFC3339),
		Relay:       RelayInfo{Addr: opts.Addr, Image: opts.Image, Port: portFromAddr(opts.Addr)},
		Quorum:      opts.Quorum,
		RoomTTL:     opts.RoomTTL,
		IdleScuttle: opts.IdleScuttle,
		Rooms:       opts.Rooms,
		Consultants: consultants,
		Dir:         pkgDir,
	}

	files := map[string]string{
		"netherchat.toml":                     renderTOML(opts, rooms, consultants),
		"docker-compose.yml":                  renderCompose(opts),
		"trust-pins.txt":                      renderTrustPins(opts, consultants),
		"README.md":                           renderReadme(manifest),
		filepath.Join("records", "README.md"): recordsReadme,
	}
	for name, content := range files {
		if err := os.WriteFile(filepath.Join(pkgDir, name), []byte(content), 0o644); err != nil {
			return nil, err
		}
	}
	mb, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return nil, err
	}
	if err := os.WriteFile(filepath.Join(pkgDir, "engagement.json"), append(mb, '\n'), 0o644); err != nil {
		return nil, err
	}
	return manifest, nil
}

func genToken() (string, error) {
	b := make([]byte, 24)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("engagement: generate token: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func portFromAddr(addr string) string {
	if _, port, err := net.SplitHostPort(addr); err == nil && port != "" {
		return port
	}
	return "3000"
}

// safeIdent allows only [A-Za-z0-9_-] so a name is safe as a filesystem path
// component, a TOML key, and a handle. It rejects empty, dotted, and separator-
// bearing values (no path traversal).
func safeIdent(s string) error {
	if s == "" {
		return errors.New("must not be empty")
	}
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-', r == '_':
		default:
			return fmt.Errorf("contains an invalid character %q (allowed: letters, digits, - and _)", r)
		}
	}
	return nil
}
