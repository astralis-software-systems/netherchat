package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"net/url"
	"runtime"
	"strings"
	"time"

	"github.com/salehkreiner/netherchat/buildinfo"
	"github.com/salehkreiner/netherchat/protocol"
	"github.com/salehkreiner/netherchat/tui/client"
	"github.com/salehkreiner/netherchat/tui/output"
)

// --- version ----------------------------------------------------------------

type versionOut struct {
	Version         string `json:"version"`
	ProtocolVersion int    `json:"protocol_version"`
	GoVersion       string `json:"go_version"`
	Platform        string `json:"platform"`
}

func versionCmd(args []string) {
	fs := flag.NewFlagSet("version", flag.ExitOnError)
	jsonMode := fs.Bool("json", false, "output JSON")
	_ = fs.Parse(args)

	if *jsonMode {
		_ = output.WriteJSON(versionOut{
			Version:         buildinfo.Version,
			ProtocolVersion: protocol.Version,
			GoVersion:       runtime.Version(),
			Platform:        runtime.GOOS + "/" + runtime.GOARCH,
		})
		return
	}
	output.WriteHuman("netherchat %s\n", buildinfo.Version)
}

// --- whoami -----------------------------------------------------------------

type whoamiIdentity struct {
	Source string `json:"source"`
	Fpr    string `json:"fpr"`
	Name   string `json:"name"`
}

type whoamiOut struct {
	Identity        whoamiIdentity `json:"identity"`
	Server          string         `json:"server"`
	Room            string         `json:"room"`
	Encryption      string         `json:"encryption"`
	ProtocolVersion int            `json:"protocol_version"`
	PeersVerified   int            `json:"peers_verified"`
}

// whoamiCmd reports the local identity (resolved offline via the BYO-key cascade)
// and the configured target. peers_verified is always 0 here: SAS verification is
// a live, in-session, in-memory state, so a one-shot command has none.
func whoamiCmd(args []string) {
	fs := flag.NewFlagSet("whoami", flag.ExitOnError)
	url := fs.String("server", "ws://localhost:3000", "server URL (display only)")
	room := fs.String("room", "general", "room (display only)")
	name := fs.String("name", defaultName(), "display name")
	identity := fs.String("identity", "", "identity key file (default: ssh-agent → ~/.ssh/id_ed25519 → generated)")
	jsonMode := fs.Bool("json", false, "output JSON")
	_ = fs.Parse(args)

	fpr, source, err := client.Identify(*identity)
	if err != nil {
		output.Fatal(*jsonMode, err)
	}

	out := whoamiOut{
		Identity:        whoamiIdentity{Source: source, Fpr: fpr, Name: *name},
		Server:          *url,
		Room:            *room,
		Encryption:      "NaCl:X25519+XChaCha20-Poly1305",
		ProtocolVersion: protocol.Version,
		PeersVerified:   0,
	}
	if *jsonMode {
		_ = output.WriteJSON(out)
		return
	}
	output.WriteHuman("fingerprint: %s\nidentity:    %s\nname:        %s\nserver:      %s\nroom:        #%s\nencryption:  %s\nprotocol:    v%d\n",
		fpr, source, *name, *url, *room, out.Encryption, out.ProtocolVersion)
}

// --- rooms ------------------------------------------------------------------

type roomInfo struct {
	Name       string `json:"name"`
	Members    int    `json:"members"`
	InviteOnly bool   `json:"invite_only"`
	TTLSeconds int    `json:"ttl_seconds"`
	Webhook    bool   `json:"webhook"`
}

// roomsCmd lists the server's active rooms via the read-only REST /rooms endpoint.
func roomsCmd(args []string) {
	fs := flag.NewFlagSet("rooms", flag.ExitOnError)
	server := fs.String("server", "ws://localhost:3000", "server URL")
	jsonMode := fs.Bool("json", false, "output JSON")
	_ = fs.Parse(args)

	base, err := httpBase(*server)
	if err != nil {
		output.Fatal(*jsonMode, err)
	}
	rooms, err := fetchRooms(base)
	if err != nil {
		output.Fatal(*jsonMode, err)
	}

	if *jsonMode {
		_ = output.WriteJSON(rooms)
		return
	}
	if len(rooms) == 0 {
		output.WriteHuman("no active rooms\n")
		return
	}
	for _, r := range rooms {
		var tags []string
		if r.InviteOnly {
			tags = append(tags, "invite-only")
		}
		if r.Webhook {
			tags = append(tags, "webhook")
		}
		if r.TTLSeconds > 0 {
			tags = append(tags, fmt.Sprintf("ttl=%ds", r.TTLSeconds))
		}
		suffix := ""
		if len(tags) > 0 {
			suffix = "  [" + strings.Join(tags, ", ") + "]"
		}
		output.WriteHuman("#%-16s %d member(s)%s\n", r.Name, r.Members, suffix)
	}
}

// fetchRooms GETs {base}/rooms and returns the parsed room list. The REST
// endpoint returns {"rooms":[…]}; we unwrap to the array the CLI prints.
func fetchRooms(base string) ([]roomInfo, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, base+"/rooms", nil)
	if err != nil {
		return nil, err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("server returned %s", resp.Status)
	}
	var body struct {
		Rooms []roomInfo `json:"rooms"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return nil, err
	}
	if body.Rooms == nil {
		body.Rooms = []roomInfo{}
	}
	return body.Rooms, nil
}

// httpBase converts a ws(s):// or http(s):// server URL to its http(s):// origin
// for REST calls (dropping any path).
func httpBase(server string) (string, error) {
	if !strings.Contains(server, "://") {
		server = "http://" + server
	}
	u, err := url.Parse(server)
	if err != nil {
		return "", err
	}
	switch u.Scheme {
	case "ws":
		u.Scheme = "http"
	case "wss":
		u.Scheme = "https"
	case "http", "https":
	default:
		return "", fmt.Errorf("unsupported server scheme %q", u.Scheme)
	}
	u.Path, u.RawQuery, u.Fragment = "", "", ""
	return u.String(), nil
}
