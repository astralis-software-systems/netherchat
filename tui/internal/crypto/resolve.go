package crypto

import (
	"bytes"
	"os"
	"path/filepath"
)

// ResolveIdentity loads the operator's identity following the BYO-key precedence
// (FEATURE_ROADMAP_FREE.md §1.1):
//
//	a. explicitPath (--identity)            any supported key file
//	b. SSH_AUTH_SOCK                         ssh-agent, first Ed25519 key
//	c. ~/.ssh/id_ed25519                     standard OpenSSH key
//	d. ~/.ssh/id_ed25519_sk                  hardware-backed OpenSSH key
//	e. ~/.config/netherchat/identity.json    the previously generated key
//	f. generate                              a fresh ephemeral key (last resort)
//
// Steps b–e are skipped silently when the source is absent or unusable; an
// explicit --identity that fails is a hard error (the operator named that key).
func ResolveIdentity(explicitPath string) (*Identity, error) {
	if explicitPath != "" {
		return loadFromPath(explicitPath, true)
	}

	// b. ssh-agent (signing delegated; SSH private key never enters this process).
	if sock := os.Getenv("SSH_AUTH_SOCK"); sock != "" {
		if id, err := identityFromAgent(sock); err == nil {
			return id, nil
		}
	}

	// c, d. standard SSH key files.
	if home, err := os.UserHomeDir(); err == nil && home != "" {
		for _, c := range []struct{ path, source string }{
			{filepath.Join(home, ".ssh", "id_ed25519"), "~/.ssh/id_ed25519"},
			{filepath.Join(home, ".ssh", "id_ed25519_sk"), "~/.ssh/id_ed25519_sk"},
		} {
			if _, statErr := os.Stat(c.path); statErr != nil {
				continue
			}
			if id, loadErr := identityFromSSHKeyFile(c.path, c.source, false); loadErr == nil {
				return id, nil
			}
		}
	}

	// e, f. the generated identity (loaded if present, created and saved if not).
	def, err := DefaultIdentityPath()
	if err != nil {
		return nil, err
	}
	id, _, err := LoadOrCreateIdentity(def)
	return id, err
}

// loadFromPath loads an explicit --identity file, detecting its format: age
// identity, the legacy Netherchat JSON identity, or (default) an OpenSSH key.
func loadFromPath(path string, prompt bool) (*Identity, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	switch {
	case isAgeIdentity(b):
		return identityFromAgeFile(b, "age: "+path)
	case isLegacyJSON(b):
		return loadIdentityFile(path)
	default:
		return identityFromSSHKeyFile(path, path, prompt)
	}
}

func isLegacyJSON(b []byte) bool {
	t := bytes.TrimSpace(b)
	return len(t) > 0 && t[0] == '{' && bytes.Contains(t, []byte(`"sign_priv"`))
}
