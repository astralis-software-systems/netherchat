package crypto

import (
	"crypto/ed25519"
	"crypto/sha512"
	"errors"
	"fmt"
	"net"
	"os"
	"runtime"

	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
	"golang.org/x/term"
)

// kxDerivationDomain is the fixed message an ssh-agent identity signs to derive
// its X25519 key-agreement key. Ed25519 signatures are deterministic (RFC 8032),
// so the same agent key always yields the same X25519 key across sessions — while
// the SSH private key itself never leaves the agent. (For file-based keys we have
// the seed and use the direct RFC 8032 → RFC 7748 conversion instead; ssh-agent
// cannot perform X25519, so this signature-based derivation is the only way to
// give an agent identity a usable encryption key without exporting the key.)
const kxDerivationDomain = "netherchat/x25519-agent-derivation/v1"

// identityFromSSHKeyFile loads an OpenSSH Ed25519 private key file. If the key is
// passphrase-protected and prompt is true (an explicit --identity), it prompts on
// the terminal; otherwise it returns an error so the cascade can fall through to
// the next source.
func identityFromSSHKeyFile(path, source string, prompt bool) (*Identity, error) {
	pem, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	raw, err := ssh.ParseRawPrivateKey(pem)
	if err != nil {
		var passErr *ssh.PassphraseMissingError
		if errors.As(err, &passErr) {
			if !prompt {
				return nil, fmt.Errorf("%s is passphrase-protected (add it to ssh-agent, or pass it via --identity)", path)
			}
			pw, perr := readPassphrase(path)
			if perr != nil {
				return nil, perr
			}
			raw, err = ssh.ParseRawPrivateKeyWithPassphrase(pem, pw)
		}
		if err != nil {
			return nil, fmt.Errorf("parse %s: %w", path, err)
		}
	}
	priv, ok := asEd25519Private(raw)
	if !ok {
		return nil, fmt.Errorf("%s is not an Ed25519 private key (only Ed25519 keys are supported)", path)
	}
	return identityFromEd25519(priv, source)
}

func asEd25519Private(raw any) (ed25519.PrivateKey, bool) {
	switch k := raw.(type) {
	case ed25519.PrivateKey:
		return k, true
	case *ed25519.PrivateKey:
		return *k, true
	default:
		return nil, false
	}
}

func readPassphrase(path string) ([]byte, error) {
	fd := int(os.Stdin.Fd())
	if !term.IsTerminal(fd) {
		return nil, fmt.Errorf("%s is passphrase-protected and stdin is not a terminal", path)
	}
	fmt.Fprintf(os.Stderr, "Enter passphrase for %s: ", path)
	pw, err := term.ReadPassword(fd)
	fmt.Fprintln(os.Stderr)
	return pw, err
}

// agentSigner delegates Ed25519 signing to ssh-agent. The SSH private key never
// enters this process; only signatures cross the socket.
type agentSigner struct {
	ag  agent.Agent
	key *agent.Key
	pub ed25519.PublicKey
}

func (s *agentSigner) Public() ed25519.PublicKey { return s.pub }

func (s *agentSigner) Sign(message []byte) ([]byte, error) {
	sig, err := s.ag.Sign(s.key, message)
	if err != nil {
		return nil, fmt.Errorf("ssh-agent sign: %w", err)
	}
	if sig.Format != ssh.KeyAlgoED25519 {
		return nil, fmt.Errorf("ssh-agent returned a %q signature, want ed25519", sig.Format)
	}
	return sig.Blob, nil // raw 64-byte Ed25519 signature, verifiable with ed25519.Verify
}

// identityFromAgent connects to the ssh-agent at sock and builds an identity from
// the first Ed25519 key it holds.
func identityFromAgent(sock string) (*Identity, error) {
	conn, err := dialAgent(sock)
	if err != nil {
		return nil, err
	}
	ag := agent.NewClient(conn)
	keys, err := ag.List()
	if err != nil {
		return nil, fmt.Errorf("list ssh-agent keys: %w", err)
	}
	for _, k := range keys {
		if k.Type() != ssh.KeyAlgoED25519 {
			continue
		}
		pub, err := ed25519FromAgentKey(k)
		if err != nil {
			continue
		}
		s := &agentSigner{ag: ag, key: k, pub: pub}

		// Derive the X25519 key-agreement key from a deterministic agent signature.
		sig, err := s.Sign([]byte(kxDerivationDomain))
		if err != nil {
			return nil, fmt.Errorf("derive x25519 key via agent: %w", err)
		}
		h := sha512.Sum512(sig)
		var kxPriv [32]byte
		copy(kxPriv[:], h[:32])
		kxPriv[0] &= 248
		kxPriv[31] &= 127
		kxPriv[31] |= 64
		kxPubB, err := curve25519.X25519(kxPriv[:], curve25519.Basepoint)
		if err != nil {
			return nil, err
		}
		var kxPub [32]byte
		copy(kxPub[:], kxPubB)

		return &Identity{SignPub: pub, KXPub: kxPub, KXPriv: kxPriv, Source: "ssh-agent", signer: s}, nil
	}
	return nil, errors.New("ssh-agent holds no Ed25519 key")
}

func ed25519FromAgentKey(k *agent.Key) (ed25519.PublicKey, error) {
	pub, err := ssh.ParsePublicKey(k.Blob)
	if err != nil {
		return nil, err
	}
	cpk, ok := pub.(ssh.CryptoPublicKey)
	if !ok {
		return nil, errors.New("agent key does not expose a crypto public key")
	}
	ed, ok := cpk.CryptoPublicKey().(ed25519.PublicKey)
	if !ok {
		return nil, errors.New("agent key is not Ed25519")
	}
	return ed, nil
}

// dialAgent opens the ssh-agent socket. On Windows the agent is a named pipe that
// net.Dial cannot open without an extra dependency, so we skip it there and let
// the cascade fall through to a key file or --identity.
func dialAgent(sock string) (net.Conn, error) {
	if runtime.GOOS == "windows" {
		return nil, errors.New("ssh-agent auto-detection is not supported on Windows; use --identity")
	}
	return net.Dial("unix", sock)
}
