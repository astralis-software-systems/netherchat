package sneakernet

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/salehkreiner/netherchat/protocol"
	"github.com/salehkreiner/netherchat/tui/internal/crypto"
)

// authHello is the first handshake frame each side sends: its identity public key
// and a fresh random nonce. It is NOT yet trusted — the proof frame that follows
// is what authenticates it.
type authHello struct {
	V     int    `json:"v"`
	Pub   []byte `json:"pub"`   // Ed25519 public key (32 bytes)
	Nonce []byte `json:"nonce"` // 16 random bytes, channel binding
}

// authProof is the second handshake frame: an Ed25519 signature over the
// channel-binding bytes (see protocol.DirectAuthBytes), proving control of the
// key announced in authHello.
type authProof struct {
	Sig []byte `json:"sig"`
}

// signer is the slice of an identity the handshake needs: its public key and the
// ability to sign. *crypto.Identity satisfies it.
type signer interface {
	Sign(message []byte) ([]byte, error)
}

// performAuth runs the mutual Ed25519 authentication handshake over fc BEFORE any
// envelope frames flow. It is symmetric — the dialer and the accepter run the
// identical exchange:
//
//  1. send my {pub, nonce}; receive the peer's {pub, nonce}
//  2. send Sign(DirectAuthBytes(myPub, myNonce, peerPub, peerNonce))
//  3. verify the peer's signature against the mirror bytes
//
// localPub/sign are this side's identity. expectFpr, when non-empty, additionally
// requires the peer to present EXACTLY that fingerprint — the dialer sets it to the
// host fingerprint it learned out of band (the offer blob or mDNS), so a rogue
// process answering on the host's address cannot impersonate it. An accepter that
// admits any authenticated peer passes "" and surfaces the verified fingerprint to
// the human/trust-pinning instead. The peer's verified public key is returned.
//
// This is the security property of §1.1: the connection is authenticated by the
// long-term identity keys before a single message frame is exchanged. A rogue peer
// that cannot produce a valid signature for the announced key is rejected here; a
// peer whose key is not the expected one is rejected by the expectFpr check.
func performAuth(fc *frameConn, localPub ed25519.PublicKey, sign signer, expectFpr string) (ed25519.PublicKey, error) {
	myNonce := make([]byte, 16)
	if _, err := rand.Read(myNonce); err != nil {
		return nil, fmt.Errorf("auth nonce: %w", err)
	}

	helloB, _ := json.Marshal(authHello{V: 1, Pub: localPub, Nonce: myNonce})
	if err := fc.writeFrame(helloB); err != nil {
		return nil, fmt.Errorf("send auth hello: %w", err)
	}
	peerB, err := fc.readFrame()
	if err != nil {
		return nil, fmt.Errorf("read peer auth hello: %w", err)
	}
	var ph authHello
	if json.Unmarshal(peerB, &ph) != nil || len(ph.Pub) != ed25519.PublicKeySize || len(ph.Nonce) == 0 {
		return nil, errors.New("malformed auth hello from peer")
	}
	peerPub := ed25519.PublicKey(ph.Pub)

	sig, err := sign.Sign(protocol.DirectAuthBytes(localPub, myNonce, peerPub, ph.Nonce))
	if err != nil {
		return nil, fmt.Errorf("sign auth proof: %w", err)
	}
	proofB, _ := json.Marshal(authProof{Sig: sig})
	if err := fc.writeFrame(proofB); err != nil {
		return nil, fmt.Errorf("send auth proof: %w", err)
	}
	peerProofB, err := fc.readFrame()
	if err != nil {
		return nil, fmt.Errorf("read peer auth proof: %w", err)
	}
	var pp authProof
	if json.Unmarshal(peerProofB, &pp) != nil {
		return nil, errors.New("malformed auth proof from peer")
	}
	// Verify the peer signed the mirror of what we signed: their key+nonce against
	// ours. A failure here means the peer does not hold the private key for the
	// announced public key (or the channel was tampered with).
	if !ed25519.Verify(peerPub, protocol.DirectAuthBytes(peerPub, ph.Nonce, localPub, myNonce), pp.Sig) {
		return nil, errors.New("peer failed Ed25519 authentication")
	}
	if expectFpr != "" {
		if got := crypto.Fingerprint(peerPub); got != expectFpr {
			return nil, fmt.Errorf("peer identity mismatch: connected to %s, expected %s", got, expectFpr)
		}
	}
	return peerPub, nil
}
