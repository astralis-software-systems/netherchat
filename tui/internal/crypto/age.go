package crypto

import (
	"bufio"
	"bytes"
	"crypto/ed25519"
	"errors"
	"fmt"
	"strings"
)

// age identity support. An age identity file holds an X25519 secret as a Bech32
// string (`AGE-SECRET-KEY-1…`). Netherchat needs an Ed25519 identity (signing +
// fingerprint), so the 32-byte age secret is used as the Ed25519 seed and the
// rest of the identity is derived from it deterministically (convert.go). This
// keeps a single, uniform "one secret → one identity" model across SSH, age, and
// generated keys, and needs no external dependency (Bech32 is decoded here).

const ageSecretHRP = "age-secret-key-" // lowercase; age files use the uppercase form

func isAgeIdentity(b []byte) bool {
	return bytes.Contains(bytes.ToUpper(b), []byte("AGE-SECRET-KEY-1"))
}

// identityFromAgeFile parses an age identity file (skipping comments) and builds
// an Identity from the first AGE-SECRET-KEY it finds.
func identityFromAgeFile(b []byte, source string) (*Identity, error) {
	sc := bufio.NewScanner(bytes.NewReader(b))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if !strings.HasPrefix(strings.ToUpper(line), "AGE-SECRET-KEY-1") {
			continue
		}
		scalar, err := decodeBech32(strings.ToLower(line), ageSecretHRP)
		if err != nil {
			return nil, fmt.Errorf("decode age key: %w", err)
		}
		if len(scalar) != 32 {
			return nil, fmt.Errorf("age key decoded to %d bytes, want 32", len(scalar))
		}
		return identityFromEd25519(ed25519.NewKeyFromSeed(scalar), source)
	}
	return nil, errors.New("no AGE-SECRET-KEY line found in identity file")
}

// --- Bech32 (BIP-173) -------------------------------------------------------

const bech32Charset = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"

// decodeBech32 decodes a (lowercased) Bech32 string with the expected HRP and
// returns the 8-bit payload (checksum stripped, padding rejected).
func decodeBech32(s, wantHRP string) ([]byte, error) {
	pos := strings.LastIndexByte(s, '1')
	if pos < 1 || pos+7 > len(s) {
		return nil, errors.New("invalid bech32 separator position")
	}
	hrp := s[:pos]
	if hrp != wantHRP {
		return nil, fmt.Errorf("unexpected bech32 prefix %q (want %q)", hrp, wantHRP)
	}
	data := make([]int, 0, len(s)-pos-1)
	for _, c := range s[pos+1:] {
		idx := strings.IndexRune(bech32Charset, c)
		if idx < 0 {
			return nil, fmt.Errorf("invalid bech32 character %q", c)
		}
		data = append(data, idx)
	}
	if !bech32VerifyChecksum(hrp, data) {
		return nil, errors.New("bad bech32 checksum")
	}
	return convertBits(data[:len(data)-6], 5, 8, false)
}

func bech32Polymod(values []int) int {
	gen := []int{0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3}
	chk := 1
	for _, v := range values {
		top := chk >> 25
		chk = (chk&0x1ffffff)<<5 ^ v
		for i := 0; i < 5; i++ {
			if (top>>uint(i))&1 == 1 {
				chk ^= gen[i]
			}
		}
	}
	return chk
}

func bech32HRPExpand(hrp string) []int {
	out := make([]int, 0, len(hrp)*2+1)
	for _, c := range hrp {
		out = append(out, int(c)>>5)
	}
	out = append(out, 0)
	for _, c := range hrp {
		out = append(out, int(c)&31)
	}
	return out
}

func bech32VerifyChecksum(hrp string, data []int) bool {
	return bech32Polymod(append(bech32HRPExpand(hrp), data...)) == 1
}

// convertBits regroups a sequence of values from fromBits-wide to toBits-wide.
func convertBits(data []int, fromBits, toBits uint, pad bool) ([]byte, error) {
	var acc, bits uint
	out := make([]byte, 0, len(data)*int(fromBits)/int(toBits)+1)
	maxv := uint(1<<toBits) - 1
	for _, value := range data {
		if value < 0 || uint(value)>>fromBits != 0 {
			return nil, errors.New("invalid value in bech32 bit conversion")
		}
		acc = (acc << fromBits) | uint(value)
		bits += fromBits
		for bits >= toBits {
			bits -= toBits
			out = append(out, byte((acc>>bits)&maxv))
		}
	}
	if pad {
		if bits > 0 {
			out = append(out, byte((acc<<(toBits-bits))&maxv))
		}
	} else if bits >= fromBits || (acc<<(toBits-bits))&maxv != 0 {
		return nil, errors.New("invalid padding in bech32 bit conversion")
	}
	return out, nil
}
