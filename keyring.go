// Package sts implements a small RFC 8693 security token service: a keyring
// that signs delegation tokens with ES256 and serves its public keys as a
// JWKS for the verifier (garmd) to check them against.
package sts

import (
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"

	jose "github.com/go-jose/go-jose/v4"
)

// KeyConfig is one signing key: its identifier and PEM-encoded ECDSA P-256
// private key (either SEC1 "EC PRIVATE KEY" or PKCS#8 "PRIVATE KEY").
type KeyConfig struct {
	KID string
	PEM []byte
}

// Keyring holds every configured signing key (so retired keys stay served
// for verification) and signs new tokens with only the active one.
type Keyring struct {
	keys   []jose.JSONWebKey // private keys, in configuration order
	active string
	signer jose.Signer
}

// NewKeyring parses each key's PEM into a P-256 ECDSA private key and builds
// a signer for the active one. It validates eagerly and fails loudly: this
// runs at startup and the operator reads the returned error.
func NewKeyring(keys []KeyConfig, active string) (*Keyring, error) {
	if len(keys) == 0 {
		return nil, fmt.Errorf("keyring: at least one key is required")
	}
	if active == "" {
		return nil, fmt.Errorf("keyring: active key id is required")
	}

	seen := make(map[string]bool, len(keys))
	jwks := make([]jose.JSONWebKey, 0, len(keys))
	var activeKey *ecdsa.PrivateKey

	for _, kc := range keys {
		if kc.KID == "" {
			return nil, fmt.Errorf("keyring: key has an empty kid")
		}
		if seen[kc.KID] {
			return nil, fmt.Errorf("keyring: duplicate kid %q", kc.KID)
		}
		seen[kc.KID] = true

		priv, err := parseECPrivateKey(kc.PEM)
		if err != nil {
			return nil, fmt.Errorf("keyring: key %q: %w", kc.KID, err)
		}

		jwks = append(jwks, jose.JSONWebKey{
			Key:       priv,
			KeyID:     kc.KID,
			Algorithm: "ES256",
			Use:       "sig",
		})

		if kc.KID == active {
			activeKey = priv
		}
	}

	if activeKey == nil {
		return nil, fmt.Errorf("keyring: active key %q not present among configured keys", active)
	}

	signer, err := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.ES256, Key: activeKey},
		(&jose.SignerOptions{}).WithType("JWT").WithHeader("kid", active),
	)
	if err != nil {
		return nil, fmt.Errorf("keyring: building signer for active key %q: %w", active, err)
	}

	return &Keyring{keys: jwks, active: active, signer: signer}, nil
}

// parseECPrivateKey accepts both common PEM encodings of an ECDSA private
// key: SEC1 (x509.ParseECPrivateKey) and PKCS#8. It requires a P-256 key.
func parseECPrivateKey(pemBytes []byte) (*ecdsa.PrivateKey, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, fmt.Errorf("not a valid PEM block")
	}

	priv, err := x509.ParseECPrivateKey(block.Bytes)
	if err != nil {
		var parsed any
		parsed, err = x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parsing EC private key: %w", err)
		}
		ecKey, ok := parsed.(*ecdsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("PKCS8 key is not an ECDSA key")
		}
		priv = ecKey
	}

	if priv.Curve.Params().Name != "P-256" {
		return nil, fmt.Errorf("key is on curve %s, want P-256 (ES256)", priv.Curve.Params().Name)
	}
	return priv, nil
}

// Sign mints a compact JWS over claims using the active key, ES256, with a
// "kid" header so the verifier can pick the right key after rotation.
func (k *Keyring) Sign(claims any) (string, error) {
	payload, err := json.Marshal(claims)
	if err != nil {
		return "", fmt.Errorf("keyring: marshalling claims: %w", err)
	}
	jws, err := k.signer.Sign(payload)
	if err != nil {
		return "", fmt.Errorf("keyring: signing: %w", err)
	}
	return jws.CompactSerialize()
}

// JWKS returns the public half of every configured key — including retired
// ones, so tokens they signed keep verifying during rotation.
func (k *Keyring) JWKS() jose.JSONWebKeySet {
	set := jose.JSONWebKeySet{Keys: make([]jose.JSONWebKey, len(k.keys))}
	for i, key := range k.keys {
		set.Keys[i] = key.Public()
	}
	return set
}

// Handler serves the JWKS as JSON, suitable for mounting at
// /.well-known/jwks.json.
func (k *Keyring) Handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "public, max-age=300")
		_ = json.NewEncoder(w).Encode(k.JWKS())
	})
}
