// Package webauthn implements the server-side WebAuthn (passkey) protocol
// for registration and authentication ceremonies. It supports ES256 (P-256
// ECDSA) credentials with "none" attestation only, which covers all modern
// passkey authenticators.
//
// This is a minimal implementation that avoids full WebAuthn libraries.
// It depends on fxamacker/cbor for CBOR decoding and Go stdlib for crypto.
package webauthn

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"math/big"

	"github.com/fxamacker/cbor/v2"
)

// Config holds the relying party configuration for WebAuthn ceremonies.
type Config struct {
	// RPID is the relying party identifier, typically the domain or IP.
	// Must match what the browser uses (the effective domain of the origin).
	RPID string
	// RPName is a human-readable name for the relying party.
	RPName string
	// RPOrigin is the full origin (scheme + host + port) of the portal.
	RPOrigin string
}

// Challenge is a 32-byte random value used in WebAuthn ceremonies.
type Challenge [32]byte

// NewChallenge generates a cryptographically random challenge.
func NewChallenge() (Challenge, error) {
	var c Challenge
	_, err := rand.Read(c[:])
	return c, err
}

// Base64 returns the challenge as a base64url-encoded string (no padding).
func (c Challenge) Base64() string {
	return base64.RawURLEncoding.EncodeToString(c[:])
}

// Credential holds the extracted public key and metadata from a registration.
type Credential struct {
	ID        []byte // raw credential ID
	PublicKey []byte // uncompressed EC point: 0x04 || x (32 bytes) || y (32 bytes)
	SignCount uint32
}

// CredentialIDBase64 returns the credential ID as base64url (no padding).
func (c *Credential) CredentialIDBase64() string {
	return base64.RawURLEncoding.EncodeToString(c.ID)
}

// attestationObject is the CBOR-decoded top-level structure returned by
// navigator.credentials.create().
type attestationObject struct {
	Fmt      string          `cbor:"fmt"`
	AttStmt  cbor.RawMessage `cbor:"attStmt"`
	AuthData []byte          `cbor:"authData"`
}

// coseKeyES256 represents the CBOR-decoded COSE_Key for ES256 (P-256).
// COSE key map labels: 1=kty, 3=alg, -1=crv, -2=x, -3=y
type coseKeyES256 struct {
	Kty int    `cbor:"1,keyasint"`
	Alg int    `cbor:"3,keyasint"`
	Crv int    `cbor:"-1,keyasint"`
	X   []byte `cbor:"-2,keyasint"`
	Y   []byte `cbor:"-3,keyasint"`
}

// VerifyRegistration verifies a WebAuthn registration response and extracts
// the credential. It validates the attestation object (none attestation only),
// checks the RP ID hash, and extracts the ES256 public key.
//
// Parameters:
//   - attestationObjectRaw: the raw CBOR attestation object from the client
//   - clientDataJSON: the raw clientDataJSON from the client
//   - challenge: the challenge that was sent to the client
func VerifyRegistration(cfg Config, attestationObjectRaw, clientDataJSON []byte, challenge Challenge) (*Credential, error) {
	// 1. Verify clientDataJSON
	if err := verifyClientData(clientDataJSON, "webauthn.create", challenge, cfg.RPOrigin); err != nil {
		return nil, fmt.Errorf("client data: %w", err)
	}

	// 2. Decode attestation object
	var att attestationObject
	if err := cbor.Unmarshal(attestationObjectRaw, &att); err != nil {
		return nil, fmt.Errorf("decode attestation object: %w", err)
	}

	// 3. Only accept "none" attestation
	if att.Fmt != "none" {
		return nil, fmt.Errorf("unsupported attestation format: %s", att.Fmt)
	}

	// 4. Parse authenticator data
	cred, err := parseAuthDataRegistration(att.AuthData, cfg.RPID)
	if err != nil {
		return nil, fmt.Errorf("auth data: %w", err)
	}

	return cred, nil
}

// VerifyAuthentication verifies a WebAuthn authentication (assertion) response.
// It checks the signature against the stored public key and validates the
// RP ID hash and client data.
//
// Parameters:
//   - authData: the raw authenticator data from the assertion
//   - clientDataJSON: the raw clientDataJSON from the client
//   - signature: the raw signature from the assertion
//   - publicKey: the stored public key (uncompressed EC point: 0x04 || x || y)
//   - challenge: the challenge that was sent to the client
//
// Returns the new sign count from the authenticator.
func VerifyAuthentication(cfg Config, authData, clientDataJSON, signature, publicKey []byte, challenge Challenge) (uint32, error) {
	// 1. Verify clientDataJSON
	if err := verifyClientData(clientDataJSON, "webauthn.get", challenge, cfg.RPOrigin); err != nil {
		return 0, fmt.Errorf("client data: %w", err)
	}

	// 2. Verify RP ID hash (first 32 bytes of authData)
	if len(authData) < 37 {
		return 0, errors.New("auth data too short")
	}
	rpIDHash := sha256.Sum256([]byte(cfg.RPID))
	if !bytesEqual(authData[:32], rpIDHash[:]) {
		return 0, errors.New("RP ID hash mismatch")
	}

	// 3. Check user presence flag (bit 0)
	flags := authData[32]
	if flags&0x01 == 0 {
		return 0, errors.New("user presence flag not set")
	}

	// 4. Extract sign count (bytes 33-36, big-endian)
	signCount := uint32(authData[33])<<24 | uint32(authData[34])<<16 | uint32(authData[35])<<8 | uint32(authData[36])

	// 5. Verify signature: sign(authData || SHA-256(clientDataJSON))
	clientDataHash := sha256.Sum256(clientDataJSON)
	verifyData := make([]byte, len(authData)+32)
	copy(verifyData, authData)
	copy(verifyData[len(authData):], clientDataHash[:])

	ecKey, err := parseUncompressedPublicKey(publicKey)
	if err != nil {
		return 0, fmt.Errorf("parse public key: %w", err)
	}

	if !ecdsa.VerifyASN1(ecKey, sha256Hash(verifyData), signature) {
		return 0, errors.New("signature verification failed")
	}

	return signCount, nil
}

// parseAuthDataRegistration parses authenticator data from a registration
// response and extracts the credential ID and public key.
func parseAuthDataRegistration(data []byte, rpID string) (*Credential, error) {
	// Minimum: 32 (rpIdHash) + 1 (flags) + 4 (signCount) = 37 bytes
	if len(data) < 37 {
		return nil, errors.New("auth data too short")
	}

	// Verify RP ID hash
	rpIDHash := sha256.Sum256([]byte(rpID))
	if !bytesEqual(data[:32], rpIDHash[:]) {
		return nil, errors.New("RP ID hash mismatch")
	}

	flags := data[32]

	// AT (attested credential data) flag must be set for registration
	if flags&0x40 == 0 {
		return nil, errors.New("attested credential data flag not set")
	}

	// Sign count (bytes 33-36, big-endian)
	signCount := uint32(data[33])<<24 | uint32(data[34])<<16 | uint32(data[35])<<8 | uint32(data[36])

	// Attested credential data starts at byte 37:
	// 16 bytes aaguid + 2 bytes credIdLen + credId + CBOR public key
	if len(data) < 37+16+2 {
		return nil, errors.New("auth data too short for attested credential data")
	}

	// Skip aaguid (16 bytes)
	credIDLen := int(data[53])<<8 | int(data[54])
	if len(data) < 55+credIDLen {
		return nil, errors.New("auth data too short for credential ID")
	}

	credID := make([]byte, credIDLen)
	copy(credID, data[55:55+credIDLen])

	// CBOR-encoded COSE public key follows
	coseKeyData := data[55+credIDLen:]
	var coseKey coseKeyES256
	if err := cbor.Unmarshal(coseKeyData, &coseKey); err != nil {
		return nil, fmt.Errorf("decode COSE key: %w", err)
	}

	// Validate ES256 (P-256 ECDSA)
	if coseKey.Kty != 2 { // EC2
		return nil, fmt.Errorf("unsupported key type: %d (expected EC2=2)", coseKey.Kty)
	}
	if coseKey.Alg != -7 { // ES256
		return nil, fmt.Errorf("unsupported algorithm: %d (expected ES256=-7)", coseKey.Alg)
	}
	if coseKey.Crv != 1 { // P-256
		return nil, fmt.Errorf("unsupported curve: %d (expected P-256=1)", coseKey.Crv)
	}
	if len(coseKey.X) != 32 || len(coseKey.Y) != 32 {
		return nil, errors.New("invalid EC point coordinates")
	}

	// Store as uncompressed point: 0x04 || x || y
	pubKey := make([]byte, 65)
	pubKey[0] = 0x04
	copy(pubKey[1:33], coseKey.X)
	copy(pubKey[33:65], coseKey.Y)

	// Verify the point is on the curve
	x := new(big.Int).SetBytes(coseKey.X)
	y := new(big.Int).SetBytes(coseKey.Y)
	if !elliptic.P256().IsOnCurve(x, y) {
		return nil, errors.New("EC point not on P-256 curve")
	}

	return &Credential{
		ID:        credID,
		PublicKey: pubKey,
		SignCount: signCount,
	}, nil
}

// clientData is the JSON structure sent by the browser during ceremonies.
type clientData struct {
	Type        string `json:"type"`
	Challenge   string `json:"challenge"`
	Origin      string `json:"origin"`
	CrossOrigin bool   `json:"crossOrigin,omitempty"`
}

// verifyClientData validates the clientDataJSON against expected values.
func verifyClientData(raw []byte, expectedType string, challenge Challenge, origin string) error {
	// The spec uses JSON, so we parse manually to be lenient
	var cd clientData
	if err := jsonUnmarshal(raw, &cd); err != nil {
		return fmt.Errorf("decode: %w", err)
	}

	if cd.Type != expectedType {
		return fmt.Errorf("type mismatch: got %q, want %q", cd.Type, expectedType)
	}

	if cd.Challenge != challenge.Base64() {
		return fmt.Errorf("challenge mismatch")
	}

	if cd.Origin != origin {
		return fmt.Errorf("origin mismatch: got %q, want %q", cd.Origin, origin)
	}

	return nil
}

// parseUncompressedPublicKey parses a 65-byte uncompressed EC point (0x04 || x || y)
// into an *ecdsa.PublicKey on the P-256 curve.
func parseUncompressedPublicKey(data []byte) (*ecdsa.PublicKey, error) {
	if len(data) != 65 || data[0] != 0x04 {
		return nil, errors.New("invalid uncompressed EC point")
	}
	x := new(big.Int).SetBytes(data[1:33])
	y := new(big.Int).SetBytes(data[33:65])
	if !elliptic.P256().IsOnCurve(x, y) {
		return nil, errors.New("EC point not on P-256 curve")
	}
	return &ecdsa.PublicKey{
		Curve: elliptic.P256(),
		X:     x,
		Y:     y,
	}, nil
}

func sha256Hash(data []byte) []byte {
	h := sha256.Sum256(data)
	return h[:]
}

func bytesEqual(a, b []byte) bool {
	return subtle.ConstantTimeCompare(a, b) == 1
}
