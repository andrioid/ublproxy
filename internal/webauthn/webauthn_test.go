package webauthn

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"math/big"
	"testing"

	"github.com/fxamacker/cbor/v2"
)

var testCfg = Config{
	RPID:     "localhost",
	RPName:   "test",
	RPOrigin: "https://localhost:8443",
}

func TestNewChallenge(t *testing.T) {
	c1, err := NewChallenge()
	if err != nil {
		t.Fatalf("NewChallenge: %v", err)
	}
	c2, _ := NewChallenge()

	if c1 == c2 {
		t.Error("two challenges should not be equal")
	}

	b64 := c1.Base64()
	decoded, err := base64.RawURLEncoding.DecodeString(b64)
	if err != nil {
		t.Fatalf("decode base64: %v", err)
	}
	if len(decoded) != 32 {
		t.Errorf("decoded length = %d, want 32", len(decoded))
	}
}

func TestVerifyRegistration(t *testing.T) {
	challenge, _ := NewChallenge()

	// Generate a real ES256 key pair
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	credID := []byte("test-credential-id-12345")
	attestObj, clientDataJSON := buildRegistration(t, privateKey, credID, challenge, testCfg)

	cred, err := VerifyRegistration(testCfg, attestObj, clientDataJSON, challenge)
	if err != nil {
		t.Fatalf("VerifyRegistration: %v", err)
	}

	if len(cred.ID) != len(credID) {
		t.Errorf("credential ID length = %d, want %d", len(cred.ID), len(credID))
	}
	if string(cred.ID) != string(credID) {
		t.Error("credential ID mismatch")
	}
	if len(cred.PublicKey) != 65 {
		t.Errorf("public key length = %d, want 65", len(cred.PublicKey))
	}
	if cred.PublicKey[0] != 0x04 {
		t.Error("public key should start with 0x04")
	}
}

func TestVerifyRegistrationWrongChallenge(t *testing.T) {
	challenge, _ := NewChallenge()
	wrongChallenge, _ := NewChallenge()

	privateKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	credID := []byte("test-cred")
	attestObj, clientDataJSON := buildRegistration(t, privateKey, credID, challenge, testCfg)

	_, err := VerifyRegistration(testCfg, attestObj, clientDataJSON, wrongChallenge)
	if err == nil {
		t.Fatal("expected error for wrong challenge")
	}
}

func TestVerifyRegistrationWrongOrigin(t *testing.T) {
	challenge, _ := NewChallenge()
	privateKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	credID := []byte("test-cred")

	wrongCfg := Config{
		RPID:     "localhost",
		RPName:   "test",
		RPOrigin: "https://evil.com:8443",
	}
	attestObj, clientDataJSON := buildRegistration(t, privateKey, credID, challenge, testCfg)

	_, err := VerifyRegistration(wrongCfg, attestObj, clientDataJSON, challenge)
	if err == nil {
		t.Fatal("expected error for wrong origin")
	}
}

func TestVerifyAuthentication(t *testing.T) {
	// Register first
	challenge, _ := NewChallenge()
	privateKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	credID := []byte("test-cred")

	attestObj, clientDataJSON := buildRegistration(t, privateKey, credID, challenge, testCfg)
	cred, err := VerifyRegistration(testCfg, attestObj, clientDataJSON, challenge)
	if err != nil {
		t.Fatalf("registration: %v", err)
	}

	// Now authenticate
	authChallenge, _ := NewChallenge()
	authData, authClientDataJSON, sig := buildAssertion(t, privateKey, authChallenge, testCfg, 1)

	signCount, err := VerifyAuthentication(testCfg, authData, authClientDataJSON, sig, cred.PublicKey, authChallenge)
	if err != nil {
		t.Fatalf("VerifyAuthentication: %v", err)
	}
	if signCount != 1 {
		t.Errorf("signCount = %d, want 1", signCount)
	}
}

func TestVerifyAuthenticationBadSignature(t *testing.T) {
	challenge, _ := NewChallenge()
	privateKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	credID := []byte("test-cred")

	attestObj, clientDataJSON := buildRegistration(t, privateKey, credID, challenge, testCfg)
	cred, err := VerifyRegistration(testCfg, attestObj, clientDataJSON, challenge)
	if err != nil {
		t.Fatalf("registration: %v", err)
	}

	authChallenge, _ := NewChallenge()
	authData, authClientDataJSON, sig := buildAssertion(t, privateKey, authChallenge, testCfg, 1)

	// Corrupt signature
	sig[0] ^= 0xff

	_, err = VerifyAuthentication(testCfg, authData, authClientDataJSON, sig, cred.PublicKey, authChallenge)
	if err == nil {
		t.Fatal("expected error for bad signature")
	}
}

// --- Test helpers: build realistic WebAuthn structures ---

// buildRegistration builds a valid attestation object and clientDataJSON for
// a registration ceremony using the given key pair.
func buildRegistration(t *testing.T, key *ecdsa.PrivateKey, credID []byte, challenge Challenge, cfg Config) ([]byte, []byte) {
	t.Helper()

	// clientDataJSON
	clientData := map[string]any{
		"type":      "webauthn.create",
		"challenge": challenge.Base64(),
		"origin":    cfg.RPOrigin,
	}
	clientDataJSON, _ := json.Marshal(clientData)

	// Build authenticator data
	rpIDHash := sha256.Sum256([]byte(cfg.RPID))

	// flags: UP (0x01) | AT (0x40) = 0x41
	flags := byte(0x41)

	authData := make([]byte, 0, 37+16+2+len(credID)+200)
	authData = append(authData, rpIDHash[:]...)
	authData = append(authData, flags)
	authData = append(authData, 0, 0, 0, 0) // sign count = 0

	// Attested credential data
	aaguid := make([]byte, 16) // all zeros
	authData = append(authData, aaguid...)

	credIDLen := make([]byte, 2)
	binary.BigEndian.PutUint16(credIDLen, uint16(len(credID)))
	authData = append(authData, credIDLen...)
	authData = append(authData, credID...)

	// COSE public key (ES256)
	x := key.PublicKey.X.Bytes()
	y := key.PublicKey.Y.Bytes()
	// Pad to 32 bytes
	x = padTo32(x)
	y = padTo32(y)

	coseKey := map[int]any{
		1:  2,  // kty: EC2
		3:  -7, // alg: ES256
		-1: 1,  // crv: P-256
		-2: x,  // x coordinate
		-3: y,  // y coordinate
	}
	coseKeyBytes, _ := cbor.Marshal(coseKey)
	authData = append(authData, coseKeyBytes...)

	// Attestation object (CBOR)
	attObj := map[string]any{
		"fmt":      "none",
		"attStmt":  map[string]any{},
		"authData": authData,
	}
	attObjBytes, err := cbor.Marshal(attObj)
	if err != nil {
		t.Fatalf("marshal attestation object: %v", err)
	}

	return attObjBytes, clientDataJSON
}

// buildAssertion builds a valid assertion (authData, clientDataJSON, signature)
// for an authentication ceremony.
func buildAssertion(t *testing.T, key *ecdsa.PrivateKey, challenge Challenge, cfg Config, signCount uint32) ([]byte, []byte, []byte) {
	t.Helper()

	// clientDataJSON
	clientData := map[string]any{
		"type":      "webauthn.get",
		"challenge": challenge.Base64(),
		"origin":    cfg.RPOrigin,
	}
	clientDataJSON, _ := json.Marshal(clientData)

	// Build authenticator data (37 bytes for assertion, no attested cred data)
	rpIDHash := sha256.Sum256([]byte(cfg.RPID))
	flags := byte(0x01) // UP only

	authData := make([]byte, 37)
	copy(authData, rpIDHash[:])
	authData[32] = flags
	binary.BigEndian.PutUint32(authData[33:], signCount)

	// Sign: SHA-256(authData || SHA-256(clientDataJSON))
	clientDataHash := sha256.Sum256(clientDataJSON)
	verifyData := make([]byte, len(authData)+32)
	copy(verifyData, authData)
	copy(verifyData[len(authData):], clientDataHash[:])

	hash := sha256.Sum256(verifyData)
	sig, err := ecdsa.SignASN1(rand.Reader, key, hash[:])
	if err != nil {
		t.Fatalf("sign assertion: %v", err)
	}

	return authData, clientDataJSON, sig
}

func padTo32(b []byte) []byte {
	if len(b) >= 32 {
		return b[:32]
	}
	padded := make([]byte, 32)
	copy(padded[32-len(b):], b)
	return padded
}

// TestVerifyRegistrationBadRPID tests that registration fails when the RP ID
// in the config doesn't match the one in authenticator data.
func TestVerifyRegistrationBadRPID(t *testing.T) {
	challenge, _ := NewChallenge()
	privateKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	credID := []byte("test-cred")

	// Build with correct config
	attestObj, clientDataJSON := buildRegistration(t, privateKey, credID, challenge, testCfg)

	// Verify with wrong RP ID
	wrongCfg := Config{
		RPID:     "wrong.example.com",
		RPName:   "test",
		RPOrigin: testCfg.RPOrigin,
	}
	_, err := VerifyRegistration(wrongCfg, attestObj, clientDataJSON, challenge)
	if err == nil {
		t.Fatal("expected error for wrong RP ID")
	}
}

// TestParseUncompressedPublicKey tests that an invalid public key is rejected.
func TestParseUncompressedPublicKey(t *testing.T) {
	// Too short
	_, err := parseUncompressedPublicKey([]byte{0x04, 1, 2, 3})
	if err == nil {
		t.Error("expected error for short key")
	}

	// Wrong prefix
	bad := make([]byte, 65)
	bad[0] = 0x03
	_, err = parseUncompressedPublicKey(bad)
	if err == nil {
		t.Error("expected error for wrong prefix")
	}

	// Point not on curve (all zeros except prefix)
	notOnCurve := make([]byte, 65)
	notOnCurve[0] = 0x04
	notOnCurve[1] = 1
	_, err = parseUncompressedPublicKey(notOnCurve)
	if err == nil {
		t.Error("expected error for point not on curve")
	}

	// Valid point
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	valid := make([]byte, 65)
	valid[0] = 0x04
	xBytes := key.PublicKey.X.Bytes()
	yBytes := key.PublicKey.Y.Bytes()
	copy(valid[1+32-len(xBytes):33], xBytes)
	copy(valid[33+32-len(yBytes):65], yBytes)
	parsed, err := parseUncompressedPublicKey(valid)
	if err != nil {
		t.Fatalf("valid key: %v", err)
	}
	if parsed.X.Cmp(key.PublicKey.X) != 0 || parsed.Y.Cmp(key.PublicKey.Y) != 0 {
		t.Error("parsed key doesn't match original")
	}
}

func TestCredentialIDBase64(t *testing.T) {
	c := &Credential{ID: []byte{0xfe, 0xed, 0xfa, 0xce}}
	got := c.CredentialIDBase64()
	// Verify it round-trips
	decoded, err := base64.RawURLEncoding.DecodeString(got)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !bytesEqual(decoded, c.ID) {
		t.Error("round-trip failed")
	}
}

// Suppress unused import warning for big package.
var _ = new(big.Int)
