package webauthn

import "encoding/json"

// jsonUnmarshal is a thin wrapper around encoding/json.Unmarshal, kept
// separate so the main webauthn.go file doesn't import encoding/json
// directly (it only needs CBOR for binary parsing).
func jsonUnmarshal(data []byte, v any) error {
	return json.Unmarshal(data, v)
}
