package store

import (
	"database/sql"
	"path/filepath"
	"testing"
	"time"
)

func testStore(t *testing.T) *Store {
	t.Helper()
	dbPath := filepath.Join(t.TempDir(), "test.db")
	s, err := Open(dbPath)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func TestCredentialCRUD(t *testing.T) {
	s := testStore(t)

	pubKey := []byte{0x04, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63, 64}

	if err := s.SaveCredential("cred-1", pubKey); err != nil {
		t.Fatalf("SaveCredential: %v", err)
	}

	cred, err := s.GetCredential("cred-1")
	if err != nil {
		t.Fatalf("GetCredential: %v", err)
	}
	if cred.ID != "cred-1" {
		t.Errorf("ID = %q, want %q", cred.ID, "cred-1")
	}
	if len(cred.PublicKey) != 65 {
		t.Errorf("PublicKey length = %d, want 65", len(cred.PublicKey))
	}
	if cred.SignCount != 0 {
		t.Errorf("SignCount = %d, want 0", cred.SignCount)
	}

	// Update sign count
	if err := s.UpdateSignCount("cred-1", 42); err != nil {
		t.Fatalf("UpdateSignCount: %v", err)
	}
	cred, _ = s.GetCredential("cred-1")
	if cred.SignCount != 42 {
		t.Errorf("SignCount after update = %d, want 42", cred.SignCount)
	}

	// Not found
	_, err = s.GetCredential("nonexistent")
	if err != sql.ErrNoRows {
		t.Errorf("GetCredential(nonexistent) err = %v, want sql.ErrNoRows", err)
	}

	// List
	if err := s.SaveCredential("cred-2", pubKey); err != nil {
		t.Fatalf("SaveCredential(cred-2): %v", err)
	}
	ids, err := s.ListCredentialIDs()
	if err != nil {
		t.Fatalf("ListCredentialIDs: %v", err)
	}
	if len(ids) != 2 {
		t.Errorf("ListCredentialIDs: got %d, want 2", len(ids))
	}
}

func TestSessionLifecycle(t *testing.T) {
	s := testStore(t)

	pubKey := make([]byte, 65)
	pubKey[0] = 0x04
	s.SaveCredential("cred-1", pubKey)

	sess, err := s.CreateSession("cred-1")
	if err != nil {
		t.Fatalf("CreateSession: %v", err)
	}
	if sess.Token == "" {
		t.Fatal("session token is empty")
	}
	if sess.CredentialID != "cred-1" {
		t.Errorf("CredentialID = %q, want %q", sess.CredentialID, "cred-1")
	}

	// Validate
	validated, err := s.ValidateSession(sess.Token)
	if err != nil {
		t.Fatalf("ValidateSession: %v", err)
	}
	if validated.CredentialID != "cred-1" {
		t.Errorf("validated CredentialID = %q, want %q", validated.CredentialID, "cred-1")
	}

	// Invalid token
	_, err = s.ValidateSession("bogus-token")
	if err != sql.ErrNoRows {
		t.Errorf("ValidateSession(bogus) err = %v, want sql.ErrNoRows", err)
	}

	// Delete (logout)
	if err := s.DeleteSession(sess.Token); err != nil {
		t.Fatalf("DeleteSession: %v", err)
	}
	_, err = s.ValidateSession(sess.Token)
	if err != sql.ErrNoRows {
		t.Errorf("ValidateSession after delete: err = %v, want sql.ErrNoRows", err)
	}
}

func TestSessionExpiry(t *testing.T) {
	s := testStore(t)

	pubKey := make([]byte, 65)
	pubKey[0] = 0x04
	s.SaveCredential("cred-1", pubKey)

	// Insert an already-expired session directly
	expiredTime := time.Now().UTC().Add(-1 * time.Hour).Format("2006-01-02 15:04:05")
	_, err := s.db.Exec(
		"INSERT INTO sessions (token, credential_id, expires_at) VALUES (?, ?, ?)",
		"expired-token", "cred-1", expiredTime,
	)
	if err != nil {
		t.Fatalf("insert expired session: %v", err)
	}

	_, err = s.ValidateSession("expired-token")
	if err != sql.ErrNoRows {
		t.Errorf("ValidateSession(expired) err = %v, want sql.ErrNoRows", err)
	}

	// CleanExpiredSessions
	if err := s.CleanExpiredSessions(); err != nil {
		t.Fatalf("CleanExpiredSessions: %v", err)
	}
}

func TestRuleCRUD(t *testing.T) {
	s := testStore(t)

	pubKey := make([]byte, 65)
	pubKey[0] = 0x04
	s.SaveCredential("cred-1", pubKey)
	s.SaveCredential("cred-2", pubKey)

	// Create
	r1, err := s.CreateRule("cred-1", "example.com##.ad-banner", "example.com")
	if err != nil {
		t.Fatalf("CreateRule: %v", err)
	}
	if r1.ID == 0 {
		t.Error("rule ID should not be 0")
	}
	if r1.Rule != "example.com##.ad-banner" {
		t.Errorf("Rule = %q, want %q", r1.Rule, "example.com##.ad-banner")
	}
	if !r1.Enabled {
		t.Error("new rule should be enabled")
	}

	r2, _ := s.CreateRule("cred-1", "||ads.example.com^", "")
	r3, _ := s.CreateRule("cred-2", "other.com##.ad", "other.com")

	// List rules for cred-1 only
	rules, err := s.ListRules("cred-1")
	if err != nil {
		t.Fatalf("ListRules: %v", err)
	}
	if len(rules) != 2 {
		t.Errorf("ListRules(cred-1): got %d, want 2", len(rules))
	}

	// List all enabled
	all, err := s.ListAllEnabledRules()
	if err != nil {
		t.Fatalf("ListAllEnabledRules: %v", err)
	}
	if len(all) != 3 {
		t.Errorf("ListAllEnabledRules: got %d, want 3", len(all))
	}

	// Disable a rule
	if err := s.SetRuleEnabled(r2.ID, "cred-1", false); err != nil {
		t.Fatalf("SetRuleEnabled: %v", err)
	}
	all, _ = s.ListAllEnabledRules()
	if len(all) != 2 {
		t.Errorf("ListAllEnabledRules after disable: got %d, want 2", len(all))
	}

	// Can't disable someone else's rule
	if err := s.SetRuleEnabled(r3.ID, "cred-1", false); err != sql.ErrNoRows {
		t.Errorf("SetRuleEnabled(wrong cred) err = %v, want sql.ErrNoRows", err)
	}

	// Delete
	if err := s.DeleteRule(r1.ID, "cred-1"); err != nil {
		t.Fatalf("DeleteRule: %v", err)
	}
	rules, _ = s.ListRules("cred-1")
	if len(rules) != 1 {
		t.Errorf("ListRules after delete: got %d, want 1", len(rules))
	}

	// Can't delete someone else's rule
	if err := s.DeleteRule(r3.ID, "cred-1"); err != sql.ErrNoRows {
		t.Errorf("DeleteRule(wrong cred) err = %v, want sql.ErrNoRows", err)
	}
}
