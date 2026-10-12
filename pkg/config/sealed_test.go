package config

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const testPassphrase = "correct horse battery"

// newTestStore returns a store in a fresh temp config dir.
func newTestStore(t *testing.T) *SessionStore {
	t.Helper()
	t.Setenv(EnvConfigDir, t.TempDir())
	store, err := NewSessionStore()
	if err != nil {
		t.Fatalf("NewSessionStore: %v", err)
	}
	return store
}

// readSessionFile returns the raw bytes of session.json.
func readSessionFile(t *testing.T, store *SessionStore) []byte {
	t.Helper()
	data, err := os.ReadFile(store.sessionPath())
	if err != nil {
		t.Fatalf("reading session.json: %v", err)
	}
	return data
}

// promptReturning returns a PromptPassphrase func answering passphrase and
// counting its calls.
func promptReturning(passphrase string, calls *int) func() (string, error) {
	return func() (string, error) {
		*calls++
		return passphrase, nil
	}
}

func TestSealedSessionRoundTrip(t *testing.T) {
	store := newTestStore(t)
	if err := store.EncryptWith(testPassphrase); err != nil {
		t.Fatalf("EncryptWith: %v", err)
	}
	sess := Session{UID: "uid-plain", AccessToken: "acc-plain", RefreshToken: "ref-plain", SaltedKeyPass: []byte("keypass-plain")}
	if err := store.Save(sess); err != nil {
		t.Fatalf("Save: %v", err)
	}

	raw := readSessionFile(t, store)
	if !isSealed(raw) {
		t.Fatalf("session.json not sealed: %s", raw)
	}
	for _, secret := range []string{"uid-plain", "acc-plain", "ref-plain", "keypass-plain", "a2V5cGFzcy1wbGFpbg"} {
		if strings.Contains(string(raw), secret) {
			t.Errorf("session.json contains %q in plaintext", secret)
		}
	}

	// A fresh store (a later command) unlocks it with one prompt, and token
	// rotations re-seal under the same salt without prompting again.
	later, err := NewSessionStore()
	if err != nil {
		t.Fatalf("NewSessionStore: %v", err)
	}
	calls := 0
	later.PromptPassphrase = promptReturning(testPassphrase, &calls)
	got, err := later.Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if got.UID != "uid-plain" || string(got.SaltedKeyPass) != "keypass-plain" {
		t.Errorf("loaded session = %+v", got)
	}
	if err := later.UpdateTokens("uid2", "acc2", "ref2"); err != nil {
		t.Fatalf("UpdateTokens: %v", err)
	}
	got, err = later.Load()
	if err != nil {
		t.Fatalf("Load after rotate: %v", err)
	}
	if got.AccessToken != "acc2" || string(got.SaltedKeyPass) != "keypass-plain" {
		t.Errorf("rotated session = %+v", got)
	}
	if calls != 1 {
		t.Errorf("passphrase prompted %d times, want 1", calls)
	}

	rotated := readSessionFile(t, store)
	if !isSealed(rotated) || strings.Contains(string(rotated), "acc2") {
		t.Errorf("rotation did not keep the session sealed: %s", rotated)
	}
	before, _ := parseSealed(raw)
	after, _ := parseSealed(rotated)
	if !before.KDF.equal(after.KDF) {
		t.Error("rotation changed the KDF parameters")
	}
	if string(before.Nonce) == string(after.Nonce) {
		t.Error("rotation reused the nonce")
	}
}

func TestSealedSessionWrongPassphrase(t *testing.T) {
	store := newTestStore(t)
	if err := store.EncryptWith(testPassphrase); err != nil {
		t.Fatalf("EncryptWith: %v", err)
	}
	if err := store.Save(Session{UID: "u", AccessToken: "a", RefreshToken: "r"}); err != nil {
		t.Fatalf("Save: %v", err)
	}

	later, err := NewSessionStore()
	if err != nil {
		t.Fatalf("NewSessionStore: %v", err)
	}
	calls := 0
	later.PromptPassphrase = promptReturning("not the passphrase", &calls)
	if _, err := later.Load(); !errors.Is(err, ErrWrongPassphrase) {
		t.Fatalf("Load with wrong passphrase = %v, want ErrWrongPassphrase", err)
	}

	// The wrong key is not cached: a retry prompts again and can succeed.
	later.PromptPassphrase = promptReturning(testPassphrase, &calls)
	if _, err := later.Load(); err != nil {
		t.Fatalf("Load with right passphrase: %v", err)
	}
	if calls != 2 {
		t.Errorf("prompted %d times, want 2", calls)
	}
}

func TestSealedSessionLockedWithoutPrompt(t *testing.T) {
	store := newTestStore(t)
	if err := store.EncryptWith(testPassphrase); err != nil {
		t.Fatalf("EncryptWith: %v", err)
	}
	if err := store.Save(Session{UID: "u", AccessToken: "a", RefreshToken: "r"}); err != nil {
		t.Fatalf("Save: %v", err)
	}
	later, err := NewSessionStore()
	if err != nil {
		t.Fatalf("NewSessionStore: %v", err)
	}
	if _, err := later.Load(); !errors.Is(err, ErrSessionLocked) {
		t.Fatalf("Load without prompt = %v, want ErrSessionLocked", err)
	}
	// UpdateTokens must not overwrite a session it cannot read.
	if err := later.UpdateTokens("u2", "a2", "r2"); !errors.Is(err, ErrSessionLocked) {
		t.Fatalf("UpdateTokens without prompt = %v, want ErrSessionLocked", err)
	}
}

func TestEncryptWithRejectsShortPassphrase(t *testing.T) {
	store := newTestStore(t)
	if err := store.EncryptWith("short"); err == nil {
		t.Fatal("EncryptWith accepted a 5-character passphrase")
	}
	if store.getKey() != nil {
		t.Error("rejected passphrase still set a key")
	}
}

// Saves follow the on-disk format: once another login replaces the session
// with a plaintext one, a store that held a key stops sealing.
func TestPlaintextSessionStaysPlaintext(t *testing.T) {
	store := newTestStore(t)
	if err := store.EncryptWith(testPassphrase); err != nil {
		t.Fatalf("EncryptWith: %v", err)
	}
	if err := store.Save(Session{UID: "u", AccessToken: "a", RefreshToken: "r"}); err != nil {
		t.Fatalf("Save: %v", err)
	}

	other, err := NewSessionStore()
	if err != nil {
		t.Fatalf("NewSessionStore: %v", err)
	}
	if err := other.Save(Session{UID: "u2", AccessToken: "a2", RefreshToken: "r2"}); err != nil {
		t.Fatalf("plaintext Save: %v", err)
	}

	if err := store.UpdateTokens("u3", "a3", "r3"); err != nil {
		t.Fatalf("UpdateTokens: %v", err)
	}
	if raw := readSessionFile(t, store); isSealed(raw) {
		t.Error("UpdateTokens sealed a session that was plaintext on disk")
	}
}

// A corrupt file with absurd KDF parameters is rejected rather than driving a
// huge Argon2 allocation.
func TestSealedSessionRejectsBadKDFParams(t *testing.T) {
	store := newTestStore(t)
	data, err := json.Marshal(sealedSession{
		Sealed: sealedVersion,
		KDF:    kdfParams{Salt: make([]byte, 16), Time: 3, Memory: 1 << 30, Threads: 4},
		Nonce:  make([]byte, 12),
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(store.dir, sessionFile), data, 0o600); err != nil {
		t.Fatal(err)
	}
	calls := 0
	store.PromptPassphrase = promptReturning(testPassphrase, &calls)
	if _, err := store.Load(); err == nil || !strings.Contains(err.Error(), "invalid key-derivation parameters") {
		t.Fatalf("Load = %v, want invalid-parameters error", err)
	}
	if calls != 0 {
		t.Error("prompted for a passphrase on an invalid file")
	}
}
