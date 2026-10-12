package auth

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ProtonMail/go-proton-api/server"

	"github.com/cheeseandcereal/proton-cal/pkg/config"
	"github.com/cheeseandcereal/proton-cal/pkg/papi"
)

// The in-memory test server implements neither the "locked" scope nor the
// unlock endpoints, so Login's unlockScope fallback is NOT exercised here; it
// is covered by live integration runs.

// scriptPrompter is a scripted fake Prompter. Answers are looked up by
// prompt label; unexpected prompts fail the flow.
type scriptPrompter struct {
	t       *testing.T
	answers map[string]string
	notices []string
}

func (p *scriptPrompter) lookup(label string) (string, error) {
	answer, ok := p.answers[label]
	if !ok {
		return "", fmt.Errorf("unexpected prompt %q", label)
	}
	return answer, nil
}

func (p *scriptPrompter) Prompt(label string) (string, error)       { return p.lookup(label) }
func (p *scriptPrompter) PromptSecret(label string) (string, error) { return p.lookup(label) }

func (p *scriptPrompter) Notify(msg string) {
	p.notices = append(p.notices, msg)
	p.t.Logf("notify: %s", msg)
}

const (
	testUser = "user"
	testPass = "pass"
)

// startServer starts a plain-HTTP test server with one user (config dir in a
// temp dir, config.toml targeting it) and returns the created address ID.
func startServer(t *testing.T) (addrID string) {
	t.Helper()
	t.Setenv(config.EnvConfigDir, t.TempDir())

	// Plain HTTP: both the proton.Manager (default transport) and the papi
	// raw client must be able to talk to it without a custom TLS config.
	s := server.New(server.WithTLS(false))
	t.Cleanup(s.Close)

	_, addrID, err := s.CreateUser(testUser, []byte(testPass))
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}

	if err := config.Save(config.Config{BaseURL: s.GetHostURL()}); err != nil {
		t.Fatalf("config.Save: %v", err)
	}
	return addrID
}

// login runs Login with an unencrypted session and persists the
// username/timezone the way the CLI login command does.
func login(t *testing.T) { loginWith(t, "") }

// loginWith is login, sealing the session under passphrase when non-empty.
func loginWith(t *testing.T, passphrase string) {
	t.Helper()
	prompter := &scriptPrompter{t: t, answers: map[string]string{
		"Proton username/email": testUser,
		"Password":              testPass,
	}}
	if passphrase != "" {
		prompter.answers["Session passphrase"] = passphrase
		prompter.answers["Confirm session passphrase"] = passphrase
	}
	cfg, err := config.Load()
	if err != nil {
		t.Fatalf("config.Load: %v", err)
	}
	username, err := Login(context.Background(), prompter, cfg, passphrase != "")
	if err != nil {
		t.Fatalf("Login: %v", err)
	}
	cfg.Username = username
	if cfg.Timezone == "" {
		cfg.Timezone = config.DetectTimezone()
	}
	if err := config.Save(cfg); err != nil {
		t.Fatalf("config.Save: %v", err)
	}
}

func TestLoginHappyPathAndUnlockKeys(t *testing.T) {
	addrID := startServer(t)
	login(t)

	store, err := config.NewSessionStore()
	if err != nil {
		t.Fatalf("NewSessionStore: %v", err)
	}
	sess, err := store.Load()
	if err != nil {
		t.Fatalf("store.Load: %v", err)
	}
	if !sess.Valid() {
		t.Errorf("persisted session not valid: %+v", sess)
	}
	if len(sess.SaltedKeyPass) == 0 {
		t.Error("persisted session has empty SaltedKeyPass")
	}

	cfg, err := config.Load()
	if err != nil {
		t.Fatalf("config.Load: %v", err)
	}
	if cfg.Username != testUser {
		t.Errorf("config username = %q, want %q", cfg.Username, testUser)
	}
	if cfg.Timezone == "" {
		t.Error("config timezone not recorded on first login")
	}

	// Restore the session as a later command would, and unlock keys from the
	// stored salted passphrase (no password prompt involved).
	client, err := papi.FromSession(store, cfg.EffectiveBaseURL())
	if err != nil {
		t.Fatalf("papi.FromSession: %v", err)
	}
	unlocked, err := UnlockKeys(context.Background(), client.Store(), client)
	if err != nil {
		t.Fatalf("UnlockKeys: %v", err)
	}
	if len(unlocked.AddrKRs) == 0 {
		t.Fatal("UnlockKeys returned no unlocked address keyrings")
	}
	if _, ok := unlocked.AddrKRs[addrID]; !ok {
		t.Errorf("address %s missing from unlocked keyrings", addrID)
	}
}

func TestLoginUsesConfiguredUsername(t *testing.T) {
	startServer(t)

	// Pre-set the username; Login must not prompt for it (the scripted
	// prompter has no answer for the username label and would fail).
	cfg, err := config.Load()
	if err != nil {
		t.Fatalf("config.Load: %v", err)
	}
	cfg.Username = testUser
	if err := config.Save(cfg); err != nil {
		t.Fatalf("config.Save: %v", err)
	}

	prompter := &scriptPrompter{t: t, answers: map[string]string{
		"Password": testPass,
	}}
	cfg, err = config.Load()
	if err != nil {
		t.Fatalf("config.Load: %v", err)
	}
	if _, err := Login(context.Background(), prompter, cfg, false); err != nil {
		t.Fatalf("Login: %v", err)
	}
}

func TestUnlockKeysMissingSaltedKeyPass(t *testing.T) {
	startServer(t)

	store, err := config.NewSessionStore()
	if err != nil {
		t.Fatalf("NewSessionStore: %v", err)
	}
	// A session with tokens but no salted key passphrase (e.g. written by an
	// older version, or a partial login).
	if err := store.Save(config.Session{
		UID:          "uid",
		AccessToken:  "acc",
		RefreshToken: "ref",
	}); err != nil {
		t.Fatalf("store.Save: %v", err)
	}

	cfg, err := config.Load()
	if err != nil {
		t.Fatalf("config.Load: %v", err)
	}
	client, err := papi.FromSession(store, cfg.EffectiveBaseURL())
	if err != nil {
		t.Fatalf("papi.FromSession: %v", err)
	}

	_, err = UnlockKeys(context.Background(), client.Store(), client)
	if err == nil {
		t.Fatal("UnlockKeys succeeded with missing SaltedKeyPass")
	}
	if !strings.Contains(err.Error(), "proton-cal login") {
		t.Errorf("error %q does not direct the user to `proton-cal login`", err)
	}
}

func TestLogout(t *testing.T) {
	startServer(t)
	login(t)

	if err := Logout(context.Background(), &scriptPrompter{t: t}); err != nil {
		t.Fatalf("Logout: %v", err)
	}

	store, err := config.NewSessionStore()
	if err != nil {
		t.Fatalf("NewSessionStore: %v", err)
	}
	if _, err := store.Load(); !errors.Is(err, config.ErrNoSession) {
		t.Errorf("session not cleared after Logout: err = %v", err)
	}

	// A second logout with no session is not an error.
	if err := Logout(context.Background(), &scriptPrompter{t: t}); err != nil {
		t.Errorf("second Logout: %v", err)
	}
}

const testSessionPass = "correct horse battery"

// An encrypted login seals session.json: no secret is readable on disk, a
// restore without a prompt is locked, and with the passphrase (prompted once)
// the keys still unlock.
func TestLoginEncryptedSession(t *testing.T) {
	addrID := startServer(t)
	loginWith(t, testSessionPass)

	cfg, err := config.Load()
	if err != nil {
		t.Fatalf("config.Load: %v", err)
	}

	locked, err := config.NewSessionStore()
	if err != nil {
		t.Fatalf("NewSessionStore: %v", err)
	}
	if _, err := papi.FromSession(locked, cfg.EffectiveBaseURL()); !errors.Is(err, config.ErrSessionLocked) {
		t.Fatalf("FromSession without a prompt = %v, want ErrSessionLocked", err)
	}

	store, err := config.NewSessionStore()
	if err != nil {
		t.Fatalf("NewSessionStore: %v", err)
	}
	prompts := 0
	store.PromptPassphrase = func() (string, error) { prompts++; return testSessionPass, nil }
	client, err := papi.FromSession(store, cfg.EffectiveBaseURL())
	if err != nil {
		t.Fatalf("papi.FromSession: %v", err)
	}
	defer client.Close()
	unlocked, err := UnlockKeys(context.Background(), client.Store(), client)
	if err != nil {
		t.Fatalf("UnlockKeys: %v", err)
	}
	if _, ok := unlocked.AddrKRs[addrID]; !ok {
		t.Errorf("address %s missing from unlocked keyrings", addrID)
	}
	if prompts != 1 {
		t.Errorf("passphrase prompted %d times, want 1", prompts)
	}

	sess, err := store.Load()
	if err != nil {
		t.Fatalf("store.Load: %v", err)
	}
	dir, err := config.Dir()
	if err != nil {
		t.Fatalf("config.Dir: %v", err)
	}
	raw, err := os.ReadFile(filepath.Join(dir, "session.json"))
	if err != nil {
		t.Fatalf("reading session.json: %v", err)
	}
	for _, secret := range []string{sess.UID, sess.AccessToken, sess.RefreshToken, "access_token", "salted_key_pass"} {
		if strings.Contains(string(raw), secret) {
			t.Errorf("session.json contains %q in plaintext", secret)
		}
	}
}

// A mismatched passphrase confirmation aborts before anything is saved.
func TestLoginPassphraseMismatch(t *testing.T) {
	startServer(t)
	prompter := &scriptPrompter{t: t, answers: map[string]string{
		"Proton username/email":      testUser,
		"Password":                   testPass,
		"Session passphrase":         testSessionPass,
		"Confirm session passphrase": testSessionPass + "x",
	}}
	if _, err := Login(context.Background(), prompter, config.Config{}, true); err == nil || !strings.Contains(err.Error(), "do not match") {
		t.Fatalf("Login = %v, want a mismatch error", err)
	}
	store, err := config.NewSessionStore()
	if err != nil {
		t.Fatalf("NewSessionStore: %v", err)
	}
	if _, err := store.Load(); !errors.Is(err, config.ErrNoSession) {
		t.Errorf("session saved despite mismatch: err = %v", err)
	}
}

// Logout with a wrong (forgotten) passphrase still removes the session
// locally, warning that it was not revoked.
func TestLogoutWrongPassphrase(t *testing.T) {
	startServer(t)
	loginWith(t, testSessionPass)

	prompter := &scriptPrompter{t: t, answers: map[string]string{"Session passphrase": "forgotten-it"}}
	if err := Logout(context.Background(), prompter); err != nil {
		t.Fatalf("Logout: %v", err)
	}
	if len(prompter.notices) == 0 || !strings.Contains(prompter.notices[0], "without revoking") {
		t.Errorf("notices = %q, want a not-revoked warning", prompter.notices)
	}
	store, err := config.NewSessionStore()
	if err != nil {
		t.Fatalf("NewSessionStore: %v", err)
	}
	if _, err := store.Load(); !errors.Is(err, config.ErrNoSession) {
		t.Errorf("session not cleared: err = %v", err)
	}
}

func TestPrimaryAddrKR(t *testing.T) {
	addrID := startServer(t)
	login(t)

	store, err := config.NewSessionStore()
	if err != nil {
		t.Fatalf("NewSessionStore: %v", err)
	}
	cfg, err := config.Load()
	if err != nil {
		t.Fatalf("config.Load: %v", err)
	}
	client, err := papi.FromSession(store, cfg.EffectiveBaseURL())
	if err != nil {
		t.Fatalf("papi.FromSession: %v", err)
	}
	unlocked, err := UnlockKeys(context.Background(), client.Store(), client)
	if err != nil {
		t.Fatalf("UnlockKeys: %v", err)
	}

	// Exact hit.
	kr, err := unlocked.PrimaryAddrKR(addrID)
	if err != nil {
		t.Fatalf("PrimaryAddrKR(%s): %v", addrID, err)
	}
	if kr != unlocked.AddrKRs[addrID] {
		t.Error("PrimaryAddrKR returned a different keyring than the exact match")
	}

	// Unknown address ID falls back to an unlocked keyring.
	kr, err = unlocked.PrimaryAddrKR("no-such-address")
	if err != nil {
		t.Fatalf("PrimaryAddrKR fallback: %v", err)
	}
	if kr == nil {
		t.Error("PrimaryAddrKR fallback returned nil keyring")
	}

	// No unlocked keyrings at all is an error.
	empty := &Unlocked{}
	if _, err := empty.PrimaryAddrKR("anything"); err == nil {
		t.Error("PrimaryAddrKR on empty Unlocked did not error")
	}
}
