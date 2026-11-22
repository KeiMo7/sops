package common

import (
	"os"
	"path/filepath"
	"testing"

	"filippo.io/age"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/getsops/sops/v3"
	"github.com/getsops/sops/v3/aes"
	sopsage "github.com/getsops/sops/v3/age"
	"github.com/getsops/sops/v3/cmd/sops/atomic"
	"github.com/getsops/sops/v3/config"
	"github.com/getsops/sops/v3/keyservice"
	"github.com/getsops/sops/v3/stores/json"
)

func newJSONStore() *json.Store {
	return json.NewStore(&config.JSONStoreConfig{})
}

// newAgeTestIdentity generates a fresh age identity and returns the secret
// (for the local key service) and recipient (for encryption).
func newAgeTestIdentity(t *testing.T) (identity, recipient string) {
	t.Helper()
	id, err := age.GenerateX25519Identity()
	require.NoError(t, err)
	return id.String(), id.Recipient().String()
}

// buildEncryptedFile produces a real, decryptable SOPS JSON document in
// memory, encrypted for the given age recipient.
func buildEncryptedFile(t *testing.T, recipient string) []byte {
	t.Helper()
	store := newJSONStore()
	branches, err := store.LoadPlainFile([]byte(`{"secret":"value","nested":{"k":1}}`))
	require.NoError(t, err)

	mk, err := sopsage.MasterKeyFromRecipient(recipient)
	require.NoError(t, err)
	tree := sops.Tree{
		Branches: branches,
		Metadata: sops.Metadata{
			KeyGroups: []sops.KeyGroup{{mk}},
			Version:   "3.9.0",
		},
	}
	svcs := []keyservice.KeyServiceClient{keyservice.NewLocalClient()}
	dataKey, errs := tree.GenerateDataKeyWithKeyServices(svcs)
	require.Empty(t, errs)

	cipher := aes.NewCipher()
	require.NoError(t, EncryptTree(EncryptTreeOpts{
		Tree: &tree, Cipher: cipher, DataKey: dataKey,
	}))
	out, err := store.EmitEncryptedFile(tree)
	require.NoError(t, err)
	return out
}

// useAgeIdentity exposes the age identity to SOPS through the standard
// SOPS_AGE_KEY environment variable, which is how the verifier's freshly
// loaded trees locate the decryption key in a real CLI invocation.
func useAgeIdentity(t *testing.T, identity string) {
	t.Helper()
	t.Setenv("SOPS_AGE_KEY", identity)
}

func TestWriteFileRoundTripsRealEncryptedDocument(t *testing.T) {
	identity, recipient := newAgeTestIdentity(t)
	useAgeIdentity(t, identity)
	encrypted := buildEncryptedFile(t, recipient)
	svcs := []keyservice.KeyServiceClient{keyservice.NewLocalClient()}
	store := newJSONStore()

	dir := t.TempDir()
	target := filepath.Join(dir, "secret.json")
	require.NoError(t, os.WriteFile(target, encrypted, 0o640))

	// Simulate a rotate: decrypt, re-emit, then atomically replace with a
	// verifier that proves the result is decryptable.
	tree, err := LoadEncryptedFile(store, target)
	require.NoError(t, err)
	dataKey, err := DecryptTree(DecryptTreeOpts{
		Tree: tree, Cipher: aes.NewCipher(), KeyServices: svcs,
	})
	require.NoError(t, err)
	require.NoError(t, EncryptTree(EncryptTreeOpts{
		Tree: tree, Cipher: aes.NewCipher(), DataKey: dataKey,
	}))
	reEmitted, err := store.EmitEncryptedFile(*tree)
	require.NoError(t, err)

	verifier := EncryptedFileVerifier(store, aes.NewCipher(), svcs, nil, false)
	require.NoError(t, WriteFile(WriteFileOptions{
		Path: target, Data: reEmitted, Verify: verifier,
	}))

	// The file on disk must independently decrypt back to the same plaintext.
	reloaded, err := LoadEncryptedFile(store, target)
	require.NoError(t, err)
	_, err = DecryptTree(DecryptTreeOpts{
		Tree: reloaded, Cipher: aes.NewCipher(), KeyServices: svcs,
	})
	assert.NoError(t, err)
}

func TestVerifierRejectsUndecryptableStagingFile(t *testing.T) {
	_, recipient := newAgeTestIdentity(t)
	encrypted := buildEncryptedFile(t, recipient)
	svcs := []keyservice.KeyServiceClient{keyservice.NewLocalClient()}
	store := newJSONStore()

	dir := t.TempDir()
	target := filepath.Join(dir, "secret.json")
	require.NoError(t, os.WriteFile(target, encrypted, 0o640))

	// A verifier running without the matching identity must reject the
	// staged content and leave the good file untouched.
	verifier := func(path string) error {
		tree, lerr := store.LoadEncryptedFile(mustRead(t, path))
		if lerr != nil {
			return lerr
		}
		_, derr := DecryptTree(DecryptTreeOpts{
			Tree: &tree, Cipher: aes.NewCipher(), KeyServices: svcs,
		})
		return derr
	}

	err := WriteFile(WriteFileOptions{
		Path: target, Data: encrypted, Verify: verifier,
	})
	require.Error(t, err)

	got, readErr := os.ReadFile(target)
	require.NoError(t, readErr)
	assert.Equal(t, encrypted, got, "the good encrypted file must be untouched")
}

func mustRead(t *testing.T, path string) []byte {
	t.Helper()
	b, err := os.ReadFile(path)
	require.NoError(t, err)
	return b
}

func TestWriteFileMapsAtomicErrorToExitCode(t *testing.T) {
	_, recipient := newAgeTestIdentity(t)
	encrypted := buildEncryptedFile(t, recipient)

	dir := t.TempDir()
	target := filepath.Join(dir, "secret.json")
	require.NoError(t, os.WriteFile(target, encrypted, 0o640))
	require.NoError(t, os.Chmod(dir, 0o500))
	t.Cleanup(func() { _ = os.Chmod(dir, 0o700) })

	err := WriteFile(WriteFileOptions{Path: target, Data: []byte("x")})
	require.Error(t, err)
	// The CLI-facing error keeps the established exit code.
	exitErr, ok := err.(interface{ ExitCode() int })
	require.True(t, ok, "error must carry an exit code")
	assert.Equal(t, 3, exitErr.ExitCode(), "CouldNotWriteOutputFile code must be preserved")
}

func TestIsWriteConflictAndLocked(t *testing.T) {
	assert.True(t, IsWriteConflict(atomic.ErrConflict))
	assert.True(t, IsWriteLocked(atomic.ErrLocked))
	assert.False(t, IsWriteConflict(atomic.ErrLocked))
	assert.False(t, IsWriteLocked(atomic.ErrConflict))
	assert.False(t, IsWriteConflict(assert.AnError))
}
