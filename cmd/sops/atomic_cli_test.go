package main

import (
	"bytes"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"filippo.io/age"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/getsops/sops/v3"
	"github.com/getsops/sops/v3/aes"
	sopsage "github.com/getsops/sops/v3/age"
	"github.com/getsops/sops/v3/cmd/sops/common"
	"github.com/getsops/sops/v3/config"
	"github.com/getsops/sops/v3/keyservice"
	"github.com/getsops/sops/v3/stores/json"
)

// reexecEnv makes the test binary run main() instead of the test harness,
// turning `go test` into a real sops subprocess.
const reexecEnv = "SOPS_ATOMIC_TEST_REEXEC"

// TestMain dispatches to the real CLI when launched as a sops subprocess.
func TestMain(m *testing.M) {
	if os.Getenv(reexecEnv) == "1" {
		main()
		return
	}
	os.Exit(m.Run())
}

type ageKeyPair struct {
	identity  string
	recipient string
}

func genAgeKey(t *testing.T) ageKeyPair {
	t.Helper()
	id, err := age.GenerateX25519Identity()
	require.NoError(t, err)
	return ageKeyPair{identity: id.String(), recipient: id.Recipient().String()}
}

// writeEncryptedFixture creates a real sops-encrypted JSON file at path.
func writeEncryptedFixture(t *testing.T, path, recipient string, mode os.FileMode) {
	t.Helper()
	store := json.NewStore(&config.JSONStoreConfig{})
	branches, err := store.LoadPlainFile([]byte(`{"field":"secret-value"}`))
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
	require.NoError(t, common.EncryptTree(common.EncryptTreeOpts{
		Tree: &tree, Cipher: aes.NewCipher(), DataKey: dataKey,
	}))
	out, err := store.EmitEncryptedFile(tree)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(path, out, mode))
}

// runSops executes the test binary as a sops subprocess with the given
// arguments and age identity available.
func runSops(t *testing.T, key ageKeyPair, args ...string) (string, int) {
	t.Helper()
	cmd := exec.Command(os.Args[0], args...)
	cmd.Env = append(os.Environ(), reexecEnv+"=1", "SOPS_AGE_KEY="+key.identity)
	var combined bytes.Buffer
	cmd.Stdout = &combined
	cmd.Stderr = &combined
	err := cmd.Run()
	code := 0
	if err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			code = exitErr.ExitCode()
		} else {
			code = -1
		}
	}
	return combined.String(), code
}

// Two real sops processes rotating the same file: exactly one must commit,
// the other must fail with a lock/conflict indication, and the surviving
// file must still decrypt.
func TestCLIConcurrentRotatesOneWins(t *testing.T) {
	key := genAgeKey(t)
	dir := t.TempDir()
	target := filepath.Join(dir, "secret.json")
	writeEncryptedFixture(t, target, key.recipient, 0o640)

	const procs = 4
	var wg sync.WaitGroup
	type result struct {
		code int
		out  string
	}
	results := make(chan result, procs)
	start := make(chan struct{})
	for i := 0; i < procs; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			out, code := runSops(t, key, "rotate", "-i", target)
			results <- result{code: code, out: out}
		}()
	}
	close(start)
	wg.Wait()
	close(results)

	successes, failures := 0, 0
	for r := range results {
		if r.code == 0 {
			successes++
			continue
		}
		failures++
		assert.Contains(t, strings.ToLower(r.out), "write",
			"the losing process must explain the write-level failure")
	}
	assert.Equal(t, 1, successes, "exactly one process may replace the file")
	assert.Equal(t, procs-1, failures)

	// The surviving file must be a complete, decryptable document.
	out, code := runSops(t, key, "decrypt", target)
	require.Equal(t, 0, code, "surviving file must decrypt: %s", out)
	assert.Contains(t, out, "secret-value")

	// No staging leftovers.
	entries, err := os.ReadDir(dir)
	require.NoError(t, err)
	for _, e := range entries {
		assert.False(t, strings.HasSuffix(e.Name(), ".tmp"),
			"staging file left behind: %s", e.Name())
	}
}

// A sops process killed mid-write must leave a decryptable file and no
// staging artifacts on the next run.
func TestCLIKillMidWriteLeavesDecryptableFile(t *testing.T) {
	key := genAgeKey(t)
	dir := t.TempDir()
	target := filepath.Join(dir, "secret.json")
	writeEncryptedFixture(t, target, key.recipient, 0o640)

	// A tight loop of rotate processes, some of which get SIGKILLed, must
	// never produce an undecryptable or empty target.
	for round := 0; round < 6; round++ {
		cmd := exec.Command(os.Args[0], "rotate", "-i", target)
		cmd.Env = append(os.Environ(), reexecEnv+"=1", "SOPS_AGE_KEY="+key.identity)
		require.NoError(t, cmd.Start())

		// Kill it after a short, deliberately racy delay. Whether the kill
		// lands before, during or after the commit, the file must stay
		// valid.
		killer := time.AfterFunc(time.Duration(1+round%3)*time.Millisecond, func() {
			_ = cmd.Process.Kill()
		})
		_ = cmd.Wait()
		killer.Stop()

		// Every round the file must still decrypt.
		out, code := runSops(t, key, "decrypt", target)
		require.Equalf(t, 0, code, "round %d: file undecryptable after kill: %s", round, out)
		assert.Contains(t, out, "secret-value")
	}

	// A final clean rotate must succeed and reclaim any crash leftovers.
	out, code := runSops(t, key, "rotate", "-i", target)
	require.Equalf(t, 0, code, "cleanup rotate failed: %s", out)

	entries, err := os.ReadDir(dir)
	require.NoError(t, err)
	for _, e := range entries {
		assert.False(t, strings.HasSuffix(e.Name(), ".tmp"),
			"staging artifact survives after restart: %s", e.Name())
	}
}

// Permissions and symlink semantics through the real CLI.
func TestCLIPreservesModeAndSymlink(t *testing.T) {
	key := genAgeKey(t)
	dir := t.TempDir()

	t.Run("mode_preserved", func(t *testing.T) {
		target := filepath.Join(dir, "mode.json")
		writeEncryptedFixture(t, target, key.recipient, 0o600)
		out, code := runSops(t, key, "rotate", "-i", target)
		require.Equalf(t, 0, code, out)
		info, err := os.Stat(target)
		require.NoError(t, err)
		assert.Equal(t, os.FileMode(0o600), info.Mode().Perm())
	})

	t.Run("readonly_mode_preserved", func(t *testing.T) {
		target := filepath.Join(dir, "ro.json")
		writeEncryptedFixture(t, target, key.recipient, 0o400)
		out, code := runSops(t, key, "rotate", "-i", target)
		require.Equalf(t, 0, code, out, "rename-based replace must not need target write bit")
		info, err := os.Stat(target)
		require.NoError(t, err)
		assert.Equal(t, os.FileMode(0o400), info.Mode().Perm())
	})

	t.Run("symlink_survives", func(t *testing.T) {
		real := filepath.Join(dir, "real.json")
		link := filepath.Join(dir, "link.json")
		writeEncryptedFixture(t, real, key.recipient, 0o640)
		require.NoError(t, os.Symlink(real, link))

		out, code := runSops(t, key, "rotate", "-i", link)
		require.Equalf(t, 0, code, out)

		target, err := os.Readlink(link)
		require.NoError(t, err)
		assert.Equal(t, real, target, "symlink must still point at the real file")
	})
}

// A read-only directory must be rejected before any write, with the target
// left intact.
func TestCLIReadOnlyDirectoryRejected(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("read-only directory checks are meaningless for root")
	}
	key := genAgeKey(t)
	dir := t.TempDir()
	target := filepath.Join(dir, "secret.json")
	writeEncryptedFixture(t, target, key.recipient, 0o640)
	before, err := os.ReadFile(target)
	require.NoError(t, err)
	require.NoError(t, os.Chmod(dir, 0o500))
	t.Cleanup(func() { _ = os.Chmod(dir, 0o700) })

	out, code := runSops(t, key, "rotate", "-i", target)
	assert.NotEqual(t, 0, code)
	assert.Contains(t, strings.ToLower(out), "preflight")

	after, err := os.ReadFile(target)
	require.NoError(t, err)
	assert.Equal(t, before, after)
}
