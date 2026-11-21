package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/getsops/sops/v3/rotation"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/urfave/cli"
)

// These identities/recipients are throwaway values generated for tests. They
// are public in this repository and protect nothing.
const (
	testIdentityOld  = "AGE-SECRET-KEY-1G0Q5K9TV4REQ3ZSQRMTMG8NSWQGYT0T7TZ33RAZEE0GZYVZN0APSU24RK7"
	testOldRecipient = "age1lzd99uklcjnc0e7d860axevet2cz99ce9pq6tzuzd05l5nr28ams36nvun"
	testIdentityNew  = "AGE-SECRET-KEY-1432K5YRNSC44GC4986NXMX6GVZ52WTMT9C79CLUVWYY4DKDHD5JSNDP4MC"
	// testNewRecipient is the recipient matching testIdentityNew. It is a
	// different key pair than the one the old identity decodes, on purpose.
	testNewRecipient = "age12t2vxw673xp4j93zvzaf2xahncjensvw7llydpxr0q9kyjrx8f4qfap2us"
)

func setupRotationFixture(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("SOPS_AGE_KEY", testIdentityOld+" "+testIdentityNew)
	t.Setenv("SOPS_AGE_KEY_FILE", "")

	write := func(name, content string) string {
		path := filepath.Join(dir, name)
		require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o755))
		require.NoError(t, os.WriteFile(path, []byte(content), 0o644))
		return path
	}
	for _, name := range []string{"a.yaml", "b.yaml", "broken.yaml"} {
		path := write(name, "foo: bar\nsecret: s3cr3t\n")
		require.NoError(t, encryptFileForTest(t, path, testOldRecipient))
	}
	// Corrupt one ciphertext so its decryption fails.
	broken := filepath.Join(dir, "broken.yaml")
	data, err := os.ReadFile(broken)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(broken, []byte(strings.Replace(string(data), "ENC[AES256_GCM,data:", "ENC[AES256_GCM,data:XX", 1)), 0o644))

	write("notes.txt", "not a sops file\n")
	return dir
}

// encryptFileForTest encrypts path in place with the given age recipient.
func encryptFileForTest(t *testing.T, path, recipient string) error {
	t.Helper()
	return runApp(t, "encrypt", "--age", recipient, "--in-place", path)
}

// runApp runs the sops CLI in-process with the given arguments. The exit
// handler is stubbed out so a non-zero exit is returned as an error instead of
// terminating the test process.
func runApp(t *testing.T, args ...string) error {
	t.Helper()
	app := newApp()
	app.ExitErrHandler = func(*cli.Context, error) {}
	return app.Run(append([]string{"sops"}, args...))
}

func readTrail(t *testing.T, dir string) []rotation.Record {
	t.Helper()
	records, spans, err := rotation.ReadAll(rotation.NewWriter(filepath.Join(dir, "trail")).Path())
	require.NoError(t, err)
	require.Empty(t, spans)
	return records
}

func TestRotateWithLogAllSuccess(t *testing.T) {
	dir := setupRotationFixture(t)
	// Remove the corrupt file so this scenario is "all success".
	require.NoError(t, os.Remove(filepath.Join(dir, "broken.yaml")))
	require.NoError(t, os.Remove(filepath.Join(dir, "notes.txt")))

	err := runApp(t, "rotate", "--rotation-log", filepath.Join(dir, "trail"),
		"--rotation-root", dir,
		"--add-age", testNewRecipient, "--rm-age", testOldRecipient, "--in-place",
		filepath.Join(dir, "a.yaml"), filepath.Join(dir, "b.yaml"))
	require.NoError(t, err)

	records := readTrail(t, dir)
	var files, summaries int
	for _, record := range records {
		switch record.Kind {
		case rotation.KindFile:
			files++
			assert.Equal(t, rotation.StatusSuccess, record.Status)
			assert.Equal(t, rotation.OutcomeRotated, record.Outcome)
			assert.NotEmpty(t, record.NewDataKeyFingerprint)
			assert.NotEmpty(t, record.MasterKeysAdded)
		case rotation.KindSummary:
			summaries++
			require.NotNil(t, record.Totals)
			assert.Equal(t, 2, record.Totals.Total)
			assert.Equal(t, 2, record.Totals.Succeeded)
			assert.Equal(t, 0, record.Totals.Failed)
		}
	}
	assert.Equal(t, 2, files)
	assert.Equal(t, 1, summaries)
}

func TestRotateWithLogPartialSkip(t *testing.T) {
	dir := setupRotationFixture(t)
	require.NoError(t, os.Remove(filepath.Join(dir, "broken.yaml")))

	args := []string{"rotate", "--rotation-log", filepath.Join(dir, "trail"),
		"--rotation-root", dir,
		"--add-age", testNewRecipient, "--rm-age", testOldRecipient, "--in-place"}
	require.NoError(t, runApp(t, append(args, dir)...))

	// Second run: a.yaml and b.yaml are already rotated; notes.txt is not a
	// supported SOPS file.
	require.NoError(t, runApp(t, append(args, dir)...))

	records := readTrail(t, dir)
	var skipReasons = map[string]int{}
	for _, record := range records {
		if record.Kind == rotation.KindFile && record.Status == rotation.StatusSkipped {
			skipReasons[record.SkipReason]++
		}
	}
	assert.Equal(t, 2, skipReasons[rotation.SkipAlreadyRotated], "both files must be skipped on the second run")
	assert.Equal(t, 2, skipReasons[rotation.SkipUnsupportedFormat], "notes.txt must be recorded as unsupported both runs")
}

func TestRotateWithLogPartialFailure(t *testing.T) {
	dir := setupRotationFixture(t)

	err := runApp(t, "rotate", "--rotation-log", filepath.Join(dir, "trail"),
		"--rotation-root", dir,
		"--add-age", testNewRecipient, "--rm-age", testOldRecipient, "--in-place", dir)
	require.Error(t, err, "a failed file must make the run exit non-zero")

	records := readTrail(t, dir)
	var failed, succeeded int
	var decryptFailure *rotation.Record
	for i := range records {
		record := records[i]
		if record.Kind != rotation.KindFile {
			continue
		}
		switch record.Status {
		case rotation.StatusFailed:
			failed++
			if record.File == "broken.yaml" {
				decryptFailure = &record
			}
		case rotation.StatusSuccess:
			succeeded++
		}
	}
	assert.Equal(t, 1, failed)
	assert.Equal(t, 2, succeeded, "healthy files must still be rotated")
	require.NotNil(t, decryptFailure)
	assert.Equal(t, rotation.ErrorDecrypt, decryptFailure.ErrorKind)
}

func TestRotateWithLogPartialFailureKeepsEveryHandledRecord(t *testing.T) {
	dir := setupRotationFixture(t)

	// Put the broken file first in walk order so it is handled before the
	// healthy files; a failure must not abort the run.
	brokenDir := filepath.Join(dir, "aaa")
	require.NoError(t, os.MkdirAll(brokenDir, 0o755))
	require.NoError(t, os.Rename(filepath.Join(dir, "broken.yaml"), filepath.Join(brokenDir, "broken.yaml")))

	err := runApp(t, "rotate", "--rotation-log", filepath.Join(dir, "trail"),
		"--rotation-root", dir,
		"--add-age", testNewRecipient, "--rm-age", testOldRecipient, "--in-place", dir)
	require.Error(t, err)

	records := readTrail(t, dir)
	// Every handled file must have an intact record, including the failed
	// one and the healthy ones processed after it.
	var statuses = map[string]string{}
	var summary *rotation.Record
	for i := range records {
		record := records[i]
		if record.Kind == rotation.KindSummary {
			summary = &record
			continue
		}
		statuses[record.File] = record.Status
	}
	assert.Equal(t, rotation.StatusFailed, statuses["aaa/broken.yaml"])
	assert.Equal(t, rotation.StatusSuccess, statuses["a.yaml"])
	assert.Equal(t, rotation.StatusSuccess, statuses["b.yaml"])
	require.NotNil(t, summary)
	assert.Equal(t, 4, summary.Totals.Total)
	assert.Equal(t, 2, summary.Totals.Succeeded)
	assert.Equal(t, 1, summary.Totals.Failed)
}

func TestRotateWithLogUnsupportedFormatSkipIsDistinctFromAlreadyRotated(t *testing.T) {
	dir := setupRotationFixture(t)
	require.NoError(t, os.Remove(filepath.Join(dir, "broken.yaml")))
	args := []string{"rotate", "--rotation-log", filepath.Join(dir, "trail"),
		"--rotation-root", dir,
		"--add-age", testNewRecipient, "--rm-age", testOldRecipient, "--in-place"}
	require.NoError(t, runApp(t, append(args, dir)...))
	require.NoError(t, runApp(t, append(args, dir)...))

	records := readTrail(t, dir)
	byFile := map[string][]rotation.Record{}
	for _, record := range records {
		if record.Kind == rotation.KindFile {
			byFile[record.File] = append(byFile[record.File], record)
		}
	}
	require.Contains(t, byFile, "notes.txt")
	assert.Equal(t, rotation.SkipUnsupportedFormat, byFile["notes.txt"][0].SkipReason)
	assert.Equal(t, rotation.StatusSkipped, byFile["notes.txt"][0].Status)
	assert.Equal(t, rotation.SkipAlreadyRotated, byFile["a.yaml"][1].SkipReason)
	assert.NotEqual(t, byFile["notes.txt"][0].SkipReason, byFile["a.yaml"][1].SkipReason)
}

func TestRotateWithoutLogWritesNoFiles(t *testing.T) {
	dir := setupRotationFixture(t)
	require.NoError(t, os.Remove(filepath.Join(dir, "broken.yaml")))
	before, err := os.ReadDir(dir)
	require.NoError(t, err)

	require.NoError(t, runApp(t, "rotate", "--add-age", testNewRecipient,
		"--rm-age", testOldRecipient, "--in-place", filepath.Join(dir, "a.yaml")))

	after, err := os.ReadDir(dir)
	require.NoError(t, err)
	assert.Equal(t, len(before), len(after), "no audit files may appear when --rotation-log is not passed")
	for _, entry := range after {
		assert.NotEqual(t, "trail", entry.Name())
	}
}

func TestRotationTrailContainsNoKeyMaterial(t *testing.T) {
	dir := setupRotationFixture(t)
	require.NoError(t, os.Remove(filepath.Join(dir, "broken.yaml")))
	require.NoError(t, os.Remove(filepath.Join(dir, "notes.txt")))
	require.NoError(t, runApp(t, "rotate", "--rotation-log", filepath.Join(dir, "trail"),
		"--rotation-root", dir,
		"--add-age", testNewRecipient, "--rm-age", testOldRecipient, "--in-place",
		filepath.Join(dir, "a.yaml")))

	raw, err := os.ReadFile(rotation.NewWriter(filepath.Join(dir, "trail")).Path())
	require.NoError(t, err)
	text := string(raw)
	for _, material := range []string{testIdentityOld, testIdentityNew} {
		assert.NotContains(t, text, material, "trail must never contain private key material")
	}
	// The encrypted data key is stored in the SOPS file, not in the trail.
	sopsFile, err := os.ReadFile(filepath.Join(dir, "a.yaml"))
	require.NoError(t, err)
	assert.NotContains(t, text, "BEGIN AGE ENCRYPTED FILE")
	assert.Contains(t, string(sopsFile), "BEGIN AGE ENCRYPTED FILE")
}
