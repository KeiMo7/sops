package diff

import (
	"bytes"
	"os"
	"path/filepath"
	"strconv"
	"strings"
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
	corediff "github.com/getsops/sops/v3/diff"
	"github.com/getsops/sops/v3/keyservice"
	jsonstore "github.com/getsops/sops/v3/stores/json"
	"github.com/getsops/sops/v3/version"
)

// testFixture bundles one generated age keypair plus its sops master key.
type testFixture struct {
	identity  string
	recipient string
	masterKey *sopsage.MasterKey
}

func newAgeFixture(t *testing.T) testFixture {
	t.Helper()
	id, err := age.GenerateX25519Identity()
	require.NoError(t, err)
	mk, err := sopsage.MasterKeyFromRecipient(id.Recipient().String())
	require.NoError(t, err)
	return testFixture{
		identity:  id.String(),
		recipient: id.Recipient().String(),
		masterKey: mk,
	}
}

func jsonStoreForTest() *jsonstore.Store {
	return jsonstore.NewStore(&config.NewStoresConfig().JSON)
}

// writeEncryptedFile builds a sops-encrypted JSON file in memory and writes
// only the encrypted bytes to disk. The plaintext input never touches disk.
func writeEncryptedFile(t *testing.T, path string, plainJSON string, fx testFixture) {
	t.Helper()
	store := jsonStoreForTest()
	branches, err := store.LoadPlainFile([]byte(plainJSON))
	require.NoError(t, err)

	tree := newEncryptedTree(t, branches, sops.KeyGroup{fx.masterKey})
	encrypted, err := store.EmitEncryptedFile(tree)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(path, encrypted, 0o600))
}

// newEncryptedTree produces a fully encrypted sops.Tree using the same
// in-memory primitives as the CLI encrypt path: data-key generation against
// the master key, then tree encryption and MAC. Nothing is written to disk.
func newEncryptedTree(t *testing.T, branches sops.TreeBranches, keyGroup sops.KeyGroup) sops.Tree {
	t.Helper()
	tree := sops.Tree{
		Branches: branches,
		Metadata: sops.Metadata{
			KeyGroups: []sops.KeyGroup{keyGroup},
			Version:   version.Version,
		},
	}
	dataKey, errs := tree.GenerateDataKey()
	require.Empty(t, errs)
	require.NoError(t, common.EncryptTree(common.EncryptTreeOpts{
		DataKey: dataKey,
		Tree:    &tree,
		Cipher:  aes.NewCipher(),
	}))
	return tree
}

// snapshotDir lists every regular file under dir recursively.
func snapshotDir(t *testing.T, dir string) map[string]int64 {
	t.Helper()
	files := map[string]int64{}
	require.NoError(t, filepath.Walk(dir, func(p string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() {
			rel, _ := filepath.Rel(dir, p)
			files[rel] = info.Size()
		}
		return nil
	}))
	return files
}

func baseOpts(t *testing.T, dir string) Opts {
	t.Helper()
	store := jsonStoreForTest()
	return Opts{
		InputStoreA:     store,
		InputStoreB:     jsonStoreForTest(),
		InputPathA:      filepath.Join(dir, "a.json"),
		InputPathB:      filepath.Join(dir, "b.json"),
		KeyServices:     []keyservice.KeyServiceClient{keyservice.NewLocalClient()},
		DecryptionOrder: nil,
		Writer:          &bytes.Buffer{},
	}
}

// TestRun_AllFourAcceptanceCases covers the four mandated scenarios in one
// fixture set: changed values, one-sided keys, order-insensitive arrays, and
// decryption failure on one side.
func TestRun_AllFourAcceptanceCases(t *testing.T) {
	dir := t.TempDir()
	fx := newAgeFixture(t)
	t.Setenv(sopsage.SopsAgeKeyEnv, fx.identity)
	// Make sure no other identity source can interfere.
	t.Setenv(sopsage.SopsAgeKeyFileEnv, "")

	prod := `{
		"db": {"host": "prod.internal", "port": 5432, "password": "prod-pw"},
		"retries": 3,
		"kind": "1",
		"only_prod": "on",
		"hosts": ["a", "b", "c"]
	}`
	staging := `{
		"db": {"host": "staging.internal", "port": 5432, "password": "staging-pw"},
		"retries": 3,
		"kind": 1,
		"only_staging": "on",
		"hosts": ["c", "a", "b"]
	}`
	writeEncryptedFile(t, filepath.Join(dir, "a.json"), prod, fx)
	writeEncryptedFile(t, filepath.Join(dir, "b.json"), staging, fx)

	before := snapshotDir(t, dir)

	opts := baseOpts(t, dir)
	var report bytes.Buffer
	opts.Writer = &report
	result, err := Run(opts)
	require.NoError(t, err)

	groups := result.ByChange()

	// Case 1: value difference, reported at the leaf path.
	host, ok := findTestEntry(groups[corediff.ValueChanged], `["db"]["host"]`)
	require.True(t, ok, "expected changed db.host, got: %v", groups[corediff.ValueChanged])
	assert.Equal(t, "prod.internal", host.ValueA)
	assert.Equal(t, "staging.internal", host.ValueB)

	// Type strictness: string "1" vs number 1.
	kind, ok := findTestEntry(groups[corediff.ValueChanged], `["kind"]`)
	require.True(t, ok)
	assert.Equal(t, "1", kind.ValueA)
	assert.Equal(t, 1, kind.ValueB)

	// Case 2: one-sided existence.
	require.Len(t, groups[corediff.OnlyInA], 1)
	assert.Equal(t, `["only_prod"]`, groups[corediff.OnlyInA][0].PathString())
	require.Len(t, groups[corediff.OnlyInB], 1)
	assert.Equal(t, `["only_staging"]`, groups[corediff.OnlyInB][0].PathString())

	// Case 3: order-different array compares equal; equal scalar too.
	hostEqual := 0
	for _, e := range groups[corediff.Equal] {
		if strings.HasPrefix(e.PathString(), `["hosts"]`) {
			hostEqual++
		}
	}
	assert.Equal(t, 3, hostEqual, "all three reordered array elements must compare equal")
	retries, ok := findTestEntry(groups[corediff.Equal], `["retries"]`)
	require.True(t, ok)
	assert.Equal(t, 3, retries.ValueA)

	// Sensitive flagging.
	pw, ok := findTestEntry(groups[corediff.ValueChanged], `["db"]["password"]`)
	require.True(t, ok)
	assert.True(t, pw.Sensitive)

	// Masking in report output: real secrets never rendered by default.
	out := report.String()
	assert.Contains(t, out, "***MASKED***")
	assert.NotContains(t, out, "prod-pw")
	assert.NotContains(t, out, "staging-pw")
	assert.Contains(t, out, `["db"]["host"]`)

	// No new plaintext files appeared on disk during the run.
	assert.Equal(t, before, snapshotDir(t, dir),
		"diff must not create any new files (no plaintext temp files)")
}

func findTestEntry(entries []corediff.Entry, path string) (corediff.Entry, bool) {
	for _, e := range entries {
		if e.PathString() == path {
			return e, true
		}
	}
	return corediff.Entry{}, false
}

// TestRun_DecryptFailureNamesSideAndKey covers case 4: one side cannot be
// decrypted because its key is unavailable. The error must name the side and
// the missing key, and must not pretend the file was empty.
func TestRun_DecryptFailureNamesSideAndKey(t *testing.T) {
	dir := t.TempDir()
	fxA := newAgeFixture(t)
	fxB := newAgeFixture(t)

	writeEncryptedFile(t, filepath.Join(dir, "a.json"), `{"x": 1}`, fxA)
	writeEncryptedFile(t, filepath.Join(dir, "b.json"), `{"x": 2}`, fxB)

	// Only A's identity is available.
	t.Setenv(sopsage.SopsAgeKeyEnv, fxA.identity)
	t.Setenv(sopsage.SopsAgeKeyFileEnv, "")

	opts := baseOpts(t, dir)
	_, err := Run(opts)
	require.Error(t, err)

	var failure *DecryptFailure
	require.ErrorAs(t, err, &failure)
	assert.Equal(t, SideB, failure.Side)
	assert.Contains(t, failure.Error(), "side B")
	assert.Contains(t, failure.KeyIDs, fxB.recipient,
		"error must name the key that could not be used")
}

func TestRun_DecryptFailureSideA(t *testing.T) {
	dir := t.TempDir()
	fxA := newAgeFixture(t)
	fxB := newAgeFixture(t)

	writeEncryptedFile(t, filepath.Join(dir, "a.json"), `{"x": 1}`, fxA)
	writeEncryptedFile(t, filepath.Join(dir, "b.json"), `{"x": 2}`, fxB)

	t.Setenv(sopsage.SopsAgeKeyEnv, fxB.identity)
	t.Setenv(sopsage.SopsAgeKeyFileEnv, "")

	_, err := Run(baseOpts(t, dir))
	require.Error(t, err)
	var failure *DecryptFailure
	require.ErrorAs(t, err, &failure)
	assert.Equal(t, SideA, failure.Side)
	assert.Contains(t, failure.KeyIDs, fxA.recipient)
}

// TestRun_UnrecognizedFormat distinguishes a malformed file from a version
// problem.
func TestRun_UnrecognizedFormat(t *testing.T) {
	dir := t.TempDir()
	fx := newAgeFixture(t)
	t.Setenv(sopsage.SopsAgeKeyEnv, fx.identity)
	t.Setenv(sopsage.SopsAgeKeyFileEnv, "")

	writeEncryptedFile(t, filepath.Join(dir, "a.json"), `{"x": 1}`, fx)
	// B is not a sops document at all.
	require.NoError(t, os.WriteFile(filepath.Join(dir, "b.json"), []byte("this is not json at all"), 0o600))

	_, err := Run(baseOpts(t, dir))
	require.Error(t, err)
	var ff *FormatFailure
	require.ErrorAs(t, err, &ff)
	assert.Equal(t, SideB, ff.Side)
	assert.True(t, ff.UnrecognizedFormat, "malformed bytes must be labeled a format problem, not a version problem")
}

func TestRun_PlainJSONWithoutMetadataIsFormatFailure(t *testing.T) {
	dir := t.TempDir()
	fx := newAgeFixture(t)
	t.Setenv(sopsage.SopsAgeKeyEnv, fx.identity)
	t.Setenv(sopsage.SopsAgeKeyFileEnv, "")

	writeEncryptedFile(t, filepath.Join(dir, "a.json"), `{"x": 1}`, fx)
	// Valid JSON, but no sops metadata.
	require.NoError(t, os.WriteFile(filepath.Join(dir, "b.json"), []byte(`{"x": 2}`), 0o600))

	_, err := Run(baseOpts(t, dir))
	require.Error(t, err)
	var ff *FormatFailure
	require.ErrorAs(t, err, &ff)
	assert.True(t, ff.UnrecognizedFormat)
}

// TestRun_UnsupportedMetadataVersion distinguishes a parseable sops document
// whose metadata version is newer than this binary supports: that is a
// version problem, not a malformed file.
func TestRun_UnsupportedMetadataVersion(t *testing.T) {
	dir := t.TempDir()
	fx := newAgeFixture(t)
	t.Setenv(sopsage.SopsAgeKeyEnv, fx.identity)
	t.Setenv(sopsage.SopsAgeKeyFileEnv, "")

	writeEncryptedFile(t, filepath.Join(dir, "a.json"), `{"x": 1}`, fx)

	// Build a valid encrypted document, then overwrite its version metadata.
	store := jsonStoreForTest()
	branches, err := store.LoadPlainFile([]byte(`{"x": 2}`))
	require.NoError(t, err)
	tree := newEncryptedTree(t, branches, sops.KeyGroup{fx.masterKey})
	tree.Metadata.Version = "99.0.0"
	encrypted, err := store.EmitEncryptedFile(tree)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(dir, "b.json"), encrypted, 0o600))

	_, err = Run(baseOpts(t, dir))
	require.Error(t, err)
	var ff *FormatFailure
	require.ErrorAs(t, err, &ff)
	assert.Equal(t, SideB, ff.Side)
	assert.False(t, ff.UnrecognizedFormat, "a parseable document with a future version must be a version error")
	assert.Contains(t, ff.Error(), "version")
}

func TestRun_PathPrefixFiltering(t *testing.T) {
	dir := t.TempDir()
	fx := newAgeFixture(t)
	t.Setenv(sopsage.SopsAgeKeyEnv, fx.identity)
	t.Setenv(sopsage.SopsAgeKeyFileEnv, "")

	writeEncryptedFile(t, filepath.Join(dir, "a.json"),
		`{"db": {"host": "prod"}, "cache": {"host": "prod"}}`, fx)
	writeEncryptedFile(t, filepath.Join(dir, "b.json"),
		`{"db": {"host": "staging"}, "cache": {"host": "staging"}}`, fx)

	opts := baseOpts(t, dir)
	opts.PathPrefixes = [][]interface{}{{"db"}}
	result, err := Run(opts)
	require.NoError(t, err)
	changed := result.ByChange()[corediff.ValueChanged]
	require.Len(t, changed, 1)
	assert.Equal(t, `["db"]["host"]`, changed[0].PathString())
}

func TestRun_ShowSensitiveRevealsValues(t *testing.T) {
	dir := t.TempDir()
	fx := newAgeFixture(t)
	t.Setenv(sopsage.SopsAgeKeyEnv, fx.identity)
	t.Setenv(sopsage.SopsAgeKeyFileEnv, "")

	writeEncryptedFile(t, filepath.Join(dir, "a.json"), `{"password": "prod-pw"}`, fx)
	writeEncryptedFile(t, filepath.Join(dir, "b.json"), `{"password": "stage-pw"}`, fx)

	var report bytes.Buffer
	opts := baseOpts(t, dir)
	opts.Writer = &report
	opts.ShowSensitive = true
	_, err := Run(opts)
	require.NoError(t, err)
	out := report.String()
	assert.Contains(t, out, "prod-pw")
	assert.Contains(t, out, "stage-pw")
	assert.NotContains(t, out, "***MASKED***")
}

func TestRun_NoPartialReportOnFailure(t *testing.T) {
	dir := t.TempDir()
	fxA := newAgeFixture(t)
	fxB := newAgeFixture(t)

	writeEncryptedFile(t, filepath.Join(dir, "a.json"), `{"x": 1}`, fxA)
	writeEncryptedFile(t, filepath.Join(dir, "b.json"), `{"x": 2}`, fxB)
	t.Setenv(sopsage.SopsAgeKeyEnv, fxA.identity)
	t.Setenv(sopsage.SopsAgeKeyFileEnv, "")

	var report bytes.Buffer
	opts := baseOpts(t, dir)
	opts.Writer = &report
	_, err := Run(opts)
	require.Error(t, err)
	assert.Empty(t, report.String(), "a failed run must not emit a half-written report")
}

func TestRun_MissingFile(t *testing.T) {
	dir := t.TempDir()
	fx := newAgeFixture(t)
	t.Setenv(sopsage.SopsAgeKeyEnv, fx.identity)

	writeEncryptedFile(t, filepath.Join(dir, "a.json"), `{"x": 1}`, fx)
	opts := baseOpts(t, dir)
	_, err := Run(opts)
	require.Error(t, err)
	var ff *FormatFailure
	require.ErrorAs(t, err, &ff)
	assert.Equal(t, SideB, ff.Side)
}

// TestRun_StressThousandsOfLeaves exercises the streaming walk on a large
// document (thousands of keys) and confirms linear, correct behavior.
func TestRun_StressThousandsOfLeaves(t *testing.T) {
	dir := t.TempDir()
	fx := newAgeFixture(t)
	t.Setenv(sopsage.SopsAgeKeyEnv, fx.identity)
	t.Setenv(sopsage.SopsAgeKeyFileEnv, "")

	const n = 3000
	var a strings.Builder
	var b strings.Builder
	a.WriteString(`{"items": {`)
	b.WriteString(`{"items": {`)
	for i := 0; i < n; i++ {
		comma := ","
		if i == n-1 {
			comma = ""
		}
		a.WriteString(`"k` + strconv.Itoa(i) + `": ` + strconv.Itoa(i) + comma)
		// B differs on every 7th key.
		val := i
		if i%7 == 0 {
			val = i + 1
		}
		b.WriteString(`"k` + strconv.Itoa(i) + `": ` + strconv.Itoa(val) + comma)
	}
	a.WriteString("}}")
	b.WriteString("}}")

	writeEncryptedFile(t, filepath.Join(dir, "a.json"), a.String(), fx)
	writeEncryptedFile(t, filepath.Join(dir, "b.json"), b.String(), fx)

	start := time.Now()
	result, err := Run(baseOpts(t, dir))
	require.NoError(t, err)
	require.Less(t, time.Since(start), 30*time.Second)

	groups := result.ByChange()
	expectedChanged := 0
	for i := 0; i < n; i++ {
		if i%7 == 0 {
			expectedChanged++
		}
	}
	assert.Len(t, groups[corediff.ValueChanged], expectedChanged)
	assert.Len(t, groups[corediff.Equal], n-expectedChanged)
}

// Sanity: ensure the store helper really is the common store type used by the
// CLI, so the test exercises the same LoadEncryptedFile path as production.
var _ common.Store = (*jsonstore.Store)(nil)
