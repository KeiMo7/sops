package common

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"
)

func writeAtomic(path string, data []byte, private bool) error {
	return WriteFileAtomic(AtomicWriteOpts{Path: path, Data: data, Private: private})
}

// readState returns the content of path and its permission bits.
func readState(t *testing.T, path string) ([]byte, os.FileMode) {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat %s: %v", path, err)
	}
	return b, fi.Mode().Perm()
}

// tempFiles lists the recognisable temporary files in dir.
func tempFiles(t *testing.T, dir string) []string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, e := range entries {
		if len(e.Name()) > 0 && e.Name()[0] == '.' && bytes.Contains([]byte(e.Name()), []byte(".sops-")) {
			names = append(names, e.Name())
		}
	}
	return names
}

func TestWriteFileAtomicPreservesMode(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "file")
	for _, mode := range []os.FileMode{0600, 0640, 0644, 0664, 0666} {
		if err := os.WriteFile(path, []byte("old"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(path, mode); err != nil {
			t.Fatal(err)
		}
		if err := writeAtomic(path, []byte("new"), false); err != nil {
			t.Fatalf("mode %o: %v", mode, err)
		}
		got, perm := readState(t, path)
		if string(got) != "new" {
			t.Fatalf("mode %o: content %q", mode, got)
		}
		if perm != mode {
			t.Errorf("mode %o: got %o", mode, perm)
		}
	}
}

func TestWriteFileAtomicPrivate(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "file")
	if err := os.WriteFile(path, []byte("old"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o666); err != nil {
		t.Fatal(err)
	}
	if err := writeAtomic(path, []byte("secret"), true); err != nil {
		t.Fatal(err)
	}
	got, perm := readState(t, path)
	if string(got) != "secret" {
		t.Fatalf("content %q", got)
	}
	if perm != 0600 {
		t.Errorf("mode %o, want 600", perm)
	}
}

func TestWriteFileAtomicPrivateKeepsOwnerBits(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "file")
	if err := os.WriteFile(path, []byte("old"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o777); err != nil {
		t.Fatal(err)
	}
	if err := writeAtomic(path, []byte("secret"), true); err != nil {
		t.Fatal(err)
	}
	if _, perm := readState(t, path); perm != 0700 {
		t.Errorf("mode %o, want 700", perm)
	}
}

func TestWriteFileAtomicNewFileIsPrivate(t *testing.T) {
	restore := setUmask(0o000)
	defer restore()
	dir := t.TempDir()
	path := filepath.Join(dir, "file")
	if err := writeAtomic(path, []byte("secret"), true); err != nil {
		t.Fatal(err)
	}
	if _, perm := readState(t, path); perm != 0600 {
		t.Errorf("mode %o, want 600", perm)
	}
}

func TestWriteFileAtomicNewFileUsesUmask(t *testing.T) {
	oldMask := currentUmask()
	restore := setUmask(0o027)
	defer restore()
	dir := t.TempDir()
	path := filepath.Join(dir, "file")
	if err := writeAtomic(path, []byte("data"), false); err != nil {
		t.Fatal(err)
	}
	if _, perm := readState(t, path); perm != 0640 {
		t.Errorf("mode %o, want 640 (umask %o)", perm, oldMask)
	}
}

func TestWriteFileAtomicLeavesNoTempFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "file")
	if err := writeAtomic(path, []byte("data"), false); err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Name() != "file" {
		names := make([]string, 0, len(entries))
		for _, e := range entries {
			names = append(names, e.Name())
		}
		t.Fatalf("unexpected directory contents: %v", names)
	}
}

func TestWriteFileAtomicOriginalIntactOnFailure(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "file")
	original := []byte("original content")
	if err := os.WriteFile(path, original, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0o500); err != nil {
		t.Fatal(err)
	}
	defer os.Chmod(dir, 0o700)

	err := writeAtomic(path, []byte("replacement"), false)
	if err == nil {
		t.Fatal("expected a failure in a read-only directory")
	}
	got, _ := readState(t, path)
	if !bytes.Equal(got, original) {
		t.Fatalf("original modified: %q", got)
	}
	if leftovers := tempFiles(t, dir); len(leftovers) != 0 {
		t.Fatalf("temporary files left behind: %v", leftovers)
	}
}

func TestWriteFileAtomicSymlink(t *testing.T) {
	dir := t.TempDir()
	real := filepath.Join(dir, "real")
	link := filepath.Join(dir, "link")
	if err := os.WriteFile(real, []byte("old"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("real", link); err != nil {
		t.Fatal(err)
	}
	if err := writeAtomic(link, []byte("new"), false); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Lstat(link)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode()&os.ModeSymlink == 0 {
		t.Fatal("symlink was replaced by a regular file")
	}
	got, _ := os.ReadFile(real)
	if string(got) != "new" {
		t.Fatalf("target content %q", got)
	}
}

func TestWriteFileAtomicHardlinkDoesNotChangeOtherName(t *testing.T) {
	dir := t.TempDir()
	a := filepath.Join(dir, "a")
	b := filepath.Join(dir, "b")
	if err := os.WriteFile(a, []byte("shared"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(a, b); err != nil {
		t.Skipf("hard links unsupported: %v", err)
	}
	before, err := os.ReadFile(b)
	if err != nil {
		t.Fatal(err)
	}
	if err := writeAtomic(a, []byte("replacement"), false); err != nil {
		t.Fatal(err)
	}
	after, err := os.ReadFile(b)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, after) {
		t.Fatalf("the other hard link changed: %q", after)
	}
}

func TestWriteFileAtomicConcurrent(t *testing.T) {
	dir := t.TempDir()
	const n = 16
	paths := make([]string, n)
	want := make(map[string][32]byte, n)
	actual := make(map[string][]byte, n)
	for i := 0; i < n; i++ {
		p := filepath.Join(dir, fmt.Sprintf("file-%d", i))
		content := bytes.Repeat([]byte(fmt.Sprintf("content-%d;", i)), 4096)
		paths[i] = p
		want[p] = sha256.Sum256(content)
		actual[p] = content
		if err := os.WriteFile(p, []byte("old"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	var wg sync.WaitGroup
	errs := make(chan error, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(p string) {
			defer wg.Done()
			errs <- writeAtomic(p, actual[p], false)
		}(paths[i])
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	for _, p := range paths {
		got, err := os.ReadFile(p)
		if err != nil {
			t.Fatal(err)
		}
		if sha256.Sum256(got) != want[p] {
			t.Errorf("%s has wrong content", p)
		}
	}
	if leftovers := tempFiles(t, dir); len(leftovers) != 0 {
		t.Fatalf("temporary files left behind: %v", leftovers)
	}
}

func TestWriteFileAtomicRefusesNonRegular(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "pipe")
	if err := os.Mkdir(path, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := writeAtomic(path, []byte("data"), false); err == nil {
		t.Fatal("expected a failure when replacing a directory")
	}
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if !fi.IsDir() {
		t.Fatal("the directory was replaced")
	}
}

func TestWriteFileAtomicPreservesOwner(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "file")
	if err := os.WriteFile(path, []byte("old"), 0o600); err != nil {
		t.Fatal(err)
	}
	before, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	wantUID, wantGID, ok := fileOwner(before)
	if !ok {
		t.Skip("file ownership is not available on this platform")
	}
	if err := writeAtomic(path, []byte("new"), false); err != nil {
		t.Fatal(err)
	}
	after, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	uid, gid, ok := fileOwner(after)
	if !ok {
		t.Skip("file ownership is not available on this platform")
	}
	if uid != wantUID || gid != wantGID {
		t.Errorf("owner %d:%d, want %d:%d", uid, gid, wantUID, wantGID)
	}
}

func TestWriteFileAtomicTempFileIsPrivate(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "file")
	if err := os.WriteFile(path, []byte("old"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	var tmpMode os.FileMode
	testHookAfterTempCreate = func(tmpName string) {
		fi, err := os.Stat(tmpName)
		if err != nil {
			t.Fatalf("stat temporary file: %v", err)
		}
		tmpMode = fi.Mode().Perm()
	}
	defer func() { testHookAfterTempCreate = nil }()
	if err := writeAtomic(path, []byte("data"), false); err != nil {
		t.Fatal(err)
	}
	if tmpMode != 0600 {
		t.Errorf("temporary file mode %o, want 600", tmpMode)
	}
}

func TestWriteFileAtomicVerifyFailureKeepsTempAndOriginal(t *testing.T) {
	for _, private := range []bool{false, true} {
		dir := t.TempDir()
		path := filepath.Join(dir, "file")
		original := []byte("original")
		if err := os.WriteFile(path, original, 0o600); err != nil {
			t.Fatal(err)
		}
		var tmpName string
		testHookAfterTempCreate = func(name string) { tmpName = name }
		testHookVerify = func(*os.File, []byte) error { return fmt.Errorf("injected verification failure") }
		err := writeAtomic(path, []byte("replacement"), private)
		testHookAfterTempCreate = nil
		testHookVerify = nil
		if err == nil {
			t.Fatalf("private=%v: expected a verification failure", private)
		}
		if !bytes.Contains([]byte(err.Error()), []byte("original file was not modified")) {
			t.Errorf("private=%v: error does not say the original is intact: %v", private, err)
		}
		if private && !bytes.Contains([]byte(err.Error()), []byte("plaintext")) {
			t.Errorf("error does not mention the plaintext in the retained temporary file: %v", err)
		}
		got, _ := readState(t, path)
		if !bytes.Equal(got, original) {
			t.Fatalf("private=%v: original modified: %q", private, got)
		}
		if _, statErr := os.Stat(tmpName); statErr != nil {
			t.Fatalf("private=%v: temporary file was removed: %v", private, statErr)
		}
		fi, statErr := os.Stat(tmpName)
		if statErr != nil {
			t.Fatal(statErr)
		}
		if fi.Mode().Perm() != 0600 {
			t.Errorf("private=%v: retained temporary file mode %o, want 600", private, fi.Mode().Perm())
		}
	}
}
