/*
Package diff implements the `sops diff` subcommand: it loads and decrypts
two encrypted SOPS files entirely in memory and compares their plaintext
configuration values without ever writing plaintext to disk.
*/
package diff // import "github.com/getsops/sops/v3/cmd/sops/subcommand/diff"

import (
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/getsops/sops/v3"
	"github.com/getsops/sops/v3/aes"
	"github.com/getsops/sops/v3/cmd/sops/codes"
	"github.com/getsops/sops/v3/cmd/sops/common"
	corediff "github.com/getsops/sops/v3/diff"
	"github.com/getsops/sops/v3/keyservice"
	"github.com/getsops/sops/v3/version"
)

// Side identifies one of the two compared files.
type Side string

const (
	// SideA is the first positional argument.
	SideA Side = "A"
	// SideB is the second positional argument.
	SideB Side = "B"
)

// DecryptFailure describes why one side could not be decrypted. It never
// wraps plaintext: only the file path, the key identifiers advertised by the
// file's metadata, and the underlying error are carried.
type DecryptFailure struct {
	Side Side
	Path string
	// KeyIDs lists every master key the file says can decrypt it.
	KeyIDs []string
	Err    error
}

func (e *DecryptFailure) Error() string {
	return fmt.Sprintf("cannot decrypt side %s (%s): %s", e.Side, e.Path, e.Err)
}

// Unwrap supports errors.Is/As on the underlying failure.
func (e *DecryptFailure) Unwrap() error { return e.Err }

// ExitCode maps decryption failures to the established sops exit code.
func (e *DecryptFailure) ExitCode() int { return codes.CouldNotRetrieveKey }

// FormatFailure means a file could not be parsed as a SOPS document of its
// declared format. UnrecognizedFormat is true for a malformed/unparseable
// file; otherwise the parse succeeded but the sops metadata version is not
// supported.
type FormatFailure struct {
	Side               Side
	Path               string
	UnrecognizedFormat bool
	Err                error
}

func (e *FormatFailure) Error() string {
	kind := "unsupported sops metadata version"
	if e.UnrecognizedFormat {
		kind = "unrecognized file format or malformed document"
	}
	return fmt.Sprintf("cannot read side %s (%s): %s: %s", e.Side, e.Path, kind, e.Err)
}

func (e *FormatFailure) Unwrap() error { return e.Err }

// ExitCode maps parse failures to the established sops exit code.
func (e *FormatFailure) ExitCode() int { return codes.CouldNotReadInputFile }

// Opts are the inputs to Run.
type Opts struct {
	// InputStoreA / InputStoreB parse their respective files.
	InputStoreA sops.Store
	InputStoreB sops.Store
	// InputPathA / InputPathB are the encrypted file locations.
	InputPathA string
	InputPathB string
	// KeyServices and DecryptionOrder mirror the decrypt subcommand.
	KeyServices     []keyservice.KeyServiceClient
	DecryptionOrder []string
	// IgnoreMAC skips integrity verification, matching `decrypt --ignore-mac`.
	IgnoreMAC bool
	// PathPrefixes restricts the comparison to selected subtrees.
	PathPrefixes [][]interface{}
	// ShowSensitive prints real secret values instead of the mask.
	ShowSensitive bool
	// ShowEqual also prints leaves that are identical on both sides.
	ShowEqual bool
	// Writer receives the report. Tests pass a buffer; the CLI passes stdout.
	Writer io.Writer
}

// loadedSide holds everything parsed from one file before decryption is
// attempted, so key IDs are available even when decryption later fails.
type loadedSide struct {
	side  Side
	path  string
	tree  *sops.Tree
	keyID []string
}

// Run loads, decrypts and compares two encrypted files. Plaintext exists only
// in memory; no temporary files are created at any point, and on error no
// partial report is written.
func Run(opts Opts) (corediff.Result, error) {
	a, err := loadSide(SideA, opts.InputPathA, opts.InputStoreA)
	if err != nil {
		return corediff.Result{}, err
	}
	b, err := loadSide(SideB, opts.InputPathB, opts.InputStoreB)
	if err != nil {
		return corediff.Result{}, err
	}

	if err := decryptSide(a, opts); err != nil {
		return corediff.Result{}, err
	}
	if err := decryptSide(b, opts); err != nil {
		return corediff.Result{}, err
	}

	// Comparison and rendering happen only after both sides have decrypted
	// successfully, so a mid-run failure never leaves a half-written report.
	result := corediff.CompareTrees(a.tree.Branches, b.tree.Branches, corediff.Options{
		PathPrefixes: opts.PathPrefixes,
	})
	if opts.Writer != nil {
		if err := corediff.RenderReport(opts.Writer, result, corediff.ReportOptions{
			ShowSensitive: opts.ShowSensitive,
			ShowEqual:     opts.ShowEqual,
		}); err != nil {
			return corediff.Result{}, fmt.Errorf("failed to write diff report: %w", err)
		}
	}
	return result, nil
}

// loadSide reads and parses one file, distinguishing three outcomes:
// success; an unrecognized/malformed file; an unsupported metadata version.
func loadSide(side Side, path string, store sops.Store) (*loadedSide, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, &FormatFailure{Side: side, Path: path, UnrecognizedFormat: true, Err: err}
	}

	tree, err := store.LoadEncryptedFile(data)
	if err != nil {
		// Any failure here means the bytes are not a parseable sops document:
		// malformed JSON/YAML, a plain (unencrypted) file (MetadataNotFound),
		// etc. Unsupported metadata *versions* are detected separately below,
		// after a successful parse.
		return nil, &FormatFailure{
			Side:               side,
			Path:               path,
			UnrecognizedFormat: true,
			Err:                err,
		}
	}

	if err := checkVersion(side, path, tree.Metadata.Version); err != nil {
		return nil, err
	}

	return &loadedSide{
		side:  side,
		path:  path,
		tree:  &tree,
		keyID: keyIdentifiers(tree.Metadata.KeyGroups),
	}, nil
}

// checkVersion rejects metadata produced by a newer, unknown sops major line.
// An empty version is treated as an unrecognized document.
func checkVersion(side Side, path, docVersion string) error {
	if strings.TrimSpace(docVersion) == "" {
		return &FormatFailure{
			Side:               side,
			Path:               path,
			UnrecognizedFormat: true,
			Err:                errors.New("document is missing its sops version metadata"),
		}
	}
	newer, err := version.AIsNewerThanB(docVersion, version.Version)
	if err != nil {
		return &FormatFailure{Side: side, Path: path, Err: fmt.Errorf("cannot parse document version %q: %w", docVersion, err)}
	}
	if newer {
		return &FormatFailure{
			Side: side,
			Path: path,
			Err: fmt.Errorf("document sops version %q is newer than this binary supports (%q)",
				docVersion, version.Version),
		}
	}
	return nil
}

// decryptSide decrypts one parsed tree in memory, translating any key failure
// into a DecryptFailure that names the side and the keys the file needs.
func decryptSide(loaded *loadedSide, opts Opts) error {
	cipher := aes.NewCipher()
	_, err := common.DecryptTree(common.DecryptTreeOpts{
		Cipher:          cipher,
		IgnoreMac:       opts.IgnoreMAC,
		Tree:            loaded.tree,
		KeyServices:     opts.KeyServices,
		DecryptionOrder: opts.DecryptionOrder,
	})
	if err != nil {
		return &DecryptFailure{
			Side:   loaded.side,
			Path:   loaded.path,
			KeyIDs: loaded.keyID,
			Err:    err,
		}
	}
	return nil
}

// keyIdentifiers extracts the human-readable ID of every master key in the
// metadata key groups, so error messages can name the missing credentials.
func keyIdentifiers(groups []sops.KeyGroup) []string {
	var ids []string
	for _, group := range groups {
		for _, key := range group {
			ids = append(ids, key.ToString())
		}
	}
	return ids
}
