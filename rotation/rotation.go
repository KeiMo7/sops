// Package rotation implements the opt-in, append-only audit trail for SOPS
// key rotations.
//
// The package deliberately depends on the standard library only. It knows
// nothing about SOPS trees, master keys or ciphers: the command layer builds
// Records from key identifiers and fingerprints and hands them to a Writer.
//
// Record format (schema version 1)
//
// The trail is a single JSON Lines file ("rotations-v1.jsonl") in the
// directory passed with --rotation-log. Every line is one self-contained JSON
// object. Two kinds of records exist:
//
//	kind=file     the outcome of rotating one file
//	kind=summary  the totals for one rotation run
//
// Compatibility rules for future versions:
//
//   - schema_version is mandatory and is 1 for every record described here.
//   - Fields are additive only: a later version may add fields, but must not
//     change the meaning of the fields defined in this version.
//   - Readers must ignore unknown fields and must not interpret records whose
//     schema_version they do not know (they are reported, never guessed at).
//   - Records are immutable and the file is append-only.
//
// Records never contain key material: only a master key's type and public
// identifier, and SHA-256 fingerprints of identifiers or of a data key. See
// KeyRef and Fingerprint.
package rotation

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// SchemaVersion is the version of the record format written by this package.
const SchemaVersion = 1

// LogFileName is the name of the append-only trail inside --rotation-log.
const LogFileName = "rotations-v1.jsonl"

// Record kinds.
const (
	KindFile    = "file"
	KindSummary = "summary"
)

// File statuses.
const (
	StatusSuccess = "success"
	StatusSkipped = "skipped"
	StatusFailed  = "failed"
)

// Outcomes and skip reasons.
const (
	OutcomeRotated        = "rotated"
	SkipAlreadyRotated    = "already-rotated"
	SkipUnsupportedFormat = "unsupported-format"
)

// Error kinds. They are intentionally coarse: each one tells an operator what
// to look at first without exposing the underlying secret material.
const (
	ErrorRead          = "read-failed"
	ErrorNotFound      = "file-not-found"
	ErrorDecrypt       = "decrypt-failed"
	ErrorKeyGeneration = "key-generation-failed"
	ErrorEncrypt       = "encrypt-failed"
	ErrorMarshal       = "marshal-failed"
	ErrorWrite         = "write-failed"
	ErrorPermission    = "permission-denied"
	ErrorUnknown       = "unknown"
)

// KeyRef is the only representation of a master key that is ever written to
// the trail. ID is a public identifier (age recipient, KMS ARN/resource ID,
// PGP fingerprint, Vault URI, ...); Fingerprint is a hash of that identifier,
// not of the key itself.
type KeyRef struct {
	Type        string `json:"type"`
	ID          string `json:"id"`
	Fingerprint string `json:"fingerprint"`
}

// Totals is the aggregate written in a summary record.
type Totals struct {
	Total     int `json:"total"`
	Succeeded int `json:"succeeded"`
	Skipped   int `json:"skipped"`
	Failed    int `json:"failed"`
}

// Record is one line of the trail. Exactly one of the file fields is populated
// for kind=file; Totals is populated for kind=summary.
type Record struct {
	SchemaVersion int    `json:"schema_version"`
	Kind          string `json:"kind"`
	RotationID    string `json:"rotation_id"`
	Timestamp     string `json:"timestamp"`

	// File is always relative to the rotation root (default: the current
	// working directory). It never contains a user home directory or an
	// absolute path.
	File       string `json:"file,omitempty"`
	FileFormat string `json:"file_format,omitempty"`

	Status     string `json:"status,omitempty"`
	Outcome    string `json:"outcome,omitempty"`
	SkipReason string `json:"skip_reason,omitempty"`
	ErrorKind  string `json:"error_kind,omitempty"`
	// Error is a short, sanitized description. It never contains key
	// material and never contains absolute paths.
	Error string `json:"error,omitempty"`

	// Fingerprints of the old and the new data key. The data key itself is
	// never written.
	OldDataKeyFingerprint string `json:"old_data_key_fingerprint,omitempty"`
	NewDataKeyFingerprint string `json:"new_data_key_fingerprint,omitempty"`

	// Which master keys this rotation added or removed, and the resulting
	// set of master keys. This is how a later reader answers "which key was
	// this file rotated to?" without decrypting the file.
	MasterKeysAdded   []KeyRef `json:"master_keys_added,omitempty"`
	MasterKeysRemoved []KeyRef `json:"master_keys_removed,omitempty"`
	MasterKeysAfter   []KeyRef `json:"master_keys,omitempty"`

	Totals *Totals `json:"totals,omitempty"`
}

// Fingerprint returns a stable identifier for an arbitrary key identifier.
// The input is public data (a recipient, ARN, resource ID, ...); the output is
// a SHA-256 hex digest prefixed with "sha256:".
func Fingerprint(identifier string) string {
	sum := sha256.Sum256([]byte(identifier))
	return "sha256:" + hex.EncodeToString(sum[:])
}

// DataKeyFingerprint fingerprints raw data key bytes. Only the digest leaves
// this function; callers must never put the key bytes into a Record.
func DataKeyFingerprint(key []byte) string {
	if len(key) == 0 {
		return ""
	}
	sum := sha256.Sum256(key)
	return "sha256:" + hex.EncodeToString(sum[:])
}

// NewRotationID returns an identifier shared by every record of one run.
func NewRotationID() string {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return time.Now().UTC().Format("20060102T150405Z")
	}
	return time.Now().UTC().Format("20060102T150405Z") + "-" + hex.EncodeToString(b[:])
}

// Timestamp returns the record timestamp format (RFC 3339, UTC).
func Timestamp(t time.Time) string {
	return t.UTC().Format(time.RFC3339Nano)
}

// RelativePath renders path relative to root. It never returns an absolute
// path and never embeds the user's home directory; a path outside root is
// rendered as an ordinary "../..." path so that two same-named files stay
// distinguishable in the trail.
func RelativePath(root, path string) string {
	if root == "" {
		root, _ = os.Getwd()
	}
	absRoot, err := filepath.Abs(root)
	if err != nil {
		return filepath.Base(path)
	}
	absPath, err := filepath.Abs(path)
	if err != nil {
		return filepath.Base(path)
	}
	rel, err := filepath.Rel(absRoot, absPath)
	if err != nil {
		return filepath.Base(absPath)
	}
	rel = filepath.ToSlash(filepath.Clean(rel))
	// A relative path never starts with "/" and, unlike an absolute path,
	// cannot embed the home directory string unless root itself is outside
	// the home directory (in which case the relative walk still cannot reach
	// it).
	return rel
}

// SanitizeText removes the user's home directory and any absolute-path prefix
// that points below root from a human-readable message. It is used for error
// details so that records do not leak host layout.
func SanitizeText(root, text string) string {
	if text == "" {
		return text
	}
	if home, err := os.UserHomeDir(); err == nil && home != "" {
		text = strings.ReplaceAll(text, home, "~")
	}
	if root != "" {
		if absRoot, err := filepath.Abs(root); err == nil {
			text = strings.ReplaceAll(text, absRoot, ".")
		}
	}
	// A path outside root is still absolute; reduce it to its base name so an
	// error message never exposes the host layout.
	fields := strings.Fields(text)
	for i, field := range fields {
		trimmed := strings.Trim(field, `"'(),;:`)
		if filepath.IsAbs(trimmed) {
			fields[i] = strings.Replace(field, trimmed, filepath.Base(trimmed), 1)
		}
	}
	return strings.Join(fields, " ")
}

// ErrorDetail produces the short, safe error description stored in a Record.
func ErrorDetail(root string, err error) string {
	if err == nil {
		return ""
	}
	if pe, ok := err.(*os.PathError); ok {
		return SanitizeText(root, fmt.Sprintf("%s: %s", pe.Op, pe.Err))
	}
	return SanitizeText(root, err.Error())
}
