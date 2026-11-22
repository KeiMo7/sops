package common

import (
	"fmt"
	"os"

	"github.com/getsops/sops/v3"
	"github.com/getsops/sops/v3/cmd/sops/codes"
	"github.com/getsops/sops/v3/keyservice"
)

// EncryptedFileVerifier builds an atomic.Verifier that proves a freshly
// written staging file can actually be decrypted before it is allowed to
// replace the previous, known-good version. This is deliberately stronger
// than a byte-count check: the whole load + key retrieval + tree decrypt
// + MAC verification pipeline runs against the staged bytes.
//
// The verifier reads from the staging path on disk (not from an in-memory
// buffer), so it also proves the bytes that survived fsync are the ones
// that will be read back after a crash.
func EncryptedFileVerifier(store sops.EncryptedFileLoader, cipher sops.Cipher, keyServices []keyservice.KeyServiceClient, decryptionOrder []string, ignoreMAC bool) func(path string) error {
	return func(path string) error {
		data, err := os.ReadFile(path)
		if err != nil {
			return fmt.Errorf("could not read staged file for verification: %w", err)
		}
		tree, err := store.LoadEncryptedFile(data)
		if err != nil {
			return fmt.Errorf("staged file is not a valid encrypted document: %w", err)
		}
		if _, err := DecryptTree(DecryptTreeOpts{
			Tree:            &tree,
			KeyServices:     keyServices,
			DecryptionOrder: decryptionOrder,
			IgnoreMac:       ignoreMAC,
			Cipher:          cipher,
		}); err != nil {
			return fmt.Errorf("staged file cannot be decrypted: %w", err)
		}
		return nil
	}
}

// VerifyError wraps a verification failure with the established exit code
// for undecryptable output.
func VerifyError(err error) error {
	return NewExitError(fmt.Sprintf("Refusing to replace the original file: %s", err),
		codes.CouldNotWriteOutputFile)
}
