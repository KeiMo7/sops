package main

import (
	"os"

	"github.com/getsops/sops/v3/cmd/sops/common"
)

// writeInPlace atomically replaces an encrypted SOPS file and proves the
// staged result can be decrypted before the old version is ever removed.
// It preserves every existing user-visible behavior: the same exit code
// (codes.CouldNotWriteOutputFile) on failure and the caller's own
// "File written successfully" log line on success.
func writeInPlace(fileName string, output []byte, verifier common.VerifierFunc) error {
	// Snapshot the target before committing so that a writer which
	// replaced it while this command was processing is detected and the
	// conflicting write is refused rather than silently overwritten.
	baseline, err := common.SnapshotBaseline(fileName)
	if err != nil {
		return err
	}
	if err := common.WriteFile(common.WriteFileOptions{
		Path:     fileName,
		Data:     output,
		Verify:   verifier,
		Baseline: &baseline,
	}); err != nil {
		return err
	}
	log.Info("File written successfully")
	return nil
}

// writeOutput either streams to stdout (behavior unchanged for the
// stdin/stdout path) or atomically replaces a file given via --output.
// A plain --output target gets no decryptability verifier because some
// subcommands legitimately emit plaintext there.
func writeOutput(outputPath string, output []byte) error {
	if outputPath == "" {
		_, err := os.Stdout.Write(output)
		return toExitError(err)
	}
	return common.WriteFile(common.WriteFileOptions{
		Path: outputPath,
		Data: output,
	})
}
