package main

import (
	"fmt"

	"github.com/getsops/sops/v3"
	"github.com/getsops/sops/v3/audit"
	"github.com/getsops/sops/v3/cmd/sops/codes"
	"github.com/getsops/sops/v3/cmd/sops/common"
	"github.com/getsops/sops/v3/keys"
	"github.com/getsops/sops/v3/keyservice"
	"github.com/getsops/sops/v3/rotation"
)

type rotateOpts struct {
	Cipher           sops.Cipher
	InputStore       sops.Store
	OutputStore      sops.Store
	InputPath        string
	IgnoreMAC        bool
	AddMasterKeys    []keys.MasterKey
	RemoveMasterKeys []keys.MasterKey
	KeyServices      []keyservice.KeyServiceClient
	DecryptionOrder  []string
}

// rotateFileInfo describes what one rotation did or why it did nothing. It is
// only used to build audit records; it never carries key material, only
// identifiers and fingerprints.
type rotateFileInfo struct {
	// AlreadyRotated is set when the file already contained every key
	// requested with --add-* and none of the ones requested with --rm-*.
	AlreadyRotated bool
	// NoNewKey is set when no --add-* key was given, so "already rotated"
	// cannot be determined from the master key set.
	NoNewKey bool

	OldDataKeyFingerprint string
	NewDataKeyFingerprint string

	MasterKeysAdded   []rotation.KeyRef
	MasterKeysRemoved []rotation.KeyRef
	MasterKeysAfter   []rotation.KeyRef
}

// rotate keeps its historical contract: rotate one file and return its
// encrypted bytes. All auditing added for this feature lives in rotateFile and
// is only consulted by callers that opt in.
func rotate(opts rotateOpts) ([]byte, error) {
	output, _, err := rotateFile(opts, false)
	return output, err
}

// rotateFile performs the rotation. When checkAlreadyRotated is false the code
// path is exactly the historical one; when true it first inspects the loaded
// tree's master keys and returns AlreadyRotated without decrypting anything if
// the requested target keys are already in place.
func rotateFile(opts rotateOpts, checkAlreadyRotated bool) ([]byte, rotateFileInfo, error) {
	var info rotateFileInfo

	tree, err := common.LoadEncryptedFileWithBugFixes(common.GenericDecryptOpts{
		Cipher:          opts.Cipher,
		InputStore:      opts.InputStore,
		InputPath:       opts.InputPath,
		IgnoreMAC:       opts.IgnoreMAC,
		KeyServices:     opts.KeyServices,
		DecryptionOrder: opts.DecryptionOrder,
	})
	if err != nil {
		return nil, info, err
	}

	if checkAlreadyRotated {
		info.NoNewKey = len(opts.AddMasterKeys) == 0
		if !info.NoNewKey && alreadyRotated(tree, opts.AddMasterKeys, opts.RemoveMasterKeys) {
			info.AlreadyRotated = true
			info.MasterKeysAfter = masterKeyRefs(tree.Metadata.KeyGroups)
			return nil, info, nil
		}
	}

	audit.SubmitEvent(audit.RotateEvent{
		File: tree.FilePath,
	})

	dataKey, err := common.DecryptTree(common.DecryptTreeOpts{
		Cipher:          opts.Cipher,
		IgnoreMac:       opts.IgnoreMAC,
		Tree:            tree,
		KeyServices:     opts.KeyServices,
		DecryptionOrder: opts.DecryptionOrder,
	})
	if err != nil {
		return nil, info, err
	}
	info.OldDataKeyFingerprint = rotation.DataKeyFingerprint(dataKey)

	// Add new master keys
	if checkAlreadyRotated {
		info.MasterKeysAdded = masterKeyRefs([]sops.KeyGroup{opts.AddMasterKeys})
		info.MasterKeysRemoved = masterKeyRefs([]sops.KeyGroup{opts.RemoveMasterKeys})
	}
	for _, key := range opts.AddMasterKeys {
		tree.Metadata.KeyGroups[0] = append(tree.Metadata.KeyGroups[0], key)
	}
	// Remove master keys
	for _, rmKey := range opts.RemoveMasterKeys {
		for i := range tree.Metadata.KeyGroups {
			for j, groupKey := range tree.Metadata.KeyGroups[i] {
				if rmKey.ToString() == groupKey.ToString() {
					tree.Metadata.KeyGroups[i] = append(tree.Metadata.KeyGroups[i][:j], tree.Metadata.KeyGroups[i][j+1:]...)
				}
			}
		}
	}

	// Create a new data key
	newDataKey, errs := tree.GenerateDataKeyWithKeyServices(opts.KeyServices)
	if len(errs) > 0 {
		err = fmt.Errorf("Could not generate data key: %s", errs)
		return nil, info, err
	}
	info.NewDataKeyFingerprint = rotation.DataKeyFingerprint(newDataKey)

	// Reencrypt the file with the new key
	err = common.EncryptTree(common.EncryptTreeOpts{
		DataKey: newDataKey, Tree: tree, Cipher: opts.Cipher,
	})
	if err != nil {
		return nil, info, err
	}

	encryptedFile, err := opts.OutputStore.EmitEncryptedFile(*tree)
	if err != nil {
		return nil, info, common.NewExitError(fmt.Sprintf("Could not marshal tree: %s", err), codes.ErrorDumpingTree)
	}
	if checkAlreadyRotated {
		info.MasterKeysAfter = masterKeyRefs(tree.Metadata.KeyGroups)
	}
	return encryptedFile, info, nil
}

// alreadyRotated reports whether the tree's master keys already match the
// requested rotation target: every --add-* key is present and no --rm-* key is.
func alreadyRotated(tree *sops.Tree, add, rm []keys.MasterKey) bool {
	if len(add) == 0 {
		return false
	}
	present := make(map[string]struct{})
	for _, group := range tree.Metadata.KeyGroups {
		for _, key := range group {
			present[key.ToString()] = struct{}{}
		}
	}
	for _, key := range add {
		if _, ok := present[key.ToString()]; !ok {
			return false
		}
	}
	for _, key := range rm {
		if _, ok := present[key.ToString()]; ok {
			return false
		}
	}
	return true
}

// masterKeyRefs projects key groups into the identifier-only form that is safe
// to persist. ToString() is a public identifier for every backend (age
// recipient, KMS ARN, PGP fingerprint, Vault URI, ...); key material in SOPS is
// stored in EncryptedDataKey(), which is deliberately never read here.
func masterKeyRefs(groups []sops.KeyGroup) []rotation.KeyRef {
	var refs []rotation.KeyRef
	for _, group := range groups {
		for _, key := range group {
			id := key.ToString()
			refs = append(refs, rotation.KeyRef{
				Type:        key.TypeToIdentifier(),
				ID:          id,
				Fingerprint: rotation.Fingerprint(id),
			})
		}
	}
	return refs
}
