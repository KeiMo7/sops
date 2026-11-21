package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/getsops/sops/v3/cmd/sops/codes"
	"github.com/getsops/sops/v3/cmd/sops/common"
	"github.com/getsops/sops/v3/cmd/sops/formats"
	"github.com/getsops/sops/v3/config"
	"github.com/getsops/sops/v3/rotation"
	"github.com/getsops/sops/v3/stores"
	"github.com/urfave/cli"
)

// rotationLogFlagName is the opt-in switch for the rotation audit trail. When
// it is empty the command behaves exactly as it did before this feature.
const rotationLogFlagName = "rotation-log"

func rotationLogEnabled(c *cli.Context) bool {
	return c.String(rotationLogFlagName) != ""
}

// rotationTarget is one file the run will process. Skip is set for files that
// are recorded as skipped without being opened (unsupported format).
type rotationTarget struct {
	path string
	skip *rotation.Record
}

// supportedRotationExtensions are the extensions a recursive walk considers
// SOPS files. Explicit file arguments are always attempted regardless of
// extension, matching the historical behaviour where an unknown extension
// means the binary store. ".binary" is not a real extension: unextended files
// are detected by sniffing for the JSON envelope instead (see isBinaryStoreFile).
var supportedRotationExtensions = map[string]bool{
	".yaml": true,
	".yml":  true,
	".json": true,
	".env":  true,
	".ini":  true,
}

// isBinaryStoreFile reports whether path looks like a SOPS binary file: a JSON
// object with a top-level "sops" key wrapping a single "data" value. This lets
// a recursive walk pick up extensionless binary files without treating every
// unrelated file (README, .gitignore, ...) as a rotation candidate.
func isBinaryStoreFile(path string) bool {
	f, err := os.Open(path)
	if err != nil {
		return false
	}
	defer f.Close()
	var envelope map[string]interface{}
	dec := json.NewDecoder(io.LimitReader(f, 1<<20))
	if err := dec.Decode(&envelope); err != nil {
		return false
	}
	if _, ok := envelope[stores.SopsMetadataKey]; !ok {
		return false
	}
	_, ok := envelope["data"]
	return ok
}

func formatNameForPath(path string) string {
	switch formats.FormatForPath(path) {
	case formats.Yaml:
		return "yaml"
	case formats.Json:
		return "json"
	case formats.Dotenv:
		return "dotenv"
	case formats.Ini:
		return "ini"
	default:
		return "binary"
	}
}

// expandRotationTargets turns positional arguments into an ordered list of
// files. Directories are walked recursively; files with an unsupported
// extension inside a directory are kept as skip records so the trail explains
// why they were not rotated.
func expandRotationTargets(logDir string, args []string) ([]rotationTarget, error) {
	absLogDir, _ := filepath.Abs(logDir)
	seen := make(map[string]struct{})
	var targets []rotationTarget

	add := func(path string, skip *rotation.Record) {
		abs, err := filepath.Abs(path)
		if err != nil {
			abs = path
		}
		if _, ok := seen[abs]; ok {
			return
		}
		seen[abs] = struct{}{}
		targets = append(targets, rotationTarget{path: path, skip: skip})
	}

	for _, arg := range args {
		info, err := os.Stat(arg)
		if err != nil {
			add(arg, &rotation.Record{
				Kind:      rotation.KindFile,
				File:      rotation.RelativePath("", arg),
				Status:    rotation.StatusFailed,
				ErrorKind: classifyFileError(err),
				Error:     rotation.ErrorDetail("", err),
			})
			continue
		}
		if !info.IsDir() {
			add(arg, nil)
			continue
		}
		absDir, _ := filepath.Abs(arg)
		if absLogDir != "" && absDir == absLogDir {
			continue
		}
		err = filepath.WalkDir(arg, func(path string, d fs.DirEntry, walkErr error) error {
			if walkErr != nil {
				return walkErr
			}
			abs, _ := filepath.Abs(path)
			inLogDir := absLogDir != "" && (abs == absLogDir || strings.HasPrefix(abs, absLogDir+string(filepath.Separator)))
			if d.IsDir() {
				if inLogDir {
					return filepath.SkipDir
				}
				if path != arg && strings.HasPrefix(d.Name(), ".") {
					return filepath.SkipDir
				}
				return nil
			}
			if inLogDir {
				return nil
			}
			if !rotationFileSupported(path) {
				add(path, &rotation.Record{
					Kind:       rotation.KindFile,
					File:       rotation.RelativePath("", path),
					FileFormat: "unsupported",
					Status:     rotation.StatusSkipped,
					SkipReason: rotation.SkipUnsupportedFormat,
				})
				return nil
			}
			add(path, nil)
			return nil
		})
		if err != nil {
			return nil, err
		}
	}
	return targets, nil
}

func rotationFileSupported(path string) bool {
	if supportedRotationExtensions[strings.ToLower(filepath.Ext(path))] {
		return true
	}
	return isBinaryStoreFile(path)
}

// rotationStores caches one store instance per (format, direction) so a
// multi-file run does not re-read the sops config for every file.
type rotationStores struct {
	config     *config.StoresConfig
	inputType  string
	outputType string
	cache      map[string]common.Store
}

func newRotationStores(c *cli.Context) (*rotationStores, error) {
	sc, err := loadStoresConfig(c, ".")
	if err != nil {
		return nil, err
	}
	if c.GlobalIsSet("indent") {
		indent := c.GlobalInt("indent")
		sc.YAML.Indent = indent
		sc.JSON.Indent = indent
		sc.JSONBinary.Indent = indent
	}
	return &rotationStores{
		config:     sc,
		inputType:  c.String("input-type"),
		outputType: c.String("output-type"),
		cache:      make(map[string]common.Store),
	}, nil
}

func (r *rotationStores) get(path string, output bool) common.Store {
	override := r.inputType
	if output {
		override = r.outputType
	}
	format := formats.FormatForPathOrString(path, override)
	key := fmt.Sprintf("%d/%t", format, output)
	if store, ok := r.cache[key]; ok {
		return store
	}
	store := common.StoreForFormat(format, r.config)
	r.cache[key] = store
	return store
}

// rotateWithLog runs a rotation over one or more files and appends the audit
// trail. It is only reachable when --rotation-log was passed, so none of its
// output or exit codes affect the historical single-file path.
func rotateWithLog(c *cli.Context, args []string, inPlace bool, logDir string) error {
	root, err := os.Getwd()
	if err != nil {
		return toExitError(err)
	}
	targets, err := expandRotationTargets(logDir, args)
	if err != nil {
		return toExitError(err)
	}
	if len(targets) == 0 {
		return common.NewExitError("Error: no file specified", codes.NoFileSpecified)
	}
	// Explicit arguments that do not exist fail the run like the historical
	// single-file path does, instead of silently "succeeding" with a failed
	// record. Directory contents are discovered by the walk, not asserted.
	for _, target := range targets {
		if target.skip == nil || target.skip.ErrorKind != rotation.ErrorNotFound {
			continue
		}
		if _, err := os.Stat(target.path); err != nil {
			return common.NewExitError(fmt.Sprintf("Error: cannot operate on non-existent file %q", target.path), codes.CannotChangeKeysFromNonExistentFile)
		}
	}

	outputPath := c.String("output")
	if len(args) > 1 || len(targets) > 1 {
		info, _ := os.Stat(args[0])
		if info != nil && info.IsDir() {
			if !inPlace {
				return common.NewExitError("Error: rotating a directory requires --in-place", codes.ErrorConflictingParameters)
			}
		}
		if outputPath != "" {
			return common.NewExitError("Error: cannot use --output when rotating multiple files", codes.ErrorConflictingParameters)
		}
		if len(targets) > 1 && !inPlace {
			return common.NewExitError("Error: rotating multiple files requires --in-place", codes.ErrorConflictingParameters)
		}
		if c.String("filename-override") != "" {
			return common.NewExitError("Error: cannot use --filename-override when rotating multiple files", codes.ErrorConflictingParameters)
		}
	}

	stores, err := newRotationStores(c)
	if err != nil {
		return toExitError(err)
	}
	svcs := keyservices(c)
	order, err := decryptionOrder(c.String("decryption-order"))
	if err != nil {
		return toExitError(err)
	}
	// Parse the add/rm key lists once, not once per file.
	base, err := getRotateOpts(c, "", nil, nil, svcs, order)
	if err != nil {
		return toExitError(err)
	}
	base.InputPath = ""
	if c.Bool("verbose") {
		log.Debugf("master keys requested for this rotation: add=%d remove=%d", len(base.AddMasterKeys), len(base.RemoveMasterKeys))
	}

	rotationID := rotation.NewRotationID()
	writer := rotation.NewRunWriter(rotation.NewWriter(logDir))
	var singleErr error

	stop, stopSignals := rotationInterruptChannel()
	defer stopSignals()

	result := rotation.Run(toWorkItems(targets), rotationID, writer, func(item rotation.WorkItem) rotation.FileOutcome {
		outcome := processRotationFile(item.Path, root, inPlace, outputPath, stores, base)
		if outcome.Err != nil && len(targets) == 1 {
			singleErr = outcome.Err
		}
		return outcome
	}, stop)

	// Logging must never change the rotation outcome: warn, then keep the
	// unwritten records in a spool file the operator can append later.
	if len(result.LogErrors) > 0 || len(writer.Pending()) > 0 {
		log.Warnf("Rotation audit trail could not be written to %s: %v (%d record(s) pending)",
			rotation.RelativePath(root, logDir), rotation.SanitizeText(root, firstError(result.LogErrors).Error()), len(writer.Pending()))
		if spool, spoolErr := writeRotationSpool(rotationID, writer.Pending()); spoolErr == nil {
			// The spool lives in the OS temp directory, which is outside the
			// rotation root, so print only its file name and the temp-dir
			// hint rather than an absolute path.
			log.Warnf("Pending rotation records were saved as %s in the temporary directory; append them later with: sops %s append <tmpdir>/%s --%s %s",
				filepath.Base(spool), rotationLogCommandName, filepath.Base(spool), rotationLogFlagName, rotation.RelativePath(root, logDir))
		} else {
			log.Warnf("Could not save pending rotation records: %v", spoolErr)
		}
	} else if err := writer.Sync(); err != nil {
		log.Warnf("Could not sync rotation audit trail: %v", err)
	}

	// Per-file and summary output go to stderr; the rotated document (if any)
	// stays on stdout. This is the only line the opt-in path adds to a
	// single-file run that previously printed nothing.
	fmt.Fprintf(os.Stderr, "rotation %s: %d file(s): %d rotated, %d skipped, %d failed (trail: %s)\n",
		rotationID, result.Totals.Total, result.Totals.Succeeded, result.Totals.Skipped, result.Totals.Failed,
		rotation.RelativePath(root, filepath.Join(logDir, rotation.LogFileName)))
	if result.Interrupted {
		fmt.Fprintf(os.Stderr, "rotation %s was interrupted after %d file(s); finished files are recorded, remaining files were not touched\n",
			rotationID, result.Totals.Total)
	}

	if singleErr != nil {
		return toExitError(singleErr)
	}
	if len(result.Errors) > 0 {
		return common.NewExitError(fmt.Sprintf("failed to rotate %d file(s)", len(result.Errors)), codes.ErrorGeneric)
	}
	return nil
}

// rotationInterruptChannel returns a channel closed on SIGINT/SIGTERM. The
// runner checks it between files; an in-flight file is always finished first,
// which is exactly the "records for handled files, none for untouched ones"
// guarantee. A second signal falls back to the default handler (immediate exit)
// through stopSignals.
func rotationInterruptChannel() (<-chan struct{}, func()) {
	stop := make(chan struct{})
	sigc := make(chan os.Signal, 2)
	signal.Notify(sigc, os.Interrupt, syscall.SIGTERM)
	go func() {
		if _, ok := <-sigc; !ok {
			return
		}
		close(stop)
		signal.Stop(sigc)
	}()
	return stop, func() {
		signal.Stop(sigc)
		close(sigc)
	}
}

func toWorkItems(targets []rotationTarget) []rotation.WorkItem {
	items := make([]rotation.WorkItem, 0, len(targets))
	for _, target := range targets {
		items = append(items, rotation.WorkItem{Path: target.path, Skip: target.skip})
	}
	return items
}

func firstError(errs []error) error {
	if len(errs) == 0 {
		return errors.New("unknown error")
	}
	return errs[0]
}

func writeRotationSpool(rotationID string, records []rotation.Record) (string, error) {
	if len(records) == 0 {
		return "", errors.New("no pending records")
	}
	path := filepath.Join(os.TempDir(), fmt.Sprintf("sops-rotation-%s.spool.jsonl", rotationID))
	return path, rotation.WriteSpool(path, records)
}

// processRotationFile rotates one file and returns its audit record. The
// record is only handed to the runner after the file has been fully handled,
// so an aborted run never leaves a trace of a file it did not finish.
func processRotationFile(path, root string, inPlace bool, outputPath string, stores *rotationStores, base rotateOpts) rotation.FileOutcome {
	rel := rotation.RelativePath(root, path)
	record := rotation.Record{
		Kind:       rotation.KindFile,
		File:       rel,
		FileFormat: formatNameForPath(path),
	}

	fail := func(kind string, err error) rotation.FileOutcome {
		record.Status = rotation.StatusFailed
		record.ErrorKind = kind
		record.Error = rotation.ErrorDetail(root, err)
		return rotation.FileOutcome{Record: record, Err: err}
	}

	opts := base
	opts.InputStore = stores.get(path, false)
	opts.OutputStore = stores.get(path, true)
	opts.InputPath = path

	encrypted, info, err := rotateFile(opts, true)
	if err != nil {
		return fail(classifyRotateError(err), err)
	}
	record.MasterKeysAdded = info.MasterKeysAdded
	record.MasterKeysRemoved = info.MasterKeysRemoved
	record.MasterKeysAfter = info.MasterKeysAfter

	if info.AlreadyRotated {
		record.Status = rotation.StatusSkipped
		record.SkipReason = rotation.SkipAlreadyRotated
		return rotation.FileOutcome{Record: record}
	}
	if info.NoNewKey {
		log.Warnf("No --add-* key was given for %s; it cannot be detected as already rotated and will be rotated every run", rel)
	}

	record.OldDataKeyFingerprint = info.OldDataKeyFingerprint
	record.NewDataKeyFingerprint = info.NewDataKeyFingerprint

	if err := writeRotatedFile(path, encrypted, inPlace, outputPath); err != nil {
		return fail(classifyWriteError(err), err)
	}

	record.Status = rotation.StatusSuccess
	record.Outcome = rotation.OutcomeRotated
	return rotation.FileOutcome{Record: record}
}

// writeRotatedFile mirrors the historical writer: os.Create for in-place and
// for --output, stdout otherwise.
func writeRotatedFile(path string, data []byte, inPlace bool, outputPath string) error {
	if inPlace {
		file, err := os.Create(path)
		if err != nil {
			return common.NewExitError(fmt.Sprintf("Could not open in-place file for writing: %s", err), codes.CouldNotWriteOutputFile)
		}
		defer file.Close()
		if _, err := file.Write(data); err != nil {
			return err
		}
		log.Info("File written successfully")
		return nil
	}
	if outputPath != "" {
		file, err := os.Create(outputPath)
		if err != nil {
			return common.NewExitError(fmt.Sprintf("Could not open output file for writing: %s", err), codes.CouldNotWriteOutputFile)
		}
		defer file.Close()
		_, err = file.Write(data)
		return err
	}
	_, err := os.Stdout.Write(data)
	return err
}

// classifyFileError maps filesystem errors to the coarse kinds an operator
// actions first.
func classifyFileError(err error) string {
	switch {
	case errors.Is(err, fs.ErrPermission):
		return rotation.ErrorPermission
	case errors.Is(err, fs.ErrNotExist):
		return rotation.ErrorNotFound
	default:
		return rotation.ErrorRead
	}
}

// classifyWriteError distinguishes "the file cannot be written" from "the
// directory/target denies access", which are different operator actions.
func classifyWriteError(err error) string {
	var exitErr *cli.ExitError
	if errors.As(err, &exitErr) {
		if strings.Contains(exitErr.Error(), "permission denied") {
			return rotation.ErrorPermission
		}
		return rotation.ErrorWrite
	}
	if errors.Is(err, fs.ErrPermission) {
		return rotation.ErrorPermission
	}
	return rotation.ErrorWrite
}

// classifyRotateError maps a rotation failure to a failure kind, using the exit
// codes the existing rotation code already assigns.
//
// The order matters: failures after the data key was retrieved (new key
// generation, re-encryption, marshalling) are separate kinds, so the cheaper
// "what failed" answer does not depend on message text. Only when no exit code
// is present does it fall back to the stable message prefixes in rotate.go.
func classifyRotateError(err error) string {
	var exitErr *cli.ExitError
	if errors.As(err, &exitErr) {
		switch exitErr.ExitCode() {
		case codes.CouldNotReadInputFile:
			return rotation.ErrorRead
		case codes.CouldNotRetrieveKey:
			return rotation.ErrorDecrypt
		case codes.ErrorDecryptingTree, codes.ErrorDecryptingMac, codes.MacMismatch:
			return rotation.ErrorDecrypt
		case codes.ErrorEncryptingTree, codes.ErrorEncryptingMac:
			return rotation.ErrorEncrypt
		case codes.ErrorDumpingTree:
			return rotation.ErrorMarshal
		case codes.CouldNotWriteOutputFile:
			return rotation.ErrorWrite
		}
	}
	if errors.Is(err, fs.ErrPermission) {
		return rotation.ErrorPermission
	}
	msg := err.Error()
	switch {
	case strings.HasPrefix(msg, "Could not generate data key"):
		return rotation.ErrorKeyGeneration
	case strings.HasPrefix(msg, "Error encrypting tree"), strings.HasPrefix(msg, "Could not encrypt MAC"):
		return rotation.ErrorEncrypt
	case strings.HasPrefix(msg, "Could not marshal tree"):
		return rotation.ErrorMarshal
	case strings.HasPrefix(msg, "Error unmarshalling"), strings.Contains(msg, "sops metadata not found"):
		return rotation.ErrorRead
	case strings.HasPrefix(msg, "Failed to get the data key"), strings.HasPrefix(msg, "Error decrypting tree"):
		return rotation.ErrorDecrypt
	}
	return rotation.ErrorUnknown
}

// --- `sops rotation-log` subcommand -------------------------------------

const rotationLogCommandName = "rotation-log"

func rotationLogCommand() cli.Command {
	dirFlag := cli.StringFlag{
		Name:  rotationLogFlagName,
		Usage: "directory containing the rotation audit trail",
	}
	return cli.Command{
		Name:  rotationLogCommandName,
		Usage: "inspect and repair the rotation audit trail written with --rotation-log",
		Subcommands: []cli.Command{
			{
				Name:      "show",
				Usage:     "print every record in the trail",
				ArgsUsage: " ",
				Flags: []cli.Flag{
					dirFlag,
					cli.StringFlag{Name: "rotation-id", Usage: "only show records of this rotation"},
					cli.BoolFlag{Name: "json", Usage: "print raw JSON lines"},
				},
				Action: func(c *cli.Context) error {
					path, records, spans, err := readRotationTrail(c)
					if err != nil {
						return err
					}
					if id := c.String("rotation-id"); id != "" {
						filtered := records[:0]
						for _, record := range records {
							if record.RotationID == id {
								filtered = append(filtered, record)
							}
						}
						records = filtered
					}
					printCorruptSpans(path, spans)
					for _, record := range records {
						if c.Bool("json") {
							printJSON(record)
						} else {
							fmt.Println(formatRecord(record))
						}
					}
					return nil
				},
			},
			{
				Name:      "summary",
				Usage:     "print the summary of a rotation run",
				ArgsUsage: "[rotation-id]",
				Flags: []cli.Flag{
					dirFlag,
					cli.StringFlag{Name: "json", Usage: "print raw JSON"},
				},
				Action: func(c *cli.Context) error {
					path, records, spans, err := readRotationTrail(c)
					if err != nil {
						return err
					}
					id := c.Args().First()
					if id == "" {
						id = c.String("rotation-id")
					}
					printCorruptSpans(path, spans)
					return printRotationSummary(records, id, c.Bool("json"))
				},
			},
			{
				Name:      "file",
				Usage:     "print the rotation history of one file",
				ArgsUsage: "file",
				Flags: []cli.Flag{
					dirFlag,
					cli.BoolFlag{Name: "json", Usage: "print raw JSON lines"},
				},
				Action: func(c *cli.Context) error {
					if c.NArg() != 1 {
						return common.NewExitError("Error: need exactly one file", codes.NoFileSpecified)
					}
					logDir := c.String(rotationLogFlagName)
					if logDir == "" {
						return common.NewExitError("Error: --rotation-log is required", codes.ErrorConflictingParameters)
					}
					root, _ := os.Getwd()
					rel := rotation.RelativePath(root, c.Args().First())
					path := rotation.NewWriter(logDir).Path()
					history, spans, err := rotation.ReadFileHistory(path, rel)
					if err != nil {
						return common.NewExitError(fmt.Sprintf("Could not read rotation trail: %s", err), codes.CouldNotReadInputFile)
					}
					printCorruptSpans(path, spans)
					if c.Bool("json") {
						for _, record := range history.Entries {
							printJSON(record)
						}
						return nil
					}
					fmt.Printf("%s: %d rotation(s)\n", history.File, len(history.Entries))
					for i, record := range history.Entries {
						fmt.Printf("  %d. %s rotation=%s %s\n", i+1, record.Timestamp, record.RotationID, formatFileStatus(record))
						if len(record.MasterKeysAdded) > 0 {
							fmt.Printf("     rotated to: %s\n", formatKeyRefs(record.MasterKeysAdded))
						}
						if len(record.MasterKeysRemoved) > 0 {
							fmt.Printf("     removed:    %s\n", formatKeyRefs(record.MasterKeysRemoved))
						}
						if record.OldDataKeyFingerprint != "" || record.NewDataKeyFingerprint != "" {
							fmt.Printf("     data key:   %s -> %s\n", record.OldDataKeyFingerprint, record.NewDataKeyFingerprint)
						}
					}
					return nil
				},
			},
			{
				Name:      "append",
				Usage:     "append records saved in a spool file to the trail (skips records already present)",
				ArgsUsage: "spool-file",
				Flags:     []cli.Flag{dirFlag},
				Action: func(c *cli.Context) error {
					if c.NArg() != 1 {
						return common.NewExitError("Error: need a spool file", codes.NoFileSpecified)
					}
					logDir := c.String(rotationLogFlagName)
					if logDir == "" {
						return common.NewExitError("Error: --rotation-log is required", codes.ErrorConflictingParameters)
					}
					spool := c.Args().First()
					pending, spans, err := rotation.ReadAll(spool)
					if err != nil {
						return common.NewExitError(fmt.Sprintf("Could not read spool file: %s", err), codes.CouldNotReadInputFile)
					}
					printCorruptSpans(spool, spans)

					target := rotation.NewWriter(logDir).Path()
					existing, _, _ := rotation.ReadAll(target)
					seen := make(map[string]struct{}, len(existing))
					for _, record := range existing {
						seen[recordKey(record)] = struct{}{}
					}
					var toWrite []rotation.Record
					skipped := 0
					for _, record := range pending {
						if _, ok := seen[recordKey(record)]; ok {
							skipped++
							continue
						}
						toWrite = append(toWrite, record)
					}
					written, err := rotation.Replay(logDir, toWrite)
					if err != nil {
						return common.NewExitError(fmt.Sprintf("Could not append rotation records (%d written before failure): %s", written, err), codes.CouldNotWriteOutputFile)
					}
					fmt.Fprintf(os.Stderr, "appended %d record(s), skipped %d already present\n", written, skipped)
					return nil
				},
			},
		},
	}
}

func recordKey(record rotation.Record) string {
	return record.RotationID + "|" + record.Kind + "|" + record.File + "|" + record.Timestamp
}

func readRotationTrail(c *cli.Context) (string, []rotation.Record, []rotation.CorruptSpan, error) {
	logDir := c.String(rotationLogFlagName)
	if logDir == "" {
		return "", nil, nil, common.NewExitError("Error: --rotation-log is required", codes.ErrorConflictingParameters)
	}
	path := rotation.NewWriter(logDir).Path()
	records, spans, err := rotation.ReadAll(path)
	if err != nil {
		return path, nil, spans, common.NewExitError(fmt.Sprintf("Could not read rotation trail: %s", err), codes.CouldNotReadInputFile)
	}
	return path, records, spans, nil
}

func printCorruptSpans(path string, spans []rotation.CorruptSpan) {
	display := path
	if root, err := os.Getwd(); err == nil {
		display = rotation.RelativePath(root, path)
	}
	for _, span := range spans {
		fmt.Fprintf(os.Stderr, "warning: %s: unreadable rotation record at %s; entries in that range may be missing\n", display, span)
	}
}

func formatFileStatus(record rotation.Record) string {
	switch record.Status {
	case rotation.StatusSuccess:
		return "rotated"
	case rotation.StatusSkipped:
		return "skipped (" + record.SkipReason + ")"
	case rotation.StatusFailed:
		detail := record.ErrorKind
		if record.Error != "" {
			detail += ": " + record.Error
		}
		return "failed (" + detail + ")"
	default:
		return record.Status
	}
}

func formatKeyRefs(refs []rotation.KeyRef) string {
	parts := make([]string, 0, len(refs))
	for _, ref := range refs {
		parts = append(parts, fmt.Sprintf("%s:%s (%s)", ref.Type, ref.ID, ref.Fingerprint))
	}
	return strings.Join(parts, ", ")
}

func formatRecord(record rotation.Record) string {
	if record.Kind == rotation.KindSummary {
		if record.Totals == nil {
			return fmt.Sprintf("%s rotation=%s summary", record.Timestamp, record.RotationID)
		}
		return fmt.Sprintf("%s rotation=%s summary total=%d rotated=%d skipped=%d failed=%d",
			record.Timestamp, record.RotationID, record.Totals.Total, record.Totals.Succeeded,
			record.Totals.Skipped, record.Totals.Failed)
	}
	return fmt.Sprintf("%s rotation=%s %s %s", record.Timestamp, record.RotationID, record.File, formatFileStatus(record))
}

func printRotationSummary(records []rotation.Record, rotationID string, asJSON bool) error {
	ids := []string{}
	seen := map[string]struct{}{}
	for _, record := range records {
		if record.RotationID == "" {
			continue
		}
		if rotationID != "" && record.RotationID != rotationID {
			continue
		}
		if _, ok := seen[record.RotationID]; !ok {
			seen[record.RotationID] = struct{}{}
			ids = append(ids, record.RotationID)
		}
	}
	if len(ids) == 0 {
		return common.NewExitError("Error: no rotation records found", codes.NoFileSpecified)
	}
	for _, id := range ids {
		var files []rotation.Record
		var summary *rotation.Record
		for i := range records {
			if records[i].RotationID != id {
				continue
			}
			if records[i].Kind == rotation.KindSummary {
				summary = &records[i]
				continue
			}
			files = append(files, records[i])
		}
		if asJSON {
			if summary != nil {
				printJSON(*summary)
			} else {
				totals := rotation.Summarize(files)
				printJSON(rotation.Record{
					SchemaVersion: rotation.SchemaVersion,
					Kind:          rotation.KindSummary,
					RotationID:    id,
					Totals:        &totals,
				})
			}
			continue
		}
		totals := rotation.Summarize(files)
		if summary != nil && summary.Totals != nil {
			totals = *summary.Totals
		}
		fmt.Printf("rotation %s\n", id)
		fmt.Printf("  total: %d  rotated: %d  skipped: %d  failed: %d\n", totals.Total, totals.Succeeded, totals.Skipped, totals.Failed)
		for _, record := range files {
			fmt.Printf("  %-7s %-30s %s\n", record.Status, record.File, formatFileStatus(record))
		}
	}
	return nil
}

func printJSON(v interface{}) {
	data, err := json.Marshal(v)
	if err != nil {
		fmt.Fprintf(os.Stderr, "warning: could not encode record: %v\n", err)
		return
	}
	fmt.Println(string(data))
}

// applyRotationRoot applies --rotation-root by changing the process working
// directory before paths are expanded, and returns the absolute trail
// directory. Recorded paths are always relative to the working directory, so
// doing this once up front keeps every record (and every error message) free
// of absolute paths.
func applyRotationRoot(c *cli.Context) (string, error) {
	logDir := c.String(rotationLogFlagName)
	absLogDir, err := filepath.Abs(logDir)
	if err != nil {
		return "", toExitError(err)
	}
	root := c.String("rotation-root")
	if root == "" {
		return absLogDir, nil
	}
	abs, err := filepath.Abs(root)
	if err != nil {
		return "", toExitError(err)
	}
	info, err := os.Stat(abs)
	if err != nil {
		return "", toExitError(err)
	}
	if !info.IsDir() {
		return "", common.NewExitError(fmt.Sprintf("Error: --rotation-root %q is not a directory", root), codes.ErrorConflictingParameters)
	}
	if err := os.Chdir(abs); err != nil {
		return "", toExitError(err)
	}
	return absLogDir, nil
}
