# Rotation audit trail

`sops rotate` can write an append-only audit trail of what it did to each file.
The trail is opt-in: without `--rotation-log` sops behaves exactly as before and
creates no files.

## What the trail answers

* Which files were rotated, which were skipped, and which failed.
* Why a file was skipped (`already-rotated` vs `unsupported-format`).
* Why a file failed (`decrypt-failed`, `write-failed`, `permission-denied`, ...).
* Which master key each file was rotated to.
* What one run totalled, and what happened to one file across runs.

Records contain key *identifiers* and SHA-256 *fingerprints* only. They never
contain a private key, a data key, or an encrypted data key.

## Enabling it

```console
$ sops rotate --rotation-log .sops-rotation \
    --add-age age1...new --rm-age age1...old --in-place secrets/
```

`secrets/` may be a directory (walked recursively) or one or more files. The
trail is written to `.sops-rotation/rotations-v1.jsonl`. Recorded paths are
relative to the working directory; use `--rotation-root <dir>` to make them
relative to a different directory. Absolute paths and the user's home directory
never appear in records.

Preconditions for a multi-file run: `--in-place`, no `--output`, no
`--filename-override`. Without `--rotation-log`, `sops rotate` still accepts
exactly one file, as before.

## Record format

One JSON object per line. `schema_version` is `1`. Future versions may add
fields but may not change the meaning of the fields below; readers must ignore
unknown fields and refuse to interpret a version they do not know.

File record:

```json
{"schema_version":1,"kind":"file","rotation_id":"20261121T214931Z-486cf88b7e1d6bde",
 "timestamp":"2026-11-21T21:49:31.73491643Z","file":"env/prod/app.yaml",
 "file_format":"yaml","status":"success","outcome":"rotated",
 "old_data_key_fingerprint":"sha256:3b2dc622...",
 "new_data_key_fingerprint":"sha256:ebcf36e0...",
 "master_keys_added":[{"type":"age","id":"age12t2vx...","fingerprint":"sha256:5103d3cf..."}],
 "master_keys_removed":[{"type":"age","id":"age1vewkm...","fingerprint":"sha256:33d640d3..."}],
 "master_keys":[{"type":"age","id":"age12t2vx...","fingerprint":"sha256:5103d3cf..."}]}
```

Summary record:

```json
{"schema_version":1,"kind":"summary","rotation_id":"20261121T214931Z-486cf88b7e1d6bde",
 "timestamp":"2026-11-21T21:49:31.866548448Z",
 "totals":{"total":5,"succeeded":1,"skipped":4,"failed":0}}
```

Skip reasons: `already-rotated`, `unsupported-format`.
Error kinds: `read-failed`, `file-not-found`, `decrypt-failed`,
`key-generation-failed`, `encrypt-failed`, `marshal-failed`, `write-failed`,
`permission-denied`, `unknown`.

### Deciding "already rotated"

A file is recorded as `already-rotated` when every key passed with `--add-*`
is already a master key of the file and no key passed with `--rm-*` is still
present. In that case sops does not decrypt, re-encrypt or write anything.

With no `--add-*` key, "already rotated" cannot be decided, so the file is
rotated every run and a warning is printed. Pass `--add-*` to get skips.

## Samples

### Rotation summary

```console
$ sops rotation-log summary --rotation-log .rotation
rotation 20261121T215813Z-96689a623f210d4a
  total: 5  rotated: 3  skipped: 2  failed: 0
  success env/prod/app.yaml              rotated
  success env/prod/locale.env            rotated
  success env/prod/token.json            rotated
  skipped env/staging/README.txt         skipped (unsupported-format)
  skipped env/staging/app.yaml           skipped (already-rotated)
```

### Single-file history

```console
$ sops rotation-log file --rotation-log .rotation env/prod/app.yaml
env/prod/app.yaml: 2 rotation(s)
  1. 2026-11-21T21:58:13.866177855Z rotation=20261121T215813Z-96689a623f210d4a rotated
     rotated to: age:age12t2vx673xp4j93zvzaf2xahncjensvw7llydpxr0q9kyjrx8f4qfap2us (sha256:5103d3cf...)
     removed:    age:age1vewkmkffc62usswx5a32ek2zfppw36z4358q0thmxnkltj4kwadsx7nelx (sha256:33d640d3...)
     data key:   sha256:a74ad27a... -> sha256:87f3e4c9...
  2. 2026-11-21T21:58:13.898641628Z rotation=20261121T215813Z-314bcf632d6dfc2d skipped (already-rotated)
```

The second entry is what answers "has this file already been rotated to the new
key?" without decrypting it.

## Degradation

* **Trail directory not writable.** Rotation continues; sops warns on stderr
  and saves the unwritten records to
  `$TMPDIR/sops-rotation-<rotation-id>.spool.jsonl`. Replay them later:
  `sops rotation-log append <spool-file> --rotation-log <dir>`. Appending is
  idempotent: records already in the trail are skipped.
* **Interrupted run** (SIGINT/SIGTERM). The file being processed when the
  signal arrives is finished; the files not yet started are not touched. Every
  finished file keeps its record; no summary is written because the totals are
  incomplete. A second signal exits immediately.
* **Per-file failure.** The failure is recorded and the run continues with the
  next file; the exit status is non-zero at the end.
* **Corrupt trail.** `rotation-log show`, `summary`, `file` and `append`
  report the unreadable line range and its cause (`invalid JSON`,
  `unsupported schema_version ...`) and still return the good records:

  ```console
  $ sops rotation-log file --rotation-log .rotation env/prod/app.yaml
  warning: .rotation/rotations-v1.jsonl: unreadable rotation record at lines 2-3:
  invalid JSON; schema_version 99; entries in that range may be missing
  env/prod/app.yaml: 1 rotation(s)
  ...
  ```

## Commands

| Command | Purpose |
| --- | --- |
| `sops rotate --rotation-log DIR ...` | rotate one or more files and record them |
| `sops rotation-log show --rotation-log DIR` | print every record (`--json` for raw lines) |
| `sops rotation-log summary --rotation-log DIR [rotation-id]` | totals for one or all runs |
| `sops rotation-log file --rotation-log DIR <file>` | history of one file |
| `sops rotation-log append <spool-file> --rotation-log DIR` | replay a spool file |

## Cost

Recording appends one line per file plus one summary line, using
`O_APPEND` writes: no lock, no rename, no copy, and no fsync per file (a single
`fsync` at the end of the run). The "already rotated" probe reuses the tree
that was already loaded for the rotation, so it adds no I/O. A multi-file run
reads the sops config once and shares store instances across files, which is
why many files are much cheaper in one run than in repeated single-file runs.
