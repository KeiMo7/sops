# Crash-safe file writing: platform semantics

Every SOPS subcommand that rewrites a file goes through the
`cmd/sops/atomic` package. This document records the exact guarantees and
where the operating systems SOPS supports behave differently.

## The write pipeline

A single replacement (`atomic.WriteFile`) runs these stages in order, and
errors are reported with the failing stage attached:

1. **preflight** — the target directory exists, is writable and has enough
   free space for the payload (`statfs`/`GetDiskFreeSpaceEx`).
2. **write lock** — an exclusive, non-blocking lock on
   `.sops-tmp-<name>.lock` next to the target. A contended lock fails
   immediately with `ErrLocked` instead of blocking the CLI.
3. **baseline** — the target's identity (device, inode, size, mode,
   mtime, ctime) is captured. A caller may instead pass a baseline taken
   before processing started, which detects a writer that committed while
   this process was waiting for the lock.
4. **stale cleanup** — staging files from crashed runs are reclaimed, but
   only when no live process holds their lock.
5. **staging file** — `.sops-tmp-<name>-<pid>-<rand>.tmp` is created in
   the *same directory* as the target with mode `0600`, so no content is
   ever exposed more loosely than the original and nothing is ever written
   to a shared temp directory.
6. **write + fsync** — the full payload is written (short writes are
   retried), `fsync`ed, and its on-disk length is checked.
7. **verify** — for encrypted output the staged file is fully reloaded and
   decrypted (including the MAC check); a failure aborts before the old
   version is touched.
8. **metadata** — the original mode, owner and extended attributes are
   copied onto the staging file.
9. **baseline re-check** — if the target moved since step 3, the write is
   refused with `ErrConflict`; the other writer's result is never
   overwritten.
10. **commit** — an atomic rename replaces the target, followed by an
    `fsync` of the parent directory.

At every instant before step 10 the previous, complete file is the only
content visible at the target path.

## Unix/Linux (including macOS)

- The commit is `rename(2)`, which is atomic on POSIX-conformant
  filesystems: concurrent readers see either the old file or the new one,
  never a mix.
- The lock is `flock(2)` (`LOCK_EX | LOCK_NB`). The lock is bound to the
  open file description, so it is released automatically when the process
  exits — even on `SIGKILL` or power loss. A stale lock file therefore can
  never block a future run; the lock file itself is retained deliberately
  as a stable mutex inode.
- Directory durability uses `fsync(2)` on the parent directory, which is
  what makes the rename survive a crash on ext4, XFS, btrfs and similar
  local filesystems.
- Extended attributes are copied with `listxattr`/`getxattr`/`setxattr`
  (Linux user and security namespaces; the flat macOS namespace via
  `xattr(2)`). On other Unix variants without an implementation the copy
  is a documented no-op.
- Free space comes from `statfs(2)`; read-only directories are detected
  from the directory mode bits and, authoritatively, from the failing
  open/rename syscall.

### Filesystem caveats

- On **NFS**, `flock` and atomic rename behave correctly with modern
  servers (NFSv4 has byte-range locking; v3 uses NLM). A server mounted
  with `nolock` cannot provide mutual exclusion — avoid that option for
  directories SOPS writes to. `fsync` durability depends on the server
  honoring it.
- On **tmpfs/overlay/network filesystems** that lack `fsync` persistence,
  the atomicity and no-partial-file guarantees still hold; only the
  survive-physical-power-loss guarantee is weaker by nature of the mount.
- A **hard link** to the target keeps pointing at the old inode after a
  rename-based replacement. This is the standard, safe rename semantic and
  intentionally differs from the historical in-place truncation; the other
  hard link is never corrupted or half-written.
- A **symlink** target is followed: the link itself is preserved and the
  real file it points at is replaced.

## Windows

- The commit is `MoveFileEx` with `MOVEFILE_REPLACE_EXISTING |
  MOVEFILE_WRITE_THROUGH`, which is atomic with respect to other processes
  on NTFS and flushes the directory metadata before returning; the
  directory `fsync` step is therefore a no-op there.
- Mutual exclusion uses a mandatory `LockFileEx` byte-range lock with
  `LOCKFILE_FAIL_IMMEDIATELY`; a contended lock maps to the same
  `ErrLocked` as on Unix.
- There is no uid/gid model, so owner preservation is a no-op, and
  alternate data streams are intentionally not propagated (they are not
  POSIX extended attributes).
- Read-only state is detected from `FILE_ATTRIBUTE_READONLY`; free space
  comes from `GetDiskFreeSpaceEx`.

## Shared temp directory and plaintext

The editor subcommand still materializes the decrypted document in a
private scratch directory (`os.MkdirTemp`, mode `0700`) containing a single
`0600` file for the external editor to open; this is required for the
editor workflow and is not a commit staging file. Every file created by the
commit pipeline itself lives next to the target at mode `0600` and is
renamed into place — plaintext is never written through a world-readable
shared path.

## What is intentionally unchanged

- stdin/stdout streaming does not create any file and is untouched.
- Exit codes remain the existing `codes` values (write failures stay
  `CouldNotWriteOutputFile` = 3); new error text only adds the failing
  pipeline stage for readability.
- No new external dependency is required: the only system call wrappers
  used come from `golang.org/x/sys`, already a direct dependency.
