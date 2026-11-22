//go:build !unix

package common

import "os"

// fileOwner is not available on this platform.
func fileOwner(fi os.FileInfo) (uid, gid int, ok bool) {
	return 0, 0, false
}

// linkCount cannot be determined on this platform.
func linkCount(fi os.FileInfo) uint64 {
	return 1
}

// currentUmask approximates the umask on platforms that do not have one.
func currentUmask() os.FileMode {
	return 0022
}

// syncDir has no equivalent on this platform.
func syncDir(dir string) error {
	return nil
}

// guardInterrupt is a no-op on this platform.
func guardInterrupt(tmpName string) (stop func()) {
	return func() {}
}
