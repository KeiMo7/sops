//go:build !windows && !linux && !darwin

package atomic

// CopyXAttr is a no-op on Unix variants without an xattr implementation in
// this package. The documented behavior is that xattr preservation is only
// guaranteed on Linux and macOS; see PLATFORM.md.
func (OSFileSystem) CopyXAttr(src, dst string) error {
	return nil
}
