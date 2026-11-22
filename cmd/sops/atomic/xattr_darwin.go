//go:build darwin

package atomic

import "golang.org/x/sys/unix"

// CopyXAttr duplicates every extended attribute from src onto dst. On
// macOS the xattr names exposed by Listxattr carry no namespace prefix.
func (OSFileSystem) CopyXAttr(src, dst string) error {
	size, err := unix.Listxattr(src, nil)
	if err != nil {
		if err == unix.ENOTSUP || err == unix.EOPNOTSUPP {
			return nil
		}
		return err
	}
	if size == 0 {
		return nil
	}
	buf := make([]byte, size)
	if _, err = unix.Listxattr(src, buf); err != nil {
		return err
	}
	start := 0
	for i, b := range buf {
		if b != 0 {
			continue
		}
		name := string(buf[start:i])
		start = i + 1
		if name == "" {
			continue
		}
		vsize, verr := unix.Getxattr(src, name, nil)
		if verr != nil {
			if verr == unix.ENOATTR {
				continue
			}
			return verr
		}
		value := make([]byte, vsize)
		if _, verr = unix.Getxattr(src, name, value); verr != nil {
			return verr
		}
		if serr := unix.Setxattr(dst, name, value, 0); serr != nil {
			return serr
		}
	}
	return nil
}
