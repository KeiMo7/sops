//go:build linux

package atomic

import (
	"golang.org/x/sys/unix"
)

// CopyXAttr duplicates every extended attribute (including security.* and
// user.* namespaces) from the previous target onto the staging file. An
// empty attribute list is normal and not an error.
func (OSFileSystem) CopyXAttr(src, dst string) error {
	buf := make([]byte, 0)
	size, err := unix.Listxattr(src, buf)
	if err != nil {
		if err == unix.ENOTSUP || err == unix.EOPNOTSUPP {
			return nil
		}
		return err
	}
	if size == 0 {
		return nil
	}
	buf = make([]byte, size)
	if _, err = unix.Listxattr(src, buf); err != nil {
		return err
	}
	// Names are NUL-separated.
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
		value, verr := getxattrAll(src, name)
		if verr != nil {
			if verr == unix.ENODATA {
				continue
			}
			return verr
		}
		if serr := unix.Setxattr(dst, name, value, 0); serr != nil {
			// A filesystem that cannot store the attribute (e.g. tmpfs
			// without the security namespace) must not silently lose it.
			return serr
		}
	}
	return nil
}

func getxattrAll(path, name string) ([]byte, error) {
	size, err := unix.Getxattr(path, name, nil)
	if err != nil {
		return nil, err
	}
	value := make([]byte, size)
	if _, err = unix.Getxattr(path, name, value); err != nil {
		return nil, err
	}
	return value, nil
}
