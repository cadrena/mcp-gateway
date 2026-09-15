//go:build linux || darwin

package refundsimulator

import (
	"os"
	"syscall"
)

func privateDirectory(path string) error {
	info, err := os.Stat(path)
	if err != nil {
		return err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.IsDir() || info.Mode().Perm()&0077 != 0 || stat.Uid != uint32(os.Getuid()) {
		return os.ErrPermission
	}
	return nil
}

func privateFile(path string, create bool) error {
	flags := syscall.O_RDWR | syscall.O_NOFOLLOW | syscall.O_NONBLOCK
	if create {
		flags |= syscall.O_CREAT
	}
	fd, err := syscall.Open(path, flags, 0600)
	if err != nil {
		if !create && os.IsNotExist(err) {
			return nil
		}
		return err
	}
	f := os.NewFile(uintptr(fd), path)
	defer f.Close()
	return validateFile(f)
}

func validateFile(f *os.File) error {
	info, err := f.Stat()
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 {
		return os.ErrPermission
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != uint32(os.Getuid()) || stat.Nlink != 1 {
		return os.ErrPermission
	}
	return nil
}

func lockFile(path string) (*os.File, error) {
	fd, err := syscall.Open(path, syscall.O_RDWR|syscall.O_CREAT|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0600)
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(fd), path)
	if err = validateFile(f); err == nil {
		err = syscall.Flock(fd, syscall.LOCK_EX|syscall.LOCK_NB)
	}
	if err != nil {
		_ = f.Close()
		return nil, err
	}
	return f, nil
}

func unlockFile(f *os.File) error {
	err := syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
	if closeErr := f.Close(); closeErr != nil {
		err = closeErr
	}
	return err
}
