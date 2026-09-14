//go:build !linux && !darwin

package sqlite

import "os"

func privateDirectory(string) error { return os.ErrInvalid }

func privateFile(string, bool) error    { return os.ErrInvalid }
func lockFile(string) (*os.File, error) { return nil, os.ErrInvalid }
func unlockFile(*os.File) error         { return os.ErrInvalid }
