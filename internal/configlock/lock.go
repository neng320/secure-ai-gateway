package configlock

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

var ErrConfigMutationLocked = errors.New("config mutation locked")

type Lock struct {
	configPath string
	path       string
	released   bool
}

func Acquire(configPath string) (*Lock, error) {
	canonical, err := canonicalPath(configPath)
	if err != nil {
		return nil, err
	}
	lockPath := filepath.Join(filepath.Dir(canonical), "."+filepath.Base(canonical)+".audit-mutation-lock")
	if err := os.Mkdir(lockPath, 0700); err != nil {
		if os.IsExist(err) {
			return nil, ErrConfigMutationLocked
		}
		return nil, fmt.Errorf("create config mutation lock: %w", err)
	}
	return &Lock{configPath: canonical, path: lockPath}, nil
}

func (l *Lock) CanonicalConfigPath() string {
	if l == nil {
		return ""
	}
	return l.configPath
}

func (l *Lock) Close() error {
	if l == nil || l.released {
		return nil
	}
	err := os.Remove(l.path)
	if err == nil {
		l.released = true
	}
	return err
}

func LockPath(configPath string) (string, error) {
	canonical, err := canonicalPath(configPath)
	if err != nil {
		return "", err
	}
	return filepath.Join(filepath.Dir(canonical), "."+filepath.Base(canonical)+".audit-mutation-lock"), nil
}

func canonicalPath(configPath string) (string, error) {
	if configPath == "" {
		return "", fmt.Errorf("config path is required")
	}
	abs, err := filepath.Abs(configPath)
	if err != nil {
		return "", err
	}
	abs = filepath.Clean(abs)
	st, err := os.Stat(abs)
	if err != nil {
		return "", err
	}
	if !st.Mode().IsRegular() {
		return "", fmt.Errorf("config path is not a regular file")
	}
	resolved, err := filepath.EvalSymlinks(abs)
	if err != nil {
		return "", err
	}
	return filepath.Clean(resolved), nil
}
