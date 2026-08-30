package configstore

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
)

type Snapshot struct {
	Bytes []byte
	Mode  fs.FileMode
}

func ReadSnapshot(path string) (Snapshot, error) {
	if path == "" {
		return Snapshot{}, fmt.Errorf("config path is required")
	}
	st, err := os.Stat(path)
	if err != nil {
		return Snapshot{}, err
	}
	if !st.Mode().IsRegular() {
		return Snapshot{}, fmt.Errorf("config path is not a regular file")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return Snapshot{}, err
	}
	return Snapshot{Bytes: data, Mode: st.Mode().Perm()}, nil
}

// AtomicReplace writes a fully materialized candidate through a same-directory
// temporary file and replaces the target without widening its prior mode.
func AtomicReplace(path string, data []byte, mode fs.FileMode) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, "."+filepath.Base(path)+".tmp-")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	removeTemp := true
	defer func() {
		if removeTemp {
			_ = os.Remove(tmpPath)
		}
	}()
	if err := tmp.Chmod(mode.Perm()); err != nil {
		_ = tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpPath, path); err != nil {
		return err
	}
	removeTemp = false
	return nil
}
