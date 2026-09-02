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

// ReplaceResult records which durability boundary was reached by a replacement.
// Renamed without DirectorySynced means the candidate may be visible but its
// directory entry durability is uncertain and compensation is required.
type ReplaceResult struct {
	Renamed         bool
	DirectorySynced bool
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

type replaceOps struct {
	rename        func(string, string) error
	syncDirectory func(*os.File) error
}

// AtomicReplace writes a fully materialized candidate through a same-directory
// temporary file and replaces the target without widening its prior mode. The
// replacement is not reported durable until the containing directory has been
// opened, synced, and closed successfully.
func AtomicReplace(path string, data []byte, mode fs.FileMode) (ReplaceResult, error) {
	return atomicReplace(path, data, mode, replaceOps{
		rename:        os.Rename,
		syncDirectory: func(dir *os.File) error { return dir.Sync() },
	})
}

func atomicReplace(path string, data []byte, mode fs.FileMode, ops replaceOps) (ReplaceResult, error) {
	if ops.rename == nil {
		ops.rename = os.Rename
	}
	if ops.syncDirectory == nil {
		ops.syncDirectory = func(dir *os.File) error { return dir.Sync() }
	}
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, "."+filepath.Base(path)+".tmp-")
	if err != nil {
		return ReplaceResult{}, err
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
		return ReplaceResult{}, err
	}
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return ReplaceResult{}, err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return ReplaceResult{}, err
	}
	if err := tmp.Close(); err != nil {
		return ReplaceResult{}, err
	}
	if err := ops.rename(tmpPath, path); err != nil {
		return ReplaceResult{}, err
	}
	removeTemp = false
	result := ReplaceResult{Renamed: true}
	directory, err := os.Open(dir)
	if err != nil {
		return result, err
	}
	if err := ops.syncDirectory(directory); err != nil {
		_ = directory.Close()
		return result, err
	}
	if err := directory.Close(); err != nil {
		return result, err
	}
	result.DirectorySynced = true
	return result, nil
}
