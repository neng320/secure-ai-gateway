package configlock

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func TestP108B_S41_CrossProcessConfigLock(t *testing.T) {
	if os.Getenv("P108B_CONFIGLOCK_CHILD") == "1" {
		lock, err := Acquire(os.Getenv("P108B_CONFIGLOCK_PATH"))
		if !errors.Is(err, ErrConfigMutationLocked) || lock != nil {
			os.Exit(2)
		}
		os.Exit(0)
	}
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte("database:\n"), 0600); err != nil {
		t.Fatal(err)
	}
	lock, err := Acquire(filepath.Join(filepath.Dir(path), ".", filepath.Base(path)))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Acquire(path); !errors.Is(err, ErrConfigMutationLocked) {
		t.Fatalf("equivalent path must share lock: %v", err)
	}
	cmd := exec.Command(os.Args[0], "-test.run=^TestP108B_S41_CrossProcessConfigLock$")
	cmd.Env = append(os.Environ(), "P108B_CONFIGLOCK_CHILD=1", "P108B_CONFIGLOCK_PATH="+path)
	if err := cmd.Run(); err != nil {
		t.Fatalf("cross-process lock contender should fail closed with stable sentinel: %v", err)
	}
	if err := lock.Close(); err != nil {
		t.Fatal(err)
	}
	finalLock, err := Acquire(path)
	if err != nil {
		t.Fatalf("lock should be reusable after normal release: %v", err)
	}
	if err := finalLock.Close(); err != nil {
		t.Fatal(err)
	}
}
