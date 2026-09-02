package configstore

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestAtomicReplaceSuccessReportsDurability(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	before := []byte("before\n")
	candidate := []byte("candidate\n")
	if err := os.WriteFile(path, before, 0640); err != nil {
		t.Fatal(err)
	}

	result, err := AtomicReplace(path, candidate, 0640)
	if err != nil {
		t.Fatal(err)
	}
	if result != (ReplaceResult{Renamed: true, DirectorySynced: true}) {
		t.Fatalf("unexpected replace result: %+v", result)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, candidate) {
		t.Fatalf("candidate bytes mismatch: %q", got)
	}
	if info, err := os.Stat(path); err != nil || info.Mode().Perm() != 0640 {
		t.Fatalf("candidate mode mismatch: info=%v err=%v", info, err)
	}
	if leftovers, err := filepath.Glob(filepath.Join(dir, ".config.yaml.tmp-*")); err != nil || len(leftovers) != 0 {
		t.Fatalf("temporary artifacts remain: %v err=%v", leftovers, err)
	}
}

func TestAtomicReplacePreRenameFailurePreservesTarget(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	before := []byte("before\n")
	if err := os.WriteFile(path, before, 0600); err != nil {
		t.Fatal(err)
	}
	renameErr := errors.New("injected pre-rename failure")

	result, err := atomicReplace(path, []byte("candidate\n"), 0600, replaceOps{
		rename: func(string, string) error { return renameErr },
	})
	if !errors.Is(err, renameErr) {
		t.Fatalf("expected pre-rename error, got %v", err)
	}
	if result != (ReplaceResult{}) {
		t.Fatalf("pre-rename result must report no rename or directory sync: %+v", result)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, before) {
		t.Fatalf("pre-rename failure changed target bytes: %q", got)
	}
	if info, err := os.Stat(path); err != nil || info.Mode().Perm() != 0600 {
		t.Fatalf("pre-rename failure changed target mode: info=%v err=%v", info, err)
	}
	if leftovers, err := filepath.Glob(filepath.Join(dir, ".config.yaml.tmp-*")); err != nil || len(leftovers) != 0 {
		t.Fatalf("temporary artifacts remain after pre-rename failure: %v err=%v", leftovers, err)
	}
}

func TestAtomicReplacePostRenameDirectorySyncFailureIsDistinguished(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(path, []byte("before\n"), 0640); err != nil {
		t.Fatal(err)
	}
	dirSyncErr := errors.New("injected directory sync failure")

	result, err := atomicReplace(path, []byte("candidate\n"), 0640, replaceOps{
		syncDirectory: func(*os.File) error { return dirSyncErr },
	})
	if !errors.Is(err, dirSyncErr) {
		t.Fatalf("expected directory sync error, got %v", err)
	}
	if result != (ReplaceResult{Renamed: true, DirectorySynced: false}) {
		t.Fatalf("post-rename result must identify uncertain directory durability: %+v", result)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, []byte("candidate\n")) {
		t.Fatalf("renamed candidate is not visible for compensation: %q", got)
	}
	if info, err := os.Stat(path); err != nil || info.Mode().Perm() != 0640 {
		t.Fatalf("candidate mode mismatch after directory sync failure: info=%v err=%v", info, err)
	}
	if leftovers, err := filepath.Glob(filepath.Join(dir, ".config.yaml.tmp-*")); err != nil || len(leftovers) != 0 {
		t.Fatalf("temporary artifacts remain after directory sync failure: %v err=%v", leftovers, err)
	}
}

func TestAtomicReplaceFailureDoesNotExposeDataInError(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(path, []byte("snapshot-secret-marker"), 0600); err != nil {
		t.Fatal(err)
	}
	secret := []byte("candidate-secret-marker")

	_, err := atomicReplace(path, secret, 0600, replaceOps{
		rename: func(string, string) error { return errors.New("rename failed") },
	})
	if err == nil {
		t.Fatal("expected injected failure")
	}
	if strings.Contains(err.Error(), string(secret)) || strings.Contains(err.Error(), "snapshot-secret-marker") {
		t.Fatalf("replace error exposed file data: %v", err)
	}
}
