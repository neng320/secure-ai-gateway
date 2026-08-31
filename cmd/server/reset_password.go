package main

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"time"

	"ai-gateway/internal/audit"
	"ai-gateway/internal/config"
	"ai-gateway/internal/configaudit"
	"ai-gateway/internal/configstore"
	"ai-gateway/internal/database"
	"ai-gateway/internal/models"

	"golang.org/x/term"
	"gorm.io/gorm"
)

const resetPasswordMaxBytes = 4096

// newAdminPasswordReader returns the only accepted password input paths for
// -reset-password. A password is never a flag value or an audit field.
func newAdminPasswordReader(r io.Reader, stdinMode bool) func() ([]byte, error) {
	if stdinMode {
		return func() ([]byte, error) {
			data, err := io.ReadAll(io.LimitReader(r, resetPasswordMaxBytes+1))
			if err != nil {
				return nil, fmt.Errorf("read reset password from stdin: %w", err)
			}
			if len(data) > resetPasswordMaxBytes {
				return nil, errors.New("reset password is too long")
			}
			data = bytes.TrimSuffix(data, []byte("\n"))
			data = bytes.TrimSuffix(data, []byte("\r"))
			if len(data) == 0 {
				return nil, errors.New("empty reset password")
			}
			if bytes.IndexByte(data, '\n') >= 0 || bytes.IndexByte(data, '\r') >= 0 {
				return nil, errors.New("reset password stdin must contain one line")
			}
			return data, nil
		}
	}

	f, ok := r.(*os.File)
	if !ok {
		return func() ([]byte, error) {
			return nil, errors.New("reset password input must be a TTY or use -reset-password-stdin")
		}
	}
	return func() ([]byte, error) {
		if !term.IsTerminal(int(f.Fd())) {
			return nil, errors.New("stdin is not a TTY — use -reset-password-stdin for explicit non-interactive reset")
		}
		fmt.Fprintln(os.Stderr, "Enter new admin password (input hidden):")
		first, err := term.ReadPassword(int(f.Fd()))
		if err != nil {
			return nil, fmt.Errorf("read reset password: %w", err)
		}
		fmt.Fprintln(os.Stderr)
		if len(first) == 0 || len(first) > resetPasswordMaxBytes {
			return nil, errors.New("invalid reset password length")
		}
		fmt.Fprintln(os.Stderr, "Re-enter new admin password (input hidden):")
		second, err := term.ReadPassword(int(f.Fd()))
		if err != nil {
			return nil, fmt.Errorf("read reset password confirmation: %w", err)
		}
		fmt.Fprintln(os.Stderr)
		if len(second) > resetPasswordMaxBytes || !bytes.Equal(first, second) {
			return nil, errors.New("reset password confirmation does not match")
		}
		return first, nil
	}
}

func openExistingResetAuditDB(path string) (*gorm.DB, error) {
	if path == "" {
		return nil, errors.New("database path is required for password reset")
	}
	st, err := os.Stat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, errors.New("configured audit database is missing")
		}
		return nil, fmt.Errorf("database %s: %w", path, err)
	}
	if !st.Mode().IsRegular() {
		return nil, fmt.Errorf("database %s is not a regular file", path)
	}
	readOnly, err := database.OpenReadOnly(path)
	if err != nil {
		return nil, fmt.Errorf("open audit database read-only: %w", err)
	}
	_, verifyErr := audit.VerifyIntegrityReadOnly(readOnly)
	if sqlDB, dbErr := readOnly.DB(); dbErr == nil {
		_ = sqlDB.Close()
	}
	if verifyErr != nil {
		return nil, fmt.Errorf("audit preflight: %w", verifyErr)
	}
	db, err := database.Open(path)
	if err != nil {
		return nil, err
	}
	var sessionTableCount int64
	if err := db.Raw("SELECT count(*) FROM sqlite_master WHERE type = 'table' AND name = 'admin_sessions'").Scan(&sessionTableCount).Error; err != nil || sessionTableCount != 1 {
		if sqlDB, dbErr := db.DB(); dbErr == nil {
			_ = sqlDB.Close()
		}
		return nil, errors.New("configured database is missing the admin session schema")
	}
	return db, nil
}

func runResetAdminPassword(configPath string, readPassword func() ([]byte, error), stdout io.Writer) error {
	return runResetAdminPasswordWithAuditDBOpener(configPath, readPassword, openExistingResetAuditDB, stdout)
}

// runResetAdminPasswordWithAuditDBOpener is a narrow test seam for injecting
// an audit INSERT failure after the real read-only preflight has passed.
func runResetAdminPasswordWithAuditDBOpener(configPath string, readPassword func() ([]byte, error), openAuditDB func(string) (*gorm.DB, error), stdout io.Writer) error {
	if configPath == "" {
		return errors.New("config path is required")
	}
	if _, err := config.LoadExistingForMigration(configPath); err != nil {
		return fmt.Errorf("load config: %w", err)
	}
	if readPassword == nil {
		return errors.New("reset password reader is required")
	}
	password, err := readPassword()
	if err != nil {
		return err
	}
	if len(password) == 0 {
		return errors.New("empty reset password")
	}
	if openAuditDB == nil {
		return errors.New("audit database opener is required")
	}
	if err := configaudit.New(nil).RunLockedTransactional(configaudit.Mutation{
		ConfigPath: configPath,
		Build: func(snapshot configstore.Snapshot) (configaudit.BuildResult, error) {
			authoritative, err := config.ParseExistingForMigration(snapshot.Bytes)
			if err != nil {
				return configaudit.BuildResult{}, fmt.Errorf("parse authoritative config: %w", err)
			}
			auditDB, err := openAuditDB(authoritative.Database.Path)
			if err != nil {
				return configaudit.BuildResult{}, err
			}
			cleanup := func() {
				if sqlDB, dbErr := auditDB.DB(); dbErr == nil {
					_ = sqlDB.Close()
				}
			}
			candidate := *authoritative
			if err := config.ResetAdminPassword(&candidate, string(password)); err != nil {
				cleanup()
				return configaudit.BuildResult{}, err
			}
			candidateBytes, err := config.MarshalYAML(&candidate)
			if err != nil {
				cleanup()
				return configaudit.BuildResult{}, fmt.Errorf("serialize authoritative config: %w", err)
			}
			return configaudit.BuildResult{
				Candidate: candidateBytes,
				Audit:     audit.NewService(auditDB),
				DB:        auditDB,
				Cleanup:   cleanup,
				Event: models.AuditEvent{
					Action: audit.ActionAdminPasswordReset, ActorType: "cli", ActorID: "reset-password",
					TargetType: "admin", TargetID: "admin",
				},
			}, nil
		},
	}, nil, func(tx *gorm.DB) error {
		return tx.Model(&models.AdminSession{}).Where("revoked_at IS NULL").Update("revoked_at", time.Now().UTC()).Error
	}); err != nil {
		return err
	}
	fmt.Fprintln(stdout, "Admin password has been reset")
	return nil
}
