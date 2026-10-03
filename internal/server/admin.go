package server

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

func (s *Store) CreateInvite(ctx context.Context, lifetime time.Duration, uses int) (string, error) {
	if lifetime < time.Minute || lifetime > 30*24*time.Hour {
		return "", errors.New("invite lifetime must be between one minute and 30 days")
	}
	if uses < 1 || uses > 100 {
		return "", errors.New("invite uses must be between 1 and 100")
	}
	code, err := randomToken(24)
	if err != nil {
		return "", err
	}
	if _, err := s.db.ExecContext(ctx, `INSERT INTO invites(hash, expires_at, remaining_uses) VALUES(?, ?, ?)`, tokenHash(code), time.Now().Add(lifetime).Unix(), uses); err != nil {
		return "", fmt.Errorf("store invite: %w", err)
	}
	return code, nil
}

func (s *Store) Backup(destination string) error {
	if strings.TrimSpace(destination) == "" {
		return errors.New("backup destination is required")
	}
	absoluteDestination, err := filepath.Abs(destination)
	if err != nil {
		return fmt.Errorf("resolve backup destination: %w", err)
	}
	if absoluteDestination == s.path {
		return errors.New("backup destination must differ from the live database")
	}
	if _, err := os.Lstat(absoluteDestination); err == nil {
		return errors.New("backup destination already exists")
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("inspect backup destination: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(absoluteDestination), 0o700); err != nil {
		return fmt.Errorf("create backup directory: %w", err)
	}
	placeholder, err := os.CreateTemp(filepath.Dir(absoluteDestination), ".phone-ledger-backup-*.tmp")
	if err != nil {
		return fmt.Errorf("reserve backup path: %w", err)
	}
	temporary := placeholder.Name()
	if err := placeholder.Close(); err != nil {
		_ = os.Remove(temporary)
		return fmt.Errorf("reserve backup path: %w", err)
	}
	if err := os.Remove(temporary); err != nil {
		return fmt.Errorf("prepare backup path: %w", err)
	}
	keep := false
	defer func() {
		if !keep {
			_ = os.Remove(temporary)
		}
	}()
	if _, err := s.db.Exec(`VACUUM INTO ?`, temporary); err != nil {
		return fmt.Errorf("create SQLite backup: %w", err)
	}
	if err := os.Chmod(temporary, 0o600); err != nil {
		return fmt.Errorf("protect backup: %w", err)
	}
	if err := os.Rename(temporary, absoluteDestination); err != nil {
		return fmt.Errorf("finish backup: %w", err)
	}
	keep = true
	return nil
}
