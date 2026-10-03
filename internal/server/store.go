package server

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"time"

	_ "modernc.org/sqlite"
)

type Store struct {
	db         *sql.DB
	path       string
	instanceID string
	retention  int
}

func OpenStore(path string, retention int) (*Store, error) {
	if retention < 2 || retention > 100 {
		return nil, errors.New("retention must be between 2 and 100")
	}
	absolutePath, err := filepath.Abs(path)
	if err != nil {
		return nil, fmt.Errorf("resolve database path: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(absolutePath), 0o700); err != nil {
		return nil, fmt.Errorf("create database directory: %w", err)
	}
	databaseURL := (&url.URL{Scheme: "file", Path: absolutePath}).String()
	db, err := sql.Open("sqlite", databaseURL+"?_pragma=foreign_keys(1)&_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)")
	if err != nil {
		return nil, fmt.Errorf("open database: %w", err)
	}
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	store := &Store{db: db, path: absolutePath, retention: retention}
	if err := store.migrate(context.Background()); err != nil {
		db.Close()
		return nil, err
	}
	if err := store.loadInstanceID(context.Background()); err != nil {
		db.Close()
		return nil, err
	}
	for _, filename := range []string{absolutePath, absolutePath + "-wal", absolutePath + "-shm"} {
		if _, err := os.Stat(filename); err == nil {
			if err := os.Chmod(filename, 0o600); err != nil {
				db.Close()
				return nil, fmt.Errorf("protect database file: %w", err)
			}
		}
	}
	return store, nil
}

func (s *Store) Close() error { return s.db.Close() }

func (s *Store) InstanceID() string { return s.instanceID }

func (s *Store) migrate(ctx context.Context) error {
	statements := []string{
		`CREATE TABLE IF NOT EXISTS metadata (key TEXT PRIMARY KEY, value TEXT NOT NULL)`,
		`CREATE TABLE IF NOT EXISTS accounts (
			id TEXT PRIMARY KEY,
			enrollment_verifier BLOB NOT NULL CHECK(length(enrollment_verifier) = 32),
			created_at INTEGER NOT NULL
		)`,
		`CREATE TABLE IF NOT EXISTS devices (
			id TEXT PRIMARY KEY,
			account_id TEXT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
			name TEXT NOT NULL,
			public_key BLOB NOT NULL CHECK(length(public_key) = 32),
			created_at INTEGER NOT NULL,
			last_seen_at INTEGER,
			revoked_at INTEGER,
			UNIQUE(account_id, id)
		)`,
		`CREATE TABLE IF NOT EXISTS challenges (
			id TEXT PRIMARY KEY,
			account_id TEXT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
			device_id TEXT NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
			nonce BLOB NOT NULL CHECK(length(nonce) = 32),
			expires_at INTEGER NOT NULL,
			used_at INTEGER
		)`,
		`CREATE TABLE IF NOT EXISTS token_families (
			id TEXT PRIMARY KEY,
			account_id TEXT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
			device_id TEXT NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
			revoked_at INTEGER
		)`,
		`CREATE TABLE IF NOT EXISTS tokens (
			hash BLOB PRIMARY KEY CHECK(length(hash) = 32),
			family_id TEXT NOT NULL REFERENCES token_families(id) ON DELETE CASCADE,
			kind TEXT NOT NULL CHECK(kind IN ('access','refresh')),
			expires_at INTEGER NOT NULL,
			rotated_at INTEGER,
			revoked_at INTEGER
		)`,
		`CREATE INDEX IF NOT EXISTS tokens_family_idx ON tokens(family_id)`,
		`CREATE TABLE IF NOT EXISTS invites (
			hash BLOB PRIMARY KEY CHECK(length(hash) = 32),
			expires_at INTEGER NOT NULL,
			remaining_uses INTEGER NOT NULL CHECK(remaining_uses > 0)
		)`,
		`CREATE TABLE IF NOT EXISTS vaults (
			account_id TEXT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
			revision INTEGER NOT NULL CHECK(revision > 0),
			format INTEGER NOT NULL,
			blob BLOB NOT NULL,
			digest BLOB NOT NULL CHECK(length(digest) = 32),
			created_at INTEGER NOT NULL,
			PRIMARY KEY(account_id, revision)
		)`,
	}
	for _, statement := range statements {
		if _, err := s.db.ExecContext(ctx, statement); err != nil {
			return fmt.Errorf("migrate database: %w", err)
		}
	}
	return nil
}

func (s *Store) loadInstanceID(ctx context.Context) error {
	if err := s.db.QueryRowContext(ctx, `SELECT value FROM metadata WHERE key = 'instance_id'`).Scan(&s.instanceID); err == nil {
		return nil
	} else if !errors.Is(err, sql.ErrNoRows) {
		return fmt.Errorf("read instance id: %w", err)
	}
	instanceID, err := newUUID()
	if err != nil {
		return err
	}
	if _, err := s.db.ExecContext(ctx, `INSERT INTO metadata(key, value) VALUES('instance_id', ?)`, instanceID); err != nil {
		return fmt.Errorf("store instance id: %w", err)
	}
	s.instanceID = instanceID
	return nil
}

func unixNow() int64 { return time.Now().UTC().Unix() }
