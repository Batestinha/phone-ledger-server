package server

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"time"
)

const (
	ProtocolVersion      = 1
	MaxVaultBytes        = 64 << 20
	MaxJSONBytes         = 64 << 10
	AccessTokenLifetime  = 15 * time.Minute
	RefreshTokenLifetime = 30 * 24 * time.Hour
	ChallengeLifetime    = time.Minute
	DefaultRetention     = 10
)

type Config struct {
	Listen    string
	Database  string
	Retention int
}

func ParseServeConfig(args []string, output io.Writer) (Config, error) {
	fs := flag.NewFlagSet("serve", flag.ContinueOnError)
	fs.SetOutput(output)
	config := Config{}
	fs.StringVar(&config.Listen, "listen", "127.0.0.1:8080", "HTTP listen address (put TLS reverse proxy in front)")
	fs.StringVar(&config.Database, "db", "phone-ledger.db", "SQLite database path")
	fs.IntVar(&config.Retention, "retain", DefaultRetention, "vault revisions retained per account")
	if err := fs.Parse(args); err != nil {
		return Config{}, err
	}
	if fs.NArg() != 0 {
		return Config{}, fmt.Errorf("unexpected arguments: %v", fs.Args())
	}
	if config.Retention < 2 || config.Retention > 100 {
		return Config{}, errors.New("retain must be between 2 and 100")
	}
	if config.Database == "" {
		return Config{}, errors.New("db path is required")
	}
	return config, nil
}
