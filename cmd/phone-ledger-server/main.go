package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/Batestinha/phone-ledger-server/internal/server"
)

var version = "dev"

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "phone-ledger-server:", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	if len(args) == 0 {
		return errors.New("usage: phone-ledger-server <serve|invite|backup|version>")
	}
	switch args[0] {
	case "serve":
		return serve(args[1:])
	case "invite":
		return invite(args[1:])
	case "backup":
		return backup(args[1:])
	case "version":
		fmt.Println(version)
		return nil
	default:
		return fmt.Errorf("unknown command %q", args[0])
	}
}

func serve(args []string) error {
	config, err := server.ParseServeConfig(args, os.Stderr)
	if err != nil {
		return err
	}
	store, err := server.OpenStore(config.Database, config.Retention)
	if err != nil {
		return err
	}
	defer store.Close()
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
	httpServer := &http.Server{
		Addr:              config.Listen,
		Handler:           server.NewHandler(store, logger),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       90 * time.Second,
		WriteTimeout:      90 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    32 << 10,
	}
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-stop
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		_ = httpServer.Shutdown(ctx)
	}()
	logger.Info("server starting", "listen", config.Listen, "instance_id", store.InstanceID(), "version", version)
	err = httpServer.ListenAndServe()
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}

func invite(args []string) error {
	fs := flag.NewFlagSet("invite", flag.ContinueOnError)
	database := fs.String("db", "phone-ledger.db", "SQLite database path")
	ttl := fs.Duration("ttl", 10*time.Minute, "invite lifetime")
	uses := fs.Int("uses", 1, "number of uses")
	if err := fs.Parse(args); err != nil {
		return err
	}
	store, err := server.OpenStore(*database, server.DefaultRetention)
	if err != nil {
		return err
	}
	defer store.Close()
	code, err := store.CreateInvite(context.Background(), *ttl, *uses)
	if err != nil {
		return err
	}
	fmt.Println(code)
	return nil
}

func backup(args []string) error {
	fs := flag.NewFlagSet("backup", flag.ContinueOnError)
	database := fs.String("db", "phone-ledger.db", "SQLite database path")
	output := fs.String("output", "", "backup output path")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *output == "" {
		return errors.New("backup --output is required")
	}
	store, err := server.OpenStore(*database, server.DefaultRetention)
	if err != nil {
		return err
	}
	defer store.Close()
	return store.Backup(*output)
}
