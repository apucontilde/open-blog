package main

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"

	_ "github.com/jackc/pgx/v5/stdlib" // registers the database/sql driver
	"github.com/pressly/goose/v3"

	"openblog/migrations"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "migrate:", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	url, ok := os.LookupEnv("DATABASE_URL")
	if !ok || url == "" {
		return errors.New("DATABASE_URL not set")
	}
	db, err := sql.Open("pgx", url)
	if err != nil {
		return err
	}
	defer db.Close()

	goose.SetBaseFS(migrations.FS)
	if err := goose.SetDialect("postgres"); err != nil {
		return err
	}

	ctx := context.Background()
	if len(args) > 0 && args[0] == "down" {
		return goose.DownContext(ctx, db, ".")
	}
	return goose.UpContext(ctx, db, ".")
}
