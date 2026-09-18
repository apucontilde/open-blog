package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/google/uuid"

	"openblog/internal/auth"
	"openblog/internal/store"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "seed:", err)
		os.Exit(1)
	}
}

func run() error {
	url := os.Getenv("DATABASE_URL")
	if url == "" {
		return errors.New("DATABASE_URL not set")
	}
	email := strings.ToLower(strings.TrimSpace(os.Getenv("SEED_EMAIL")))
	password := os.Getenv("SEED_PASSWORD")
	if email == "" || password == "" {
		return errors.New("SEED_EMAIL and SEED_PASSWORD are required")
	}
	super := os.Getenv("SEED_SUPER_ADMIN") != "false"
	slug := strEnv("SEED_TENANT_SLUG", "demo")
	name := strEnv("SEED_TENANT_NAME", "Demo Blog")
	role := strEnv("SEED_ROLE", "owner")

	ctx := context.Background()
	db, err := store.New(ctx, url)
	if err != nil {
		return err
	}
	defer db.Close()

	hash, err := auth.HashPassword(password)
	if err != nil {
		return err
	}
	userID, err := uuid.NewV7()
	if err != nil {
		return err
	}
	tenantID, err := uuid.NewV7()
	if err != nil {
		return err
	}

	return db.ScopedRW(ctx, store.Scope{}, func(q *store.Queries) error {
		if err := q.SeedUser(ctx, userID, email, hash, super); err != nil {
			return err
		}
		if err := q.SeedTenant(ctx, tenantID, slug, name); err != nil {
			return err
		}
		return q.SeedMembership(ctx, slug, email, role)
	})
}

func strEnv(name, def string) string {
	if v := os.Getenv(name); v != "" {
		return v
	}
	return def
}
