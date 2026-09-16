package main

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/pressly/goose/v3"

	"openblog/internal/api"
	"openblog/internal/auth"
	"openblog/internal/import"
	"openblog/internal/jobs"
	"openblog/internal/media"
	"openblog/internal/oauth"
	"openblog/internal/posts"
	"openblog/internal/publicapi"
	"openblog/internal/store"

	"openblog/migrations"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run() error {
	cfg, err := loadConfig()
	if err != nil {
		return fmt.Errorf("config: %w", err)
	}

	if err := migrate(cfg.DBURL); err != nil {
		return fmt.Errorf("migrate: %w", err)
	}

	db, err := store.New(context.Background(), cfg.DBURL)
	if err != nil {
		return fmt.Errorf("store: %w", err)
	}
	defer db.Close()

	session := auth.New(db)
	postsSvc := posts.New(db, posts.Config{MediaOrigin: cfg.Posts.MediaOrigin})
	mediaCfg := media.Config{
		Endpoint:        cfg.Media.Endpoint,
		Bucket:          cfg.Media.Bucket,
		AccessKeyID:     cfg.Media.AccessKeyID,
		SecretAccessKey: cfg.Media.SecretAccessKey,
		PresignExpiry:   cfg.Media.PresignExpiry,
		CDNBase:         cfg.Media.CDNBase,
	}
	mediaSvc := media.New(mediaCfg, db, nil)
	worker := jobs.New(db.Pool())

	var oauthSvc *oauth.OAuth
	if cfg.OAuth.Google.ClientID != "" || cfg.OAuth.GitHub.ClientID != "" {
		oauthSvc, err = oauth.New(oauth.Config{
			Store:         db,
			Sessions:      session,
			Key:           cfg.OAuthKey,
			Google:        toProviderCfg(cfg.OAuth.Google),
			GitHub:        toProviderCfg(cfg.OAuth.GitHub),
			RedirectAllow: cfg.OAuth.RedirectAllow,
		})
		if err != nil {
			return fmt.Errorf("oauth: %w", err)
		}
	}

	importSvc := docimport.New(docimport.Config{
		DB:         db.Pool(),
		R2:         &noopR2{},
		Posts:      postsSvc,
		TenantSlug: "",
	})
	var googleExporter oauth.GoogleExporter
	if oauthSvc != nil {
		googleExporter = oauthSvc.GoogleExporter()
	}
	importSvc.RegisterWorker(worker, googleExporter)

	worker.Register(posts.PurgeJobKind, func(ctx context.Context, p jobs.JobPayload) error {
		slog.Info("purge job consumed", "tenant_id", p.TenantID)
		return nil
	})
	mediaSvc.RegisterVariantsWorker(worker, media.NewR2Client(mediaCfg))

	srv := api.New(api.Deps{
		DB:            db,
		Posts:         postsSvc,
		Media:         mediaSvc,
		Imports:       importSvc,
		Session:       session,
		OAuth:         oauthSvc,
		Pub:           publicapi.New(db, publicapi.Config{MediaCDN: cfg.Media.CDNBase}),
		SessionName:   cfg.Session.Name,
		SessionSecure: cfg.Session.Secure,
		Origins:       cfg.Origins,
	})

	router := srv.Routes()
	addr := fmt.Sprintf(":%d", cfg.Port)
	hsrv := &http.Server{
		Addr:              addr,
		Handler:           router,
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       120 * time.Second,
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	go func() {
		slog.Info("api listening", "addr", addr)
		if err := hsrv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			slog.Error("listen failed", "err", err)
			stop()
		}
	}()

	go worker.Run(ctx, cfg.Workers)

	<-ctx.Done()
	slog.Info("shutting down")
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	worker.Close()
	return hsrv.Shutdown(shutdownCtx)
}

func migrate(url string) error {
	db, err := sql.Open("pgx", url)
	if err != nil {
		return err
	}
	defer db.Close()
	goose.SetBaseFS(migrations.FS)
	if err := goose.SetDialect("postgres"); err != nil {
		return err
	}
	return goose.Up(db, ".")
}

type noopR2 struct{}

func (n *noopR2) Put(_ context.Context, _ string, _ []byte) error { return nil }
func (n *noopR2) Get(_ context.Context, _ string) ([]byte, error) { return nil, nil }

func toProviderCfg(c struct {
	ClientID     string
	ClientSecret string
	RedirectURL  string
}) oauth.ProviderConfig {
	return oauth.ProviderConfig{
		ClientID:     c.ClientID,
		ClientSecret: c.ClientSecret,
		RedirectURL:  c.RedirectURL,
	}
}
