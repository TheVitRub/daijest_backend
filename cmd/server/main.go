package main

import (
	"context"
	"database/sql"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"djst/backend/internal/app"
	"djst/backend/internal/migrations"

	_ "github.com/jackc/pgx/v5/stdlib"
)

func main() {
	ctx := context.Background()
	store := app.Store(app.NewMemoryStore())

	databaseURL := os.Getenv("DATABASE_URL")
	if databaseURL != "" {
		db, err := sql.Open("pgx", databaseURL)
		if err != nil {
			log.Fatalf("open database: %v", err)
		}
		defer db.Close()
		if err := db.PingContext(ctx); err != nil {
			log.Fatalf("ping database: %v", err)
		}
		if env("RUN_MIGRATIONS", "true") == "true" {
			if err := migrations.Run(ctx, db, env("MIGRATIONS_DIR", "migrations")); err != nil {
				log.Fatalf("run migrations: %v", err)
			}
		}
		store = app.NewPostgresStore(db)
	} else {
		log.Print("DATABASE_URL is empty, using in-memory storage for local preview")
	}

	api := app.NewServer(store, app.Config{SessionTTL: 30 * 24 * time.Hour})
	frontendDir := env("FRONTEND_DIR", filepath.Join("..", "frontend"))

	mux := http.NewServeMux()
	mux.Handle("/api/", api.Routes())
	mux.Handle("/healthz", api.Routes())
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/" {
			http.ServeFile(w, r, filepath.Join(frontendDir, "digest-builder.html"))
			return
		}
		http.FileServer(http.Dir(frontendDir)).ServeHTTP(w, r)
	})

	addr := ":" + env("PORT", "8080")
	log.Printf("djst listening on http://localhost%s", addr)
	log.Fatal(http.ListenAndServe(addr, mux))
}

func env(key, fallback string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return fallback
}
