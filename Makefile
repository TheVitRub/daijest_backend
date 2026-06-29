.PHONY: help run test build migrate-up migrate-state-media

MIGRATIONS_DIR := ./migrations
DATABASE_URL ?= postgres://djst:djst@localhost:5432/djst?sslmode=disable
MEDIA_DIR ?= ./media
MEDIA_URL_PREFIX ?= /daijest/api/media

help:
	@echo "make run                 - run API"
	@echo "make test                - run tests"
	@echo "make build               - build binary"
	@echo "make migrate-up          - run app migrations through server startup"
	@echo "make migrate-state-media - move inline state images from DB JSON into media files"

run:
	go run ./cmd/server

test:
	go test ./...

build:
	go build -o bin/djst-server ./cmd/server

migrate-up:
	RUN_MIGRATIONS=true DATABASE_URL="$(DATABASE_URL)" MIGRATIONS_DIR="$(MIGRATIONS_DIR)" go run ./cmd/server

migrate-state-media:
	DATABASE_URL="$(DATABASE_URL)" MEDIA_DIR="$(MEDIA_DIR)" MEDIA_URL_PREFIX="$(MEDIA_URL_PREFIX)" go run ./cmd/migrate-state-media
