.PHONY: help run test build migrate-up

MIGRATIONS_DIR := ./migrations
DATABASE_URL ?= postgres://djst:djst@localhost:5432/djst?sslmode=disable

help:
	@echo "make run        - run API"
	@echo "make test       - run tests"
	@echo "make build      - build binary"
	@echo "make migrate-up - run app migrations through server startup"

run:
	go run ./cmd/server

test:
	go test ./...

build:
	go build -o bin/djst-server ./cmd/server

migrate-up:
	RUN_MIGRATIONS=true DATABASE_URL="$(DATABASE_URL)" MIGRATIONS_DIR="$(MIGRATIONS_DIR)" go run ./cmd/server

