# Daijest Backend Instructions

This is the Go backend repository for Daijest.

## Required Checks

- Run `go test ./...` before finishing backend changes.
- Run `go run ./cmd/migrate-state-media -h` when touching media migration code.
- Run `docker compose -f deploy/docker-compose.yml config` when touching deploy files.

## Production Deployment

- Production runs on `ssh ant` under `/opt/daijest`.
- Do not patch `/opt/daijest/backend` directly on the server.
- Fixes must be made in this repository, committed, and pushed to `main`.
- The server-side `/opt/daijest/deploy-daijest.sh` script is triggered by `daijest-update.timer` and updates this checkout with `git reset --hard origin/main`.
- Manual server edits are temporary by definition and will be overwritten by the next deployment.

## Backend Notes

- Main service entrypoint: `cmd/server/main.go`.
- Application code: `internal/app`.
- SQL migrations: `migrations`.
- Media files are stored outside the container via `MEDIA_DIR`; production uses `/opt/daijest/media`.
- Production media URLs use `/api/media` through Caddy and frontend nginx.

## Server Verification

- `ssh ant 'systemctl status daijest-update.service --no-pager'`
- `ssh ant 'journalctl -u daijest-update.service -n 200 --no-pager'`
- `ssh ant 'curl -fsS http://127.0.0.1/healthz'`
- `ssh ant 'curl -fsS http://127.0.0.1/api/digest-types'`
- If git reports dubious ownership, use `git -c safe.directory=/opt/daijest/backend -C /opt/daijest/backend ...` for read-only diagnostics.
