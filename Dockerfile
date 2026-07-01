FROM golang:1.25-alpine AS build

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -o /out/djst-server ./cmd/server

FROM alpine:3.22

WORKDIR /app
COPY --from=build /out/djst-server /app/djst-server
COPY migrations /app/migrations

# Production bind-mounts /opt/daijest/media as a root-owned host directory.
# Keep the runtime able to write that mount; otherwise photo uploads fail.
RUN mkdir -p /app/media

EXPOSE 8080

CMD ["/app/djst-server"]
