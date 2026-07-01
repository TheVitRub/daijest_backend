FROM golang:1.25-alpine AS build

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -o /out/djst-server ./cmd/server

FROM alpine:3.22

WORKDIR /app
RUN apk add --no-cache su-exec && adduser -D -H djst
COPY --from=build /out/djst-server /app/djst-server
COPY migrations /app/migrations
COPY docker-entrypoint.sh /app/docker-entrypoint.sh

# Media storage dir, owned by the non-root runtime user. The entrypoint repeats
# this for bind mounts, because a host directory can hide image ownership.
RUN mkdir -p /app/media && chown djst:djst /app/media && chmod 0755 /app/docker-entrypoint.sh

EXPOSE 8080

ENTRYPOINT ["/app/docker-entrypoint.sh"]
CMD ["/app/djst-server"]
