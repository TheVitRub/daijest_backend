FROM golang:1.25-alpine AS build

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -o /out/djst-server ./cmd/server

FROM alpine:3.22

WORKDIR /app
RUN adduser -D -H djst
COPY --from=build /out/djst-server /app/djst-server
COPY migrations /app/migrations

# Media storage dir, owned by the non-root runtime user. A fresh named volume
# mounted here inherits this ownership on first creation, so djst can write.
RUN mkdir -p /app/media && chown djst /app/media

USER djst
EXPOSE 8080

CMD ["/app/djst-server"]

