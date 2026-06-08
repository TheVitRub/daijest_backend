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

USER djst
EXPOSE 8080

CMD ["/app/djst-server"]

