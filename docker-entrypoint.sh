#!/bin/sh
set -eu

media_dir="${MEDIA_DIR:-/app/media}"

if [ "$(id -u)" = "0" ]; then
  mkdir -p "$media_dir"

  if ! su-exec djst sh -c 'test -w "$1"' sh "$media_dir"; then
    chown -R djst:djst "$media_dir"
  fi

  exec su-exec djst "$@"
fi

exec "$@"
