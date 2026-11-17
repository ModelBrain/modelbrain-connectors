#!/usr/bin/env bash
# ============================================================================
# Adds the gsc.modelbrain.net site block to the shared box's live Caddyfile.
# One-time step, run before the first deploy. Same safety pattern as the
# relay's setup-caddy.sh: build a candidate copy, validate it in a throwaway
# container, back up the live file, swap, reload (not restart), and restore
# the backup if the reload fails. Idempotent.
#
# Usage on the box:  ./setup-caddy.sh
# ============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SNIPPET="$SCRIPT_DIR/caddy-snippet.conf"
CADDYFILE="${NEXSPARK_CADDYFILE:-/opt/nexspark/Caddyfile}"
CERTS_DIR="${NEXSPARK_CERTS_DIR:-/opt/nexspark/certs}"
MARKER="gsc.modelbrain.net {"

say() { echo "$(date -uIs) [setup-caddy] $*"; }

[ -f "$SNIPPET" ] || { say "FATAL: $SNIPPET not found"; exit 1; }
[ -f "$CADDYFILE" ] || { say "FATAL: $CADDYFILE not found (set NEXSPARK_CADDYFILE)"; exit 1; }

if grep -qF "$MARKER" "$CADDYFILE"; then
  say "already present in $CADDYFILE, nothing to do"
  exit 0
fi

CANDIDATE="$(mktemp "${CADDYFILE}.candidate.XXXXXX")"
trap 'rm -f "$CANDIDATE"' EXIT
cp "$CADDYFILE" "$CANDIDATE"
{ echo ""; grep -v '^#' "$SNIPPET"; } >> "$CANDIDATE"

say "validating candidate config"
if ! docker run --rm \
  -v "$CANDIDATE:/etc/caddy/Caddyfile:ro" \
  -v "$CERTS_DIR:/etc/caddy/certs:ro" \
  caddy:2 caddy validate --config /etc/caddy/Caddyfile; then
  say "FATAL: candidate failed validation; $CADDYFILE was NOT touched"
  exit 1
fi

BACKUP="${CADDYFILE}.bak.$(date -u +%Y%m%dT%H%M%SZ)"
cp "$CADDYFILE" "$BACKUP"
cp "$CANDIDATE" "$CADDYFILE"
say "backed up to $BACKUP and wrote the validated config"

CADDY_CID="$(docker ps -q -f label=com.docker.swarm.service.name=nexspark_caddy)"
if [ -z "$CADDY_CID" ]; then
  say "FATAL: no running nexspark_caddy container; file updated but NOT reloaded."
  say "Restore with:  cp $BACKUP $CADDYFILE"
  exit 1
fi

say "reloading Caddy"
if ! docker exec "$CADDY_CID" caddy reload --config /etc/caddy/Caddyfile; then
  say "FATAL: reload failed; restoring the backup"
  cp "$BACKUP" "$CADDYFILE"
  docker exec "$CADDY_CID" caddy reload --config /etc/caddy/Caddyfile || \
    say "FATAL: rollback reload also failed; Caddy needs a human now"
  exit 1
fi
say "done: gsc.modelbrain.net is routed. Backup kept at $BACKUP"
