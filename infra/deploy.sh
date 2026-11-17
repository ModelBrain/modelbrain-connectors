#!/usr/bin/env bash
# ============================================================================
# Deploys the ModelBrain connectors stack on the shared Swarm box.
# Same discipline as the relay's relay-deploy.sh: one deploy at a time,
# refuse on drift instead of self-updating, tag images with the commit, and
# verify the running tag and health after Swarm accepts the spec.
#
# Usage on the box:  sudo /opt/modelbrain-connectors/deploy.sh [git-ref]
# (default ref: origin/main)
# ============================================================================
set -euo pipefail

REF="${1:-origin/main}"
STACK_DIR=/opt/modelbrain-connectors
REPO="$STACK_DIR/repo"
STACK=modelbrain-connectors
SERVICE="${STACK}_gsc"
LOG=/var/log/modelbrain-connectors-deploy.log

say() { echo "$(date -uIs) [connectors-deploy] $*" | tee -a "$LOG"; }

LOCK=/var/lock/modelbrain-connectors-deploy.lock
exec 9>"$LOCK"
flock -w 1800 9 || { say "FATAL: another deploy holds $LOCK"; exit 1; }

[ -d "$REPO/.git" ] || { say "FATAL: $REPO is not a git checkout (see infra/README.md)"; exit 1; }
git -C "$REPO" fetch --quiet origin
git -C "$REPO" checkout --quiet --detach "$REF"
SHA="$(git -C "$REPO" rev-parse --short=12 HEAD)"
say "deploying $SHA"

[ -r "$STACK_DIR/deploy.env" ] || { say "FATAL: $STACK_DIR/deploy.env missing"; exit 1; }
set -a
if ! . "$STACK_DIR/deploy.env"; then set +a; say "FATAL: deploy.env has a line that is not KEY=value"; exit 1; fi
set +a
[ -n "${MBC_GSC_BASE_URL:-}" ] || { say "FATAL: MBC_GSC_BASE_URL not set in deploy.env"; exit 1; }

for s in mbc_google_oauth_json mbc_token_key; do
  docker secret inspect "$s" >/dev/null 2>&1 || { say "FATAL: Docker secret $s does not exist (see infra/README.md)"; exit 1; }
done

# Drift gates: the active script and compose file must match the repo.
for pair in "deploy.sh:infra/deploy.sh" "docker-compose.yml:infra/docker-compose.yml"; do
  active="$STACK_DIR/${pair%%:*}"; repo="$REPO/${pair##*:}"
  if ! diff -q "$active" "$repo" >/dev/null 2>&1; then
    say "FATAL: $active differs from the repo copy; refusing to deploy"
    diff "$active" "$repo" | head -40 | tee -a "$LOG" || true
    say "To accept it:  sudo cp $repo $active  (then chmod 0755 for deploy.sh) and re-run"
    exit 1
  fi
done

say "building image modelbrain-connectors:$SHA"
docker build -t "modelbrain-connectors:$SHA" -f "$REPO/Dockerfile" "$REPO" 2>&1 | tee -a "$LOG"
export MBC_IMAGE="modelbrain-connectors:$SHA"

cd "$STACK_DIR"
docker stack config -c docker-compose.yml >/dev/null || { say "FATAL: compose file rejected"; exit 1; }

attempt=1
until out="$(docker stack deploy -c docker-compose.yml --resolve-image never --prune "$STACK" 2>&1)"; do
  printf '%s\n' "$out" | tee -a "$LOG"
  printf '%s' "$out" | grep -qi 'update out of sequence' || { say "FATAL: stack deploy failed"; exit 1; }
  [ "$attempt" -lt 4 ] || { say "FATAL: Swarm version race after 4 attempts"; exit 1; }
  sleep $(( attempt * 10 )); attempt=$(( attempt + 1 ))
done
printf '%s\n' "$out" | tee -a "$LOG"

diagnose() {
  say "FATAL: $1"
  docker service ps --no-trunc "$SERVICE" 2>&1 | tee -a "$LOG"
  docker service logs --tail 50 "$SERVICE" 2>&1 | tee -a "$LOG"
  exit 1
}
running_tag() {
  docker ps --filter "label=com.docker.swarm.service.name=$SERVICE" --format '{{.Image}}' \
    | sed 's/@.*//; s/.*://' | sort -u
}

deadline=$(( $(date +%s) + 300 ))
say "waiting for $SERVICE to run $SHA and report healthy"
while :; do
  st="$(docker ps --filter "label=com.docker.swarm.service.name=$SERVICE" \
        --filter "ancestor=modelbrain-connectors:$SHA" --format '{{.Status}}' | head -1)"
  case "$st" in
    *"(healthy)"*) [ "$(running_tag)" = "$SHA" ] && { say "healthy on $SHA"; break; } ;;
    *"(unhealthy)"*) diagnose "unhealthy: $st" ;;
  esac
  [ "$(date +%s)" -lt "$deadline" ] || diagnose "did not become healthy on $SHA within 5 minutes (running: $(running_tag | paste -sd, -))"
  sleep 5
done

sleep 10
[ "$(running_tag)" = "$SHA" ] || diagnose "rolled back off $SHA after the health check; the deploy shipped nothing"

echo "$SHA  $(date -uIs)" >> "$STACK_DIR/.deploy-history"
docker image prune -f >/dev/null 2>&1 || true
say "deploy complete: $SHA"
