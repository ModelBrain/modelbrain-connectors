# Deploying the connectors on the shared box

Runs as its own Swarm stack, `modelbrain-connectors`, next to the platform and the relay. Caddy reaches it over the shared `edge` network. Memory cap: 128 MB.

## One-time setup

1. **DNS.** In Cloudflare, add `gsc` as a proxied (orange cloud) record pointing at the box, the same as `relay` and `api`. The existing origin certificate for `*.modelbrain.net` covers it.

2. **Copy the Google client file to the box** (from the Mac):
   ```bash
   scp ~/Downloads/client_secret_*.json <box>:/tmp/mbc-google.json
   ```

3. **On the box, as root:**
   ```bash
   mkdir -p /opt/modelbrain-connectors
   git clone https://github.com/ModelBrain/modelbrain-connectors.git /opt/modelbrain-connectors/repo

   # Secrets live in Swarm, never in a file on disk or in git.
   docker secret create mbc_google_oauth_json /tmp/mbc-google.json && shred -u /tmp/mbc-google.json
   openssl rand -base64 32 | tr -d '\n' | docker secret create mbc_token_key -

   echo 'MBC_GSC_BASE_URL=https://gsc.modelbrain.net' > /opt/modelbrain-connectors/deploy.env
   chmod 600 /opt/modelbrain-connectors/deploy.env

   cp /opt/modelbrain-connectors/repo/infra/deploy.sh /opt/modelbrain-connectors/deploy.sh
   cp /opt/modelbrain-connectors/repo/infra/docker-compose.yml /opt/modelbrain-connectors/docker-compose.yml
   chmod 0755 /opt/modelbrain-connectors/deploy.sh

   /opt/modelbrain-connectors/repo/infra/setup-caddy.sh
   ```

The token key encrypts the stored Google sign-ins. If it is lost or replaced, everyone has to sign in again; nothing else breaks.

## Every deploy

```bash
sudo /opt/modelbrain-connectors/deploy.sh
```

It pulls `origin/main`, builds the image on the box tagged with the commit, deploys, and waits until the container is healthy on that commit. If the deploy script or compose file changed in git, it stops and prints the `cp` to accept the new version.

## Checks

```bash
curl -s https://gsc.modelbrain.net/healthz                                   # ok
curl -s https://gsc.modelbrain.net/.well-known/oauth-protected-resource/mcp  # JSON
curl -si https://gsc.modelbrain.net/mcp -X POST | head -1                    # 401
docker service logs --tail 50 modelbrain-connectors_gsc
```

## Rollback

```bash
sudo /opt/modelbrain-connectors/deploy.sh <previous-sha>
```
Previous commits are listed in `/opt/modelbrain-connectors/.deploy-history`.
