#!/usr/bin/env bash
# Bring up the local OpenShell gateway for the ODIS contract harness OpenShell-gated demo.
#
# Repo-free: pulls the PUBLISHED gateway image (no OpenShell source checkout). The only
# prerequisites are Docker + the `openshell` CLI (mise: `pipx:openshell`) + openssl.
#
#   bash setup.sh
#   mise run openshell-connect   # register/select; status -> Connected
set -euo pipefail
cd "$(dirname "$0")"

# The Docker compute driver mints supervisor<->gateway JWTs and requires an ed25519
# signing key. jwt-signing.pem is a PRIVATE key — created under umask 077 (private
# from the first byte, no chmod window), gitignored, never committed. Each artifact
# is derived independently so an interrupted setup is recoverable on re-run.
umask 077
if [ ! -f jwt-signing.pem ]; then
  echo "[setup] generating gateway JWT signing material (ed25519)..."
  openssl genpkey -algorithm ed25519 -out jwt-signing.pem
fi
chmod 600 jwt-signing.pem
[ -f jwt-public.pem ] || openssl pkey -in jwt-signing.pem -pubout -out jwt-public.pem
[ -f jwt-kid ] || openssl rand -hex 8 > jwt-kid

# Port 8080 is NON-NEGOTIABLE: the sandbox->gateway callback dials
# host.openshell.internal:8080 through the host-published mapping. If another
# service owns 8080, sandbox provisioning strands in a restart loop mid-demo —
# fail fast here instead (unless the listener is our own already-running gateway).
if ! docker compose ps --status running 2>/dev/null | grep -q gateway; then
  if curl -s -o /dev/null --max-time 2 "http://localhost:8080/"; then
    echo "[setup] FAIL: another service already listens on port 8080; the sandbox->gateway"
    echo "        callback path requires it. Free port 8080 and re-run."
    exit 1
  fi
fi

echo "[setup] starting the OpenShell gateway (docker compose up -d)..."
docker compose up -d

echo "[setup] waiting for the gateway to accept connections on :8080..."
ready=""
for _ in $(seq 1 60); do
  if curl -s -o /dev/null "http://localhost:8080/"; then
    ready=1
    break
  fi
  sleep 1
done
if [ -z "$ready" ]; then
  echo "[setup] FAIL: gateway not reachable on http://localhost:8080 after 60s (see: docker compose logs gateway)"
  exit 1
fi

echo "[setup] gateway up on http://localhost:8080"
echo "[setup] next: mise run openshell-connect"
