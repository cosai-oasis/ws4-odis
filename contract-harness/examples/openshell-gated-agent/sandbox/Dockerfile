# Sandbox image for the OpenShell-gated demo agent.
#
# Built locally by the gateway's Docker driver (`openshell sandbox create --from .`) — the
# build has network access, so the MCP client is installed HERE, at build time. This is
# load-bearing: once the sandbox is running it is egress-locked to the Router only and
# CANNOT reach PyPI to install anything.
FROM ghcr.io/nvidia/openshell-community/sandboxes/base:latest

# The base image ships a venv at /sandbox/.venv (python 3.14) + uv. Bake in the MCP client —
# this is the only thing the image must add, and it must happen at build time because the
# running sandbox is egress-locked to the Router and cannot reach PyPI.
#
# Pinned to the exact version in the repo's `uv.lock`, not a floor. A floor resolves to
# whatever is newest at build time, and `agent.py` is written against the 1.x client API
# (`streamablehttp_client`, renamed in 2.x) — so an unpinned build fails inside a sandbox
# that cannot reach PyPI to correct itself. Bump this and the lock together.
RUN uv pip install --python /sandbox/.venv/bin/python --no-cache "mcp==1.27.1"

# agent.py is NOT baked in. The demo uploads it into the running sandbox at runtime (to /tmp,
# a read-write path owned by the sandbox user). Baking it via COPY trips over the base image's
# non-root build user (root-owned COPY + non-root chmod = "operation not permitted").
