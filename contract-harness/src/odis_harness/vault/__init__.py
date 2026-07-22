"""Vault-bundle-issuer harness-side support.

`fixtures` mints the MVP fixture workload-identity JWT; production swaps
the issuer for SPIRE by repointing trust, with no change to the validate/map/sign
path. The Vault client and dev-server lifecycle land alongside it.
"""
