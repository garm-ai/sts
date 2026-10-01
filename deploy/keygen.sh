#!/usr/bin/env bash
# Generates the two kinds of keys a dev deployment needs:
#   1. the STS's own ES256 (ECDSA P-256) signing key — loaded into the
#      environment, never referenced by path in config.yaml (see
#      deploy/config.yaml's keys.keys[].pem, which names only an env var).
#   2. a client key pair per calling service, for private_key_jwt (RFC 7523)
#      authentication to POST /token and POST /approve — registered by
#      deploy/config.yaml's clients: block. The runner's client id is
#      additionally what makes its "runner:<id>" identity, which
#      deploy/tuples.yaml's can_run tuple names.
#
# Both MUST be on the algorithm allowlist this service actually accepts
# (issuer.go / clients.go permittedAlgorithms: ES256/384/512, RS256/384/512,
# PS256/384/512). EdDSA is deliberately NOT on that list, so an Ed25519 key
# here would generate cleanly and then silently never verify.
set -euo pipefail

openssl ecparam -name prime256v1 -genkey -noout -out sts-sign-k1.pem
echo "Wrote sts-sign-k1.pem — the STS's own signing key. Load it into the"
echo "environment and do not commit it or leave it on disk in production:"
echo "  export STS_SIGN_KEY_K1=\"\$(cat sts-sign-k1.pem)\""
echo

mkdir -p clients
for client in shop-bff agentd; do
  openssl ecparam -name prime256v1 -genkey -noout -out "clients/$client.key"
  openssl ec -in "clients/$client.key" -pubout -out "clients/$client.pub.pem" 2>/dev/null
  echo "Wrote clients/$client.key ($client signs its client_assertion with this)"
  echo "Wrote clients/$client.pub.pem (registered in deploy/config.yaml's clients: block)"
done
echo
echo "agentd is also the RUNNER identity: deploy/tuples.yaml grants"
echo "runner:agentd the can_run relation on agent:order-assistant."
