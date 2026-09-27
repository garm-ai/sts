#!/usr/bin/env bash
# Generate a signing seed and a BFF client keypair.
set -euo pipefail
echo "STS_SIGN_SEED_K1=$(head -c32 /dev/urandom | base64)"
# BFF client key (Ed25519). Register shop-bff.pub.pem with the STS; the BFF
# signs its client_assertion with shop-bff.key.
openssl genpkey -algorithm ed25519 -out clients/shop-bff.key
openssl pkey -in clients/shop-bff.key -pubout -out clients/shop-bff.pub.pem
echo "wrote clients/shop-bff.key and clients/shop-bff.pub.pem"
