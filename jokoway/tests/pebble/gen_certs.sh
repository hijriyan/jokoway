#!/bin/bash
set -e

# Create certs directory if it doesn't exist
mkdir -p certs

# Generate CA
echo "Generating CA..."
openssl req -x509 -newkey rsa:4096 -keyout certs/ca.key -out certs/ca.pem -days 365 -nodes -subj "/CN=pebble-ca"

# Generate Server Key and CSR
echo "Generating Server Key and CSR..."
openssl req -newkey rsa:4096 -keyout certs/key.pem -out certs/server.csr -nodes -subj "/CN=pebble" -addext "subjectAltName=DNS:pebble,DNS:localhost"

# Sign Server Certificate
echo "Signing Server Certificate..."
openssl x509 -req -in certs/server.csr -CA certs/ca.pem -CAkey certs/ca.key -CAcreateserial -out certs/cert.pem -days 365 -extensions v3_req -extfile <(printf "[v3_req]\nsubjectAltName=DNS:pebble,DNS:localhost")

# Clean up
rm certs/server.csr

echo "Certificates generated in certs/"
