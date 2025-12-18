#!/bin/bash

# Generate server certificate and key
openssl req -x509 -newkey rsa:4096 -keyout certs/server.key -out certs/server.crt -days 365 -nodes -subj "/CN=localhost"

# Generate client certificate and key
openssl req -x509 -newkey rsa:4096 -keyout certs/client.key -out certs/client.crt -days 365 -nodes -subj "/CN=webhook-client"

# Extract client leaf certificate for pinning
openssl x509 -in certs/client.crt -out certs/allowed_client_leaf.pem

echo "Certificates generated successfully in certs/ directory:"
echo "- certs/server.crt and certs/server.key (server certificate)"
echo "- certs/client.crt and certs/client.key (client certificate)"
echo "- certs/allowed_client_leaf.pem (trusted client leaf for pinning)"