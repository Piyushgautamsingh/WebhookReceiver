# WebhookReceiver

A secure webhook receiver server that implements mutual TLS (mTLS) authentication with leaf certificate pinning for enhanced security.

## Features

- **HTTPS Server**: Runs on HTTPS with configurable IP and port
- **Mutual TLS Authentication**: Requires client certificates for authentication
- **Leaf Certificate Pinning**: Trusts only a specific pre-configured client certificate
- **Webhook Handling**: Processes POST requests and logs payload data
- **Certificate Fingerprint Verification**: Validates client certificates by SHA256 fingerprint comparison

## Prerequisites

- Python 3.6+
- OpenSSL (for certificate generation)

## Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/Piyushgautamsingh/WebhookReceiver.git
   cd WebhookReceiver
   ```

2. Generate certificates:
   ```bash
   chmod +x generate_certs.sh
   ./generate_certs.sh
   ```

   This will create all necessary certificates in the `certs/` directory:
   - `certs/server.crt` and `certs/server.key`: Server certificate and private key
   - `certs/client.crt` and `certs/client.key`: Client certificate and private key
   - `certs/allowed_client_leaf.pem`: Trusted client leaf certificate for pinning

## Configuration

Edit the configuration variables in `main.py`:

```python
SERVER_IP = '0.0.0.0'      # Listen on all interfaces
SERVER_PORT = 8443         # HTTPS port
SERVER_CERT = 'certs/server.crt' # Server certificate file
SERVER_KEY = 'certs/server.key'  # Server private key file
TRUSTED_CLIENT_LEAF = 'certs/allowed_client_leaf.pem'  # Trusted client certificate
```

## Usage

1. Start the server:
   ```bash
   python3 main.py
   ```

2. The server will start listening on `https://0.0.0.0:8443`

3. Send webhooks using curl with client certificate:
   ```bash
   curl -X POST https://localhost:8443/webhook \
        --cert certs/client.crt \
        --key certs/client.key \
        --cacert certs/server.crt \
        -H "Content-Type: application/json" \
        -d '{"message": "Hello, webhook!"}'
   ```

## Security Notes

- **Certificate Pinning**: Only clients with the exact certificate matching `allowed_client_leaf.pem` are allowed
- **No Default Trust**: The SSL context is configured without system CA bundles for maximum security
- **Fingerprint Verification**: Client certificates are verified by SHA256 fingerprint comparison
- **Partial Chain Support**: Supports certificates that are not self-signed (Python 3.10+)

## API

### POST /

Receives webhook payloads. Requires valid client certificate.

**Request:**
- Method: POST
- Headers: Standard HTTP headers
- Body: Raw payload data

**Response:**
- Status: 200 OK
- Body: `{"status": "received"}`

**Error Responses:**
- 403 Forbidden: Invalid or missing client certificate

## Development

### Certificate Management

The `generate_certs.sh` script automates certificate generation:
- Creates self-signed certificates for both server and client
- Extracts the client leaf certificate for pinning
- Places all files in the `certs/` directory

To regenerate certificates:
```bash
./generate_certs.sh
```

**Note:** When regenerating certificates, update any client applications with the new `certs/client.crt` and `certs/client.key`. Certificates are valid for 365 days by default.

### Logging

The server logs:
- Successful webhook receipts with client IP and payload
- Certificate verification failures
- Server startup and shutdown events

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.