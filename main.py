import http.server
import ssl
import sys
import hashlib
import binascii

# --- CONFIGURATION ---
SERVER_IP = '0.0.0.0'
SERVER_PORT = 8443

# Server's own credentials (to establish HTTPS)
SERVER_CERT = 'certs/server.crt'
SERVER_KEY = 'certs/server.key'

# The specific Leaf Certificate to trust (The "Pin")
TRUSTED_CLIENT_LEAF = 'certs/allowed_client_leaf.pem'

# --- WEBHOOK HANDLER ---
class WebhookReceiver(http.server.BaseHTTPRequestHandler):
    def do_POST(self):
        """Handle incoming webhook POST requests."""
        if not self.verify_client_fingerprint():
            self.send_error(403, "Forbidden: Certificate Fingerprint Mismatch")
            return

        # 2. Read Payload
        content_length = int(self.headers.get('Content-Length', 0))
        post_data = self.rfile.read(content_length)
        
        print(f"\n[+] Received Webhook from {self.client_address[0]}")
        print(f"    Payload: {post_data.decode('utf-8', errors='ignore')}")

        # 3. Respond
        self.send_response(200)
        self.send_header('Content-type', 'application/json')
        self.end_headers()
        self.wfile.write(b'{"status": "received"}')

    def verify_client_fingerprint(self):
        """
        Extracts the client cert and compares its SHA256 fingerprint 
        against the local trusted leaf file.
        """
        try:
            # Retrieve the cert presented by the client during handshake
            # binary_form=True gives us the DER encoded cert
            client_cert_der = self.request.getpeercert(binary_form=True)
            if not client_cert_der:
                return False

            # Calculate fingerprint of the connected client
            client_fingerprint = hashlib.sha256(client_cert_der).hexdigest()

            # Calculate fingerprint of our local trusted file
            # (In production, cache this value instead of reading file every time)
            with open(TRUSTED_CLIENT_LEAF, 'rb') as f:
                trusted_pem = f.read()
                # Convert PEM to DER for comparison if needed, or better:
                # Just rely on the SSL Context trust. 
                # But to be 100% sure we match the file bytes:
                trusted_der = ssl.PEM_cert_to_DER_cert(trusted_pem.decode())
                trusted_fingerprint = hashlib.sha256(trusted_der).hexdigest()

            if client_fingerprint == trusted_fingerprint:
                return True
            
            print(f"[-] Fingerprint Mismatch! Expected: {trusted_fingerprint}, Got: {client_fingerprint}")
            return False

        except Exception as e:
            print(f"[!] Verification Error: {e}")
            return False

    def log_message(self, format, *args):
        # Override to clean up console output
        sys.stderr.write("%s - - [%s] %s\n" %
                         (self.client_address[0],
                          self.log_date_time_string(),
                          format % args))

# --- SERVER SETUP ---
def run_server():
    print(f"[*] Starting Webhook Receiver on {SERVER_IP}:{SERVER_PORT}")
    print(f"[*] Mode: mTLS Enabled (Leaf Trust Only)")
    
    # 1. Create a "Clean" SSL Context (PROTOCOL_TLS_SERVER)
    # This context does NOT load default system CA bundles, ensuring an empty truststore initially.
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    
    # 2. Load Server Credentials
    try:
        context.load_cert_chain(certfile=SERVER_CERT, keyfile=SERVER_KEY)
    except FileNotFoundError:
        print(f"[!] Error: Server cert/key not found. Please create {SERVER_CERT} and {SERVER_KEY}")
        sys.exit(1)

    # 3. Configure mTLS (Client Auth)
    context.verify_mode = ssl.CERT_REQUIRED
    
    # 4. Trust ONLY the specific Leaf Node
    # By loading the leaf cert as the "CA", we treat it as a trusted root.
    # Note: If the leaf is not self-signed, we usually need the VERIFY_X509_PARTIAL_CHAIN flag.
    try:
        context.load_verify_locations(cafile=TRUSTED_CLIENT_LEAF)
        
        # Enable Partial Chain support (Python 3.10+ / OpenSSL 1.1.0+)
        # This allows a leaf certificate to be treated as a trust anchor even if it has an Issuer.
        if hasattr(ssl, 'VERIFY_X509_PARTIAL_CHAIN'):
            context.verify_flags |= ssl.VERIFY_X509_PARTIAL_CHAIN
        
    except FileNotFoundError:
        print(f"[!] Error: Trusted client leaf not found. Please create {TRUSTED_CLIENT_LEAF}")
        sys.exit(1)

    # 5. Initialize and Run Server
    server = http.server.HTTPServer((SERVER_IP, SERVER_PORT), WebhookReceiver)
    server.socket = context.wrap_socket(server.socket, server_side=True)

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[*] Stopping server...")
        server.server_close()

if __name__ == '__main__':
    run_server()