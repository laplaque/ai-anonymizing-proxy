# HTTPS Interception (MITM TLS)

The proxy performs MITM TLS termination on HTTPS connections to AI API domains. It decrypts,
anonymizes PII in the request body, and re-encrypts before forwarding to the real API server.
Non-AI domains are tunneled transparently without inspection.

## How it works

1. Client sends `CONNECT api.openai.com:443`
2. Proxy checks if the domain is in `aiApiDomains`
   - **Yes**: generates a TLS certificate for that domain signed by the proxy's CA, performs TLS
     handshake with the client, reads plaintext HTTP, anonymizes PII, forwards over real TLS to
     the API
   - **No**: establishes an opaque TCP tunnel — traffic is not inspected (private IPs blocked)
3. Supports both HTTP/1.1 and HTTP/2 (ALPN negotiation)

## CA certificate setup

On first start, the proxy **auto-generates** a CA certificate (`ca-cert.pem` / `ca-key.pem`) in
its working directory if the files don't exist.

**Auto-generate (default):** Just start the proxy. The CA files will be created and the log will
show trust instructions.

**Manual generation:**

```bash
make gen-ca
```

**Bring your own CA:** Set `CA_CERT_FILE` and `CA_KEY_FILE` (or `caCertFile`/`caKeyFile` in
`proxy-config.json`) to point at your own PEM files. Useful for corporate PKI or a shared CA.

## Trusting the CA

Clients must trust the proxy's CA certificate. Without this, clients will reject the proxy's
certificates with TLS errors.

**macOS (system-wide, requires admin):**

```bash
sudo security add-trusted-cert -d -r trustRoot \
    -k /Library/Keychains/System.keychain /opt/ai-proxy/ca-cert.pem

# Or from the proxy directory:
cd /opt/ai-proxy && make import-ca-macos
```

**Linux (Debian/Ubuntu):**

```bash
sudo cp ca-cert.pem /usr/local/share/ca-certificates/ai-proxy-ca.crt
sudo update-ca-certificates

# Or use: make import-ca-linux
```

**Linux (RHEL/Fedora):**

```bash
sudo cp ca-cert.pem /etc/pki/ca-trust/source/anchors/ai-proxy-ca.crt
sudo update-ca-trust
```

**Windows (elevated Command Prompt):**

```cmd
certutil -addstore -f "ROOT" ca-cert.pem
```

**Node.js / npm:**

```bash
export NODE_EXTRA_CA_CERTS=/path/to/ca-cert.pem
```

Add to `~/.zshrc` / `~/.bashrc` to make it permanent:

```bash
export NODE_EXTRA_CA_CERTS=/opt/ai-proxy/ca-cert.pem
```

**Python (requests / pip):**

```bash
export REQUESTS_CA_BUNDLE=/path/to/ca-cert.pem
# or
export SSL_CERT_FILE=/path/to/ca-cert.pem
```

## Disabling MITM

To fall back to opaque TCP tunneling for all HTTPS traffic, set the CA paths to empty strings:

```bash
CA_CERT_FILE="" CA_KEY_FILE="" ./bin/proxy
```

Or in `proxy-config.json`:

```json
{
  "caCertFile": "",
  "caKeyFile": ""
}
```
