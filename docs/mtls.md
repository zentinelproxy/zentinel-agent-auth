# mTLS Client Certificate Authentication

The auth agent supports mutual TLS (mTLS) authentication using X.509 client certificates. This enables zero-trust service-to-service authentication.

## Overview

In mTLS authentication, the Zentinel proxy handles TLS termination and forwards the client certificate to the auth agent in a header. The agent validates the certificate and extracts identity information.

## How It Works

```
Client with TLS certificate
         │
         ▼
┌─────────────────────┐
│ Zentinel Proxy      │
│ TLS termination     │
│ Extract client cert │
└─────────┬───────────┘
          │
          │ X-Client-Cert: <PEM or URL-encoded>
          ▼
┌─────────────────────┐
│ Auth Agent          │
│ Parse certificate   │
└─────────┬───────────┘
          │
          ▼
┌─────────────────────┐
│ Validate:           │
│ - Not expired       │
│ - DN in allowlist   │
│ - SAN in allowlist  │
└─────────┬───────────┘
          │
          ▼
┌─────────────────────┐
│ Extract identity    │
│ CN or SAN email     │
└─────────────────────┘
```

## Configuration

### Zentinel Proxy Configuration

First, configure Zentinel to require client certificates and forward them:

```kdl
listener {
    tls {
        client-auth "require"
        forward-client-cert-header "X-Client-Cert"
        ca-cert-file "/etc/ssl/ca.crt"
    }
}
```

### Auth Agent Configuration

```kdl
agents {
    agent "auth" {
        config {
            mtls {
                enabled true
                client-cert-header "X-Client-Cert"
                allowed-dns "CN=service.example.com,O=Example Corp"
                extract-cn-as-user true
            }
        }
    }
}
```

### Full Configuration

```json
{
  "mtls": {
    "enabled": true,
    "client-cert-header": "X-Client-Cert",
    "ca-cert-path": "/etc/ssl/ca.crt",
    "allowed-dns": [
      "CN=api-gateway,O=Example Corp",
      "CN=backend-service,O=Example Corp"
    ],
    "allowed-sans": [
      "api-gateway@example.com",
      "backend@example.com"
    ],
    "extract-cn-as-user": true,
    "extract-san-email-as-user": false,
    "log-certs": false
  }
}
```

### Configuration Options

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `enabled` | bool | `false` | Enable mTLS authentication |
| `client-cert-header` | string | `X-Client-Cert` | Header containing the certificate |
| `ca-cert-path` | string | - | CA cert for chain validation (optional) |
| `allowed-dns` | array | `[]` | Allowed Distinguished Names |
| `allowed-sans` | array | `[]` | Allowed Subject Alternative Names |
| `extract-cn-as-user` | bool | `true` | Use CN as user ID |
| `extract-san-email-as-user` | bool | `false` | Use SAN email as user ID |
| `log-certs` | bool | `false` | Log certificate details |

## Certificate Validation

### Distinguished Name (DN) Allowlist

Restrict which certificates are accepted by DN:

```json
{
  "mtls": {
    "allowed-dns": [
      "CN=payment-service,OU=Services,O=Example Corp,C=US",
      "CN=inventory-service,OU=Services,O=Example Corp,C=US"
    ]
  }
}
```

The DN must match exactly as formatted by the certificate.

### Subject Alternative Name (SAN) Allowlist

Restrict by SAN email or DNS:

```json
{
  "mtls": {
    "allowed-sans": [
      "payment@services.example.com",
      "inventory@services.example.com",
      "api.internal.example.com"
    ]
  }
}
```

### Combined Allowlists

When both `allowed-dns` and `allowed-sans` are configured:
- DN must be in the `allowed-dns` list
- If the cert has SANs and `allowed-sans` is non-empty, at least one SAN must match

## User ID Extraction

The agent extracts a user ID from the certificate for identity headers.

### From Common Name (CN)

```json
{
  "mtls": {
    "extract-cn-as-user": true
  }
}
```

Certificate: `CN=payment-service,O=Example`
User ID: `payment-service`

### From SAN Email

```json
{
  "mtls": {
    "extract-san-email-as-user": true,
    "extract-cn-as-user": false
  }
}
```

Certificate SAN: `email:payment@services.example.com`
User ID: `payment@services.example.com`

### Priority

When both are enabled, the priority is:
1. SAN email (if `extract-san-email-as-user` is true and email exists)
2. CN (if `extract-cn-as-user` is true and CN exists)
3. First SAN DNS name
4. Full Subject DN (fallback)

## Headers Added

On successful mTLS authentication:

| Header | Description | Example |
|--------|-------------|---------|
| `X-User-Id` | Extracted user ID | `payment-service` |
| `X-Auth-Method` | Authentication method | `mtls` |
| `X-Client-Cert-CN` | Common Name | `payment-service` |
| `X-Client-Cert-DN` | Full Distinguished Name | `CN=payment-service,O=Example` |
| `X-Client-Cert-Serial` | Certificate serial | `01:23:45:67` |

## Certificate Formats

The agent accepts certificates in these formats:

### PEM Format

```
-----BEGIN CERTIFICATE-----
MIIBkjCB/AIJAOUHvh4oD+yrMA0GCSqGSIb3DQEBCwUAMBExDzANBgNVBAMMBnRl
...
-----END CERTIFICATE-----
```

### URL-Encoded PEM

Proxies may URL-encode the certificate:

```
-----BEGIN%20CERTIFICATE-----%0AMIIB...
```

The agent automatically URL-decodes before parsing.

### Base64 DER

Raw DER bytes encoded as base64:

```
MIIBkjCB/AIJAOUHvh4oD+yrMA0G...
```

## Generating Test Certificates

### Create CA

```bash
# Generate CA private key
openssl genrsa -out ca.key 4096

# Generate CA certificate
openssl req -new -x509 -days 365 -key ca.key -out ca.crt \
  -subj "/C=US/O=Example Corp/CN=Example CA"
```

### Create Service Certificate

```bash
# Generate service private key
openssl genrsa -out service.key 2048

# Generate CSR
openssl req -new -key service.key -out service.csr \
  -subj "/C=US/O=Example Corp/OU=Services/CN=payment-service"

# Sign with CA
openssl x509 -req -days 365 -in service.csr -CA ca.crt -CAkey ca.key \
  -CAcreateserial -out service.crt

# Verify
openssl x509 -in service.crt -text -noout
```

### Add SAN Extension

Create `san.cnf`:

```ini
[req]
distinguished_name = req_distinguished_name
req_extensions = v3_req

[req_distinguished_name]
CN = payment-service

[v3_req]
subjectAltName = @alt_names

[alt_names]
email.1 = payment@services.example.com
DNS.1 = payment.internal.example.com
```

Sign with SAN:

```bash
openssl x509 -req -days 365 -in service.csr -CA ca.crt -CAkey ca.key \
  -CAcreateserial -out service.crt -extfile san.cnf -extensions v3_req
```

## Troubleshooting

### Certificate Not Found

If you see "No client certificate in request":

1. Verify Zentinel is configured to forward the certificate header
2. Check the header name matches (`X-Client-Cert` by default)
3. Verify the client is sending a certificate

### DN Not Allowed

If you see "Certificate DN not allowed":

1. Enable `log-certs` to see the actual DN
2. The DN format must match exactly
3. Use `openssl x509 -in cert.pem -subject -noout` to see the DN

### Certificate Expired

The agent checks `notBefore` and `notAfter` fields:

```
openssl x509 -in cert.pem -dates -noout
```

### SAN Not Allowed

If SANs are required but not matching:

1. Check the certificate's SAN extension
2. Verify SANs are listed in `allowed-sans`

```bash
openssl x509 -in cert.pem -text -noout | grep -A1 "Subject Alternative Name"
```

## Security Considerations

1. **Use a private CA** for service certificates
2. **Restrict allowlists** to only required services
3. **Short certificate lifetimes** (e.g., 90 days) with automated renewal
4. **Protect CA private keys** with HSM or secure storage
5. **Enable certificate revocation** checking if supported
6. **Log certificate details** for audit purposes
