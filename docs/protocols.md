# Protocols and Endpoints

For the default IIS application path `/OpenTimeStamp`:

| Path | Method | Purpose |
| --- | --- | --- |
| `/OpenTimeStamp/timestamp/rfc3161` | `POST` | RFC 3161 request (`application/timestamp-query`) and reply (`application/timestamp-reply`); use this for SignTool `/tr` |
| `/OpenTimeStamp/timestamp/authenticode` | `POST` | Legacy Authenticode base64 request/response (`application/octet-stream`); use this for SignTool `/t` |
| `/OpenTimeStamp/health` | `GET` | Operational health response; inherits the public authentication mode |
| `/OpenTimeStamp/admin` | `GET`, `POST` | Administrative UI; Windows-authenticated and local-computer-only regardless of public mode |

There is intentionally no content-sniffing `/timestamp` endpoint. Clients must
select the protocol explicitly.

RFC 3161/RFC 5816 message imprints support MD5, SHA-1, SHA-224, SHA-256,
SHA-384, and SHA-512 OIDs. Safe defaults enable SHA-256, SHA-384, and SHA-512.
SHA-224 is an accepted precomputed imprint algorithm, but it is not available as
a Windows CMS signing digest. CMS token signatures support SHA-1, SHA-256,
SHA-384, and SHA-512 with eligible RSA certificates and the appropriate ESS
signing-certificate attribute. RSA remains the supported default for both
protocols.

Pure ML-DSA-44, ML-DSA-65, and ML-DSA-87 certificates are also supported for
RFC 3161 only when the installed Windows version and updates expose ML-DSA
through the operating system cryptographic provider. Their CMS digest choices
are deliberately limited to the standardized combinations:

| Signing key | Allowed CMS signing digests |
| --- | --- |
| ML-DSA-44 | SHA-256, SHA-384, SHA-512 |
| ML-DSA-65 | SHA-384, SHA-512 |
| ML-DSA-87 | SHA-512 |

The legacy Authenticode endpoint remains RSA-only. The service makes no support
claim for composite signatures or SLH-DSA. MD5, SHA-1, and Authenticode are
legacy choices and are subject to the FIPS behavior described below. RFC 3161
protocol rejections are returned as DER protocol-format status replies over
HTTP 200, so clients must inspect the PKI status rather than treating HTTP
success as a granted timestamp.

OID values are centralized in one catalog. Where .NET Framework exposes a
Windows `Oid.FromFriendlyName` mapping, the service uses it only when it exactly
matches the standards value; otherwise it uses the catalog's numeric fallback.
SHA-224, RFC 3161 content types, Authenticode, and ESS attributes have no
complete public .NET Framework constant/mapping set, so their authoritative
numeric values remain centralized and regression-tested rather than scattered
through protocol code.
