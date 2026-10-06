# Timestamp Signing Certificate Template

Create a dedicated Active Directory Certificate Services (AD CS) template for the key that signs timestamp tokens. The IIS HTTPS certificate and the client's code or document signing certificate serve different purposes and use their own templates. OpenTimeStamp requires a currently valid RSA signing certificate with an accessible private key, a critical timestamp-only Extended Key Usage (EKU), and a usable certificate chain. RSA supports both timestamp protocols. See [RFC 3161, section 2.3](https://www.rfc-editor.org/rfc/rfc3161.html#section-2.3) for the exclusive signing-key purpose and critical EKU requirement.

## Create and Publish the AD CS Template

Use an enterprise issuing CA and an account authorized to manage certificate templates. A standalone CA does not publish Active Directory templates. Open `certtmpl.msc`, duplicate **Code Signing**, and give the duplicate the display name **OpenTimeStamp Timestamp Signing** and short template name **OpenTimeStampTsa**. Record the short name for enrollment. Select CA and recipient compatibility levels that support your installed servers and a Key Storage Provider. Microsoft's [template management guide](https://learn.microsoft.com/en-us/windows-server/identity/ad-cs/manage-certificate-templates) describes duplication, template permissions, and publication.

Configure the duplicate as follows:

| Template area | Setting |
| --- | --- |
| General | Choose validity and renewal periods under your PKI policy. Plan renewal before expiry and retain verification certificates for existing timestamps. |
| Request Handling | Purpose **Signature**. Clear **Allow private key to be exported**. Use a provider that can sign without an interactive prompt. |
| Cryptography | **Key Storage Provider**, **RSA**, minimum **3072** bits, and **SHA256** request hash. Select **Microsoft Software Key Storage Provider**. |
| Subject Name | **Supply in the request** for the dedicated TSA identity. This needs narrowly restricted enrollment permissions. A DNS SAN is unnecessary for the timestamp signing certificate; configure DNS names on the separate TLS certificate. |
| Extensions: Application Policies | Remove **Code Signing** and every other purpose. Add **Time Stamping** (`1.3.6.1.5.5.7.3.8`); use **New** with that OID if it is absent from the list. Select **Make this extension critical**. |
| Extensions: Key Usage | Enable **Digital signature** and remove encryption/key-exchange purposes. Keep the certificate an end entity, without CA signing rights. |
| Security | Grant **Read** and **Enroll** only to the designated enrollment operators or TSA computer accounts. Remove broad **Enroll** and **Autoenroll** grants. Retain administrative template-management permissions. |
| Issuance Requirements | Apply your CA's approval requirements. An approval requirement means the enrollment command can return a pending request rather than an issued certificate. |

The software provider above matches the supplied private-key ACL helper. For an HSM, use a provider and access-control procedure supported by that device and validate unattended IIS signing separately; the helper does not manage hardware-key permissions. Pure ML-DSA deployment has additional operating-system and client requirements and is RFC 3161-only; see [Protocols and Endpoints](protocols.md).

In `certsrv.msc`, expand the issuing CA, right-click **Certificate Templates**, select **New > Certificate Template to Issue**, and select the duplicate. Allow directory replication before enrolling from another server. The template controls the final issued extensions; marking an extension critical in a request alone does not establish that the CA issued the correct certificate. Always inspect the issued `2.5.29.37` EKU rather than relying only on the Microsoft Application Policies extension or the template's display name.

## Enroll on the Timestamp Server

Copy [timestamp-signing.inf](examples/timestamp-signing.inf) to the TSA server and edit its subject to identify that authority. In an elevated Windows PowerShell prompt, generate the non-exportable machine key and submit its public request to the issuing CA:

```powershell
certreq.exe -new .\timestamp-signing.inf .\timestamp-signing.req
certreq.exe -submit -config 'CAHOST\Issuing CA' `
    -attrib 'CertificateTemplate:OpenTimeStampTsa' `
    .\timestamp-signing.req .\timestamp-signing.cer
certreq.exe -accept -machine .\timestamp-signing.cer
```

Run enrollment using the account granted **Enroll** on the template. Replace `CAHOST\Issuing CA` with the CA configuration string. If approval is required, retain the request ID; after approval, retrieve it with `certreq.exe -retrieve -config 'CAHOST\Issuing CA' <request-id> .\timestamp-signing.cer`, then run `-accept -machine` on the server that created the key. The request contains the public key; the private key remains on that server. See Microsoft's [certreq reference](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/certreq_1) for the INF and command options.

Install the issuing intermediate certificates in **Local Computer > Intermediate Certification Authorities** and the approved root in **Local Computer > Trusted Root Certification Authorities**. The TSA certificate belongs in **Local Computer > Personal**, associated with the machine private key created during enrollment. Make the CA's revocation and issuer-certificate locations reachable from both the IIS identity and the signing clients.

## Check the Issued Certificate and Grant IIS Access

Inspect the certificate before enabling issuance:

```powershell
certutil.exe -dump .\timestamp-signing.cer
certutil.exe -verify -urlfetch .\timestamp-signing.cer
$thumbprint = '<issued-certificate-thumbprint>'
$certificate = Get-Item -LiteralPath "Cert:\LocalMachine\My\$thumbprint"
$certificate | Format-List Subject, Issuer, NotBefore, NotAfter, HasPrivateKey
$eku = $certificate.Extensions | Where-Object { $_.Oid.Value -eq '2.5.29.37' }
$eku | Format-List Critical, EnhancedKeyUsages
```

Require exactly one EKU extension, marked critical, containing only **Time Stamping**. Check digital-signature key usage, end-entity basic constraints, validity, RSA key size, private-key association, and successful chain/revocation validation. If the EKU is noncritical or includes another purpose, correct the template and enroll a replacement. Do not disable certificate validation to accommodate an incorrectly issued production certificate.

Create the dedicated IIS application pool through the [IIS installer](deployment.md), then grant its identity read access to the selected machine key:

```powershell
.\deploy\Grant-TsaPrivateKeyAccess.ps1 `
    -Thumbprint $thumbprint `
    -Identity 'IIS AppPool\OpenTimeStamp'
```

On the local `/admin` page, select that certificate in **Manual** mode, choose the signing digest and policy OID, and enable the required protocols. Keep the development trust exception disabled. Confirm healthy readiness and obtain a real timestamp with an independent client; a visible certificate or successful enrollment does not prove that the IIS identity can sign. For separate signing profiles, grant each key only to its own pool and follow [Signing Endpoints and Hash Policies](signing-endpoints.md).

## Renewal

Enroll a replacement on the TSA server, validate its complete profile and chain, and grant the same dedicated pool access before switching **Manual** selection. **Automatic** selection chooses the eligible accessible certificate with the latest expiry, so a newly installed certificate can change the active signer after refresh. Use manual selection when an endpoint must remain bound to one authority or profile. Retain public certificates, chains, policy records, and revocation evidence needed to validate old timestamps; protect or retire private keys according to your PKI policy.
