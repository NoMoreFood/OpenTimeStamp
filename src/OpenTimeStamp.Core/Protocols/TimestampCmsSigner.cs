using System;
using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.X509Certificates;
using OpenTimeStamp.Asn1;
using OpenTimeStamp.Cryptography;

namespace OpenTimeStamp.Protocols;

internal static class TimestampCmsSigner
{
    public static byte[] Sign(
        byte[] content,
        string contentTypeOid,
        X509Certificate2 certificate,
        TimestampHashAlgorithm signingHash,
        X509IncludeOption includeOption,
        DateTime signingTimeUtc)
    {
        if (content is null) throw new ArgumentNullException(nameof(content));
        if (certificate is null) throw new ArgumentNullException(nameof(certificate));
        if (!PlatformSecurityPolicy.IsSigningHashAllowed(signingHash))
        {
            throw new CryptographicException(
                "The selected timestamp signing hash is not allowed by the current Windows security policy.");
        }

        var rfc3161 = string.Equals(contentTypeOid, KnownOids.TstInfoContentType, StringComparison.Ordinal);
        var isMldsa = CertificateRepository.IsMldsaCertificate(certificate);
        var effectiveSigningTimeUtc = signingTimeUtc.Kind == DateTimeKind.Utc
            ? signingTimeUtc
            : signingTimeUtc.ToUniversalTime();
        if (isMldsa && !rfc3161)
        {
            throw new CryptographicException("ML-DSA CMS signing is supported only for RFC 3161 TSTInfo content.");
        }

        if (effectiveSigningTimeUtc < certificate.NotBefore.ToUniversalTime() ||
            effectiveSigningTimeUtc > certificate.NotAfter.ToUniversalTime())
        {
            throw new CryptographicException(
                "The timestamp signing certificate is not valid at the next timestamp signing time.");
        }

        // SignedCms on .NET Framework requires non-id-data content to arrive as an encoded ASN.1 OCTET STRING.
        var cmsContent = string.Equals(contentTypeOid, KnownOids.Pkcs7Data, StringComparison.Ordinal)
            ? content
            : EncodeOctetString(content);
        SignedCms cms = new(new ContentInfo(new Oid(contentTypeOid), cmsContent), false);
        CmsSigner signer = new(SubjectIdentifierType.IssuerAndSerialNumber, certificate)
        {
            DigestAlgorithm = new Oid(signingHash.Oid),
            IncludeOption = includeOption
        };

        // Bind the signing time and ESS certificate identifier into authenticated attributes.
        signer.SignedAttributes.Add(new Pkcs9SigningTime(effectiveSigningTimeUtc));
        signer.SignedAttributes.Add(CreateEssAttribute(certificate, signingHash));
        if (isMldsa)
        {
            signer.SignedAttributes.Add(CreateCmsAlgorithmProtectionAttribute(
                signingHash.Oid,
                certificate.PublicKey.Oid.Value));
        }

        cms.ComputeSignature(signer, true);

        // Decode and verify the emitted CMS before returning cryptographic output to a client.
        var encoded = cms.Encode();
        if (rfc3161)
        {
            encoded = NormalizeRfc3161SignedData(
                encoded,
                signingHash.Oid,
                isMldsa ? certificate.PublicKey.Oid.Value : null);
        }
        SignedCms verification = new();
        verification.Decode(encoded);
        verification.CheckSignature(new X509Certificate2Collection(certificate), true);
        // SignedCms exposes a version-3 non-id-data eContent as its unwrapped ASN.1 value.
        var expectedVerifiedContent = rfc3161 ? content : cmsContent;
        if (!FixedEquals(verification.ContentInfo.Content, expectedVerifiedContent) ||
            !string.Equals(verification.ContentInfo.ContentType.Value, contentTypeOid, StringComparison.Ordinal))
        {
            throw new CryptographicException("CMS post-sign verification found altered content.");
        }

        return encoded;
    }

    private static byte[] EncodeOctetString(byte[] content)
    {
        DerWriter writer = new();
        writer.WriteOctetString(content);
        return writer.Encode();
    }

    private static CryptographicAttributeObject CreateEssAttribute(
        X509Certificate2 certificate,
        TimestampHashAlgorithm signingHash)
    {
        // ESSCertID uses SHA-1. ESSCertIDv2 defaults to SHA-256 and otherwise carries
        // the same hash algorithm as the CMS signature for commensurate protection.
        var useVersionOne = string.Equals(signingHash.Name, "SHA1", StringComparison.Ordinal);
        var oid = useVersionOne ? KnownOids.SigningCertificate : KnownOids.SigningCertificateV2;
        var certificateHash = signingHash.Name switch
        {
            "SHA1" => WindowsHash.ComputeSha1(certificate.RawData),
            "SHA256" => WindowsHash.ComputeSha256(certificate.RawData),
            "SHA384" => WindowsHash.ComputeSha384(certificate.RawData),
            "SHA512" => WindowsHash.ComputeSha512(certificate.RawData),
            _ => throw new CryptographicException("The ESS certificate hash algorithm is not supported.")
        };

        DerWriter writer = new();
        writer.WriteSequence(signingCertificate =>
            signingCertificate.WriteSequence(certs =>
                certs.WriteSequence(essCertId =>
                {
                    if (!useVersionOne && !string.Equals(signingHash.Name, "SHA256", StringComparison.Ordinal))
                    {
                        essCertId.WriteSequence(hashAlgorithm =>
                            hashAlgorithm.WriteObjectIdentifier(signingHash.Oid));
                    }

                    essCertId.WriteOctetString(certificateHash);
                })));
        AsnEncodedData value = new(new Oid(oid), writer.Encode());
        return new CryptographicAttributeObject(new Oid(oid), new AsnEncodedDataCollection(value));
    }

    internal static CryptographicAttributeObject CreateCmsAlgorithmProtectionAttribute(
        string digestAlgorithmOid,
        string signatureAlgorithmOid)
    {
        // RFC 6211 uses IMPLICIT tagging for the protected signature AlgorithmIdentifier.
        DerWriter writer = new();
        writer.WriteSequence(protection =>
        {
            protection.WriteSequence(digest => digest.WriteObjectIdentifier(digestAlgorithmOid));
            protection.WriteContextSpecificConstructed(
                1,
                signature => signature.WriteObjectIdentifier(signatureAlgorithmOid));
        });
        AsnEncodedData value = new(new Oid(KnownOids.CmsAlgorithmProtection), writer.Encode());
        return new CryptographicAttributeObject(
            new Oid(KnownOids.CmsAlgorithmProtection),
            new AsnEncodedDataCollection(value));
    }

    private static byte[] NormalizeRfc3161SignedData(
        byte[] encodedCms,
        string expectedDigestOid,
        string expectedSignatureOid)
    {
        try
        {
            DerReader outer = new(encodedCms);
            var contentInfo = outer.ReadSequence();
            outer.ThrowIfNotEmpty();
            if (!string.Equals(
                    contentInfo.ReadObjectIdentifier(),
                    KnownOids.Pkcs7SignedDataValue,
                    StringComparison.Ordinal))
            {
                throw new DerEncodingException("The CMS ContentInfo is not SignedData.");
            }

            var explicitContent = contentInfo.ReadConstructed(0xa0);
            contentInfo.ThrowIfNotEmpty();
            var signedData = explicitContent.ReadSequence();
            explicitContent.ThrowIfNotEmpty();
            signedData.ReadIntegerInt32();

            var digestAlgorithms = signedData.ReadConstructed(0x31);
            var normalizedDigestAlgorithm = NormalizeDigestAlgorithm(digestAlgorithms, expectedDigestOid);
            digestAlgorithms.ThrowIfNotEmpty();
            var encapsulatedContent = signedData.ReadEncodedValue();
            ValidateTstInfoEncapsulatedContent(encapsulatedContent);
            byte[] certificates = null;
            byte[] revocationInfo = null;
            if (signedData.HasData && signedData.PeekTag() == 0xa0)
            {
                certificates = signedData.ReadEncodedValue();
            }

            if (signedData.HasData && signedData.PeekTag() == 0xa1)
            {
                revocationInfo = signedData.ReadEncodedValue();
            }

            var signerInfos = signedData.ReadConstructed(0x31);
            var normalizedSignerInfo = NormalizeSignerInfo(
                signerInfos,
                expectedDigestOid,
                expectedSignatureOid);
            signerInfos.ThrowIfNotEmpty();
            signedData.ThrowIfNotEmpty();

            DerWriter writer = new();
            writer.WriteSequence(normalizedContentInfo =>
            {
                normalizedContentInfo.WriteObjectIdentifier(KnownOids.Pkcs7SignedDataValue);
                normalizedContentInfo.WriteContextSpecificConstructed(0, normalizedExplicit =>
                    normalizedExplicit.WriteSequence(normalizedSignedData =>
                    {
                        // RFC 5652 requires version 3 for the non-id-data TSTInfo content type.
                        normalizedSignedData.WriteInteger(3);
                        normalizedSignedData.WriteSet(set => set.WriteEncodedValue(normalizedDigestAlgorithm));
                        normalizedSignedData.WriteEncodedValue(encapsulatedContent);
                        if (certificates is not null) normalizedSignedData.WriteEncodedValue(certificates);
                        if (revocationInfo is not null) normalizedSignedData.WriteEncodedValue(revocationInfo);
                        normalizedSignedData.WriteSet(set => set.WriteEncodedValue(normalizedSignerInfo));
                    }));
            });
            return writer.Encode();
        }
        catch (Exception ex) when (ex is DerEncodingException or ArgumentException or OverflowException)
        {
            throw new CryptographicException("The generated RFC 3161 CMS value is malformed.", ex);
        }
    }

    private static byte[] NormalizeSignerInfo(
        DerReader signerInfos,
        string expectedDigestOid,
        string expectedSignatureOid)
    {
        var signerInfo = signerInfos.ReadSequence();
        var version = signerInfo.ReadIntegerInt32();
        var signerIdentifier = signerInfo.ReadEncodedValue();
        var digestAlgorithm = NormalizeDigestAlgorithm(signerInfo, expectedDigestOid);
        if (!signerInfo.HasData || signerInfo.PeekTag() != 0xa0)
        {
            throw new DerEncodingException("The RFC 3161 SignerInfo has no signed attributes.");
        }

        var signedAttributes = signerInfo.ReadEncodedValue();
        if (!signerInfo.HasData || signerInfo.PeekTag() != 0x30)
        {
            throw new DerEncodingException("The RFC 3161 signature AlgorithmIdentifier is missing.");
        }

        var signatureAlgorithm = signerInfo.ReadEncodedValue();
        if (expectedSignatureOid is not null)
        {
            ValidateMldsaSignatureAlgorithm(signatureAlgorithm, expectedSignatureOid);
        }
        if (!signerInfo.HasData || signerInfo.PeekTag() != 0x04)
        {
            throw new DerEncodingException("The RFC 3161 signature value is missing.");
        }

        var signature = signerInfo.ReadEncodedValue();
        byte[] unsignedAttributes = null;
        if (signerInfo.HasData && signerInfo.PeekTag() == 0xa1)
        {
            unsignedAttributes = signerInfo.ReadEncodedValue();
        }

        signerInfo.ThrowIfNotEmpty();
        DerWriter writer = new();
        writer.WriteSequence(normalizedSignerInfo =>
        {
            normalizedSignerInfo.WriteInteger(version);
            normalizedSignerInfo.WriteEncodedValue(signerIdentifier);
            normalizedSignerInfo.WriteEncodedValue(digestAlgorithm);
            normalizedSignerInfo.WriteEncodedValue(signedAttributes);
            normalizedSignerInfo.WriteEncodedValue(signatureAlgorithm);
            normalizedSignerInfo.WriteEncodedValue(signature);
            if (unsignedAttributes is not null)
            {
                normalizedSignerInfo.WriteEncodedValue(unsignedAttributes);
            }
        });
        return writer.Encode();
    }

    private static byte[] NormalizeDigestAlgorithm(DerReader parent, string expectedDigestOid)
    {
        var algorithmIdentifier = parent.ReadSequence();
        var algorithmOid = algorithmIdentifier.ReadObjectIdentifier();
        byte[] parameters = null;
        if (algorithmIdentifier.HasData) parameters = algorithmIdentifier.ReadEncodedValue();
        algorithmIdentifier.ThrowIfNotEmpty();
        if (!string.Equals(algorithmOid, expectedDigestOid, StringComparison.Ordinal))
        {
            throw new DerEncodingException("The generated timestamp signature uses an inconsistent hash algorithm.");
        }

        if (IsSha2Digest(algorithmOid) &&
            parameters is not null &&
            (parameters.Length != 2 || parameters[0] != 0x05 || parameters[1] != 0x00))
        {
            throw new DerEncodingException("The generated timestamp signature has invalid hash parameters.");
        }

        DerWriter writer = new();
        writer.WriteSequence(normalizedAlgorithm =>
        {
            normalizedAlgorithm.WriteObjectIdentifier(algorithmOid);
            if (!IsSha2Digest(algorithmOid) && parameters is not null)
            {
                normalizedAlgorithm.WriteEncodedValue(parameters);
            }
        });
        return writer.Encode();
    }

    private static void ValidateTstInfoEncapsulatedContent(byte[] encodedContent)
    {
        DerReader outer = new(encodedContent);
        var content = outer.ReadSequence();
        outer.ThrowIfNotEmpty();
        if (!string.Equals(
                content.ReadObjectIdentifier(),
                KnownOids.TstInfoContentType,
                StringComparison.Ordinal))
        {
            throw new DerEncodingException("The generated CMS content type is not TSTInfo.");
        }

        var explicitContent = content.ReadConstructed(0xa0);
        explicitContent.ReadOctetString();
        explicitContent.ThrowIfNotEmpty();
        content.ThrowIfNotEmpty();
    }

    private static void ValidateMldsaSignatureAlgorithm(byte[] encodedAlgorithm, string expectedSignatureOid)
    {
        DerReader outer = new(encodedAlgorithm);
        var algorithm = outer.ReadSequence();
        outer.ThrowIfNotEmpty();
        var algorithmOid = algorithm.ReadObjectIdentifier();
        if (!string.Equals(algorithmOid, expectedSignatureOid, StringComparison.Ordinal))
        {
            throw new DerEncodingException("The generated CMS signature algorithm is inconsistent.");
        }

        if (algorithm.HasData)
        {
            throw new DerEncodingException("ML-DSA CMS signature AlgorithmIdentifier parameters must be absent.");
        }
    }

    private static bool IsSha2Digest(string oid) =>
        string.Equals(oid, KnownOids.Sha224Value, StringComparison.Ordinal) ||
        string.Equals(oid, KnownOids.Sha256Value, StringComparison.Ordinal) ||
        string.Equals(oid, KnownOids.Sha384Value, StringComparison.Ordinal) ||
        string.Equals(oid, KnownOids.Sha512Value, StringComparison.Ordinal);

    private static bool FixedEquals(byte[] left, byte[] right) =>
        WindowsHash.FixedTimeEquals(left, right);
}
