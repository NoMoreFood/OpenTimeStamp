using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using OpenTimeStamp.Asn1;
using OpenTimeStamp.Configuration;
using OpenTimeStamp.Cryptography;
using OpenTimeStamp.Protocols;

namespace OpenTimeStamp.Tests;

internal static class PostQuantumProtocolTests
{
    private const string CmsAlgorithmProtectionOid = "1.2.840.113549.1.9.52";
    private const string MlDsa44Oid = "2.16.840.1.101.3.4.3.17";
    private const string MlDsa65Oid = "2.16.840.1.101.3.4.3.18";
    private const string MlDsa87Oid = "2.16.840.1.101.3.4.3.19";
    private const string Pkcs7SignedDataOid = "1.2.840.113549.1.7.2";
    private const string RsaEncryptionOid = "1.2.840.113549.1.1.1";
    private const string Sha384Oid = "2.16.840.1.101.3.4.2.2";
    private const string Sha512Oid = "2.16.840.1.101.3.4.2.3";
    private const string TstInfoContentTypeOid = "1.2.840.113549.1.9.16.1.4";

    public static void Register(ICollection<TestCase> tests)
    {
        tests.Add(new TestCase(
            "ML-DSA RFC 9881 identifiers, public keys, usages, and digest profiles are validated",
            MldsaProviderIndependentValidation));
        tests.Add(new TestCase(
            "ML-DSA-65 certificate enforces CMS digest and protocol constraints",
            Mldsa65CertificateCompatibility));
        tests.Add(new TestCase(
            "ML-DSA-65 RFC3161 token is standards-shaped, verifiable, and Authenticode-safe",
            Mldsa65Rfc3161AndAuthenticode));
    }

    private static void Mldsa65CertificateCompatibility()
    {
        SkipUnlessMldsaSupported();

        using var certificate = new MldsaTimestampCertificateFixture();
        var signingTimeUtc = new DateTime(2026, 7, 17, 16, 0, 0, DateTimeKind.Utc);
        AssertEx.False(CertificateRepository.ValidateCertificate(
            certificate.Certificate, "SHA256", signingTimeUtc, out var reason));
        AssertEx.Contains("SHA384 or SHA512", reason);
        AssertEx.True(CertificateRepository.ValidateCertificate(
            certificate.Certificate, "SHA384", signingTimeUtc, out reason), reason);
        AssertEx.Equal<string>(null, reason);
        AssertEx.True(CertificateRepository.ValidateCertificate(
            certificate.Certificate, "SHA512", signingTimeUtc, out reason), reason);
        AssertEx.Equal<string>(null, reason);
        AssertEx.False(CertificateRepository.ValidateCertificate(
            certificate.Certificate, "SHA512", signingTimeUtc, true, out reason));
        AssertEx.Contains("legacy Authenticode requires an RSA certificate", reason);
    }

    private static void Mldsa65Rfc3161AndAuthenticode()
    {
        SkipUnlessMldsaSupported();

        using var directory = new TemporaryDirectory();
        using var certificate = new MldsaTimestampCertificateFixture();
        var configuration = TestFixtures.CreateConfiguration();
        var signingTimeUtc = new DateTime(2026, 7, 17, 16, 30, 0, DateTimeKind.Utc);
        var request = TestFixtures.BuildRfc3161Request(
            TestFixtures.Sha256Oid, new byte[32], certificateRequested: true);
        AssertRfc3161DigestRejectedBeforeIssuance(
            directory, certificate.Certificate, configuration, request, signingTimeUtc);

        configuration.SigningDigestAlgorithm = "SHA512";
        var rfc3161 = new Rfc3161TimestampProcessor().Process(
            request,
            configuration,
            certificate.Certificate,
            TestFixtures.CreateInitializedStateStore(directory.File("mldsa-rfc3161.bin")),
            signingTimeUtc);
        AssertEx.True(rfc3161.Granted, rfc3161.Detail);

        var encodedToken = TestFixtures.ExtractGrantedRfc3161Token(rfc3161.EncodedResponse);
        var cms = TestFixtures.DecodeCms(encodedToken);
        AssertEx.Equal(1, cms.SignerInfos.Count);
        AssertEx.Equal(Sha512Oid, cms.SignerInfos[0].DigestAlgorithm.Value);
        cms.CheckSignature(true);

        var signer = ReadSignerInfo(encodedToken);
        AssertEx.Equal(3, signer.SignedDataVersion);
        AssertEx.Equal(Sha512Oid, signer.OuterDigestAlgorithmOid);
        AssertEx.False(signer.OuterDigestAlgorithmHasParameters,
            "RFC 9882 requires absent SHA-512 digest AlgorithmIdentifier parameters.");
        AssertEx.Equal(Sha512Oid, signer.DigestAlgorithmOid);
        AssertEx.False(signer.DigestAlgorithmHasParameters,
            "RFC 9882 requires absent SHA-512 digest AlgorithmIdentifier parameters.");
        AssertEx.Equal(MlDsa65Oid, signer.SignatureAlgorithmOid);
        AssertEx.False(
            signer.SignatureAlgorithmHasParameters,
            "RFC 9882 requires absent ML-DSA AlgorithmIdentifier parameters.");
        AssertEx.Equal(1, signer.CmsAlgorithmProtectionCount);
        AssertEx.Equal(Sha512Oid, signer.ProtectedDigestAlgorithmOid);
        AssertEx.False(signer.ProtectedDigestAlgorithmHasParameters);
        AssertEx.Equal(MlDsa65Oid, signer.ProtectedSignatureAlgorithmOid);
        AssertEx.False(signer.ProtectedSignatureAlgorithmHasParameters);

        AssertAuthenticodeRejectedBeforeIssuance(
            directory, certificate.Certificate, configuration, signingTimeUtc);
    }

    private static void MldsaProviderIndependentValidation()
    {
        var algorithmProtection = TimestampCmsSigner.CreateCmsAlgorithmProtectionAttribute(
            Sha512Oid,
            MlDsa65Oid);
        AssertEx.Equal(CmsAlgorithmProtectionOid, algorithmProtection.Oid.Value);
        AssertEx.Equal(1, algorithmProtection.Values.Count);
        AssertEx.SequenceEqual(
            [
                0x30, 0x1a,
                0x30, 0x0b, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03,
                0xa1, 0x0b, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x12
            ],
            algorithmProtection.Values[0].RawData,
            "CMSAlgorithmProtection must use RFC 6211's IMPLICIT signature-algorithm tag.");

        var profiles = new[]
        {
            (Oid: MlDsa44Oid, KeyLength: 1312, MinimumHash: "SHA256", RejectedHash: "SHA1"),
            (Oid: MlDsa65Oid, KeyLength: 1952, MinimumHash: "SHA384", RejectedHash: "SHA256"),
            (Oid: MlDsa87Oid, KeyLength: 2592, MinimumHash: "SHA512", RejectedHash: "SHA384")
        };
        foreach (var profile in profiles)
        {
            AssertEx.True(CertificateRepository.IsMldsaPublicKeyEncodingCompatible(
                profile.Oid,
                null,
                new byte[profile.KeyLength],
                out var reason), reason);
            AssertEx.False(CertificateRepository.IsMldsaPublicKeyEncodingCompatible(
                profile.Oid,
                [0x05, 0x00],
                new byte[profile.KeyLength],
                out reason));
            AssertEx.Contains("parameters must be absent", reason);
            AssertEx.False(CertificateRepository.IsMldsaPublicKeyEncodingCompatible(
                profile.Oid,
                null,
                new byte[profile.KeyLength - 1],
                out reason));
            AssertEx.Contains("length", reason);

            AssertEx.True(CertificateRepository.IsMldsaSigningHashCompatible(
                profile.Oid,
                HashAlgorithmCatalog.FindByName(profile.MinimumHash),
                out reason), reason);
            AssertEx.False(CertificateRepository.IsMldsaSigningHashCompatible(
                profile.Oid,
                HashAlgorithmCatalog.FindByName(profile.RejectedHash),
                out reason));
            AssertEx.Contains("require", reason);

            var validCertificate = BuildCertificateSignatureFixture(
                profile.Oid,
                false,
                profile.Oid,
                false);
            AssertEx.True(CertificateRepository.HasValidMldsaCertificateSignatureAlgorithmIdentifiers(
                validCertificate,
                out reason), reason);
        }

        AssertEx.True(CertificateRepository.IsMldsaKeyUsageCompatible(
            X509KeyUsageFlags.DigitalSignature,
            out var usageReason), usageReason);
        AssertEx.True(CertificateRepository.IsMldsaKeyUsageCompatible(
            X509KeyUsageFlags.NonRepudiation,
            out usageReason), usageReason);
        AssertEx.False(CertificateRepository.IsMldsaKeyUsageCompatible(
            X509KeyUsageFlags.KeyCertSign,
            out usageReason));
        AssertEx.Contains("timestamp signatures", usageReason);
        AssertEx.False(CertificateRepository.IsMldsaKeyUsageCompatible(
            X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.KeyEncipherment,
            out usageReason));
        AssertEx.Contains("encryption", usageReason);

        AssertCertificateSignatureRejected(MlDsa65Oid, true, MlDsa65Oid, false, "parameters must be absent");
        AssertCertificateSignatureRejected(MlDsa65Oid, false, MlDsa65Oid, true, "parameters must be absent");
        AssertCertificateSignatureRejected(MlDsa44Oid, false, MlDsa65Oid, false, "do not match");
        AssertCertificateSignatureRejected(RsaEncryptionOid, true, MlDsa65Oid, false, "do not match");
        AssertCertificateSignatureRejected(MlDsa65Oid, false, RsaEncryptionOid, true, "do not match");

        var rsaCertificate = BuildCertificateSignatureFixture(
            RsaEncryptionOid,
            true,
            RsaEncryptionOid,
            true);
        AssertEx.True(CertificateRepository.HasValidMldsaCertificateSignatureAlgorithmIdentifiers(
            rsaCertificate,
            out var rsaReason), rsaReason);
        AssertEx.False(CertificateRepository.HasValidMldsaCertificateSignatureAlgorithmIdentifiers(
            [0x30, 0x00],
            out var malformedReason));
        AssertEx.Contains("malformed", malformedReason);
    }

    private static void AssertCertificateSignatureRejected(
        string innerOid,
        bool innerHasNull,
        string outerOid,
        bool outerHasNull,
        string expectedReason)
    {
        var encoded = BuildCertificateSignatureFixture(innerOid, innerHasNull, outerOid, outerHasNull);
        AssertEx.False(CertificateRepository.HasValidMldsaCertificateSignatureAlgorithmIdentifiers(
            encoded,
            out var reason));
        AssertEx.Contains(expectedReason, reason);
    }

    private static byte[] BuildCertificateSignatureFixture(
        string innerOid,
        bool innerHasNull,
        string outerOid,
        bool outerHasNull)
    {
        DerWriter writer = new();
        writer.WriteSequence(certificate =>
        {
            certificate.WriteSequence(tbsCertificate =>
            {
                tbsCertificate.WritePositiveInteger([1]);
                WriteAlgorithmIdentifier(tbsCertificate, innerOid, innerHasNull);
            });
            WriteAlgorithmIdentifier(certificate, outerOid, outerHasNull);
            certificate.WriteEncodedValue([0x03, 0x02, 0x00, 0x01]);
        });
        return writer.Encode();
    }

    private static void WriteAlgorithmIdentifier(DerWriter writer, string oid, bool includeNull) =>
        writer.WriteSequence(algorithmIdentifier =>
        {
            algorithmIdentifier.WriteObjectIdentifier(oid);
            if (includeNull) algorithmIdentifier.WriteNull();
        });

    private static void SkipUnlessMldsaSupported()
    {
        if (!PlatformSecurityPolicy.IsMldsaSupported)
        {
            throw new TestSkippedException("The installed Windows cryptography provider does not support ML-DSA.");
        }
    }

    private static void AssertRfc3161DigestRejectedBeforeIssuance(
        TemporaryDirectory directory,
        X509Certificate2 certificate,
        ServiceConfiguration configuration,
        byte[] request,
        DateTime signingTimeUtc)
    {
        var statePath = directory.File("mldsa-incompatible-rfc3161.bin");
        var stateStore = TestFixtures.CreateInitializedStateStore(statePath);
        var stateBefore = File.ReadAllBytes(statePath);
        var markerBefore = File.ReadAllBytes(statePath + ".meta");
        var rejection = new Rfc3161TimestampProcessor().Process(
            request,
            configuration,
            certificate,
            stateStore,
            signingTimeUtc);
        AssertEx.False(rejection.Granted);
        AssertEx.Equal<Rfc3161FailureInfo?>(Rfc3161FailureInfo.SystemFailure, rejection.FailureInfo);
        AssertEx.Contains("SHA384 or SHA512", rejection.Detail);
        AssertEx.SequenceEqual(
            stateBefore,
            File.ReadAllBytes(statePath),
            "An incompatible ML-DSA signing digest must not consume durable issuance state.");
        AssertEx.SequenceEqual(
            markerBefore,
            File.ReadAllBytes(statePath + ".meta"),
            "An incompatible ML-DSA signing digest must not advance the issuance high-water marker.");
    }

    private static void AssertAuthenticodeRejectedBeforeIssuance(
        TemporaryDirectory directory,
        X509Certificate2 certificate,
        ServiceConfiguration configuration,
        DateTime signingTimeUtc)
    {
        var statePath = directory.File("mldsa-authenticode.bin");
        var stateStore = TestFixtures.CreateInitializedStateStore(statePath);
        var stateBefore = File.ReadAllBytes(statePath);
        var markerBefore = File.ReadAllBytes(statePath + ".meta");
        var request = TestFixtures.BuildAuthenticodeRequest(new byte[64]);
        var processor = new AuthenticodeTimestampProcessor();
        if (PlatformSecurityPolicy.IsLegacyAuthenticodeAllowed)
        {
            var rejection = AssertEx.Throws<CryptographicException>(() =>
                processor.Process(request, configuration, certificate, stateStore, signingTimeUtc));
            AssertEx.Contains("legacy Authenticode requires an RSA certificate", rejection.Message);
        }
        else
        {
            AssertEx.Throws<AuthenticodeProtocolException>(() =>
                processor.Process(request, configuration, certificate, stateStore, signingTimeUtc));
        }

        AssertEx.SequenceEqual(
            stateBefore,
            File.ReadAllBytes(statePath),
            "Rejected legacy requests must not consume durable issuance state.");
        AssertEx.SequenceEqual(
            markerBefore,
            File.ReadAllBytes(statePath + ".meta"),
            "Rejected legacy requests must not advance the issuance high-water marker.");
    }

    private static MldsaSignerInfo ReadSignerInfo(byte[] encodedCms)
    {
        var outer = new DerReader(encodedCms);
        var contentInfo = outer.ReadSequence();
        outer.ThrowIfNotEmpty();
        AssertEx.Equal(Pkcs7SignedDataOid, contentInfo.ReadObjectIdentifier());
        var explicitContent = contentInfo.ReadConstructed(0xa0);
        contentInfo.ThrowIfNotEmpty();
        var signedData = explicitContent.ReadSequence();
        explicitContent.ThrowIfNotEmpty();
        MldsaSignerInfo result = new()
        {
            SignedDataVersion = signedData.ReadIntegerInt32()
        };

        var digestAlgorithms = signedData.ReadConstructed(0x31);
        ReadAlgorithmIdentifier(
            digestAlgorithms,
            out var outerDigestAlgorithmOid,
            out var outerDigestAlgorithmHasParameters);
        digestAlgorithms.ThrowIfNotEmpty();
        result.OuterDigestAlgorithmOid = outerDigestAlgorithmOid;
        result.OuterDigestAlgorithmHasParameters = outerDigestAlgorithmHasParameters;

        var encapsulatedContent = signedData.ReadSequence();
        AssertEx.Equal(TstInfoContentTypeOid, encapsulatedContent.ReadObjectIdentifier());
        var explicitEncapsulatedContent = encapsulatedContent.ReadConstructed(0xa0);
        AssertEx.True(explicitEncapsulatedContent.ReadOctetString().Length > 0);
        explicitEncapsulatedContent.ThrowIfNotEmpty();
        encapsulatedContent.ThrowIfNotEmpty();
        while (signedData.HasData && (signedData.PeekTag() == 0xa0 || signedData.PeekTag() == 0xa1))
        {
            signedData.ReadEncodedValue();
        }

        var signerInfos = signedData.ReadConstructed(0x31);
        signedData.ThrowIfNotEmpty();
        var signerInfo = signerInfos.ReadSequence();
        signerInfos.ThrowIfNotEmpty();
        signerInfo.ReadIntegerInt32();
        signerInfo.ReadEncodedValue();
        ReadAlgorithmIdentifier(
            signerInfo,
            out var digestAlgorithmOid,
            out var digestAlgorithmHasParameters);
        result.DigestAlgorithmOid = digestAlgorithmOid;
        result.DigestAlgorithmHasParameters = digestAlgorithmHasParameters;

        var signedAttributes = signerInfo.ReadConstructed(0xa0);
        while (signedAttributes.HasData)
        {
            var attribute = signedAttributes.ReadSequence();
            var attributeOid = attribute.ReadObjectIdentifier();
            var values = attribute.ReadConstructed(0x31);
            if (string.Equals(attributeOid, CmsAlgorithmProtectionOid, StringComparison.Ordinal))
            {
                result.CmsAlgorithmProtectionCount++;
                var protection = values.ReadSequence();
                values.ThrowIfNotEmpty();
                ReadAlgorithmIdentifier(
                    protection,
                    out var protectedDigestAlgorithmOid,
                    out var protectedDigestAlgorithmHasParameters);
                result.ProtectedDigestAlgorithmOid = protectedDigestAlgorithmOid;
                result.ProtectedDigestAlgorithmHasParameters = protectedDigestAlgorithmHasParameters;

                var protectedSignatureAlgorithm = protection.ReadConstructed(0xa1);
                result.ProtectedSignatureAlgorithmOid = protectedSignatureAlgorithm.ReadObjectIdentifier();
                result.ProtectedSignatureAlgorithmHasParameters = protectedSignatureAlgorithm.HasData;
                if (protectedSignatureAlgorithm.HasData) protectedSignatureAlgorithm.ReadEncodedValue();
                protectedSignatureAlgorithm.ThrowIfNotEmpty();
                protection.ThrowIfNotEmpty();
            }
            else
            {
                while (values.HasData) values.ReadEncodedValue();
            }

            attribute.ThrowIfNotEmpty();
        }

        ReadAlgorithmIdentifier(
            signerInfo,
            out var signatureAlgorithmOid,
            out var signatureAlgorithmHasParameters);
        result.SignatureAlgorithmOid = signatureAlgorithmOid;
        result.SignatureAlgorithmHasParameters = signatureAlgorithmHasParameters;
        var signature = signerInfo.ReadOctetString();
        AssertEx.True(signature.Length > 0, "SignerInfo must contain an ML-DSA signature value.");
        if (signerInfo.HasData && signerInfo.PeekTag() == 0xa1) signerInfo.ReadEncodedValue();
        signerInfo.ThrowIfNotEmpty();
        return result;
    }

    private static void ReadAlgorithmIdentifier(
        DerReader parent,
        out string algorithmOid,
        out bool hasParameters)
    {
        var algorithmIdentifier = parent.ReadSequence();
        algorithmOid = algorithmIdentifier.ReadObjectIdentifier();
        hasParameters = algorithmIdentifier.HasData;
        if (hasParameters) algorithmIdentifier.ReadEncodedValue();
        algorithmIdentifier.ThrowIfNotEmpty();
    }

    private sealed class MldsaSignerInfo
    {
        public int SignedDataVersion { get; set; }

        public string OuterDigestAlgorithmOid { get; set; }

        public bool OuterDigestAlgorithmHasParameters { get; set; }

        public string DigestAlgorithmOid { get; set; }

        public bool DigestAlgorithmHasParameters { get; set; }

        public string SignatureAlgorithmOid { get; set; }

        public bool SignatureAlgorithmHasParameters { get; set; }

        public int CmsAlgorithmProtectionCount { get; set; }

        public string ProtectedDigestAlgorithmOid { get; set; }

        public bool ProtectedDigestAlgorithmHasParameters { get; set; }

        public string ProtectedSignatureAlgorithmOid { get; set; }

        public bool ProtectedSignatureAlgorithmHasParameters { get; set; }
    }
}

internal sealed class MldsaTimestampCertificateFixture : IDisposable
{
    private const string Password = "OpenTimeStamp-Test-Only";
    private const string ResourceName = "OpenTimeStamp.Tests.MlDsa65TimestampCertificate.pfx.b64";

    public MldsaTimestampCertificateFixture()
    {
        using var resource = typeof(MldsaTimestampCertificateFixture).Assembly.GetManifestResourceStream(ResourceName);
        AssertEx.NotNull(resource, "The embedded ML-DSA regression certificate resource was not found.");
        using var reader = new StreamReader(resource);
        var pfx = Convert.FromBase64String(reader.ReadToEnd());
        Certificate = X509CertificateLoader.LoadPkcs12(
            pfx,
            Password,
            X509KeyStorageFlags.EphemeralKeySet,
            Pkcs12LoaderLimits.Defaults);
        AssertEx.True(
            Certificate.HasPrivateKey,
            "The embedded ML-DSA regression certificate must retain its test-only private key.");
        AssertEx.Equal(MlDsa65Oid, Certificate.PublicKey.Oid.Value);
    }

    public X509Certificate2 Certificate { get; }

    public void Dispose() => Certificate.Dispose();

    private const string MlDsa65Oid = "2.16.840.1.101.3.4.3.18";
}
