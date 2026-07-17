using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.X509Certificates;
using OpenTimeStamp.Asn1;
using OpenTimeStamp.Configuration;
using OpenTimeStamp.Issuance;
using OpenTimeStamp.Protocols;

namespace OpenTimeStamp.Tests;

internal static class TestFixtures
{
    public const string DefaultPolicyOid = "1.3.6.1.4.1.55555.1";
    public const string AlternatePolicyOid = "1.3.6.1.4.1.55555.2";
    public const string Sha256Oid = "2.16.840.1.101.3.4.2.1";
    public const string Sha384Oid = "2.16.840.1.101.3.4.2.2";

    public static IssuanceStateStore CreateInitializedStateStore(string path)
    {
        var store = new IssuanceStateStore(path);
        store.Initialize();
        return store;
    }

    public static ServiceConfiguration CreateConfiguration() =>
        new()
        {
            DefaultPolicyOid = DefaultPolicyOid,
            AcceptedPolicyOids = [DefaultPolicyOid, AlternatePolicyOid],
            AllowedHashAlgorithms = ["SHA256", "SHA384", "SHA512"],
            SigningDigestAlgorithm = "SHA256",
            IncludeCertificateChain = false,
            AccuracySeconds = 0,
            AccuracyMilliseconds = 0,
            Ordering = false,
            ClockRollbackToleranceSeconds = 2
        };

    // Build canonical client requests without relying on production parsers.
    public static byte[] BuildRfc3161Request(
        string hashOid,
        byte[] digest,
        string policyOid = null,
        byte[] nonce = null,
        bool certificateRequested = false,
        int version = 1,
        bool includeNullParameters = true,
        bool includeExtensions = false,
        bool explicitFalseCertificateRequest = false)
    {
        var writer = new DerWriter();
        writer.WriteSequence(request =>
        {
            request.WriteInteger(version);
            request.WriteSequence(imprint =>
            {
                imprint.WriteSequence(algorithm =>
                {
                    algorithm.WriteObjectIdentifier(hashOid);
                    if (includeNullParameters)
                    {
                        algorithm.WriteNull();
                    }
                });
                imprint.WriteOctetString(digest);
            });

            if (!string.IsNullOrEmpty(policyOid))
            {
                request.WriteObjectIdentifier(policyOid);
            }

            if (nonce != null)
            {
                request.WritePositiveInteger(nonce);
            }

            if (certificateRequested)
            {
                request.WriteBoolean(true);
            }
            else if (explicitFalseCertificateRequest)
            {
                request.WriteBoolean(false);
            }

            if (includeExtensions)
            {
                request.WriteContextSpecificConstructed(0, extensions => extensions.WriteSequence(extension =>
                {
                    extension.WriteObjectIdentifier("1.3.6.1.5.5.7.1.1");
                    extension.WriteOctetString(new byte[] { 0x05, 0x00 });
                }));
            }
        });
        return writer.Encode();
    }

    public static byte[] BuildRfc3161RequestWithAlgorithmParameters(byte[] encodedParameters)
    {
        var writer = new DerWriter();
        writer.WriteSequence(request =>
        {
            request.WriteInteger(1);
            request.WriteSequence(imprint =>
            {
                imprint.WriteSequence(algorithm =>
                {
                    algorithm.WriteObjectIdentifier(Sha256Oid);
                    algorithm.WriteEncodedValue(encodedParameters);
                });
                imprint.WriteOctetString(new byte[32]);
            });
        });
        return writer.Encode();
    }

    public static byte[] BuildAuthenticodeRequest(
        byte[] signature,
        string counterSignatureOid = AuthenticodeTimestampProcessor.CounterSignatureTypeOid,
        string contentTypeOid = AuthenticodeTimestampProcessor.DataContentTypeOid,
        bool includeAttributes = false)
    {
        var writer = new DerWriter();
        writer.WriteSequence(request =>
        {
            request.WriteObjectIdentifier(counterSignatureOid);
            if (includeAttributes)
            {
                request.WriteSet(attributes => attributes.WriteSequence(attribute =>
                {
                    attribute.WriteObjectIdentifier("1.2.840.113549.1.9.3");
                    attribute.WriteSet(values => values.WriteObjectIdentifier(contentTypeOid));
                }));
            }

            request.WriteSequence(contentInfo =>
            {
                contentInfo.WriteObjectIdentifier(contentTypeOid);
                contentInfo.WriteContextSpecificConstructed(0, content => content.WriteOctetString(signature));
            });
        });
        return writer.Encode();
    }

    public static byte[] ExtractGrantedRfc3161Token(byte[] encodedResponse)
    {
        var outer = new DerReader(encodedResponse);
        var response = outer.ReadSequence();
        outer.ThrowIfNotEmpty();
        var status = response.ReadSequence();
        AssertEx.Equal(0, status.ReadIntegerInt32(), "Expected a granted PKIStatusInfo value.");
        status.ThrowIfNotEmpty();
        var token = response.ReadEncodedValue();
        response.ThrowIfNotEmpty();
        return token;
    }

    public static int ExtractRfc3161Status(byte[] encodedResponse)
    {
        var outer = new DerReader(encodedResponse);
        var response = outer.ReadSequence();
        outer.ThrowIfNotEmpty();
        var status = response.ReadSequence();
        return status.ReadIntegerInt32();
    }

    public static int ExtractRfc3161FailureBit(byte[] encodedResponse)
    {
        var outer = new DerReader(encodedResponse);
        var response = outer.ReadSequence();
        outer.ThrowIfNotEmpty();
        var status = response.ReadSequence();
        AssertEx.Equal(2, status.ReadIntegerInt32());
        var statusText = status.ReadSequence();
        var encodedText = statusText.ReadEncodedValue();
        AssertEx.Equal((byte)0x0c, encodedText[0], "PKIFreeText must contain a UTF8String.");
        statusText.ThrowIfNotEmpty();
        var encodedBits = status.ReadEncodedValue();
        status.ThrowIfNotEmpty();
        response.ThrowIfNotEmpty();
        AssertEx.True(encodedBits.Length >= 4 && encodedBits[0] == 0x03 && encodedBits[1] == encodedBits.Length - 2,
            "PKIFailureInfo must be a short-form DER BIT STRING.");
        var unusedBits = encodedBits[2];
        AssertEx.True(unusedBits <= 7);
        var found = -1;
        var availableBits = ((encodedBits.Length - 3) * 8) - unusedBits;
        for (var bit = 0; bit < availableBits; bit++)
        {
            if ((encodedBits[3 + (bit / 8)] & (0x80 >> (bit % 8))) != 0)
            {
                AssertEx.Equal(-1, found, "PKIFailureInfo must contain exactly one failure bit.");
                found = bit;
            }
        }

        AssertEx.True(found >= 0, "PKIFailureInfo did not contain a failure bit.");
        return found;
    }

    public static SignedCms DecodeCms(byte[] encodedCms)
    {
        var cms = new SignedCms();
        cms.Decode(encodedCms);
        return cms;
    }

    public static byte[] Incremented(byte[] value)
    {
        var result = (byte[])value.Clone();
        for (var index = result.Length - 1; index >= 0; index--)
        {
            result[index]++;
            if (result[index] != 0) return result;
        }

        throw new InvalidOperationException("Test serial overflowed unexpectedly.");
    }

    public static string Hex(byte[] value) => BitConverter.ToString(value).Replace("-", string.Empty);
}

internal sealed class TemporaryDirectory : IDisposable
{
    public TemporaryDirectory()
    {
        Path = System.IO.Path.Combine(System.IO.Path.GetTempPath(), "OpenTimeStamp.Tests", Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(Path);
    }

    public string Path { get; }

    public string File(string name) => System.IO.Path.Combine(Path, name);

    public void Dispose()
    {
        try
        {
            if (Directory.Exists(Path)) Directory.Delete(Path, true);
        }
        catch (IOException)
        {
        }
        catch (UnauthorizedAccessException)
        {
        }
    }
}

internal sealed class TimestampCertificateFixture : IDisposable
{
    private readonly RSA key;

    public TimestampCertificateFixture(int keySize = 2048)
    {
        key = new RSACng(keySize);
        var request = new CertificateRequest(
            "CN=OpenTimeStamp Regression TSA",
            key,
            HashAlgorithmName.SHA256,
            RSASignaturePadding.Pkcs1);
        request.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, true));
        request.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature, true));
        var usages = new OidCollection { new Oid("1.3.6.1.5.5.7.3.8", "Time Stamping") };
        request.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(usages, true));
        request.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(request.PublicKey, false));
        Certificate = request.CreateSelfSigned(
            new DateTimeOffset(2020, 1, 1, 0, 0, 0, TimeSpan.Zero),
            new DateTimeOffset(2100, 1, 1, 0, 0, 0, TimeSpan.Zero));
        AssertEx.True(Certificate.HasPrivateKey, "The ephemeral timestamp certificate must retain its private key.");
    }

    public X509Certificate2 Certificate { get; }

    public void Dispose()
    {
        Certificate.Dispose();
        key.Dispose();
    }
}
