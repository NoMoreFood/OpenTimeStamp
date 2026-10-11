using System;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Threading;
using OpenTimeStamp.Asn1;
using OpenTimeStamp.Configuration;
using OpenTimeStamp.Cryptography;
using OpenTimeStamp.Issuance;

namespace OpenTimeStamp.Protocols;

public sealed class AuthenticodeResult
{
    internal AuthenticodeResult(byte[] encodedResponse, byte[] requestedSignature, byte[] auditSerialNumber)
    {
        EncodedResponse = encodedResponse;
        RequestedSignature = requestedSignature;
        AuditSerialNumber = auditSerialNumber;
    }

    public byte[] EncodedResponse { get; }

    public byte[] RequestedSignature { get; }

    public byte[] AuditSerialNumber { get; }

    public DateTime GenerationTimeUtc { get; internal set; }

    public string? CertificateThumbprint { get; internal set; }
}

public static class AuthenticodeTimestampProcessor
{
    private const int MaximumSignatureLength = 1048576;

    public const string CounterSignatureTypeOid = KnownOids.AuthenticodeCounterSignature;
    public const string DataContentTypeOid = KnownOids.Pkcs7Data;

    /// <summary>Countersigns a signature already extracted by <see cref="ParseRequest"/>.</summary>
    public static AuthenticodeResult ProcessParsedSignature(
        byte[] signature,
        ServiceConfiguration configuration,
        X509Certificate2? certificate,
        IssuanceStateStore? stateStore,
        Func<DateTime> utcNowProvider,
        CancellationToken cancellationToken)
    {
        if (utcNowProvider is null) throw new ArgumentNullException(nameof(utcNowProvider));
        ValidateInvocation(configuration);
        if (signature is null || signature.Length is 0 or > MaximumSignatureLength)
        {
            throw new AuthenticodeProtocolException(
                "The parsed Authenticode signature must contain between 1 byte and 1 MiB.");
        }

        var signingHash = HashAlgorithmCatalog.FindByName(configuration.SigningDigestAlgorithm);
        if (!PlatformSecurityPolicy.IsSigningHashAllowed(signingHash))
        {
            throw new CryptographicException(
                "The selected timestamp signing hash is not allowed by the current Windows security policy.");
        }

        if (certificate is null)
        {
            throw new CryptographicException("No usable timestamp signing certificate is configured.");
        }

        if (!CertificateRepository.ValidateCertificateProfile(
                certificate,
                signingHash.Name,
                utcNowProvider(),
                true,
                out var keyReason))
        {
            throw new CryptographicException(keyReason);
        }

        if (stateStore is null)
        {
            throw new CryptographicException("Timestamp state is unavailable.");
        }

        // Allocate audit state before producing the legacy CMS countersignature response.
        cancellationToken.ThrowIfCancellationRequested();
        var allocation = stateStore.Allocate(
            utcNowProvider,
            TimeSpan.FromSeconds(configuration.ClockRollbackToleranceSeconds),
            false,
            cancellationToken);
        var includeOption = configuration.IncludeCertificateChain
            ? X509IncludeOption.ExcludeRoot
            : X509IncludeOption.EndCertOnly;
        var response = TimestampCmsSigner.Sign(
            signature,
            KnownOids.Pkcs7Data,
            certificate,
            signingHash,
            includeOption,
            allocation.GenerationTimeUtc);
        return new AuthenticodeResult(response, signature, allocation.SerialNumber)
        {
            GenerationTimeUtc = allocation.GenerationTimeUtc,
            CertificateThumbprint = ConfigurationStore.NormalizeThumbprint(certificate.Thumbprint)
        };
    }

    private static void ValidateInvocation(ServiceConfiguration configuration)
    {
        if (configuration is null) throw new ArgumentNullException(nameof(configuration));

        // Gate the entire legacy protocol before parsing or allocating durable state.
        if (!PlatformSecurityPolicy.IsLegacyAuthenticodeAllowed)
        {
            throw new AuthenticodeProtocolException(
                "Legacy Authenticode timestamping is disabled while Windows FIPS mode is enabled.");
        }
    }

    public static byte[] ParseRequest(byte[] encodedRequest)
    {
        if (encodedRequest is null || encodedRequest.Length == 0)
        {
            throw new AuthenticodeProtocolException("The Authenticode timestamp request is empty.");
        }

        try
        {
            // Validate the outer Microsoft countersignature request envelope.
            DerReader outer = new(encodedRequest);
            var request = outer.ReadSequence();
            outer.ThrowIfNotEmpty();
            var counterSignatureType = request.ReadObjectIdentifier();
            if (!string.Equals(counterSignatureType, CounterSignatureTypeOid, StringComparison.Ordinal))
            {
                throw new AuthenticodeProtocolException("The countersignature type is not supported.");
            }

            if (request.HasData && request.PeekTag() == 0x31)
            {
                throw new AuthenticodeProtocolException("Authenticode request attributes are not supported.");
            }

            // Extract the signature bytes from the required PKCS #7 Data ContentInfo.
            var contentInfo = request.ReadSequence();
            request.ThrowIfNotEmpty();
            var contentType = contentInfo.ReadObjectIdentifier();
            if (!string.Equals(contentType, KnownOids.Pkcs7Data, StringComparison.Ordinal))
            {
                throw new AuthenticodeProtocolException("The Authenticode request content type must be PKCS #7 Data.");
            }

            var explicitContent = contentInfo.ReadConstructed(0xa0);
            var signature = explicitContent.ReadOctetString(MaximumSignatureLength);
            explicitContent.ThrowIfNotEmpty();
            contentInfo.ThrowIfNotEmpty();
            if (signature.Length == 0)
            {
                throw new AuthenticodeProtocolException("The Authenticode request signature is empty.");
            }

            return signature;
        }
        catch (Exception ex) when (ex is DerEncodingException or ArgumentException or OverflowException)
        {
            throw new AuthenticodeProtocolException("The Authenticode timestamp request is malformed.", ex);
        }
    }
}

public sealed class AuthenticodeProtocolException(string message, Exception? innerException = null)
    : Exception(message, innerException);
