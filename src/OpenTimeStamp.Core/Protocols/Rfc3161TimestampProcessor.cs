using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Threading;
using OpenTimeStamp.Asn1;
using OpenTimeStamp.Configuration;
using OpenTimeStamp.Cryptography;
using OpenTimeStamp.Issuance;

namespace OpenTimeStamp.Protocols;

public sealed class Rfc3161TimestampProcessor
{
    public const string TstInfoContentTypeOid = KnownOids.TstInfoContentType;

    public bool TryPreflight(
        Rfc3161Request request,
        ServiceConfiguration configuration,
        out Rfc3161Result rejection)
    {
        try
        {
            ValidateRequestPolicy(request, configuration, out _, out _);
            rejection = null;
            return true;
        }
        catch (Rfc3161ProtocolException ex)
        {
            rejection = Rejection(ex.FailureInfo, ex.Message, request);
            return false;
        }
        catch (InvalidOperationException ex)
        {
            rejection = Rejection(Rfc3161FailureInfo.SystemFailure, ex.Message, request);
            return false;
        }
    }

    public Rfc3161Result Process(
        byte[] encodedRequest,
        ServiceConfiguration configuration,
        X509Certificate2 certificate,
        IssuanceStateStore stateStore,
        DateTime utcNow) =>
        Process(encodedRequest, configuration, certificate, stateStore, utcNow, CancellationToken.None);

    public Rfc3161Result Process(
        byte[] encodedRequest,
        ServiceConfiguration configuration,
        X509Certificate2 certificate,
        IssuanceStateStore stateStore,
        DateTime utcNow,
        CancellationToken cancellationToken)
    {
        try
        {
            return Process(
                Rfc3161Request.Parse(encodedRequest),
                configuration,
                certificate,
                stateStore,
                utcNow,
                cancellationToken);
        }
        catch (Rfc3161ProtocolException ex)
        {
            return Rejection(ex.FailureInfo, ex.Message, null);
        }
    }

    public Rfc3161Result Process(
        Rfc3161Request request,
        ServiceConfiguration configuration,
        X509Certificate2 certificate,
        IssuanceStateStore stateStore,
        DateTime utcNow) =>
        Process(request, configuration, certificate, stateStore, utcNow, CancellationToken.None);

    public Rfc3161Result Process(
        Rfc3161Request request,
        ServiceConfiguration configuration,
        X509Certificate2 certificate,
        IssuanceStateStore stateStore,
        DateTime utcNow,
        CancellationToken cancellationToken) =>
        Process(request, configuration, certificate, stateStore, () => utcNow, cancellationToken);

    public Rfc3161Result Process(
        Rfc3161Request request,
        ServiceConfiguration configuration,
        X509Certificate2 certificate,
        IssuanceStateStore stateStore,
        Func<DateTime> utcNowProvider,
        CancellationToken cancellationToken)
    {
        if (utcNowProvider is null) throw new ArgumentNullException(nameof(utcNowProvider));
        try
        {
            ValidateRequestPolicy(request, configuration, out var policy, out var signingHash);

            if (certificate is null)
            {
                throw new InvalidOperationException("No usable timestamp signing certificate is configured.");
            }

            if (!CertificateRepository.ValidateCertificateProfile(
                    certificate,
                    signingHash.Name,
                    utcNowProvider(),
                    false,
                    out var keyReason))
            {
                throw new InvalidOperationException(keyReason);
            }

            if (stateStore is null)
            {
                throw new InvalidOperationException("Timestamp state is unavailable.");
            }

            // Allocate durable serial/time state before constructing and signing TSTInfo.
            cancellationToken.ThrowIfCancellationRequested();
            var allocation = stateStore.Allocate(
                utcNowProvider,
                TimeSpan.FromSeconds(configuration.ClockRollbackToleranceSeconds),
                configuration.Ordering,
                cancellationToken);
            var tstInfo = BuildTstInfo(request, policy, allocation, configuration);
            var includeOption = request.CertificateRequested
                ? configuration.IncludeCertificateChain ? X509IncludeOption.ExcludeRoot : X509IncludeOption.EndCertOnly
                : X509IncludeOption.None;
            var token = TimestampCmsSigner.Sign(
                tstInfo,
                TstInfoContentTypeOid,
                certificate,
                signingHash,
                includeOption,
                allocation.GenerationTimeUtc);
            return new Rfc3161Result
            {
                EncodedResponse = BuildResponse(token),
                Granted = true,
                Detail = "granted",
                PolicyOid = policy,
                HashAlgorithmOid = request.HashAlgorithmOid,
                MessageImprint = request.MessageImprint,
                SerialNumber = allocation.SerialNumber,
                GenerationTimeUtc = allocation.GenerationTimeUtc,
                CertificateThumbprint = ConfigurationStore.NormalizeThumbprint(certificate.Thumbprint)
            };
        }
        catch (Rfc3161ProtocolException ex)
        {
            return Rejection(ex.FailureInfo, ex.Message, request);
        }
        catch (ClockRollbackException ex)
        {
            return Rejection(Rfc3161FailureInfo.TimeNotAvailable, ex.Message, request);
        }
        catch (Exception ex) when (ex is CryptographicException or InvalidOperationException or IssuanceStateException)
        {
            return Rejection(Rfc3161FailureInfo.SystemFailure, ex.Message, request);
        }
    }

    private static void ValidateRequestPolicy(
        Rfc3161Request request,
        ServiceConfiguration configuration,
        out string policy,
        out TimestampHashAlgorithm signingHash)
    {
        if (request is null)
        {
            throw new Rfc3161ProtocolException(
                Rfc3161FailureInfo.BadDataFormat,
                "The timestamp request is empty.");
        }

        if (configuration is null)
        {
            throw new InvalidOperationException("The timestamp service settings are unavailable.");
        }

        // Enforce digest length, configured allow-list, and the effective Windows security policy.
        var requestHash = HashAlgorithmCatalog.FindByOid(request.HashAlgorithmOid);
        if (requestHash is null || request.MessageImprint.Length != requestHash.DigestLength ||
            !IsConfiguredHash(configuration.AllowedHashAlgorithms, requestHash.Name) ||
            !PlatformSecurityPolicy.IsRequestHashAllowed(requestHash))
        {
            throw new Rfc3161ProtocolException(
                Rfc3161FailureInfo.BadAlgorithm,
                "The request hash algorithm is not allowed by the timestamp service.");
        }

        policy = SelectPolicy(configuration, request.RequestedPolicyOid);
        signingHash = HashAlgorithmCatalog.FindByName(configuration.SigningDigestAlgorithm);
        if (!PlatformSecurityPolicy.IsSigningHashAllowed(signingHash))
        {
            throw new InvalidOperationException(
                "The configured timestamp signing hash is not allowed by the current Windows security policy.");
        }
    }

    private static string SelectPolicy(ServiceConfiguration configuration, string requestedPolicy)
    {
        var defaultPolicy = (configuration.DefaultPolicyOid ?? string.Empty).Trim();
        if (string.IsNullOrEmpty(defaultPolicy))
        {
            throw new InvalidOperationException("No default RFC 3161 policy OID is configured.");
        }

        if (string.IsNullOrEmpty(requestedPolicy)) return defaultPolicy;

        var accepted = configuration.AcceptedPolicyOids ?? [];
        if (!accepted.Contains(requestedPolicy, StringComparer.Ordinal))
        {
            throw new Rfc3161ProtocolException(
                Rfc3161FailureInfo.UnacceptedPolicy,
                "The requested RFC 3161 policy OID is not allowed by the timestamp service.");
        }

        return requestedPolicy;
    }

    private static bool IsConfiguredHash(IEnumerable<string> configured, string name) =>
        configured is not null && configured.Any(item =>
            string.Equals(HashAlgorithmCatalog.NormalizeName(item), name, StringComparison.Ordinal));

    private static byte[] BuildTstInfo(
        Rfc3161Request request,
        string policy,
        IssuanceAllocation allocation,
        ServiceConfiguration configuration)
    {
        // Emit mandatory TSTInfo fields followed by optional accuracy, ordering, and nonce fields.
        DerWriter writer = new();
        writer.WriteSequence(tstInfo =>
        {
            tstInfo.WriteInteger(1);
            tstInfo.WriteObjectIdentifier(policy);
            tstInfo.WriteSequence(imprint =>
            {
                imprint.WriteEncodedValue(request.AlgorithmIdentifier);
                imprint.WriteOctetString(request.MessageImprint);
            });
            tstInfo.WritePositiveInteger(allocation.SerialNumber);
            tstInfo.WriteGeneralizedTime(allocation.GenerationTimeUtc);
            if (configuration.AccuracySeconds > 0 || configuration.AccuracyMilliseconds > 0)
            {
                tstInfo.WriteSequence(accuracy =>
                {
                    if (configuration.AccuracySeconds > 0) accuracy.WriteInteger(configuration.AccuracySeconds);
                    if (configuration.AccuracyMilliseconds > 0)
                    {
                        accuracy.WriteContextSpecificInteger(0, configuration.AccuracyMilliseconds);
                    }
                });
            }

            if (configuration.Ordering) tstInfo.WriteBoolean(true);
            if (request.Nonce is not null) tstInfo.WritePositiveInteger(request.Nonce);
        });
        return writer.Encode();
    }

    private static byte[] BuildResponse(byte[] token)
    {
        // Wrap the signed token in a granted TimeStampResp status envelope.
        DerWriter writer = new();
        writer.WriteSequence(response =>
        {
            response.WriteSequence(status => status.WriteInteger(0));
            response.WriteEncodedValue(token);
        });
        return writer.Encode();
    }

    private static Rfc3161Result Rejection(Rfc3161FailureInfo failure, string detail, Rfc3161Request request)
    {
        // Return a standards-shaped rejection while retaining private detail for server auditing.
        DerWriter writer = new();
        writer.WriteSequence(response => response.WriteSequence(status =>
        {
            status.WriteInteger(2);
            status.WriteSequence(text => text.WriteUtf8String(PublicStatus(failure)));
            status.WriteBitString((int)failure);
        }));
        return new Rfc3161Result
        {
            EncodedResponse = writer.Encode(),
            Granted = false,
            FailureInfo = failure,
            Detail = detail,
            PolicyOid = request?.RequestedPolicyOid,
            HashAlgorithmOid = request?.HashAlgorithmOid,
            MessageImprint = request?.MessageImprint
        };
    }

    private static string PublicStatus(Rfc3161FailureInfo failure) => failure switch
    {
        Rfc3161FailureInfo.BadAlgorithm => "Request hash algorithm is not allowed.",
        Rfc3161FailureInfo.BadRequest => "Timestamp request is not accepted.",
        Rfc3161FailureInfo.BadDataFormat => "Timestamp request is malformed.",
        Rfc3161FailureInfo.TimeNotAvailable => "A trustworthy time is not available.",
        Rfc3161FailureInfo.UnacceptedPolicy => "Requested RFC 3161 policy OID is not allowed.",
        Rfc3161FailureInfo.UnacceptedExtension => "Request extension is not accepted.",
        _ => "Timestamp authority is temporarily unavailable."
    };
}
