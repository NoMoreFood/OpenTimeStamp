using System;
using OpenTimeStamp.Asn1;

namespace OpenTimeStamp.Protocols;

public enum Rfc3161FailureInfo
{
    BadAlgorithm = 0,
    BadRequest = 2,
    BadDataFormat = 5,
    TimeNotAvailable = 14,
    UnacceptedPolicy = 15,
    UnacceptedExtension = 16,
    AddInfoNotAvailable = 17,
    SystemFailure = 25
}

public sealed class Rfc3161Request
{
    private const int MaximumAlgorithmIdentifierLength = 272;
    private const int MaximumMessageImprintLength = 64;
    private const int MaximumNonceLength = 32;

    private Rfc3161Request()
    {
    }

    public byte[] AlgorithmIdentifier { get; private set; }

    public string HashAlgorithmOid { get; private set; }

    public byte[] MessageImprint { get; private set; }

    public string RequestedPolicyOid { get; private set; }

    public byte[] Nonce { get; private set; }

    public bool CertificateRequested { get; private set; }

    public static Rfc3161Request Parse(byte[] encoded)
    {
        if (encoded is null || encoded.Length == 0)
        {
            throw new Rfc3161ProtocolException(Rfc3161FailureInfo.BadDataFormat, "The timestamp request is empty.");
        }

        try
        {
            // Validate the outer TimeStampReq envelope and mandatory version.
            DerReader outer = new(encoded);
            var request = outer.ReadSequence();
            outer.ThrowIfNotEmpty();

            var version = request.ReadIntegerInt32();
            if (version != 1)
            {
                throw new Rfc3161ProtocolException(Rfc3161FailureInfo.BadRequest, "Only TimeStampReq version 1 is supported.");
            }

            // Preserve the request AlgorithmIdentifier byte-for-byte after validating its structure.
            var imprint = request.ReadSequence();
            var algorithmIdentifier = imprint.ReadEncodedValue(MaximumAlgorithmIdentifierLength);
            DerReader algorithmOuter = new(algorithmIdentifier);
            var algorithm = algorithmOuter.ReadSequence();
            algorithmOuter.ThrowIfNotEmpty();
            var hashOid = algorithm.ReadObjectIdentifier();
            if (algorithm.HasData)
            {
                if (algorithm.PeekTag() != 0x05)
                {
                    throw new DerEncodingException("Digest AlgorithmIdentifier parameters must be absent or NULL.");
                }

                algorithm.ReadNull();
            }

            algorithm.ThrowIfNotEmpty();
            var digest = imprint.ReadOctetString(MaximumMessageImprintLength);
            imprint.ThrowIfNotEmpty();

            // Read the optional policy, nonce, certificate flag, and unsupported extensions in order.
            string requestedPolicy = null;
            byte[] nonce = null;
            var certificateRequested = false;
            if (request.HasData && request.PeekTag() == 0x06) requestedPolicy = request.ReadObjectIdentifier();

            if (request.HasData && request.PeekTag() == 0x02)
            {
                try
                {
                    nonce = request.ReadPositiveInteger(MaximumNonceLength);
                }
                catch (DerSizeLimitException ex)
                {
                    throw new Rfc3161ProtocolException(
                        Rfc3161FailureInfo.BadRequest,
                        "The request nonce exceeds 256 bits.",
                        ex);
                }
            }

            if (request.HasData && request.PeekTag() == 0x01)
            {
                certificateRequested = request.ReadBoolean();
                if (!certificateRequested)
                {
                    throw new DerEncodingException("The default FALSE certReq value must be omitted in DER.");
                }
            }

            if (request.HasData && request.PeekTag() == 0xa0)
            {
                throw new Rfc3161ProtocolException(Rfc3161FailureInfo.UnacceptedExtension, "Request extensions are not supported.");
            }

            request.ThrowIfNotEmpty();
            return new Rfc3161Request
            {
                AlgorithmIdentifier = algorithmIdentifier,
                HashAlgorithmOid = hashOid,
                MessageImprint = digest,
                RequestedPolicyOid = requestedPolicy,
                Nonce = nonce,
                CertificateRequested = certificateRequested
            };
        }
        catch (Rfc3161ProtocolException)
        {
            throw;
        }
        catch (Exception ex) when (ex is DerEncodingException or ArgumentException or OverflowException)
        {
            throw new Rfc3161ProtocolException(Rfc3161FailureInfo.BadDataFormat, "The timestamp request is not valid DER.", ex);
        }
    }
}

public sealed class Rfc3161Result
{
    internal Rfc3161Result()
    {
    }

    public byte[] EncodedResponse { get; internal set; }

    public bool Granted { get; internal set; }

    public Rfc3161FailureInfo? FailureInfo { get; internal set; }

    public string Detail { get; internal set; }

    public string PolicyOid { get; internal set; }

    public string HashAlgorithmOid { get; internal set; }

    public byte[] MessageImprint { get; internal set; }

    public byte[] SerialNumber { get; internal set; }

    public DateTime GenerationTimeUtc { get; internal set; }

    public string CertificateThumbprint { get; internal set; }
}

public sealed class Rfc3161ProtocolException : Exception
{
    public Rfc3161ProtocolException(Rfc3161FailureInfo failureInfo, string message)
        : base(message)
    {
        FailureInfo = failureInfo;
    }

    public Rfc3161ProtocolException(Rfc3161FailureInfo failureInfo, string message, Exception innerException)
        : base(message, innerException)
    {
        FailureInfo = failureInfo;
    }

    public Rfc3161FailureInfo FailureInfo { get; }
}
