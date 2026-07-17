using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Text;
using OpenTimeStamp.Asn1;
using OpenTimeStamp.Cryptography;
using OpenTimeStamp.Protocols;

namespace OpenTimeStamp.Tests;

internal static class Asn1AndRequestTests
{
    public static void Register(ICollection<TestCase> tests)
    {
        // Cover canonical DER, RFC 3161 parsing, and legacy HTTP framing independently.
        tests.Add(new TestCase("DER writer/reader canonical round-trip", CanonicalDerRoundTrip));
        tests.Add(new TestCase("DER writer canonicalizes SET values and OID text", CanonicalSetAndOidText));
        tests.Add(new TestCase("DER reader rejects non-canonical encodings", RejectsNonCanonicalDer));
        tests.Add(new TestCase("DER reader rejects bounded values before copying", RejectsBoundedValues));
        tests.Add(new TestCase("DER reader bounds untrusted OBJECT IDENTIFIER work", BoundsObjectIdentifierWork));
        tests.Add(new TestCase("Windows OID resolution preserves standards values", OidResolutionPreservesStandards));
        tests.Add(new TestCase("RFC3161 request parses all optional fields", ParsesRfc3161Request));
        tests.Add(new TestCase("RFC3161 request rejects invalid version and nonce", RejectsInvalidVersionAndNonce));
        tests.Add(new TestCase("RFC3161 request rejects extensions and malformed DER", RejectsExtensionsAndMalformedDer));
        tests.Add(new TestCase("RFC3161 request rejects invalid algorithm parameters", RejectsInvalidAlgorithmParameters));
        tests.Add(new TestCase("Authenticode request parsing and rejection", ParsesAndRejectsAuthenticodeRequests));
        tests.Add(new TestCase("SignTool legacy HTTP base64 framing", SignToolHttpFraming));
    }

    private static void OidResolutionPreservesStandards()
    {
        // Verify built-in Windows lookups and centralized fallbacks cannot change wire identifiers.
        Dictionary<string, string> expectedHashes = new(StringComparer.Ordinal)
        {
            ["MD5"] = "1.2.840.113549.2.5",
            ["SHA1"] = "1.3.14.3.2.26",
            ["SHA224"] = "2.16.840.1.101.3.4.2.4",
            ["SHA256"] = "2.16.840.1.101.3.4.2.1",
            ["SHA384"] = "2.16.840.1.101.3.4.2.2",
            ["SHA512"] = "2.16.840.1.101.3.4.2.3"
        };
        foreach (var expected in expectedHashes)
            AssertEx.Equal(expected.Value, HashAlgorithmCatalog.FindByName(expected.Key)?.Oid);

        AssertEx.Equal("1.3.6.1.5.5.7.3.8", CertificateRepository.TimeStampingEkuOid);
        AssertEx.Equal("1.3.6.1.4.1.311.3.2.1", AuthenticodeTimestampProcessor.CounterSignatureTypeOid);
        AssertEx.Equal("1.2.840.113549.1.7.1", AuthenticodeTimestampProcessor.DataContentTypeOid);
        AssertEx.Equal("1.2.840.113549.1.9.16.1.4", Rfc3161TimestampProcessor.TstInfoContentTypeOid);
    }

    private static void CanonicalDerRoundTrip()
    {
        var writer = new DerWriter();
        writer.WriteSequence(sequence =>
        {
            sequence.WriteInteger(128);
            sequence.WriteObjectIdentifier("2.999.3.0.42");
            sequence.WriteBoolean(true);
            sequence.WritePositiveInteger([0x00, 0x80]);
        });
        var encoded = writer.Encode();
        AssertEx.Equal((byte)0x30, encoded[0]);

        var outer = new DerReader(encoded);
        var sequenceReader = outer.ReadSequence();
        outer.ThrowIfNotEmpty();
        AssertEx.Equal(128, sequenceReader.ReadIntegerInt32());
        AssertEx.Equal("2.999.3.0.42", sequenceReader.ReadObjectIdentifier());
        AssertEx.True(sequenceReader.ReadBoolean());
        AssertEx.SequenceEqual([0x80], sequenceReader.ReadPositiveInteger());
        sequenceReader.ThrowIfNotEmpty();
    }

    private static void RejectsNonCanonicalDer()
    {
        AssertEx.Throws<DerEncodingException>(() => new DerReader(new byte[] { 0x30, 0x80, 0x00, 0x00 }).ReadSequence());
        AssertEx.Throws<DerEncodingException>(() => new DerReader(new byte[] { 0x04, 0x81, 0x01, 0x00 }).ReadOctetString());
        AssertEx.Throws<DerEncodingException>(() => new DerReader(new byte[] { 0x04, 0x82, 0x00, 0x80 }).ReadOctetString());
        AssertEx.Throws<DerEncodingException>(() => new DerReader(new byte[] { 0x02, 0x02, 0x00, 0x7f }).ReadIntegerInt32());
        AssertEx.Throws<DerEncodingException>(() => new DerReader(new byte[] { 0x02, 0x00 }).ReadPositiveInteger());
        AssertEx.Throws<DerEncodingException>(() => new DerReader(new byte[] { 0x02, 0x05, 0x00, 0x80, 0x00, 0x00, 0x00 }).ReadIntegerInt32());
        AssertEx.Throws<DerEncodingException>(() => new DerReader(new byte[] { 0x02, 0x01, 0xff }).ReadPositiveInteger());
        AssertEx.Throws<DerEncodingException>(() => new DerReader(new byte[] { 0x01, 0x01, 0x01 }).ReadBoolean());
        AssertEx.Throws<DerEncodingException>(() => new DerReader(new byte[] { 0x06, 0x02, 0x80, 0x00 }).ReadObjectIdentifier());
        AssertEx.Throws<ArgumentException>(() =>
            new DerWriter().WriteObjectIdentifier("2.18446744073709551615"));
        AssertEx.Throws<DerEncodingException>(() =>
        {
            var reader = new DerReader(new byte[] { 0x05, 0x00, 0x00 });
            reader.ReadNull();
            reader.ThrowIfNotEmpty();
        });
    }

    private static void CanonicalSetAndOidText()
    {
        DerWriter writer = new();
        writer.WriteSet(set =>
        {
            set.WriteOctetString([2]);
            set.WriteOctetString([1]);
        });
        var setReader = new DerReader(writer.Encode()).ReadConstructed(0x31);
        AssertEx.SequenceEqual([1], setReader.ReadOctetString());
        AssertEx.SequenceEqual([2], setReader.ReadOctetString());
        setReader.ThrowIfNotEmpty();
        AssertEx.Throws<DerEncodingException>(() =>
            new DerReader([0x31, 0x06, 0x04, 0x01, 0x02, 0x04, 0x01, 0x01]).ReadConstructed(0x31));

        AssertEx.Throws<ArgumentException>(() => new DerWriter().WriteObjectIdentifier("01.2.3"));
        AssertEx.Throws<ArgumentException>(() => new DerWriter().WriteObjectIdentifier("1.02.3"));
        AssertEx.Throws<ArgumentException>(() => new DerWriter().WriteObjectIdentifier("1.2.03"));
    }

    private static void RejectsBoundedValues()
    {
        DerWriter writer = new();
        writer.WriteOctetString(new byte[33]);
        AssertEx.Throws<DerSizeLimitException>(() => new DerReader(writer.Encode()).ReadOctetString(32));

        writer = new DerWriter();
        var largeInteger = new byte[33];
        largeInteger[0] = 1;
        writer.WritePositiveInteger(largeInteger);
        AssertEx.Throws<DerSizeLimitException>(() => new DerReader(writer.Encode()).ReadPositiveInteger(32));

        writer = new DerWriter();
        writer.WriteSequence(sequence => sequence.WriteOctetString(new byte[32]));
        AssertEx.Throws<DerSizeLimitException>(() => new DerReader(writer.Encode()).ReadEncodedValue(16));
    }

    private static void BoundsObjectIdentifierWork()
    {
        // The maximum supported component count remains comfortably above standards OIDs.
        var maximumComponents = new byte[128];
        maximumComponents[0] = 42; // 1.2
        for (var index = 1; index < maximumComponents.Length; index++) maximumComponents[index] = 1;
        var maximumText = new DerReader(BuildEncodedObjectIdentifier(maximumComponents)).ReadObjectIdentifier();
        AssertEx.Equal(129, maximumText.Split('.').Length);
        DerWriter maximumWriter = new();
        maximumWriter.WriteObjectIdentifier(maximumText);
        AssertEx.Equal(maximumText, new DerReader(maximumWriter.Encode()).ReadObjectIdentifier());

        var tooManyComponents = new byte[129];
        tooManyComponents[0] = 42;
        for (var index = 1; index < tooManyComponents.Length; index++) tooManyComponents[index] = 1;
        AssertEx.Throws<DerEncodingException>(() =>
            new DerReader(BuildEncodedObjectIdentifier(tooManyComponents)).ReadObjectIdentifier());

        // Reject a maximum-size HTTP-body OID before iterating over attacker-supplied arcs.
        var oversizedContents = new byte[1024 * 1024];
        oversizedContents[0] = 42;
        var encoded = BuildEncodedObjectIdentifier(oversizedContents);
        var timer = Stopwatch.StartNew();
        AssertEx.Throws<DerEncodingException>(() => new DerReader(encoded).ReadObjectIdentifier());
        AssertEx.True(timer.Elapsed < TimeSpan.FromSeconds(2),
            "Oversized OID rejection should be bounded independently of its arc count.");

        // Protocol parsing must map the bounded DER rejection to an RFC 3161 format error.
        var protocolOid = BuildEncodedObjectIdentifier(new byte[257]);
        var requestWriter = new DerWriter();
        requestWriter.WriteSequence(request =>
        {
            request.WriteInteger(1);
            request.WriteSequence(imprint =>
            {
                imprint.WriteSequence(algorithm => algorithm.WriteEncodedValue(protocolOid));
                imprint.WriteOctetString(new byte[32]);
            });
        });
        var exception = AssertEx.Throws<Rfc3161ProtocolException>(() =>
            Rfc3161Request.Parse(requestWriter.Encode()));
        AssertEx.Equal(Rfc3161FailureInfo.BadDataFormat, exception.FailureInfo);
    }

    private static byte[] BuildEncodedObjectIdentifier(byte[] contents)
    {
        var lengthBytes = contents.Length switch
        {
            < 128 => new byte[] { (byte)contents.Length },
            <= byte.MaxValue => new byte[] { 0x81, (byte)contents.Length },
            <= ushort.MaxValue => new byte[] { 0x82, (byte)(contents.Length >> 8), (byte)contents.Length },
            <= 0x00ffffff => new byte[]
            {
                0x83,
                (byte)(contents.Length >> 16),
                (byte)(contents.Length >> 8),
                (byte)contents.Length
            },
            _ => new byte[]
            {
                0x84,
                (byte)(contents.Length >> 24),
                (byte)(contents.Length >> 16),
                (byte)(contents.Length >> 8),
                (byte)contents.Length
            }
        };
        var encoded = new byte[1 + lengthBytes.Length + contents.Length];
        encoded[0] = 0x06;
        Buffer.BlockCopy(lengthBytes, 0, encoded, 1, lengthBytes.Length);
        Buffer.BlockCopy(contents, 0, encoded, 1 + lengthBytes.Length, contents.Length);
        return encoded;
    }

    private static void ParsesRfc3161Request()
    {
        var digest = new byte[32];
        for (var index = 0; index < digest.Length; index++)
        {
            digest[index] = (byte)index;
        }

        byte[] nonce = [0x80, 0x01, 0x02, 0x03];
        var encoded = TestFixtures.BuildRfc3161Request(
            TestFixtures.Sha256Oid,
            digest,
            TestFixtures.AlternatePolicyOid,
            nonce,
            true,
            includeNullParameters: false);
        var request = Rfc3161Request.Parse(encoded);
        AssertEx.Equal(TestFixtures.Sha256Oid, request.HashAlgorithmOid);
        AssertEx.SequenceEqual(digest, request.MessageImprint);
        AssertEx.Equal(TestFixtures.AlternatePolicyOid, request.RequestedPolicyOid);
        AssertEx.SequenceEqual(nonce, request.Nonce);
        AssertEx.True(request.CertificateRequested);

        var noOptions = Rfc3161Request.Parse(TestFixtures.BuildRfc3161Request(TestFixtures.Sha256Oid, digest));
        AssertEx.Equal<string>(null, noOptions.RequestedPolicyOid);
        AssertEx.Equal<byte[]>(null, noOptions.Nonce);
        AssertEx.False(noOptions.CertificateRequested);
    }

    private static void RejectsInvalidVersionAndNonce()
    {
        var badVersion = AssertEx.Throws<Rfc3161ProtocolException>(() => Rfc3161Request.Parse(
            TestFixtures.BuildRfc3161Request(TestFixtures.Sha256Oid, new byte[32], version: 2)));
        AssertEx.Equal(Rfc3161FailureInfo.BadRequest, badVersion.FailureInfo);

        var oversizedNonce = new byte[33];
        oversizedNonce[0] = 1;
        var badNonce = AssertEx.Throws<Rfc3161ProtocolException>(() => Rfc3161Request.Parse(
            TestFixtures.BuildRfc3161Request(TestFixtures.Sha256Oid, new byte[32], nonce: oversizedNonce)));
        AssertEx.Equal(Rfc3161FailureInfo.BadRequest, badNonce.FailureInfo);
        AssertEx.True(badNonce.InnerException is DerSizeLimitException);

        var oversizedDigest = AssertEx.Throws<Rfc3161ProtocolException>(() => Rfc3161Request.Parse(
            TestFixtures.BuildRfc3161Request(TestFixtures.Sha256Oid, new byte[65])));
        AssertEx.Equal(Rfc3161FailureInfo.BadDataFormat, oversizedDigest.FailureInfo);
        AssertEx.True(oversizedDigest.InnerException is DerSizeLimitException);

        DerWriter parameters = new();
        parameters.WriteOctetString(new byte[300]);
        var oversizedAlgorithm = AssertEx.Throws<Rfc3161ProtocolException>(() => Rfc3161Request.Parse(
            TestFixtures.BuildRfc3161RequestWithAlgorithmParameters(parameters.Encode())));
        AssertEx.Equal(Rfc3161FailureInfo.BadDataFormat, oversizedAlgorithm.FailureInfo);
        AssertEx.True(oversizedAlgorithm.InnerException is DerSizeLimitException);
    }

    private static void RejectsExtensionsAndMalformedDer()
    {
        var extension = AssertEx.Throws<Rfc3161ProtocolException>(() => Rfc3161Request.Parse(
            TestFixtures.BuildRfc3161Request(TestFixtures.Sha256Oid, new byte[32], includeExtensions: true)));
        AssertEx.Equal(Rfc3161FailureInfo.UnacceptedExtension, extension.FailureInfo);

        var valid = TestFixtures.BuildRfc3161Request(TestFixtures.Sha256Oid, new byte[32]);
        var trailing = new byte[valid.Length + 1];
        Buffer.BlockCopy(valid, 0, trailing, 0, valid.Length);
        var malformed = AssertEx.Throws<Rfc3161ProtocolException>(() => Rfc3161Request.Parse(trailing));
        AssertEx.Equal(Rfc3161FailureInfo.BadDataFormat, malformed.FailureInfo);

        malformed = AssertEx.Throws<Rfc3161ProtocolException>(() => Rfc3161Request.Parse(new byte[] { 0x30, 0x80 }));
        AssertEx.Equal(Rfc3161FailureInfo.BadDataFormat, malformed.FailureInfo);
        malformed = AssertEx.Throws<Rfc3161ProtocolException>(() => Rfc3161Request.Parse(
            TestFixtures.BuildRfc3161Request(
                TestFixtures.Sha256Oid,
                new byte[32],
                explicitFalseCertificateRequest: true)));
        AssertEx.Equal(Rfc3161FailureInfo.BadDataFormat, malformed.FailureInfo);
        AssertEx.Equal(Rfc3161FailureInfo.BadDataFormat,
            AssertEx.Throws<Rfc3161ProtocolException>(() => Rfc3161Request.Parse(null)).FailureInfo);
    }

    private static void RejectsInvalidAlgorithmParameters()
    {
        var exception = AssertEx.Throws<Rfc3161ProtocolException>(() => Rfc3161Request.Parse(
            TestFixtures.BuildRfc3161RequestWithAlgorithmParameters(new byte[] { 0x04, 0x00 })));
        AssertEx.Equal(Rfc3161FailureInfo.BadDataFormat, exception.FailureInfo);
    }

    private static void ParsesAndRejectsAuthenticodeRequests()
    {
        byte[] signature = [0x01, 0x02, 0x80, 0xff, 0x55];
        AssertEx.SequenceEqual(signature, AuthenticodeTimestampProcessor.ParseRequest(
            TestFixtures.BuildAuthenticodeRequest(signature)));

        AssertEx.Throws<AuthenticodeProtocolException>(() => AuthenticodeTimestampProcessor.ParseRequest(null));
        AssertEx.Throws<AuthenticodeProtocolException>(() => AuthenticodeTimestampProcessor.ParseRequest(
            TestFixtures.BuildAuthenticodeRequest(signature, "1.2.3")));
        AssertEx.Throws<AuthenticodeProtocolException>(() => AuthenticodeTimestampProcessor.ParseRequest(
            TestFixtures.BuildAuthenticodeRequest(signature, includeAttributes: true)));
        AssertEx.Throws<AuthenticodeProtocolException>(() => AuthenticodeTimestampProcessor.ParseRequest(
            TestFixtures.BuildAuthenticodeRequest(signature, contentTypeOid: "1.2.840.113549.1.7.2")));
        AssertEx.Throws<AuthenticodeProtocolException>(() => AuthenticodeTimestampProcessor.ParseRequest(
            TestFixtures.BuildAuthenticodeRequest(new byte[0])));
        AssertEx.Throws<AuthenticodeProtocolException>(() => AuthenticodeTimestampProcessor.ParseRequest(
            new byte[] { 0x30, 0x80 }));
        var oversized = AssertEx.Throws<AuthenticodeProtocolException>(() =>
            AuthenticodeTimestampProcessor.ParseRequest(
                TestFixtures.BuildAuthenticodeRequest(new byte[1048577])));
        AssertEx.True(oversized.InnerException is DerSizeLimitException);
    }

    private static void SignToolHttpFraming()
    {
        var der = TestFixtures.BuildAuthenticodeRequest([1, 2, 3, 4]);
        var base64 = Encoding.ASCII.GetBytes(Convert.ToBase64String(der, Base64FormattingOptions.InsertLineBreaks));
        var signToolBody = new byte[base64.Length + 1];
        Buffer.BlockCopy(base64, 0, signToolBody, 0, base64.Length);
        signToolBody[signToolBody.Length - 1] = 0;
        AssertEx.SequenceEqual(der, LegacyAuthenticodeHttpCodec.DecodeRequestBody(signToolBody));
        AssertEx.SequenceEqual(der, Convert.FromBase64String(Encoding.ASCII.GetString(
            LegacyAuthenticodeHttpCodec.EncodeResponseBody(der))));
        AssertEx.Throws<AuthenticodeProtocolException>(() =>
            LegacyAuthenticodeHttpCodec.DecodeRequestBody(new byte[] { (byte)'Q', 0, (byte)'Q', (byte)'=' }));
    }
}
