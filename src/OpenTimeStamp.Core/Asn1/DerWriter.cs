using System;
using System.Formats.Asn1;
using System.Globalization;

namespace OpenTimeStamp.Asn1;

public sealed class DerWriter
{
    private readonly AsnWriter writer = new(AsnEncodingRules.DER);

    public byte[] Encode() => writer.Encode();

    public void WriteSequence(Action<DerWriter> content) =>
        WriteConstructed(new Asn1Tag(UniversalTagNumber.Sequence, isConstructed: true), content);

    public void WriteSet(Action<DerWriter> content)
    {
        if (content is null) throw new ArgumentNullException(nameof(content));

        using (writer.PushSetOf()) content(this);
    }

    public void WriteContextSpecificConstructed(int tagNumber, Action<DerWriter> content)
    {
        if (tagNumber is < 0 or > 30) throw new ArgumentOutOfRangeException(nameof(tagNumber));

        WriteConstructed(new Asn1Tag(TagClass.ContextSpecific, tagNumber, isConstructed: true), content);
    }

    public void WriteContextSpecificInteger(int tagNumber, int value)
    {
        if (tagNumber is < 0 or > 30) throw new ArgumentOutOfRangeException(nameof(tagNumber));
        if (value < 0) throw new ArgumentOutOfRangeException(nameof(value));

        writer.WriteInteger((long)value, new Asn1Tag(TagClass.ContextSpecific, tagNumber));
    }

    public void WriteInteger(int value)
    {
        if (value < 0) throw new ArgumentOutOfRangeException(nameof(value));

        writer.WriteInteger((long)value);
    }

    public void WritePositiveInteger(byte[] magnitude)
    {
        if (magnitude is null) throw new ArgumentNullException(nameof(magnitude));

        // Remove redundant leading zeros; the platform writer adds a sign-protection byte only when needed.
        var first = 0;
        while (first < magnitude.Length - 1 && magnitude[first] == 0) first++;

        if (magnitude.Length == 0)
        {
            writer.WriteInteger(0L);
            return;
        }

        writer.WriteIntegerUnsigned(magnitude.AsSpan(first));
    }

    public void WriteObjectIdentifier(string oid)
    {
        if (string.IsNullOrWhiteSpace(oid))
        {
            throw new ArgumentException("An object identifier is required.", nameof(oid));
        }

        // Preserve the wrapper's canonical text and UInt64 component limits before delegating the encoding.
        var parts = oid.Split('.');
        if (parts.Length < 2)
        {
            throw new ArgumentException("The object identifier is invalid.", nameof(oid));
        }

        if (!ulong.TryParse(parts[0], NumberStyles.None, CultureInfo.InvariantCulture, out var first) ||
            !ulong.TryParse(parts[1], NumberStyles.None, CultureInfo.InvariantCulture, out var second) ||
            !IsCanonicalOidComponent(parts[0]) || !IsCanonicalOidComponent(parts[1]) ||
            first > 2 || (first < 2 && second > 39))
        {
            throw new ArgumentException("The object identifier is invalid.", nameof(oid));
        }

        if (first == 2 && second > ulong.MaxValue - 80)
        {
            throw new ArgumentException("The object identifier component is too large.", nameof(oid));
        }

        for (var i = 2; i < parts.Length; i++)
        {
            if (!ulong.TryParse(parts[i], NumberStyles.None, CultureInfo.InvariantCulture, out _) ||
                !IsCanonicalOidComponent(parts[i]))
            {
                throw new ArgumentException("The object identifier is invalid.", nameof(oid));
            }
        }

        writer.WriteObjectIdentifier(oid);
    }

    public void WriteOctetString(byte[] value)
    {
        if (value is null) throw new ArgumentNullException(nameof(value));

        writer.WriteOctetString(value);
    }

    public void WriteBoolean(bool value) => writer.WriteBoolean(value);

    public void WriteNull() => writer.WriteNull();

    public void WriteUtf8String(string value) =>
        writer.WriteCharacterString(UniversalTagNumber.UTF8String, value ?? string.Empty);

    public void WriteGeneralizedTime(DateTime value)
    {
        var utc = value.ToUniversalTime();
        writer.WriteGeneralizedTime(new DateTimeOffset(utc), omitFractionalSeconds: false);
    }

    public void WriteBitString(int bitIndex)
    {
        if (bitIndex < 0) throw new ArgumentOutOfRangeException(nameof(bitIndex));

        var byteCount = (bitIndex / 8) + 1;
        var unusedBits = (byteCount * 8) - (bitIndex + 1);
        var value = new byte[byteCount];
        value[bitIndex / 8] = (byte)(0x80 >> (bitIndex % 8));
        writer.WriteBitString(value, unusedBits);
    }

    public void WriteEncodedValue(byte[] encoded)
    {
        if (encoded is null || encoded.Length == 0)
        {
            throw new ArgumentException("An encoded value is required.", nameof(encoded));
        }

        writer.WriteEncodedValue(encoded);
    }

    private void WriteConstructed(Asn1Tag tag, Action<DerWriter> content)
    {
        if (content is null) throw new ArgumentNullException(nameof(content));

        using (writer.PushSequence(tag)) content(this);
    }

    private static bool IsCanonicalOidComponent(string value) =>
        value.Length == 1 || value[0] != '0';
}
