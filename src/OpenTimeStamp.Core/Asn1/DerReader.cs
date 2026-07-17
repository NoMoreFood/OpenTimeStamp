using System;
using System.Formats.Asn1;
using System.Globalization;
using System.Text;

namespace OpenTimeStamp.Asn1;

public sealed class DerReader
{
    // OIDs in the supported protocols are short (typically fewer than 32 bytes).
    // Bound both encoded size and arc count before doing attacker-controlled work.
    private const int MaximumObjectIdentifierBytes = 256;
    private const int MaximumObjectIdentifierComponents = 128;
    private readonly AsnReader reader;

    public DerReader(byte[] data)
    {
        if (data is null) throw new ArgumentNullException(nameof(data));

        reader = new AsnReader(data, AsnEncodingRules.DER);
    }

    private DerReader(AsnReader reader) =>
        this.reader = reader;

    public bool HasData => reader.HasData;

    public byte PeekTag()
    {
        try
        {
            return GetEncodedTagByte(reader.PeekTag());
        }
        catch (AsnContentException)
        {
            throw new DerEncodingException("The DER value is truncated or invalid.");
        }
    }

    public DerReader ReadSequence() => ReadConstructed(0x30);

    public DerReader ReadConstructed(byte expectedTag)
    {
        if (expectedTag == 0x31)
        {
            PeekContents(expectedTag, "The constructed DER value is invalid.");
            try
            {
                return new DerReader(reader.ReadSetOf());
            }
            catch (AsnContentException)
            {
                throw new DerEncodingException("The constructed DER value is invalid.");
            }
        }

        var contents = PeekContents(expectedTag, "The constructed DER value is invalid.");
        ReadEncodedValueCore("The constructed DER value is invalid.");
        return new DerReader(new AsnReader(contents, AsnEncodingRules.DER));
    }

    public int ReadIntegerInt32()
    {
        var encoded = ReadIntegerContents();
        if ((encoded.Span[0] & 0x80) != 0 || encoded.Length > 5 || (encoded.Length == 5 && encoded.Span[0] != 0))
        {
            throw new DerEncodingException("The INTEGER is outside the supported non-negative Int32 range.");
        }

        // Decode through Int64 so values beyond Int32 can be rejected before a narrowing conversion.
        long result = 0;
        foreach (var item in encoded.Span)
        {
            result = (result << 8) | item;
            if (result > int.MaxValue)
            {
                throw new DerEncodingException("The INTEGER is outside the supported non-negative Int32 range.");
            }
        }

        return (int)result;
    }

    public byte[] ReadPositiveInteger() => ReadPositiveInteger(int.MaxValue);

    public byte[] ReadPositiveInteger(int maximumLength)
    {
        if (maximumLength < 0) throw new ArgumentOutOfRangeException(nameof(maximumLength));

        var encoded = ReadIntegerContents();
        if ((encoded.Span[0] & 0x80) != 0)
        {
            throw new DerEncodingException("Negative INTEGER values are not accepted.");
        }

        // Strip the optional sign-protection byte while preserving the integer magnitude.
        var start = encoded.Length > 1 && encoded.Span[0] == 0 ? 1 : 0;
        var length = encoded.Length - start;
        if (length > maximumLength)
        {
            throw new DerSizeLimitException("The INTEGER exceeds the supported size.");
        }

        var result = new byte[length];
        encoded.Span.Slice(start).CopyTo(result);
        return result;
    }

    public string ReadObjectIdentifier()
    {
        var contents = PeekContents(0x06, "The OBJECT IDENTIFIER is invalid.");
        if (contents.Length == 0)
        {
            throw new DerEncodingException("The OBJECT IDENTIFIER is empty.");
        }

        if (contents.Length > MaximumObjectIdentifierBytes)
        {
            throw new DerEncodingException("The OBJECT IDENTIFIER is too large.");
        }

        // Bound and validate each base-128 component before constructing the dotted-decimal text.
        var position = 0;
        var componentCount = 0;
        StringBuilder text = new();
        while (position < contents.Length)
        {
            componentCount++;
            if (componentCount > MaximumObjectIdentifierComponents)
            {
                throw new DerEncodingException("The OBJECT IDENTIFIER contains too many components.");
            }

            ulong component = 0;
            var firstByte = true;
            while (true)
            {
                if (position >= contents.Length)
                {
                    throw new DerEncodingException("The OBJECT IDENTIFIER is truncated.");
                }

                var current = contents.Span[position++];
                if (firstByte && current == 0x80)
                {
                    throw new DerEncodingException("The OBJECT IDENTIFIER is not minimally encoded.");
                }

                firstByte = false;
                if (component > (ulong.MaxValue >> 7))
                {
                    throw new DerEncodingException("The OBJECT IDENTIFIER component is too large.");
                }

                component = (component << 7) | (uint)(current & 0x7f);
                if ((current & 0x80) == 0) break;
            }

            if (componentCount == 1)
            {
                var firstArc = component < 40 ? 0UL : component < 80 ? 1UL : 2UL;
                var secondArc = component - (firstArc * 40);
                text.Append(firstArc.ToString(CultureInfo.InvariantCulture));
                text.Append('.');
                text.Append(secondArc.ToString(CultureInfo.InvariantCulture));
            }
            else
            {
                text.Append('.');
                text.Append(component.ToString(CultureInfo.InvariantCulture));
            }
        }

        ReadEncodedValueCore("The OBJECT IDENTIFIER is invalid.");
        return text.ToString();
    }

    public byte[] ReadOctetString() => ReadOctetString(int.MaxValue);

    public byte[] ReadOctetString(int maximumLength)
    {
        if (maximumLength < 0) throw new ArgumentOutOfRangeException(nameof(maximumLength));

        var contents = PeekContents(0x04, "The OCTET STRING is invalid.");
        if (contents.Length > maximumLength)
        {
            throw new DerSizeLimitException("The OCTET STRING exceeds the supported size.");
        }

        try
        {
            return reader.ReadOctetString();
        }
        catch (AsnContentException)
        {
            throw new DerEncodingException("The OCTET STRING is invalid.");
        }
    }

    public bool ReadBoolean()
    {
        var contents = PeekContents(0x01, "The BOOLEAN is not canonically encoded.");
        if (contents.Length != 1 || (contents.Span[0] != 0x00 && contents.Span[0] != 0xff))
        {
            throw new DerEncodingException("The BOOLEAN is not canonically encoded.");
        }

        try
        {
            return reader.ReadBoolean();
        }
        catch (AsnContentException)
        {
            throw new DerEncodingException("The BOOLEAN is not canonically encoded.");
        }
    }

    public void ReadNull()
    {
        var contents = PeekContents(0x05, "The NULL value is invalid.");
        if (contents.Length != 0)
        {
            throw new DerEncodingException("The NULL value is invalid.");
        }

        try
        {
            reader.ReadNull();
        }
        catch (AsnContentException)
        {
            throw new DerEncodingException("The NULL value is invalid.");
        }
    }

    public byte[] ReadEncodedValue() => ReadEncodedValue(int.MaxValue);

    public byte[] ReadEncodedValue(int maximumEncodedLength)
    {
        if (maximumEncodedLength < 0) throw new ArgumentOutOfRangeException(nameof(maximumEncodedLength));

        ReadOnlyMemory<byte> encoded;
        try
        {
            encoded = reader.PeekEncodedValue();
        }
        catch (AsnContentException)
        {
            throw new DerEncodingException("The DER value is truncated or invalid.");
        }

        if (encoded.Length > maximumEncodedLength)
        {
            throw new DerSizeLimitException("The encoded DER value exceeds the supported size.");
        }

        return ReadEncodedValueCore("The DER value is truncated or invalid.").ToArray();
    }

    public void ThrowIfNotEmpty()
    {
        if (HasData)
        {
            throw new DerEncodingException("Unexpected trailing ASN.1 data was present.");
        }
    }

    private ReadOnlyMemory<byte> ReadIntegerContents()
    {
        var contents = PeekContents(0x02, "The INTEGER is invalid.");
        ValidateInteger(contents.Span);
        try
        {
            return reader.ReadIntegerBytes();
        }
        catch (AsnContentException)
        {
            throw new DerEncodingException("The INTEGER is invalid.");
        }
    }

    private ReadOnlyMemory<byte> PeekContents(byte expectedTag, string invalidMessage)
    {
        try
        {
            var actualTag = reader.PeekTag();
            var expected = DecodeTag(expectedTag);
            if (actualTag != expected)
            {
                throw new DerEncodingException(string.Format(CultureInfo.InvariantCulture,
                    "Expected ASN.1 tag 0x{0:x2}, found 0x{1:x2}.", expectedTag, GetEncodedTagByte(actualTag)));
            }

            return reader.PeekContentBytes();
        }
        catch (AsnContentException)
        {
            throw new DerEncodingException(invalidMessage);
        }
    }

    private ReadOnlyMemory<byte> ReadEncodedValueCore(string invalidMessage)
    {
        try
        {
            return reader.ReadEncodedValue();
        }
        catch (AsnContentException)
        {
            throw new DerEncodingException(invalidMessage);
        }
    }

    private static void ValidateInteger(ReadOnlySpan<byte> value)
    {
        if (value.Length == 0)
        {
            throw new DerEncodingException("The INTEGER is empty.");
        }

        if (value.Length > 1)
        {
            var first = value[0];
            var second = value[1];
            if ((first == 0x00 && (second & 0x80) == 0) || (first == 0xff && (second & 0x80) != 0))
            {
                throw new DerEncodingException("The INTEGER is not minimally encoded.");
            }
        }
    }

    private static Asn1Tag DecodeTag(byte encoded) => new(
        (TagClass)(encoded & 0xc0), encoded & 0x1f, (encoded & 0x20) != 0);

    private static byte GetEncodedTagByte(Asn1Tag tag) =>
        (byte)((int)tag.TagClass | (tag.IsConstructed ? 0x20 : 0) | Math.Min(tag.TagValue, 0x1f));
}
