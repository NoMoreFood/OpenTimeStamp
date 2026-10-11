namespace OpenTimeStamp.Infrastructure;

/// <summary>The single hexadecimal text encoder for digests, serials, and thumbprints.</summary>
public static class Hex
{
    /// <summary>Returns lowercase hexadecimal text, or null when <paramref name="value"/> is null.</summary>
    public static string ToLower(byte[] value) => Encode(value, "0123456789abcdef");

    /// <summary>Returns uppercase hexadecimal text, or null when <paramref name="value"/> is null.</summary>
    public static string ToUpper(byte[] value) => Encode(value, "0123456789ABCDEF");

    private static string Encode(byte[] value, string alphabet)
    {
        if (value is null) return null;

        var characters = new char[value.Length * 2];
        for (var index = 0; index < value.Length; index++)
        {
            characters[index * 2] = alphabet[value[index] >> 4];
            characters[(index * 2) + 1] = alphabet[value[index] & 0x0f];
        }

        return new string(characters);
    }
}
