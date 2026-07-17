using System;
using System.Security.Cryptography;

namespace OpenTimeStamp.Cryptography;

public static class WindowsHash
{
    public static bool FixedTimeEquals(byte[] left, byte[] right)
    {
        if (left is null || right is null || left.Length != right.Length) return false;

        var difference = 0;
        for (var index = 0; index < left.Length; index++) difference |= left[index] ^ right[index];
        return difference == 0;
    }

    public static byte[] ComputeSha1(byte[] value)
    {
        if (value is null) throw new ArgumentNullException(nameof(value));

        // Use the Windows CNG provider rather than a managed hash implementation.
        using SHA1Cng algorithm = new();
        return algorithm.ComputeHash(value);
    }

    public static byte[] ComputeSha256(byte[] value)
    {
        if (value is null) throw new ArgumentNullException(nameof(value));

        // Use the Windows CNG provider rather than a managed hash implementation.
        using SHA256Cng algorithm = new();
        return algorithm.ComputeHash(value);
    }

    public static byte[] ComputeSha384(byte[] value)
    {
        if (value is null) throw new ArgumentNullException(nameof(value));

        using SHA384Cng algorithm = new();
        return algorithm.ComputeHash(value);
    }

    public static byte[] ComputeSha512(byte[] value)
    {
        if (value is null) throw new ArgumentNullException(nameof(value));

        using SHA512Cng algorithm = new();
        return algorithm.ComputeHash(value);
    }
}
