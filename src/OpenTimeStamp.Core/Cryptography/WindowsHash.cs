using System;
using System.Security.Cryptography;

namespace OpenTimeStamp.Cryptography;

public static class WindowsHash
{
    public static bool FixedTimeEquals(byte[]? left, byte[]? right)
    {
        if (left is null || right is null || left.Length != right.Length) return false;

        var difference = 0;
        for (var index = 0; index < left.Length; index++) difference |= left[index] ^ right[index];
        return difference == 0;
    }

    public static byte[] ComputeSha256(byte[] value) => Compute("SHA256", value);

    /// <summary>
    /// Hashes with the Windows CNG provider for a catalog name that CMS signing supports
    /// (SHA1, SHA256, SHA384, or SHA512) rather than a managed implementation.
    /// </summary>
    public static byte[] Compute(string algorithmName, byte[] value)
    {
        if (value is null) throw new ArgumentNullException(nameof(value));

        using HashAlgorithm algorithm = algorithmName switch
        {
#pragma warning disable CA5350 // SHA-1 is required for explicitly enabled legacy timestamp algorithms.
            "SHA1" => new SHA1Cng(),
#pragma warning restore CA5350
            "SHA256" => new SHA256Cng(),
            "SHA384" => new SHA384Cng(),
            "SHA512" => new SHA512Cng(),
            _ => throw new CryptographicException("The hash algorithm is not supported.")
        };
        return algorithm.ComputeHash(value);
    }
}
