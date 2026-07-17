using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Linq;

namespace OpenTimeStamp.Cryptography;

public sealed class TimestampHashAlgorithm
{
    internal TimestampHashAlgorithm(string name, string oid, int digestLength, bool legacy, bool cmsSigningSupported)
    {
        Name = name;
        Oid = oid;
        DigestLength = digestLength;
        IsLegacy = legacy;
        CmsSigningSupported = cmsSigningSupported;
    }

    public string Name { get; }

    public string Oid { get; }

    public int DigestLength { get; }

    public bool IsLegacy { get; }

    public bool CmsSigningSupported { get; }
}

public static class HashAlgorithmCatalog
{
    // Keep digest length, legacy status, and CMS support in one immutable lookup table.
    private static readonly ReadOnlyCollection<TimestampHashAlgorithm> algorithms = new(
    [
        new("MD5", KnownOids.Md5, 16, true, false),
        new("SHA1", KnownOids.Sha1, 20, true, true),
        new("SHA224", KnownOids.Sha224, 28, false, false),
        new("SHA256", KnownOids.Sha256, 32, false, true),
        new("SHA384", KnownOids.Sha384, 48, false, true),
        new("SHA512", KnownOids.Sha512, 64, false, true)
    ]);

    public static IReadOnlyList<TimestampHashAlgorithm> All => algorithms;

    public static TimestampHashAlgorithm FindByOid(string oid) =>
        algorithms.FirstOrDefault(item => string.Equals(item.Oid, oid, StringComparison.Ordinal));

    public static TimestampHashAlgorithm FindByName(string name)
    {
        var normalized = NormalizeName(name);
        return algorithms.FirstOrDefault(item => string.Equals(item.Name, normalized, StringComparison.Ordinal));
    }

    public static string NormalizeName(string value) =>
        (value ?? string.Empty).Replace("-", string.Empty).Trim().ToUpperInvariant();
}
