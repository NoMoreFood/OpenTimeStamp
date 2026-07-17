using System;
using System.Security.Cryptography;

namespace OpenTimeStamp.Cryptography;

internal static class KnownOids
{
    // Keep canonical values as fail-safe fallbacks for machines with incomplete OID registration.
    internal const string Md5Value = "1.2.840.113549.2.5";
    internal const string Sha1Value = "1.3.14.3.2.26";
    internal const string Sha224Value = "2.16.840.1.101.3.4.2.4";
    internal const string Sha256Value = "2.16.840.1.101.3.4.2.1";
    internal const string Sha384Value = "2.16.840.1.101.3.4.2.2";
    internal const string Sha512Value = "2.16.840.1.101.3.4.2.3";
    internal const string MlDsa44Value = "2.16.840.1.101.3.4.3.17";
    internal const string MlDsa65Value = "2.16.840.1.101.3.4.3.18";
    internal const string MlDsa87Value = "2.16.840.1.101.3.4.3.19";
    internal const string TimeStampingEkuValue = "1.3.6.1.5.5.7.3.8";
    internal const string Pkcs7DataValue = "1.2.840.113549.1.7.1";
    internal const string Pkcs7SignedDataValue = "1.2.840.113549.1.7.2";

    // .NET Framework has no public constants for these RFC and Microsoft protocol identifiers.
    internal const string AuthenticodeCounterSignature = "1.3.6.1.4.1.311.3.2.1";
    internal const string TstInfoContentType = "1.2.840.113549.1.9.16.1.4";
    internal const string SigningCertificate = "1.2.840.113549.1.9.16.2.12";
    internal const string SigningCertificateV2 = "1.2.840.113549.1.9.16.2.47";
    internal const string CmsAlgorithmProtection = "1.2.840.113549.1.9.52";

    // Prefer Windows' built-in OID registry only when it returns the exact standards value.
    internal static readonly string Md5 = Resolve("MD5", OidGroup.HashAlgorithm, Md5Value);
    internal static readonly string Sha1 = Resolve("SHA1", OidGroup.HashAlgorithm, Sha1Value);
    internal static readonly string Sha224 = Resolve("SHA224", OidGroup.HashAlgorithm, Sha224Value);
    internal static readonly string Sha256 = Resolve("SHA256", OidGroup.HashAlgorithm, Sha256Value);
    internal static readonly string Sha384 = Resolve("SHA384", OidGroup.HashAlgorithm, Sha384Value);
    internal static readonly string Sha512 = Resolve("SHA512", OidGroup.HashAlgorithm, Sha512Value);
    internal static readonly string TimeStampingEku = Resolve("Time Stamping", OidGroup.EnhancedKeyUsage, TimeStampingEkuValue);
    internal static readonly string Pkcs7Data = Resolve("PKCS 7 Data", OidGroup.All, Pkcs7DataValue);

    private static string Resolve(string friendlyName, OidGroup group, string requiredValue)
    {
        try
        {
            var registered = Oid.FromFriendlyName(friendlyName, group);
            if (string.Equals(registered?.Value, requiredValue, StringComparison.Ordinal)) return registered.Value;
        }
        catch (Exception ex) when (ex is CryptographicException or ArgumentException)
        {
            // A missing Windows registration must never alter protocol behavior.
        }

        return requiredValue;
    }
}
